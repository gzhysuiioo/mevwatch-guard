package mevwatch

import (
	"reflect"
	"testing"
)

// incrOverflowStuckInitial 是“已提交 incr 溢出使应用停住，随后发生任期冲突替换”
// 回归场景共享的初始状态：当前任期 1，索引 1..3 的任期均为 1，提交位置为 2。
// idx1 把 count 写成有符号 64 位整数最大值，idx2 的 incr count=1 已提交但累加
// 结果超出 int64 范围——应用位置因此停在 1，错误指向 idx2；idx3 的
// incr count=-1 尚未提交，既不能提前把计数减回来消除溢出错误，也不能提前暴露。
func incrOverflowStuckInitial() InitialState {
	return InitialState{CurrentTerm: 1, CommittedIndex: 2, Log: []LogEntry{
		entry(1, 1, "set count=9223372036854775807"),
		entry(2, 1, "incr count=1"),
		entry(3, 1, "incr count=-1"), // 未提交：不能提前生效
	}}
}

// wantOverflowLog 是任期 2 替换完成后的期望日志：原两条已提交记录保留，旧的
// 减一命令消失，新后缀（idx3 set count=0、idx4 incr count=1，任期均为 2）完整出现。
var wantOverflowLog = []LogEntry{
	entry(1, 1, "set count=9223372036854775807"),
	entry(2, 1, "incr count=1"),
	entry(3, 2, "set count=0"),
	entry(4, 2, "incr count=1"),
}

// checkOverflowStuck 断言应用状态仍停在最初的溢出错误上：应用位置 1、错误指向
// idx2 且原因为 incr 结果超出有符号 64 位整数范围；kv 非 nil 时还要求键值表
// 只有最大整数的字符串值（逐条结果没有键值表，传 nil 跳过该项）。
func checkOverflowStuck(t *testing.T, appliedIndex int, kv map[string]string, applyErr *ApplyError) {
	t.Helper()
	if appliedIndex != 1 {
		t.Fatalf("appliedIndex = %d, want 1 (stuck before the overflowing incr)", appliedIndex)
	}
	if kv != nil && !reflect.DeepEqual(kv, map[string]string{"count": "9223372036854775807"}) {
		t.Fatalf("kv = %v, want only count=9223372036854775807", kv)
	}
	if applyErr == nil || applyErr.Index != 2 || applyErr.Reason != ApplyReasonIncrOverflow {
		t.Fatalf("applyError = %+v, want index 2 incr overflow", applyErr)
	}
}

// TestKVIncrOverflowStuckOnInitialCommittedPrefix 回归保障起点状态：初始已提交
// 前缀应用后，count 保留最大整数的字符串值，应用位置停在 1，错误指向 idx2 且
// 原因明确表示累加结果超出有符号 64 位整数范围；未提交的 idx3（incr count=-1）
// 不能提前把计数减小来消除这个错误。
func TestKVIncrOverflowStuckOnInitialCommittedPrefix(t *testing.T) {
	start := runKV(t, incrOverflowStuckInitial())
	checkOverflowStuck(t, *start.FinalAppliedIndex, finalKVOf(t, start), start.FinalApplyError)
	if len(start.FinalLog) != 3 {
		t.Fatalf("initial log = %d entries, want 3", len(start.FinalLog))
	}
	if start.FinalCommittedIndex != 2 {
		t.Fatalf("initial committedIndex = %d, want 2", start.FinalCommittedIndex)
	}
}

// TestKVIncrOverflowStuckSurvivesSuffixReplacement 回归保障两种行为相遇：已提交
// 的 incr 因数值溢出让应用停住后，任期 2 的合法复制请求（前置 idx2/任期 1）用
// 两条任期 2 的日志替换未提交的旧 idx3 并追加 idx4，提交位置推进到 4。复制层面
// 一切照常——请求接受、任期升到 2、旧减一命令消失、新后缀完整出现；但新命令
// 格式再正确也不能清掉第一次错误或让应用继续：键值表仍保留最大整数值，应用位置
// 仍为 1，逐条结果与最终结果都保留 idx2 的同一溢出原因——已复制、已提交不等于
// 已经生效。
func TestKVIncrOverflowStuckSurvivesSuffixReplacement(t *testing.T) {
	initial := incrOverflowStuckInitial()
	out := runKV(t, initial,
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 4,
			Entries: []LogEntry{
				entry(3, 2, "set count=0"),
				entry(4, 2, "incr count=1"),
			}},
	)

	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("legal suffix replacement should be accepted: %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("accepted replacement must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 2 || result.CommittedIndex != 4 {
		t.Fatalf("result state = term %d ci %d, want term 2 ci 4",
			result.Term, result.CommittedIndex)
	}
	// 逐条结果保留当时的应用状态：仍是第一次溢出错误，不被新提交的清掉。
	checkOverflowStuck(t, appliedIndexOf(t, result), nil, result.ApplyError)

	// 最终日志：原两条已提交记录保留，旧 idx3（incr count=-1）消失，新后缀完整出现。
	if !reflect.DeepEqual(out.FinalLog, wantOverflowLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantOverflowLog)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 4 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 4",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	// 尽管新命令格式正确且已提交，应用状态保持停住：set count=0 与 incr count=1
	// 都不得生效，第一次溢出错误保留在最终输出中。
	checkOverflowStuck(t, *out.FinalAppliedIndex, finalKVOf(t, out), out.FinalApplyError)
}

// TestKVIncrOverflowCommittedErrorEntryNotOverwritable 回归保障直接相关的边界：
// 应用位置落后于提交位置，不代表出错记录可以被覆盖。上述替换完成后，任期 3 的
// 请求匹配 idx1 并试图以不同任期改写已提交的 idx2，整条请求必须因覆盖已提交
// 日志被拒绝；较高任期 3 按现有规则保留，但日志、提交位置、键值表与首次应用
// 错误均不改变。同一调用中先合法替换后缀再收到这次拒绝，逐条结果各自保留当时
// 的接受状态，借此区分合法后缀替换与这次拒绝。
func TestKVIncrOverflowCommittedErrorEntryNotOverwritable(t *testing.T) {
	initial := incrOverflowStuckInitial()
	replace := AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 4,
		Entries: []LogEntry{
			entry(3, 2, "set count=0"),
			entry(4, 2, "incr count=1"),
		}}
	// 前置匹配 idx1，但 idx2 以任期 3 改写：idx2 已提交，不可覆盖。
	overwriteCommitted := AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
		Entries: []LogEntry{entry(2, 3, "set count=0")}}

	out := runKV(t, initial, replace, overwriteCommitted)
	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(out.Results))
	}

	// 第一条：合法后缀替换，接受且当时状态为任期 2、提交 4。
	first := out.Results[0]
	if !first.Accepted || first.Reason != ReasonOK {
		t.Fatalf("first request (legal replacement) should be accepted: %+v", first)
	}
	if first.Term != 2 || first.CommittedIndex != 4 {
		t.Fatalf("first result state = term %d ci %d, want term 2 ci 4",
			first.Term, first.CommittedIndex)
	}
	checkOverflowStuck(t, appliedIndexOf(t, first), nil, first.ApplyError)

	// 第二条：试图以不同任期改写已提交的 idx2，整条拒绝；较高任期 3 保留，
	// 提交位置不变，首次溢出错误原样保留在该条结果中。
	second := out.Results[1]
	if second.Accepted || second.Reason != ReasonWouldOverwriteCommitted {
		t.Fatalf("second request should be rejected as overwriting committed entry: %+v", second)
	}
	if second.Conflict != nil {
		t.Fatalf("overwrite-committed rejection must not carry a conflict hint: %+v", second.Conflict)
	}
	if second.Term != 3 {
		t.Fatalf("higher request term must survive the rejection, term = %d, want 3", second.Term)
	}
	if second.CommittedIndex != 4 {
		t.Fatalf("commit moved on rejection: %d, want 4", second.CommittedIndex)
	}
	checkOverflowStuck(t, appliedIndexOf(t, second), nil, second.ApplyError)

	// 最终状态：任期 3（较高任期保留），其余与替换完成后完全一致——日志是
	// 替换后的四条，提交位置 4，应用状态仍停在 idx2 的首次溢出错误上。
	if !reflect.DeepEqual(out.FinalLog, wantOverflowLog) {
		t.Fatalf("final log = %+v, want %+v (rejection must not change the log)",
			out.FinalLog, wantOverflowLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 4 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 4",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	checkOverflowStuck(t, *out.FinalAppliedIndex, finalKVOf(t, out), out.FinalApplyError)
}
