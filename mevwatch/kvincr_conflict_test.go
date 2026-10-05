package mevwatch

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// incrSuffixConflictInitial 是任期冲突替换回归场景共享的初始状态：当前任期 2，
// 索引 1..3 的任期均为 1；只有 idx1（incr count=10）已提交，计数因此为 "10"。
// idx2（incr count=100）与 idx3（incr count=1.5，增量不是整数）构成未提交旧
// 后缀：它们既不能提前累加，也不能提前暴露 idx3 的非法增量；后续被整段替换时
// 两条都必须从最终日志消失，且不在键值表留下任何效果。
func incrSuffixConflictInitial() InitialState {
	return InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "incr count=10"),
		entry(2, 1, "incr count=100"),
		entry(3, 1, "incr count=1.5"),
	}}
}

// TestKVIncrTermConflictReplacesUncommittedIncrSuffix 回归保障任务主场景：
// 已提交的 incr count=10 使计数为 "10"，未提交后缀另有合法增量 incr count=100
// 与非法增量 incr count=1.5。后续请求匹配前置日志 idx1，并在未提交起点 idx2
// 带来不同任期的条目（旧任期 1、新任期 2），只携带一条 incr count=-3 并将其
// 提交。旧冲突位置及其后的日志必须被新内容整段替换：
//   - 请求正常接受（reason ok），提交位置与应用位置都推进到 2；
//   - 最终日志只剩原已提交前缀 idx1 与新条目 idx2，incr count=100 与
//     incr count=1.5 均从最终日志消失；
//   - 已生效的前缀不能重新累加，被丢弃的合法增量 100 也不能影响计数：
//     最终计数为 10 + (-3) = "7"，键值表只有 count 一个键，无应用错误。
func TestKVIncrTermConflictReplacesUncommittedIncrSuffix(t *testing.T) {
	initial := incrSuffixConflictInitial()

	// 起点：只有初始已提交前缀生效，未提交后缀既不累加也不暴露格式错误。
	start := runKV(t, initial)
	if *start.FinalAppliedIndex != 1 {
		t.Fatalf("initial appliedIndex = %d, want 1", *start.FinalAppliedIndex)
	}
	if !reflect.DeepEqual(finalKVOf(t, start), map[string]string{"count": "10"}) {
		t.Fatalf("initial kv = %v, want only count=10", start.FinalKV)
	}
	if start.FinalApplyError != nil {
		t.Fatalf("uncommitted bad incr reported early: %+v", start.FinalApplyError)
	}
	if len(start.FinalLog) != 3 {
		t.Fatalf("initial log = %d entries, want 3", len(start.FinalLog))
	}

	out := runKV(t, initial,
		AppendRequest{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 2, "incr count=-3")}},
	)
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("different-term replacement should be accepted: %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("accepted replacement must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 2 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 2 ci 2",
			result.Term, result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 2 {
		t.Fatalf("result appliedIndex = %d, want 2 (new entry took effect)", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("replacement incr must apply cleanly: %+v", result.ApplyError)
	}

	wantLog := []LogEntry{
		entry(1, 1, "incr count=10"),
		entry(2, 2, "incr count=-3"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v (old suffix must vanish)", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 2 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 2",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 2 {
		t.Fatalf("final appliedIndex = %d, want 2", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "7"}) {
		t.Fatalf("final kv = %v, want only count=7 (prefix kept, discarded incr ignored)", kv)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

// TestKVIncrConflictReplacementPerRequestState 回归保障每条请求结果只保留处理
// 当时的接受状态、任期、提交与应用位置：先到的空条目心跳不确认未提交后缀
// （计数停在 "10"、提交与应用位置停在 1），随后的不同任期替换把 idx2 换成
// incr count=-3 并提交，第二条结果才反映提交/应用位置 2 与计数 "7"；第一条
// 结果不被后续状态覆盖。
func TestKVIncrConflictReplacementPerRequestState(t *testing.T) {
	out := runKV(t, incrSuffixConflictInitial(),
		// 心跳匹配到 idx3 但不推进提交：未提交后缀不能借此生效。
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 1, LeaderCommit: 0},
		// 从后缀起点以任期 2 替换 idx2 并提交到 2。
		AppendRequest{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 2, "incr count=-3")}},
	)
	first := out.Results[0]
	if !first.Accepted || first.Reason != ReasonOK {
		t.Fatalf("heartbeat should be accepted: %+v", first)
	}
	if first.CommittedIndex != 1 || appliedIndexOf(t, first) != 1 {
		t.Fatalf("first result must keep point-in-time state ci %d applied %d, want 1/1",
			first.CommittedIndex, *first.AppliedIndex)
	}
	if first.ApplyError != nil {
		t.Fatalf("heartbeat must not surface uncommitted bad incr: %+v", first.ApplyError)
	}
	second := out.Results[1]
	if !second.Accepted || second.CommittedIndex != 2 || appliedIndexOf(t, second) != 2 {
		t.Fatalf("second result = %+v applied %d, want accepted ci 2 applied 2",
			second, *second.AppliedIndex)
	}
	if second.ApplyError != nil {
		t.Fatalf("replacement incr must apply cleanly: %+v", second.ApplyError)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "7"}) {
		t.Fatalf("final kv = %v, want count=7", kv)
	}
	wantLog := []LogEntry{
		entry(1, 1, "incr count=10"),
		entry(2, 2, "incr count=-3"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
}

// TestKVIncrSameTermConflictRejectsWholeRequest 回归保障两种冲突的区分：冲突
// 位置的索引与任期都与旧条目相同（idx2 仍是任期 1）、只是命令改为
// incr count=-3 时，必须按现有同任期命令冲突拒绝整个请求——不能借任期冲突
// 替换提交旧后缀，也不能应用新命令。日志（含未提交的 incr count=100 与
// incr count=1.5）、计数 "10"、提交位置 1 与应用位置 1 全部保持原样；请求
// 携带的较高任期 3 仍按现有规则保留，且拒绝不附带 conflict。
func TestKVIncrSameTermConflictRejectsWholeRequest(t *testing.T) {
	initial := incrSuffixConflictInitial()
	out := runKV(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 3,
			Entries: []LogEntry{
				entry(2, 1, "incr count=-3"), // 与旧 idx2 同任期、不同命令：拒绝
				entry(3, 3, "set other=x"),
			}},
	)
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonCommandConflictSameTerm {
		t.Fatalf("expected same-term command conflict rejection, got %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("command conflict must not carry a conflict hint: %+v", result.Conflict)
	}
	if result.Term != 3 {
		t.Fatalf("higher request term must survive the rejection, term = %d, want 3", result.Term)
	}
	if result.CommittedIndex != 1 {
		t.Fatalf("commit moved on rejection: %d, want 1", result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 1 {
		t.Fatalf("result appliedIndex = %d, want 1", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("rejected commands must not produce an apply error: %+v", result.ApplyError)
	}

	// 原子拒绝：日志、提交位置、应用位置、键值表全部保持请求前状态。
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed after rejection: %+v", out.FinalLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 1",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("final kv = %v, want only count=10 (old suffix not committed, new incr not applied)", kv)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}

	// 输出约定：该拒绝的 JSON 中不出现 conflict 键（注意拒绝原因文本本身含
	// "entry conflict"，因此按键名 "conflict" 判断）；被拒命令
	// incr count=-3 也不应出现在最终输出里（finalLog 仍是旧日志，结果对象不含命令）。
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if strings.Contains(body, `"conflict"`) {
		t.Fatalf("command-conflict rejection JSON must omit conflict key: %s", body)
	}
	if strings.Contains(body, "incr count=-3") || strings.Contains(body, "set other=x") {
		t.Fatalf("rejected entries leaked into output: %s", body)
	}
}

// TestKVIncrTermConflictBadDeltaOnlyFailsApplication 回归保障第二种区分：不同
// 任期的替换本身合法（idx2 旧任期 1、新任期 3），但新增量不是整数
// （incr count=x）时，复制与提交照常成功（请求接受、提交位置到 2、最终日志
// 完成替换，旧后缀 incr count=100 与 incr count=1.5 消失）；只有提交后的应用
// 报告错误——appliedIndex 停在出错条目前的 1，applyError 指向 idx2 且原因为
// incr delta 非法，计数保留此前的 "10"，出错条目之后的命令均不存在故不生效。
func TestKVIncrTermConflictBadDeltaOnlyFailsApplication(t *testing.T) {
	initial := incrSuffixConflictInitial()
	out := runKV(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 3, "incr count=x")}},
	)
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("replication of the legal replacement must succeed: %+v", result)
	}
	if result.Term != 3 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 3 ci 2",
			result.Term, result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 1 {
		t.Fatalf("result appliedIndex = %d, want 1 (stopped before bad new entry)", got)
	}
	if result.ApplyError == nil || result.ApplyError.Index != 2 ||
		result.ApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("result applyError = %+v, want index 2 bad delta", result.ApplyError)
	}

	// 复制层面替换仍然完成：旧后缀两条消失，换成新的非法增量条目。
	wantLog := []LogEntry{
		entry(1, 1, "incr count=10"),
		entry(2, 3, "incr count=x"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 2",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("final kv = %v, want only count=10 (discarded +100 must not count, bad new incr unchanged)", kv)
	}
	if out.FinalApplyError == nil || out.FinalApplyError.Index != 2 ||
		out.FinalApplyError.Reason != ApplyReasonIncrBadDelta {
		t.Fatalf("final applyError = %+v, want index 2 bad delta", out.FinalApplyError)
	}
}

// TestKVIncrTermConflictDisabledStaysPlainString 不开启 applyKV 时，不同任期
// 替换照常发生，但 incr 命令只是普通字符串：增量不解释、计数不存在，输出形状
// 保持现状（无任何应用字段）。
func TestKVIncrTermConflictDisabledStaysPlainString(t *testing.T) {
	out, err := Replicate(incrSuffixConflictInitial(), []AppendRequest{
		{Term: 2, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 2, "incr count=-3")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Results[0].Accepted || out.FinalCommittedIndex != 2 {
		t.Fatalf("replication should succeed without applyKV: %+v", out.Results)
	}
	wantLog := []LogEntry{
		entry(1, 1, "incr count=10"),
		entry(2, 2, "incr count=-3"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, field := range []string{"appliedIndex", "applyError", "finalAppliedIndex", "finalKV", "finalApplyError"} {
		if strings.Contains(body, field) {
			t.Fatalf("applyKV disabled: output must not contain %q: %s", field, body)
		}
	}
	if !strings.Contains(body, "incr count=-3") {
		t.Fatalf("incr command must stay in the log verbatim: %s", body)
	}
}
