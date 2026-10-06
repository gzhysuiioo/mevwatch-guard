package mevwatch

import (
	"reflect"
	"testing"
)

// 本文件的测试共同保障一件事：Replicate / ReplicateWithOptions 的多次独立调用
// 之间不共享任何可变状态。调用方保存的初始状态与请求是比较各次复制结果的基准，
// 每次调用都必须从这份基准开始，不能把处理后的状态写回输入；某次调用返回的
// 结果对象也只属于该次调用，改动它不影响基准输入，也不影响其他调用已经得到
// 或之后得到的结果。

// isolationInitial 是各测试共用的基准初始状态：已提交前缀 set count=10
// （索引 1），未提交尾部 incr count=5（索引 2）。
func isolationInitial() InitialState {
	return InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"),
	}}
}

// replaceUncommittedRequest 是合法的较高任期请求：用 incr count=2 替换未提交
// 尾部并把提交位置推进到索引 2。
func replaceUncommittedRequest() AppendRequest {
	return AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
		Entries: []LogEntry{entry(2, 3, "incr count=2")}}
}

// 主场景：较高任期请求替换未提交条目并提交，结果保留已提交前缀、count 为
// "12"、提交与应用位置都到达索引 2；调用结束后基准输入（任期、提交位置、
// 日志、请求内容）保持原值。
func TestReplaceUncommittedEntryLeavesBaselineUntouched(t *testing.T) {
	initial := isolationInitial()
	request := replaceUncommittedRequest()
	originalLog := append([]LogEntry(nil), initial.Log...)
	originalEntries := append([]LogEntry(nil), request.Entries...)

	out := runKV(t, initial, request)

	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("replacement request rejected: %+v", result)
	}
	want := []LogEntry{entry(1, 1, "set count=10"), entry(2, 3, "incr count=2")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, want)
	}
	if result.CommittedIndex != 2 || out.FinalCommittedIndex != 2 {
		t.Fatalf("commit = result %d final %d, want 2", result.CommittedIndex, out.FinalCommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 2 {
		t.Fatalf("appliedIndex = %d, want 2", got)
	}
	if kv := finalKVOf(t, out); kv["count"] != "12" {
		t.Fatalf("count = %q, want %q (committed 10 + 2)", kv["count"], "12")
	}

	// 基准输入保持原值：任期、提交位置、日志与请求内容都没有被写回。
	if initial.CurrentTerm != 2 || initial.CommittedIndex != 1 {
		t.Fatalf("initial state mutated: term=%d ci=%d", initial.CurrentTerm, initial.CommittedIndex)
	}
	if !reflect.DeepEqual(initial.Log, originalLog) {
		t.Fatalf("initial log mutated: %+v", initial.Log)
	}
	if !reflect.DeepEqual(request.Entries, originalEntries) {
		t.Fatalf("request entries mutated: %+v", request.Entries)
	}
	if request.Term != 3 || request.PrevLogIndex != 1 || request.LeaderCommit != 2 {
		t.Fatalf("request mutated: %+v", request)
	}
}

// 第一次调用替换并提交了未提交尾部；随后用同一份基准再发起一次没有复制请求
// 的独立调用，必须仍从基准状态开始：保留原未提交尾部，键值表只应用已提交
// 前缀，不能继承前次的替换、提交或应用进度。
func TestIndependentCallStartsFromBaseline(t *testing.T) {
	initial := isolationInitial()
	first := runKV(t, initial, replaceUncommittedRequest())
	if got := finalKVOf(t, first)["count"]; got != "12" {
		t.Fatalf("first call count = %q, want 12", got)
	}

	second := runKV(t, initial)
	if len(second.Results) != 0 {
		t.Fatalf("no requests, want no results, got %+v", second.Results)
	}
	want := []LogEntry{entry(1, 1, "set count=10"), entry(2, 2, "incr count=5")}
	if !reflect.DeepEqual(second.FinalLog, want) {
		t.Fatalf("second call log = %+v, want original %+v", second.FinalLog, want)
	}
	if second.FinalCommittedIndex != 1 {
		t.Fatalf("second call commit = %d, want 1", second.FinalCommittedIndex)
	}
	if got := *second.FinalAppliedIndex; got != 1 {
		t.Fatalf("second call applied = %d, want 1", got)
	}
	if kv := finalKVOf(t, second); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("second call kv = %v, want only committed prefix {count:10}", kv)
	}
	// 前次调用已经得到的结果对象也不受后续调用影响。
	if first.FinalLog[1].Command != "incr count=2" || first.FinalCommittedIndex != 2 {
		t.Fatalf("first call result changed after second call: %+v", first)
	}
}

// 初始日志与请求条目都可以是一段更大数组的局部视图：调用只读取视图内的
// 内容，视图本身与视图之外的元素都不能被改动。
func TestInputViewsIntoLargerArraysAreIsolated(t *testing.T) {
	logBacking := []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"),
		entry(3, 9, "log tail beyond view"),
		entry(4, 9, "log tail beyond view 2"),
	}
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: logBacking[:2]}

	entriesBacking := []LogEntry{
		entry(7, 7, "request padding before"),
		entry(2, 3, "incr count=2"),
		entry(8, 8, "request padding after"),
	}
	request := AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
		Entries: entriesBacking[1:2]}

	out := runKV(t, initial, request)
	if !out.Results[0].Accepted {
		t.Fatalf("request from view rejected: %+v", out.Results[0])
	}
	want := []LogEntry{entry(1, 1, "set count=10"), entry(2, 3, "incr count=2")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, want)
	}
	if kv := finalKVOf(t, out); kv["count"] != "12" {
		t.Fatalf("count = %q, want 12", kv["count"])
	}

	// 视图之外的元素与视图本身都保持原值。
	wantLogBacking := []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"),
		entry(3, 9, "log tail beyond view"),
		entry(4, 9, "log tail beyond view 2"),
	}
	if !reflect.DeepEqual(logBacking, wantLogBacking) {
		t.Fatalf("log backing array mutated: %+v", logBacking)
	}
	wantEntriesBacking := []LogEntry{
		entry(7, 7, "request padding before"),
		entry(2, 3, "incr count=2"),
		entry(8, 8, "request padding after"),
	}
	if !reflect.DeepEqual(entriesBacking, wantEntriesBacking) {
		t.Fatalf("entries backing array mutated: %+v", entriesBacking)
	}
}

// 结果对象归当次调用所有：修改结果里的日志命令、键值表或逐条结果，既不改动
// 缓存的基准输入，也不影响其他独立调用已经得到或之后得到的结果。
func TestResultsAreOwnedByTheirCall(t *testing.T) {
	initial := isolationInitial()
	request := replaceUncommittedRequest()
	first := runKV(t, initial, request)
	second := runKV(t, initial, request)

	// 修改第一份结果里的日志命令、键值表与逐条结果。
	first.FinalLog[0].Command = "corrupted"
	first.FinalLog[1].Command = "corrupted"
	first.FinalKV["count"] = "corrupted"
	first.Results[0].CommittedIndex = 99
	if p := first.Results[0].AppliedIndex; p != nil {
		*p = 99
	} else {
		t.Fatalf("appliedIndex missing in %+v", first.Results[0])
	}

	// 基准输入未被波及。
	if initial.Log[0].Command != "set count=10" || initial.Log[1].Command != "incr count=5" {
		t.Fatalf("baseline log mutated via result: %+v", initial.Log)
	}
	if request.Entries[0].Command != "incr count=2" {
		t.Fatalf("baseline request mutated via result: %+v", request.Entries)
	}
	// 之前得到的另一份结果未被波及。
	if second.FinalLog[0].Command != "set count=10" || second.FinalLog[1].Command != "incr count=2" {
		t.Fatalf("second call log affected: %+v", second.FinalLog)
	}
	if second.FinalKV["count"] != "12" {
		t.Fatalf("second call kv affected: %v", second.FinalKV)
	}
	if second.Results[0].CommittedIndex != 2 || *second.Results[0].AppliedIndex != 2 {
		t.Fatalf("second call result affected: %+v", second.Results[0])
	}
	// 之后得到的新结果同样不受影响。
	fresh := runKV(t, initial, request)
	if fresh.FinalLog[1].Command != "incr count=2" || fresh.FinalKV["count"] != "12" {
		t.Fatalf("fresh call affected by earlier mutation: %+v", fresh)
	}
}

// 用基准初始状态加一条格式合法但前置日志不匹配的较高任期请求：该次结果保留
// 任期更新与冲突提示，日志仍为原来的两条，提交与应用位置停在第一条，count
// 仍为 "10"；任期更新只属于该次调用，基准初始状态不能被抬高任期。
func TestHigherTermMismatchDoesNotLeakAcrossCalls(t *testing.T) {
	initial := isolationInitial()
	bad := AppendRequest{Term: 5, PrevLogIndex: 2, PrevLogTerm: 5, LeaderCommit: 2}
	out := runKV(t, initial, bad)

	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonPrevLogMismatch {
		t.Fatalf("expected prev log mismatch, got %+v", result)
	}
	if result.Term != 5 {
		t.Fatalf("term update should survive in this call, got %d", result.Term)
	}
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 2, Term: 2}) {
		t.Fatalf("conflict = %+v, want {2 2}", result.Conflict)
	}
	if result.CommittedIndex != 1 || out.FinalCommittedIndex != 1 {
		t.Fatalf("commit moved: result %d final %d, want 1", result.CommittedIndex, out.FinalCommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 1 {
		t.Fatalf("appliedIndex = %d, want 1", got)
	}
	want := []LogEntry{entry(1, 1, "set count=10"), entry(2, 2, "incr count=5")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
	if kv := finalKVOf(t, out); kv["count"] != "10" {
		t.Fatalf("count = %q, want 10 (only committed prefix applied)", kv["count"])
	}

	// 任期更新只属于该次调用：基准初始状态仍是任期 2，下一次独立调用也从
	// 任期 2 开始，而不是被抬高的 5。
	if initial.CurrentTerm != 2 {
		t.Fatalf("baseline term raised to %d", initial.CurrentTerm)
	}
	followUp := runKV(t, initial)
	if followUp.FinalTerm != 2 {
		t.Fatalf("follow-up call started from term %d, want 2", followUp.FinalTerm)
	}
}

// 未开启键值应用的 Replicate 入口同样保持输入隔离，并继续省略应用字段。
func TestReplicateWithoutKVAlsoIsolatesInputs(t *testing.T) {
	initial := isolationInitial()
	request := replaceUncommittedRequest()
	originalLog := append([]LogEntry(nil), initial.Log...)
	originalEntries := append([]LogEntry(nil), request.Entries...)

	out := run(t, initial, request)
	if !out.Results[0].Accepted {
		t.Fatalf("rejected: %+v", out.Results[0])
	}
	want := []LogEntry{entry(1, 1, "set count=10"), entry(2, 3, "incr count=2")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, want)
	}
	if out.FinalCommittedIndex != 2 {
		t.Fatalf("commit = %d, want 2", out.FinalCommittedIndex)
	}
	// 未启用键值应用：应用字段整体缺省。
	if out.FinalAppliedIndex != nil || out.FinalKV != nil || out.FinalApplyError != nil {
		t.Fatalf("apply fields should be omitted: %+v", out)
	}
	if out.Results[0].AppliedIndex != nil || out.Results[0].ApplyError != nil {
		t.Fatalf("result apply fields should be omitted: %+v", out.Results[0])
	}
	// 基准输入保持原值。
	if initial.CurrentTerm != 2 || initial.CommittedIndex != 1 {
		t.Fatalf("initial state mutated: term=%d ci=%d", initial.CurrentTerm, initial.CommittedIndex)
	}
	if !reflect.DeepEqual(initial.Log, originalLog) {
		t.Fatalf("initial log mutated: %+v", initial.Log)
	}
	if !reflect.DeepEqual(request.Entries, originalEntries) {
		t.Fatalf("request entries mutated: %+v", request.Entries)
	}
	// 后续独立调用仍从基准开始：保留原未提交尾部，提交位置不前进。
	fresh := run(t, initial)
	if fresh.FinalLog[1].Command != "incr count=5" || fresh.FinalCommittedIndex != 1 {
		t.Fatalf("follow-up call did not start from baseline: %+v", fresh)
	}
}
