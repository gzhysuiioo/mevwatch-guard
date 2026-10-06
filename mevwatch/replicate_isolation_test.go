package mevwatch

import (
	"reflect"
	"testing"
)

// 本文件是“多次独立调用之间不共享可变状态”的回归保障：调用方可以保留一份初始
// 状态和请求作为比较不同复制结果的基准，每次模拟都从传入的基准开始——实现不得
// 把处理后的状态写回输入，也不得让一次调用的结果与其他独立调用的输入或结果
// 共享可变的切片、映射或指针。

// isolationInitial 是本文件回归场景共享的初始状态：当前任期 2，idx1
// （set count=10，任期 1）已提交，idx2（incr count=5，任期 2）是未提交尾部。
func isolationInitial() InitialState {
	return InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"), // 未提交尾部：独立调用之间不得互相继承对它的替换
	}}
}

// isolationReplaceRequest 是共享的合法较高任期请求：任期 3、前置匹配 idx1，
// 用任期 3 的 incr count=2 替换未提交的 idx2 并提交到 2。
func isolationReplaceRequest() AppendRequest {
	return AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 2,
		Entries: []LogEntry{entry(2, 3, "incr count=2")}}
}

// cloneInitial 深拷贝初始状态，用于在调用后逐字段确认输入仍保持原值。
func cloneInitial(initial InitialState) InitialState {
	return InitialState{
		CurrentTerm:    initial.CurrentTerm,
		CommittedIndex: initial.CommittedIndex,
		Log:            append([]LogEntry(nil), initial.Log...),
	}
}

// cloneAppendRequest 深拷贝一条请求（含条目切片），用途同 cloneInitial。
func cloneAppendRequest(request AppendRequest) AppendRequest {
	clone := request
	clone.Entries = append([]LogEntry(nil), request.Entries...)
	return clone
}

// wantIsolationReplaceOutcome 断言“替换并提交”调用的完整预期结果：已提交前缀
// 保留，idx2 换成 incr count=2，count 为 "12"，提交位置与应用位置都到达第二条。
func wantIsolationReplaceOutcome(t *testing.T, out ReplicateOutput) {
	t.Helper()
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("legal replacement should be accepted: %+v", result)
	}
	if result.Term != 3 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 3 ci 2",
			result.Term, result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 2 {
		t.Fatalf("result appliedIndex = %d, want 2", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("unexpected apply error: %+v", result.ApplyError)
	}
	wantLog := []LogEntry{
		entry(1, 1, "set count=10"), // 已提交前缀必须保留
		entry(2, 3, "incr count=2"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 2",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 2 {
		t.Fatalf("final appliedIndex = %d, want 2", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "12"}) {
		t.Fatalf("final kv = %v, want only count=12", kv)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

// wantIsolationStartOutcome 断言“从基准开始、没有任何复制请求”的完整预期结果：
// 未提交尾部保留，键值表只得到已提交前缀对应的 "10"，提交与应用位置停在第一条。
func wantIsolationStartOutcome(t *testing.T, out ReplicateOutput) {
	t.Helper()
	if len(out.Results) != 0 {
		t.Fatalf("unexpected results: %+v", out.Results)
	}
	wantLog := []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"), // 原未提交尾部必须保留
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v (uncommitted tail must be kept)", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 1",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("final kv = %v, want only count=10 (committed prefix only)", kv)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}
}

// TestReplicateCallsDoNotShareMutableState 主场景：调用方保存一份初始状态与请求
// 作为基准。第一次调用用 incr count=2 替换未提交条目并提交，结果保留已提交前缀、
// count 为 "12"、提交与应用位置都到第二条；调用结束后基准（初始任期、提交位置、
// 原日志、请求内容）仍保持原值。随后用同一基准发起一次没有复制请求的独立调用，
// 必须保留原来的未提交尾部，键值表只能得到已提交前缀对应的 "10"——不能继承前次
// 的替换、提交或应用进度。
func TestReplicateCallsDoNotShareMutableState(t *testing.T) {
	initial := isolationInitial()
	request := isolationReplaceRequest()
	initialSnapshot := cloneInitial(initial)
	requestSnapshot := cloneAppendRequest(request)

	out := runKV(t, initial, request)
	wantIsolationReplaceOutcome(t, out)

	// 调用结束后，调用方保存的基准仍保持原值：处理后的状态不能写回输入。
	if !reflect.DeepEqual(initial, initialSnapshot) {
		t.Fatalf("initial state mutated by call:\n got %+v\nwant %+v", initial, initialSnapshot)
	}
	if !reflect.DeepEqual(request, requestSnapshot) {
		t.Fatalf("request mutated by call:\n got %+v\nwant %+v", request, requestSnapshot)
	}

	// 用原初始状态发起一次没有复制请求的独立调用：从基准开始，不继承前次进度。
	fresh := runKV(t, initial)
	wantIsolationStartOutcome(t, fresh)

	// 基准在经历两次调用后依然原样，可继续作为比较基准。
	if !reflect.DeepEqual(initial, initialSnapshot) {
		t.Fatalf("initial state mutated across calls:\n got %+v\nwant %+v", initial, initialSnapshot)
	}
}

// TestReplicateInputSlicesMayBeViewsIntoLargerArrays 输入日志或请求条目来自一段
// 更大数组的局部视图时，同样满足隔离要求：视图之外（未参与本次调用）的内容不能
// 受到影响，视图本身的内容也不能被写回。
func TestReplicateInputSlicesMayBeViewsIntoLargerArrays(t *testing.T) {
	logBacking := []LogEntry{
		entry(1, 1, "set logguard=before"),
		entry(1, 1, "set count=10"),
		entry(2, 2, "incr count=5"),
		entry(4, 4, "set logguard=after"),
	}
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: logBacking[1:3]}
	entriesBacking := []LogEntry{
		entry(1, 1, "set reqguard=before"),
		entry(2, 3, "incr count=2"),
		entry(3, 3, "set reqguard=after"),
	}
	request := isolationReplaceRequest()
	request.Entries = entriesBacking[1:2]

	out := runKV(t, initial, request)
	wantIsolationReplaceOutcome(t, out)

	// 视图之外的内容不受影响。
	if logBacking[0] != entry(1, 1, "set logguard=before") ||
		logBacking[3] != entry(4, 4, "set logguard=after") {
		t.Fatalf("log backing array outside the view changed: %+v", logBacking)
	}
	if entriesBacking[0] != entry(1, 1, "set reqguard=before") ||
		entriesBacking[2] != entry(3, 3, "set reqguard=after") {
		t.Fatalf("entries backing array outside the view changed: %+v", entriesBacking)
	}
	// 视图本身的内容也保持原值。
	wantLogView := []LogEntry{entry(1, 1, "set count=10"), entry(2, 2, "incr count=5")}
	if !reflect.DeepEqual(initial.Log, wantLogView) {
		t.Fatalf("initial log view changed: %+v, want %+v", initial.Log, wantLogView)
	}
	wantEntriesView := []LogEntry{entry(2, 3, "incr count=2")}
	if !reflect.DeepEqual(request.Entries, wantEntriesView) {
		t.Fatalf("request entries view changed: %+v, want %+v", request.Entries, wantEntriesView)
	}
}

// TestReplicateOutputIsOwnedByCaller 返回结果的归属：调用方修改一次结果里的日志
// 命令、键值表或逐条接收结果后，不得改动缓存的输入，也不得影响其他独立调用已经
// 得到或之后得到的结果。
func TestReplicateOutputIsOwnedByCaller(t *testing.T) {
	initial := isolationInitial()
	first := runKV(t, initial, isolationReplaceRequest())
	second := runKV(t, initial, isolationReplaceRequest())

	// 调用方随意改写第一份结果：日志命令、键值表、逐条接收结果。
	first.FinalLog[0].Command = "set count=999"
	first.FinalLog[1].Command = "incr count=999"
	first.FinalKV["count"] = "999"
	first.FinalKV["injected"] = "x"
	first.Results[0].CommittedIndex = 99
	*first.Results[0].AppliedIndex = 99
	*first.FinalAppliedIndex = 99

	// 缓存的输入不被改动。
	if !reflect.DeepEqual(initial, isolationInitial()) {
		t.Fatalf("cached input changed after mutating a result: %+v", initial)
	}
	// 之前已经得到的另一份独立结果不受影响。
	wantIsolationReplaceOutcome(t, second)
	// 之后用同一基准得到的结果也不受影响。
	third := runKV(t, initial, isolationReplaceRequest())
	wantIsolationReplaceOutcome(t, third)
}

// TestReplicateRejectionDoesNotLeakStateIntoInput 拒绝路径：用原初始状态和一条
// 格式合法但前置日志不匹配的较高任期请求。该次结果仍保留现有的任期更新和冲突
// 提示，日志仍为原来的两条，提交和应用位置停在第一条，count 仍为 "10"；任期更新
// 只属于该次调用，原初始状态不能被抬高任期。
func TestReplicateRejectionDoesNotLeakStateIntoInput(t *testing.T) {
	initial := isolationInitial()
	initialSnapshot := cloneInitial(initial)
	// 前置索引存在（idx2）但声明的任期 9 与本地任期 2 不同：格式合法的前置不匹配。
	mismatch := AppendRequest{Term: 5, PrevLogIndex: 2, PrevLogTerm: 9, LeaderCommit: 2}

	out := runKV(t, initial, mismatch)
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonPrevLogMismatch {
		t.Fatalf("expected prev log mismatch rejection, got %+v", result)
	}
	// 该次结果仍保留现有的任期更新和冲突提示。
	if result.Term != 5 {
		t.Fatalf("higher term should survive in this call's result: term = %d, want 5", result.Term)
	}
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 2, Term: 2}) {
		t.Fatalf("conflict = %+v, want {2 2}", result.Conflict)
	}
	// 日志仍为原来的两条，提交和应用位置停在第一条。
	if result.CommittedIndex != 1 {
		t.Fatalf("commit moved on rejection: %d, want 1", result.CommittedIndex)
	}
	if got := appliedIndexOf(t, result); got != 1 {
		t.Fatalf("applied index moved on rejection: %d, want 1", got)
	}
	if result.ApplyError != nil {
		t.Fatalf("rejection must not produce an apply error: %+v", result.ApplyError)
	}
	if !reflect.DeepEqual(out.FinalLog, initialSnapshot.Log) {
		t.Fatalf("log changed after rejection: %+v, want %+v", out.FinalLog, initialSnapshot.Log)
	}
	if out.FinalTerm != 5 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final state = term %d ci %d, want term 5 ci 1",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	if *out.FinalAppliedIndex != 1 {
		t.Fatalf("final appliedIndex = %d, want 1", *out.FinalAppliedIndex)
	}
	if kv := finalKVOf(t, out); !reflect.DeepEqual(kv, map[string]string{"count": "10"}) {
		t.Fatalf("final kv = %v, want only count=10", kv)
	}
	if out.FinalApplyError != nil {
		t.Fatalf("final apply error = %+v, want none", out.FinalApplyError)
	}

	// 任期更新只属于该次调用：原初始状态不能被抬高任期，其余字段同样原样。
	if initial.CurrentTerm != 2 {
		t.Fatalf("initial term raised by a rejected call: %d, want 2", initial.CurrentTerm)
	}
	if !reflect.DeepEqual(initial, initialSnapshot) {
		t.Fatalf("initial state mutated by rejected call:\n got %+v\nwant %+v", initial, initialSnapshot)
	}

	// 用同一基准再发起一次没有复制请求的独立调用：从原任期开始，不继承任期更新。
	fresh := runKV(t, initial)
	wantIsolationStartOutcome(t, fresh)
}

// TestReplicateWithoutApplyKVAlsoIsolatesInput 未开启键值应用的复制入口同样保持
// 输入隔离，并继续省略应用字段。
func TestReplicateWithoutApplyKVAlsoIsolatesInput(t *testing.T) {
	initial := isolationInitial()
	request := isolationReplaceRequest()
	initialSnapshot := cloneInitial(initial)
	requestSnapshot := cloneAppendRequest(request)

	out := run(t, initial, request)
	if len(out.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(out.Results))
	}
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("legal replacement should be accepted: %+v", result)
	}
	if result.Term != 3 || result.CommittedIndex != 2 {
		t.Fatalf("result state = term %d ci %d, want term 3 ci 2",
			result.Term, result.CommittedIndex)
	}
	wantLog := []LogEntry{
		entry(1, 1, "set count=10"),
		entry(2, 3, "incr count=2"),
	}
	if !reflect.DeepEqual(out.FinalLog, wantLog) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, wantLog)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 2",
			out.FinalTerm, out.FinalCommittedIndex)
	}
	// 未开启键值应用：继续省略全部应用字段。
	if result.AppliedIndex != nil || result.ApplyError != nil {
		t.Fatalf("applyKV disabled: result must omit apply fields: %+v", result)
	}
	if out.FinalAppliedIndex != nil || out.FinalKV != nil || out.FinalApplyError != nil {
		t.Fatalf("applyKV disabled: output must omit apply fields: %+v", out)
	}

	// 输入隔离：基准在调用后仍保持原值。
	if !reflect.DeepEqual(initial, initialSnapshot) {
		t.Fatalf("initial state mutated by call:\n got %+v\nwant %+v", initial, initialSnapshot)
	}
	if !reflect.DeepEqual(request, requestSnapshot) {
		t.Fatalf("request mutated by call:\n got %+v\nwant %+v", request, requestSnapshot)
	}

	// 用同一基准发起一次没有复制请求的独立调用：保留未提交尾部，不继承前次
	// 的替换与提交进度，应用字段同样省略。
	fresh := run(t, initial)
	if len(fresh.Results) != 0 {
		t.Fatalf("unexpected results: %+v", fresh.Results)
	}
	if !reflect.DeepEqual(fresh.FinalLog, initialSnapshot.Log) {
		t.Fatalf("final log = %+v, want %+v (uncommitted tail must be kept)",
			fresh.FinalLog, initialSnapshot.Log)
	}
	if fresh.FinalTerm != 2 || fresh.FinalCommittedIndex != 1 {
		t.Fatalf("final state = term %d ci %d, want term 2 ci 1",
			fresh.FinalTerm, fresh.FinalCommittedIndex)
	}
	if fresh.FinalAppliedIndex != nil || fresh.FinalKV != nil || fresh.FinalApplyError != nil {
		t.Fatalf("applyKV disabled: output must omit apply fields: %+v", fresh)
	}
}
