package mevwatch

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func entry(index, term int, command string) LogEntry {
	return LogEntry{Index: index, Term: term, Command: command}
}

func run(t *testing.T, initial InitialState, requests ...AppendRequest) ReplicateOutput {
	t.Helper()
	out, err := Replicate(initial, requests)
	if err != nil {
		t.Fatalf("Replicate returned error: %v", err)
	}
	return out
}

func expectError(t *testing.T, initial InitialState, requests []AppendRequest, fragments ...string) {
	t.Helper()
	_, err := Replicate(initial, requests)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	message := err.Error()
	for _, fragment := range fragments {
		if !strings.Contains(message, fragment) {
			t.Fatalf("error %q does not contain %q", message, fragment)
		}
	}
}

func TestBasicAppendFromOrigin(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "x"), entry(2, 1, "y")}},
	)
	if !out.Results[0].Accepted || out.Results[0].Reason != ReasonOK {
		t.Fatalf("expected acceptance, got %+v", out.Results[0])
	}
	want := []LogEntry{entry(1, 1, "x"), entry(2, 1, "y")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
}

func TestStaleTermRejectionChangesNothing(t *testing.T) {
	initial := InitialState{CurrentTerm: 5, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 5, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 5, LeaderCommit: 1,
			Entries: []LogEntry{entry(2, 4, "b")}},
	)
	result := out.Results[0]
	if result.Accepted || !strings.Contains(result.Reason, "stale term") {
		t.Fatalf("expected stale-term rejection, got %+v", result)
	}
	if result.Term != 5 || result.CommittedIndex != 1 {
		t.Fatalf("state changed: %+v", result)
	}
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
}

// 较高任期即使因前缀不匹配被拒，任期更新也必须保留。
func TestHigherTermUpdateSurvivesPrefixRejection(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 7, PrevLogIndex: 1, PrevLogTerm: 3, LeaderCommit: 0},
	)
	result := out.Results[0]
	if result.Accepted {
		t.Fatalf("expected rejection, got %+v", result)
	}
	if result.Term != 7 {
		t.Fatalf("term should be updated to 7, got %d", result.Term)
	}
	if result.CommittedIndex != 0 || len(out.FinalLog) != 1 {
		t.Fatalf("log/commit changed: ci=%d log=%+v", result.CommittedIndex, out.FinalLog)
	}
}

func TestHigherTermUpdateSurvivesIndexBeyondLog(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 7, PrevLogIndex: 3, PrevLogTerm: 2},
	)
	if out.Results[0].Accepted {
		t.Fatalf("expected rejection")
	}
	if out.Results[0].Term != 7 {
		t.Fatalf("term should be 7, got %d", out.Results[0].Term)
	}
}

func TestPrevLogSentinelSemantics(t *testing.T) {
	initial := InitialState{CurrentTerm: 3}
	// 日志起点：索引 0 只与任期 0 匹配。
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 1},
	)
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "prev log mismatch") {
		t.Fatalf("expected prev mismatch for (0,1), got %+v", out.Results[0])
	}
	if out.Results[0].Term != 3 {
		t.Fatalf("term changed: %d", out.Results[0].Term)
	}
	// 有日志时 (0,0) 表示新领导者从起点重传整个日志，应匹配成功。
	initial = InitialState{CurrentTerm: 3, Log: []LogEntry{entry(1, 2, "old")}}
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 3, "new")}},
	)
	if !out.Results[0].Accepted {
		t.Fatalf("expected acceptance, got %+v", out.Results[0])
	}
	want := []LogEntry{entry(1, 3, "new")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
}

func TestPrevLogMissingOrWrongTerm(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		// prevLogIndex 超出日志长度。
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2},
		// 索引存在但任期不同。
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 3},
	)
	for i, result := range out.Results {
		if result.Accepted || !strings.Contains(result.Reason, "prev log mismatch") {
			t.Fatalf("result %d: expected prev log mismatch, got %+v", i, result)
		}
		if result.CommittedIndex != 0 || len(out.FinalLog) != 1 {
			t.Fatalf("state changed after rejection %d: %+v", i, result)
		}
	}
}

func TestKeepIdenticalEntriesAndNoDuplicate(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, Log: []LogEntry{
		entry(1, 1, "a"), entry(2, 2, "b"),
	}}
	request := AppendRequest{Term: 2, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 2,
		Entries: []LogEntry{entry(1, 1, "a"), entry(2, 2, "b")}}
	out := run(t, initial, request, request)
	for i, result := range out.Results {
		if !result.Accepted {
			t.Fatalf("result %d rejected: %s", i, result.Reason)
		}
	}
	if len(out.FinalLog) != 2 {
		t.Fatalf("duplicate entries created: %+v", out.FinalLog)
	}
}

func TestFullyMatchingShortRequestKeepsTail(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 2, "b"), entry(3, 3, "c")}}
	// 空条目心跳：确认位置是前一条索引，本地尾部不能因此被提交。
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 5},
	)
	result := out.Results[0]
	if !result.Accepted {
		t.Fatalf("heartbeat rejected: %s", result.Reason)
	}
	if result.CommittedIndex != 2 {
		t.Fatalf("heartbeat committed index = %d, want 2", result.CommittedIndex)
	}
	if len(out.FinalLog) != 3 {
		t.Fatalf("tail deleted: %+v", out.FinalLog)
	}

	// 覆盖已提交位置的冲突必须拒绝——先推进提交到 3，再试图在同一位置换任期。
	out = run(t, InitialState{CurrentTerm: 3, CommittedIndex: 3,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 2, "b"), entry(3, 3, "c")}},
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2,
			Entries: []LogEntry{entry(3, 3, "d")}},
	)
	if out.Results[0].Accepted {
		t.Fatalf("same-term command conflict should reject")
	}

	// 全部匹配的短条目请求同样不得删除尾部。
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 2, "a")}},
	)
	if !out.Results[0].Accepted {
		t.Fatalf("short request rejected: %s", out.Results[0].Reason)
	}
	if len(out.FinalLog) != 3 || out.FinalLog[2].Command != "c" {
		t.Fatalf("tail changed: %+v", out.FinalLog)
	}
}

func TestConflictTruncatesSuffix(t *testing.T) {
	initial := InitialState{CurrentTerm: 4, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}}
	out := run(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 2, LeaderCommit: 1,
			Entries: []LogEntry{entry(2, 4, "e"), entry(3, 4, "f")}},
	)
	result := out.Results[0]
	if !result.Accepted {
		t.Fatalf("rejected: %s", result.Reason)
	}
	want := []LogEntry{entry(1, 2, "a"), entry(2, 4, "e"), entry(3, 4, "f")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
}

func TestConflictOnCommittedRejectsAtomically(t *testing.T) {
	initial := InitialState{CurrentTerm: 4, CommittedIndex: 3,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}}
	original := append([]LogEntry(nil), initial.Log...)
	// 新条目可追加在 idx5，但 idx2 处要覆盖已提交条目——整次拒绝。
	out := run(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(2, 4, "e"), entry(3, 4, "f"), entry(4, 4, "g"), entry(5, 4, "h")}},
	)
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "committed") {
		t.Fatalf("expected committed overwrite rejection, got %+v", out.Results[0])
	}
	if !reflect.DeepEqual(out.FinalLog, original) {
		t.Fatalf("partial change left behind: %+v", out.FinalLog)
	}
	if out.FinalCommittedIndex != 3 {
		t.Fatalf("committed index changed: %d", out.FinalCommittedIndex)
	}
}

func TestSameTermDifferentCommandRejectsAtomically(t *testing.T) {
	initial := InitialState{CurrentTerm: 4, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c")}}
	original := append([]LogEntry(nil), initial.Log...)
	// idx2 处有可追加……实际这里 idx2 任期相同命令不同；idx3 任期不同且未提交。
	out := run(t, initial,
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(2, 3, "X"), entry(3, 4, "f")}},
	)
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "conflict") {
		t.Fatalf("expected command-conflict rejection, got %+v", out.Results[0])
	}
	if !reflect.DeepEqual(out.FinalLog, original) {
		t.Fatalf("partial change left behind: %+v", out.FinalLog)
	}
}

func TestCommitAdvanceRules(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 2,
		Log: []LogEntry{entry(1, 1, "a"), entry(2, 2, "b")}}
	out := run(t, initial,
		// leaderCommit 低于当前提交位置：保持原值。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 0},
		// 追加两条，leaderCommit 很大：只推进到本次确认的最后索引 4。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 9,
			Entries: []LogEntry{entry(3, 2, "c"), entry(4, 2, "d")}},
	)
	if out.Results[0].CommittedIndex != 2 {
		t.Fatalf("commit moved backward: %d", out.Results[0].CommittedIndex)
	}
	if out.Results[1].CommittedIndex != 4 {
		t.Fatalf("commit = %d, want 4", out.Results[1].CommittedIndex)
	}
	if out.FinalCommittedIndex != 4 {
		t.Fatalf("final commit = %d, want 4", out.FinalCommittedIndex)
	}
}

func TestHeartbeatEmptyEntries(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c")}}
	out := run(t, initial,
		// 空条目 + prev 指向 idx1：确认位置只有 1，即便 leaderCommit=10
		// 也不能提交本地尾部 idx2/idx3。
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2, LeaderCommit: 10},
	)
	result := out.Results[0]
	if !result.Accepted {
		t.Fatalf("heartbeat rejected: %s", result.Reason)
	}
	if result.CommittedIndex != 1 {
		t.Fatalf("heartbeat advanced commit to %d, want 1", result.CommittedIndex)
	}
	if len(out.FinalLog) != 3 {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
}

func TestAppendOnlyNewSuffix(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 2,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b")}}
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 3, LeaderCommit: 4,
			Entries: []LogEntry{entry(3, 3, "c"), entry(4, 3, "d")}},
	)
	if !out.Results[0].Accepted {
		t.Fatalf("rejected: %s", out.Results[0].Reason)
	}
	want := []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
	if out.FinalCommittedIndex != 4 {
		t.Fatalf("commit = %d, want 4", out.FinalCommittedIndex)
	}
}

func TestInvalidRequestDoesNotTouchStateOrTerm(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		// 非法：条目索引没有从 prevLogIndex+1 开始；还携带更高任期 9。
		AppendRequest{Term: 9, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(5, 9, "x")}},
		// 非法：空任期。
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 0, "x")}},
		// 非法：条目任期下降。
		AppendRequest{Term: 5, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 5, "x"), entry(2, 4, "y")}},
		// 非法：条目任期超过请求任期。
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 4, "x")}},
		// 非法：负的 leaderCommit。
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: -1},
	)
	for i, result := range out.Results {
		if result.Accepted {
			t.Fatalf("result %d should be rejected: %+v", i, result)
		}
		if result.Term != 2 || result.CommittedIndex != 1 {
			t.Fatalf("result %d changed state: %+v", i, result)
		}
	}
	if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 {
		t.Fatalf("final state changed: term=%d ci=%d", out.FinalTerm, out.FinalCommittedIndex)
	}
	if len(out.FinalLog) != 1 {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}

	// 非法请求之后，下一条合法请求仍正常处理。
	out = run(t, initial,
		AppendRequest{Term: 9, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(5, 9, "x")}},
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2, LeaderCommit: 1,
			Entries: []LogEntry{entry(2, 3, "b")}},
	)
	if !out.Results[1].Accepted {
		t.Fatalf("valid request after invalid one rejected: %+v", out.Results[1])
	}
	if out.Results[1].Term != 3 {
		t.Fatalf("term = %d, want 3", out.Results[1].Term)
	}
}

func TestInvalidInitialStates(t *testing.T) {
	cases := []struct {
		name      string
		initial   InitialState
		fragments []string
	}{
		{"negative term", InitialState{CurrentTerm: -1}, []string{"currentTerm"}},
		{"negative commit", InitialState{CurrentTerm: 2, CommittedIndex: -1}, []string{"committedIndex"}},
		{"commit beyond log", InitialState{CurrentTerm: 2, CommittedIndex: 2,
			Log: []LogEntry{entry(1, 2, "a")}}, []string{"committedIndex", "exceeds"}},
		{"index gap", InitialState{CurrentTerm: 2,
			Log: []LogEntry{entry(2, 2, "a")}}, []string{"index"}},
		{"zero term entry", InitialState{CurrentTerm: 2,
			Log: []LogEntry{entry(1, 0, "a")}}, []string{"term"}},
		{"decreasing terms", InitialState{CurrentTerm: 3,
			Log: []LogEntry{entry(1, 3, "a"), entry(2, 2, "b")}}, []string{"term"}},
		{"entry term beyond current", InitialState{CurrentTerm: 2,
			Log: []LogEntry{entry(1, 3, "a")}}, []string{"currentTerm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectError(t, tc.initial, nil, tc.fragments...)
		})
	}
}

func TestDeterministicJSONRoundTrip(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 2, "a")}}
	requests := []AppendRequest{
		{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 3, "b")}},
		{Term: 2, PrevLogIndex: 2, PrevLogTerm: 3}, // stale term
	}
	first, err := Replicate(initial, requests)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Replicate(initial, requests)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("non-deterministic output:\n%+v\n%+v", first, second)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReplicateOutput
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, first) {
		t.Fatalf("JSON round trip mismatch:\n%+v\n%+v", decoded, first)
	}
}

func TestSequentialScenario(t *testing.T) {
	// 经典场景：领导者连续发送，中间夹一次旧领导者的低任期请求。
	out := run(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(1, 1, "set x=1"), entry(2, 1, "set y=2")}},
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1, LeaderCommit: 2,
			Entries: []LogEntry{entry(3, 2, "set z=3")}},
		AppendRequest{Term: 1, PrevLogIndex: 3, PrevLogTerm: 2}, // 旧领导者，低任期
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2, LeaderCommit: 3},
	)
	statuses := []bool{true, true, false, true}
	for i, result := range out.Results {
		if result.Accepted != statuses[i] {
			t.Fatalf("result %d = %+v, want accepted=%v", i, result, statuses[i])
		}
	}
	if out.Results[2].Term != 2 {
		t.Fatalf("stale request changed term: %d", out.Results[2].Term)
	}
	want := []LogEntry{entry(1, 1, "set x=1"), entry(2, 1, "set y=2"), entry(3, 2, "set z=3")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
	if out.FinalCommittedIndex != 3 {
		t.Fatalf("final commit = %d, want 3", out.FinalCommittedIndex)
	}
}

// 首条位置越过 int 上限：prevLogIndex 取 MaxInt、非空条目的首条索引以最小负值
// 给出（恰好是回绕后的位置）。这是字段错误，按条目索引不连续拒绝：任期、提交
// 位置与日志都保持请求前状态，不能借高任期抬高节点任期。
func TestEntryIndexOverflowAtFirstPositionIsFieldError(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 9, PrevLogIndex: math.MaxInt, PrevLogTerm: 0, LeaderCommit: 0,
			Entries: []LogEntry{entry(math.MinInt, 9, "x")}},
	)
	result := out.Results[0]
	if result.Accepted || !strings.Contains(result.Reason, "not consecutive") {
		t.Fatalf("expected index-gap field error, got %+v", result)
	}
	if result.Term != 2 || result.CommittedIndex != 1 {
		t.Fatalf("field error changed state: %+v", result)
	}
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
	if out.FinalTerm != 2 {
		t.Fatalf("final term changed: %d", out.FinalTerm)
	}
}

// 高任期溢出非法请求不能影响后续合法请求：第二条任期 3 的合法追加正常接受，
// 最终任期为 3，原有已提交条目保留，提交位置随第二条推进。
func TestOverflowFieldErrorDoesNotPoisonLaterRequest(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 9, PrevLogIndex: math.MaxInt, PrevLogTerm: 0,
			Entries: []LogEntry{entry(math.MinInt, 9, "x")}},
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2, LeaderCommit: 2,
			Entries: []LogEntry{entry(2, 3, "b")}},
	)
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "not consecutive") {
		t.Fatalf("first request should be an index-gap field error, got %+v", out.Results[0])
	}
	if out.Results[0].Term != 2 {
		t.Fatalf("term should stay 2, got %d", out.Results[0].Term)
	}
	if !out.Results[1].Accepted || out.Results[1].Reason != ReasonOK {
		t.Fatalf("valid request after field error rejected: %+v", out.Results[1])
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 2 {
		t.Fatalf("unexpected final state: term=%d ci=%d", out.FinalTerm, out.FinalCommittedIndex)
	}
	want := []LogEntry{entry(1, 2, "a"), entry(2, 3, "b")}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
}

// 溢出点在链中间：首条索引恰好为 MaxInt 合法，下一位置无法表示即整体字段错误，
// 即使输入的第二个索引恰好是回绕后的 MinInt。
func TestEntryIndexOverflowMidChainIsFieldError(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		AppendRequest{Term: 9, PrevLogIndex: math.MaxInt - 1, PrevLogTerm: 0,
			Entries: []LogEntry{entry(math.MaxInt, 9, "x"), entry(math.MinInt, 9, "y")}},
	)
	result := out.Results[0]
	if result.Accepted || !strings.Contains(result.Reason, "not consecutive") {
		t.Fatalf("expected index-gap field error, got %+v", result)
	}
	if result.Term != 2 || result.CommittedIndex != 1 {
		t.Fatalf("field error changed state: %+v", result)
	}
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
}

// 大索引本身不是字段非法：entries 为空时 prevLogIndex 取 MaxInt 也不要求存在
// 下一位置；非空请求最后条目恰好到达 MaxInt 同样合法。两者前置位置都不在本地
// 日志中，按原有的前缀不匹配规则拒绝，并保留较高任期更新。
func TestLargeRepresentableIndexesRemainLegalPrefixMismatch(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a")}}
	out := run(t, initial,
		// 空条目心跳：不要求下一条索引存在。
		AppendRequest{Term: 7, PrevLogIndex: math.MaxInt, PrevLogTerm: 0},
		// 非空请求，最后一条恰好到达 MaxInt。
		AppendRequest{Term: 8, PrevLogIndex: math.MaxInt - 1, PrevLogTerm: 0,
			Entries: []LogEntry{entry(math.MaxInt, 8, "z")}},
	)
	if out.Results[0].Accepted || !strings.Contains(out.Results[0].Reason, "prev log mismatch") {
		t.Fatalf("empty MaxInt heartbeat should be prev mismatch, got %+v", out.Results[0])
	}
	if out.Results[0].Term != 7 {
		t.Fatalf("term update should survive: %d", out.Results[0].Term)
	}
	if out.Results[1].Accepted || !strings.Contains(out.Results[1].Reason, "prev log mismatch") {
		t.Fatalf("last-entry-at-MaxInt request should be prev mismatch, got %+v", out.Results[1])
	}
	if out.Results[1].Term != 8 {
		t.Fatalf("term update should survive: %d", out.Results[1].Term)
	}
	if out.FinalTerm != 8 || out.FinalCommittedIndex != 1 || len(out.FinalLog) != 1 {
		t.Fatalf("state changed: term=%d ci=%d log=%+v", out.FinalTerm, out.FinalCommittedIndex, out.FinalLog)
	}
}

// 任何非正的真实条目索引都是字段错误：哨兵之后首条索引不能为 0 或负值，
// 即使它在补码意义下等于某个回绕位置。
func TestNonPositiveEntryIndexIsFieldError(t *testing.T) {
	initial := InitialState{CurrentTerm: 2}
	cases := []AppendRequest{
		{Term: 9, PrevLogIndex: 0, Entries: []LogEntry{entry(0, 9, "x")}},
		{Term: 9, PrevLogIndex: 0, Entries: []LogEntry{entry(-1, 9, "x")}},
		{Term: 9, PrevLogIndex: 1, Entries: []LogEntry{entry(0, 9, "x")}},
	}
	for i, request := range cases {
		out := run(t, initial, request)
		result := out.Results[0]
		if result.Accepted || !strings.Contains(result.Reason, "not consecutive") {
			t.Fatalf("case %d: expected index-gap field error, got %+v", i, result)
		}
		if result.Term != 2 {
			t.Fatalf("case %d: term changed to %d", i, result.Term)
		}
	}
}

// prevLogIndex 超过本地日志末尾：conflict.index 为本地最后索引加一、term 为 0。
func TestConflictBeyondLogEnd(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 1,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b")}}
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 5, PrevLogTerm: 3},
		// 恰好是末尾加一。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 9},
	)
	want := []ConflictHint{{Index: 3, Term: 0}, {Index: 3, Term: 0}}
	for i, result := range out.Results {
		if result.Accepted || !strings.Contains(result.Reason, "prev log mismatch") {
			t.Fatalf("result %d: expected prev log mismatch, got %+v", i, result)
		}
		if !reflect.DeepEqual(result.Conflict, &want[i]) {
			t.Fatalf("result %d: conflict = %+v, want %+v", i, result.Conflict, want[i])
		}
	}
}

// 空日志：任何不存在的前置索引都反馈 index 1、term 0。
func TestConflictEmptyLog(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 1},
		AppendRequest{Term: 1, PrevLogIndex: 1, PrevLogTerm: 0},
		AppendRequest{Term: 1, PrevLogIndex: 9, PrevLogTerm: 4},
	)
	for i, result := range out.Results {
		want := &ConflictHint{Index: 1, Term: 0}
		if !reflect.DeepEqual(result.Conflict, want) {
			t.Fatalf("result %d: conflict = %+v, want %+v", i, result.Conflict, want)
		}
	}
}

// 索引存在但任期不同：反馈该位置本地任期，以及该任期在完整本地日志中第一次
// 出现的索引——不能只回冲突位置本身。
func TestConflictTermMismatchFindsFirstIndexOfTerm(t *testing.T) {
	// idx1 任期 1，idx2..4 任期 3。
	initial := InitialState{CurrentTerm: 3,
		Log: []LogEntry{entry(1, 1, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}}
	out := run(t, initial,
		// 在 idx4 声称前置任期 2：反馈 idx2、term 3。
		AppendRequest{Term: 3, PrevLogIndex: 4, PrevLogTerm: 2},
		// 在 idx3 声称其他任期：同样回退到任期 3 段的起点 idx2。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 1},
		// 在 idx2 声称任期 4：本地就是任期 3 段起点 idx2。
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 4},
		// 在 idx1 声称任期 2：本地任期 1 段起点就是 idx1。
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2},
	)
	want := []ConflictHint{
		{Index: 2, Term: 3},
		{Index: 2, Term: 3},
		{Index: 2, Term: 3},
		{Index: 1, Term: 1},
	}
	for i, result := range out.Results {
		if !reflect.DeepEqual(result.Conflict, &want[i]) {
			t.Fatalf("result %d: conflict = %+v, want %+v", i, result.Conflict, want[i])
		}
	}
}

// 起点按完整本地日志确定：冲突任期段的一部分甚至全部已经提交时，也不能把
// 起点改成提交位置之后。
func TestConflictFirstIndexCountsCommittedPrefix(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 4,
		Log: []LogEntry{entry(1, 1, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}}
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 4, PrevLogTerm: 2},
	)
	want := &ConflictHint{Index: 2, Term: 3}
	if got := out.Results[0].Conflict; !reflect.DeepEqual(got, want) {
		t.Fatalf("conflict = %+v, want %+v (committed prefix must not shift the start)", got, want)
	}
	if out.FinalCommittedIndex != 4 || len(out.FinalLog) != 4 {
		t.Fatalf("state changed: ci=%d log=%+v", out.FinalCommittedIndex, out.FinalLog)
	}
}

// 索引 0 哨兵携带非零前置任期：按前置不匹配拒绝，反馈 index 1、term 0，
// 无论本地日志是否为空。
func TestConflictSentinelNonZeroTerm(t *testing.T) {
	cases := []InitialState{
		{CurrentTerm: 3},
		{CurrentTerm: 3, Log: []LogEntry{entry(1, 2, "old")}},
	}
	for i, initial := range cases {
		out := run(t, initial,
			AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 1},
		)
		want := &ConflictHint{Index: 1, Term: 0}
		if got := out.Results[0].Conflict; !reflect.DeepEqual(got, want) {
			t.Fatalf("case %d: conflict = %+v, want %+v", i, got, want)
		}
	}
}

// 成功请求，以及因低任期、字段非法、同任期命令冲突、覆盖已提交条目而拒绝的
// 请求，都不输出 conflict。
func TestConflictAbsentForOtherOutcomes(t *testing.T) {
	initial := InitialState{CurrentTerm: 4, CommittedIndex: 3,
		Log: []LogEntry{entry(1, 2, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d")}}
	out := run(t, initial,
		// 成功：心跳。
		AppendRequest{Term: 4, PrevLogIndex: 4, PrevLogTerm: 3},
		// 低任期拒绝。
		AppendRequest{Term: 2, PrevLogIndex: 4, PrevLogTerm: 3},
		// 字段非法：负 leaderCommit（虽也看似前置问题，字段规则优先）。
		AppendRequest{Term: 4, PrevLogIndex: 4, PrevLogTerm: 3, LeaderCommit: -1},
		// 同任期命令冲突。
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(2, 3, "X")}},
		// 覆盖已提交条目。
		AppendRequest{Term: 4, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(2, 4, "e")}},
	)
	for i, result := range out.Results {
		if result.Conflict != nil {
			t.Fatalf("result %d must carry no conflict, got %+v (reason=%s)", i, result.Conflict, result.Reason)
		}
	}
	if accepted := out.Results[0]; !accepted.Accepted {
		t.Fatalf("result 0 should be accepted: %+v", accepted)
	}
}

// 合法的更高任期请求即使前置不匹配，任期更新保留，conflict 照常附带。
func TestConflictWithHigherTermKeepsTermUpdate(t *testing.T) {
	initial := InitialState{CurrentTerm: 3,
		Log: []LogEntry{entry(1, 1, "a"), entry(2, 3, "b"), entry(3, 3, "c")}}
	out := run(t, initial,
		AppendRequest{Term: 7, PrevLogIndex: 3, PrevLogTerm: 2},
	)
	result := out.Results[0]
	want := &ConflictHint{Index: 2, Term: 3}
	if !reflect.DeepEqual(result.Conflict, want) {
		t.Fatalf("conflict = %+v, want %+v", result.Conflict, want)
	}
	if result.Term != 7 {
		t.Fatalf("term update should survive, got %d", result.Term)
	}
	if len(out.FinalLog) != 3 {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
}

// 顺序处理：每条反馈反映各自处理时的日志，不能借用最终日志生成；前置不匹配
// 不改变任何状态。
func TestConflictHintsReflectLogAtEachRequest(t *testing.T) {
	initial := InitialState{CurrentTerm: 3,
		Log: []LogEntry{entry(1, 1, "a")}}
	out := run(t, initial,
		// 此刻本地只有 idx1：声称 idx3 缺失 → index 2、term 0。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 1},
		// 合法追加 idx2..3（任期 3）。
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 1, LeaderCommit: 0,
			Entries: []LogEntry{entry(2, 3, "b"), entry(3, 3, "c")}},
		// 现在 idx3 存在但任期与声称的 2 不同：回退到任期 3 段起点 idx2。
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 2},
	)
	want := []ConflictHint{{Index: 2, Term: 0}, {}, {Index: 2, Term: 3}}
	if got := out.Results[0].Conflict; !reflect.DeepEqual(got, &want[0]) {
		t.Fatalf("result 0 conflict = %+v, want %+v", got, want[0])
	}
	if !out.Results[1].Accepted {
		t.Fatalf("result 1 should be accepted: %+v", out.Results[1])
	}
	if got := out.Results[2].Conflict; !reflect.DeepEqual(got, &want[2]) {
		t.Fatalf("result 2 conflict = %+v, want %+v（must reflect the grown log, not the first one）", got, want[2])
	}
}

// conflict 字段的 JSON 形状：不匹配时出现，成功/其他拒绝时整体缺省；往返保留。
func TestConflictJSONShapeAndRoundTrip(t *testing.T) {
	initial := InitialState{CurrentTerm: 3,
		Log: []LogEntry{entry(1, 1, "a"), entry(2, 3, "b"), entry(3, 3, "c")}}
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 2},
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 3},
	)
	rejected, err := json.Marshal(out.Results[0])
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := json.Marshal(out.Results[1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rejected), `"conflict":{"index":2,"term":3}`) {
		t.Fatalf("rejected result missing conflict: %s", rejected)
	}
	if strings.Contains(string(accepted), "conflict") {
		t.Fatalf("accepted result must omit conflict: %s", accepted)
	}
	var decoded AppendResult
	if err := json.Unmarshal(rejected, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, out.Results[0]) {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", decoded, out.Results[0])
	}
}
