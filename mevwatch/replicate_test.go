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

// 前置索引越过本地日志末尾：建议从末尾加一处重发，任期记 0；空日志因此是索引 1。
func TestConflictHintIndexBeyondLog(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 2},
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2},
	)
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonPrevLogMismatch {
		t.Fatalf("expected prev log mismatch, got %+v", result)
	}
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 1, Term: 0}) {
		t.Fatalf("empty log conflict = %+v, want {1 0}", result.Conflict)
	}

	initial := InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 1, "a"), entry(2, 2, "b")}}
	out = run(t, initial,
		AppendRequest{Term: 2, PrevLogIndex: 5, PrevLogTerm: 2},
	)
	result = out.Results[0]
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 3, Term: 0}) {
		t.Fatalf("beyond-end conflict = %+v, want {3 0}", result.Conflict)
	}
}

// 前置索引存在但任期不同：反馈该位置的本地任期，以及这个任期在完整本地日志中
// 第一次出现的索引——即使该任期的部分条目已经提交，起点也不能推到提交位置之后。
func TestConflictHintTermMismatchFirstOccurrence(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 3, Log: []LogEntry{
		entry(1, 1, "a"), entry(2, 3, "b"), entry(3, 3, "c"), entry(4, 3, "d"),
	}}
	out := run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 4, PrevLogTerm: 2},
	)
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonPrevLogMismatch {
		t.Fatalf("expected prev log mismatch, got %+v", result)
	}
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 2, Term: 3}) {
		t.Fatalf("conflict = %+v, want {2 3}", result.Conflict)
	}
	// 同任期段中间的索引同样回到段首。
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 3, PrevLogTerm: 1},
	)
	if got := out.Results[0].Conflict; got == nil || *got != (ConflictHint{Index: 2, Term: 3}) {
		t.Fatalf("conflict = %+v, want {2 3}", got)
	}
	// 冲突在首个任期段上时，起点是该段第一条。
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 3},
	)
	if got := out.Results[0].Conflict; got == nil || *got != (ConflictHint{Index: 1, Term: 1}) {
		t.Fatalf("conflict = %+v, want {1 1}", got)
	}
}

// 索引 0 是日志起点哨兵：携带非零前置任期按现有规则拒绝，反馈 index 1、term 0。
func TestConflictHintSentinelNonZeroTerm(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 3},
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 1},
	)
	if got := out.Results[0].Conflict; got == nil || *got != (ConflictHint{Index: 1, Term: 0}) {
		t.Fatalf("empty log sentinel conflict = %+v, want {1 0}", got)
	}
	initial := InitialState{CurrentTerm: 3, Log: []LogEntry{entry(1, 2, "a"), entry(2, 2, "b")}}
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 2},
	)
	if got := out.Results[0].Conflict; got == nil || *got != (ConflictHint{Index: 1, Term: 0}) {
		t.Fatalf("sentinel conflict = %+v, want {1 0}", got)
	}
}

// 成功请求与其他原因的拒绝（低任期、字段非法、同任期命令冲突、覆盖已提交
// 条目）都不携带 conflict；多种问题并存时沿用现有拒绝顺序，只有实际因前置
// 日志不匹配而拒绝的结果附带反馈。
func TestConflictHintOnlyOnPrevLogMismatch(t *testing.T) {
	initial := InitialState{CurrentTerm: 3, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 2, "a"), entry(2, 2, "b"),
	}}
	out := run(t, initial,
		// 成功。
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 2},
		// 低任期（同时前置索引也越界，但拒绝原因是低任期）。
		AppendRequest{Term: 2, PrevLogIndex: 9, PrevLogTerm: 9},
		// 字段非法（同时前置索引越界）。
		AppendRequest{Term: -1, PrevLogIndex: 9, PrevLogTerm: 0},
		// 同任期命令冲突。
		AppendRequest{Term: 3, PrevLogIndex: 1, PrevLogTerm: 2,
			Entries: []LogEntry{entry(2, 2, "changed")}},
		// 覆盖已提交条目。
		AppendRequest{Term: 3, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 3, "new")}},
	)
	for i, result := range out.Results {
		if result.Conflict != nil {
			t.Fatalf("result %d (%s) should not carry conflict, got %+v", i, result.Reason, result.Conflict)
		}
	}
	if !out.Results[0].Accepted {
		t.Fatalf("first request should be accepted, got %+v", out.Results[0])
	}
	// 同时携带更高任期与前置不匹配：实际拒绝原因是前置不匹配，附带反馈，
	// 且任期更新保留。
	out = run(t, InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 2, "a")}},
		AppendRequest{Term: 7, PrevLogIndex: 1, PrevLogTerm: 3},
	)
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonPrevLogMismatch {
		t.Fatalf("expected prev log mismatch, got %+v", result)
	}
	if result.Term != 7 {
		t.Fatalf("term update should survive, got %d", result.Term)
	}
	if result.Conflict == nil || *result.Conflict != (ConflictHint{Index: 1, Term: 2}) {
		t.Fatalf("conflict = %+v, want {1 2}", result.Conflict)
	}
}

// 每条反馈反映各自请求处理时的本地日志，不能借用最终日志生成。
func TestConflictHintReflectsLogAtRequestTime(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 1},
		// 先复制两条任期 1 的条目。
		AppendRequest{Term: 1, PrevLogIndex: 0, PrevLogTerm: 0,
			Entries: []LogEntry{entry(1, 1, "a"), entry(2, 1, "b")}},
		// 此时本地日志有两条：越界反馈末尾加一。
		AppendRequest{Term: 1, PrevLogIndex: 4, PrevLogTerm: 1},
		// 再追加一条任期 2 的条目。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 1,
			Entries: []LogEntry{entry(3, 2, "c")}},
		// 此时本地日志有三条：同样的越界请求反馈随之变化。
		AppendRequest{Term: 2, PrevLogIndex: 4, PrevLogTerm: 1},
	)
	if got := out.Results[1].Conflict; got == nil || *got != (ConflictHint{Index: 3, Term: 0}) {
		t.Fatalf("second result conflict = %+v, want {3 0}", got)
	}
	if got := out.Results[3].Conflict; got == nil || *got != (ConflictHint{Index: 4, Term: 0}) {
		t.Fatalf("fourth result conflict = %+v, want {4 0}", got)
	}
}

// TestFirstEntryTermBelowPrevLogTermIsFieldError 回归保障任期衔接规则：非空请求
// 除了条目自身任期不下降，第一条日志的任期也不能低于请求声明的前置任期。这种
// 错误属于字段非法：即使请求携带更高任期、leaderCommit 更大、甚至前置日志本身
// 也匹配不上，都必须在任期更新与前缀核对之前拒绝——原因固定为
// "entry terms are not non-decreasing"，不输出 conflict，任期、日志、提交位置
// 全部保持请求前状态。
func TestFirstEntryTermBelowPrevLogTermIsFieldError(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set balance=100"),
		entry(2, 2, "set balance=200"),
	}}
	original := append([]LogEntry(nil), initial.Log...)
	cases := []struct {
		name    string
		request AppendRequest
	}{
		{
			// 任务主场景：任期 7、前置 idx2/任期2 与本地一致，首条 idx3 任期 1
			// 低于声明的前置任期 2；leaderCommit 再大也无济于事。
			"matching prev, higher term, huge leaderCommit",
			AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 9,
				Entries: []LogEntry{entry(3, 1, "x")}},
		},
		{
			// 声明的前置任期与本地日志不一致（本地 idx2 任期 2，声明 5），但
			// 首条任期 1 仍低于声明值：仍是同一条字段错误，不能改成前置日志
			// 不匹配，也不能留下较高任期更新。
			"declared prev term mismatches local too",
			AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 5, LeaderCommit: 9,
				Entries: []LogEntry{entry(3, 1, "x")}},
		},
		{
			// 前置索引越过本地日志末尾，首条索引随之合法地落在日志之后：衔接
			// 错误仍先于前缀核对，不附带重发建议。
			"prev index beyond log",
			AppendRequest{Term: 8, PrevLogIndex: 5, PrevLogTerm: 3, LeaderCommit: 0,
				Entries: []LogEntry{entry(6, 2, "x")}},
		},
		{
			// 首条任期等于……严格低于才非法：这里首条比前置任期低 1，且声明
			// 前置任期与本地不同，字段错误判定只看声明值。
			"first term one below declared prev term",
			AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 3, LeaderCommit: 4,
				Entries: []LogEntry{entry(3, 2, "x")}},
		},
		{
			// 多条目自身任期不下降（1 -> 7），但首条低于前置任期 2：条目内部
			// 规则通过，衔接规则单独拒绝；第二条的高任期同样不能留下更新。
			"multiple entries internally non-decreasing but bridge too low",
			AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 4,
				Entries: []LogEntry{entry(3, 1, "x"), entry(4, 7, "y")}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := run(t, initial, tc.request)
			result := out.Results[0]
			if result.Accepted {
				t.Fatalf("request should be rejected: %+v", result)
			}
			if result.Reason != ReasonEntryTermDecreases {
				t.Fatalf("reason = %q, want exact %q", result.Reason, ReasonEntryTermDecreases)
			}
			if !strings.Contains(result.Reason, "entry terms are not non-decreasing") {
				t.Fatalf("reason text changed: %q", result.Reason)
			}
			if result.Conflict != nil {
				t.Fatalf("field error must not be treated as a replication conflict: %+v", result.Conflict)
			}
			if result.Term != 2 {
				t.Fatalf("higher term must not survive a field error, term = %d, want 2", result.Term)
			}
			if result.CommittedIndex != 1 {
				t.Fatalf("commit changed: %d, want 1", result.CommittedIndex)
			}
			if out.FinalTerm != 2 || out.FinalCommittedIndex != 1 {
				t.Fatalf("final state changed: term=%d ci=%d", out.FinalTerm, out.FinalCommittedIndex)
			}
			if !reflect.DeepEqual(out.FinalLog, original) {
				t.Fatalf("log changed: %+v", out.FinalLog)
			}
			// 输出约定：该拒绝的 JSON 中不出现 conflict 键。
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "conflict") {
				t.Fatalf("rejection JSON must omit conflict: %s", encoded)
			}
		})
	}
}

// TestFirstEntryTermEqualPrevLogTermIsLegal 首条任期恰好等于前置任期是合法衔接，
// 包括领导者任期更高、首条沿用旧任期的情形。
func TestFirstEntryTermEqualPrevLogTermIsLegal(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "a"), entry(2, 2, "b"),
	}}
	out := run(t, initial,
		// 同任期追加：首条任期 2 == 前置任期 2。
		AppendRequest{Term: 2, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3,
			Entries: []LogEntry{entry(3, 2, "c")}},
	)
	if !out.Results[0].Accepted || out.Results[0].Reason != ReasonOK {
		t.Fatalf("equal-term bridge should be accepted: %+v", out.Results[0])
	}

	// 更高任期的领导者携带一条旧任期条目：首条任期 2 仍等于前置任期 2，
	// 合法；随后条目任期升到 3 同样合法。
	out = run(t, initial,
		AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 4,
			Entries: []LogEntry{entry(3, 2, "c"), entry(4, 3, "d")}},
	)
	result := out.Results[0]
	if !result.Accepted || result.Reason != ReasonOK {
		t.Fatalf("equal-term bridge under higher leader term should be accepted: %+v", result)
	}
	want := []LogEntry{
		entry(1, 1, "a"), entry(2, 2, "b"), entry(3, 2, "c"), entry(4, 3, "d"),
	}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("log = %+v, want %+v", out.FinalLog, want)
	}
	if result.Term != 3 || result.CommittedIndex != 4 {
		t.Fatalf("state = term %d ci %d, want term 3 ci 4", result.Term, result.CommittedIndex)
	}
}

// TestEmptyEntriesHaveNoFirstTermBridge 空条目请求没有首条日志，不能因此报任期
// 下降：前置不匹配时仍按前置日志不匹配拒绝、附带 conflict 并保留较高任期更新；
// 前置匹配时就是正常心跳。
func TestEmptyEntriesHaveNoFirstTermBridge(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "a"), entry(2, 2, "b"),
	}}
	out := run(t, initial,
		// 前置任期与本地不一致：拒绝原因是前置不匹配，不是条目任期下降。
		AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 5, LeaderCommit: 9},
		// 前置索引越过日志末尾：同样是前置不匹配。
		AppendRequest{Term: 8, PrevLogIndex: 5, PrevLogTerm: 3},
		// 前置匹配的空条目心跳：接受，leaderCommit 再大也只确认到前置索引。
		AppendRequest{Term: 8, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 9},
	)
	first := out.Results[0]
	if first.Accepted || first.Reason != ReasonPrevLogMismatch {
		t.Fatalf("empty request should be a prev mismatch, got %+v", first)
	}
	if first.Term != 7 {
		t.Fatalf("higher term should survive mismatch, term = %d, want 7", first.Term)
	}
	if first.Conflict == nil || *first.Conflict != (ConflictHint{Index: 2, Term: 2}) {
		t.Fatalf("conflict = %+v, want {2 2}", first.Conflict)
	}
	second := out.Results[1]
	if second.Accepted || second.Reason != ReasonPrevLogMismatch {
		t.Fatalf("beyond-end empty request should be a prev mismatch, got %+v", second)
	}
	if second.Conflict == nil || *second.Conflict != (ConflictHint{Index: 3, Term: 0}) {
		t.Fatalf("conflict = %+v, want {3 0}", second.Conflict)
	}
	heartbeat := out.Results[2]
	if !heartbeat.Accepted || heartbeat.Reason != ReasonOK {
		t.Fatalf("matching heartbeat should be accepted: %+v", heartbeat)
	}
	if heartbeat.CommittedIndex != 2 {
		t.Fatalf("heartbeat confirmed only index 2, commit = %d, want 2", heartbeat.CommittedIndex)
	}
	if len(out.FinalLog) != 2 {
		t.Fatalf("heartbeat must not change the log: %+v", out.FinalLog)
	}
}

// TestStaleTermPrecedesFirstTermBridge 低任期请求沿用现有的拒绝顺序：即使它同时
// 满足“首条任期低于前置任期”，拒绝原因仍是低任期，且不附带 conflict。
func TestStaleTermPrecedesFirstTermBridge(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "a"), entry(2, 2, "b"),
	}}
	out := run(t, initial,
		AppendRequest{Term: 1, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3,
			Entries: []LogEntry{entry(3, 1, "c")}},
	)
	result := out.Results[0]
	if result.Accepted || result.Reason != ReasonStaleTerm {
		t.Fatalf("expected stale-term rejection, got %+v", result)
	}
	if result.Conflict != nil {
		t.Fatalf("stale-term rejection must not carry conflict: %+v", result.Conflict)
	}
	if result.Term != 2 || result.CommittedIndex != 1 {
		t.Fatalf("state changed: %+v", result)
	}
	if !reflect.DeepEqual(out.FinalLog, initial.Log) {
		t.Fatalf("log changed: %+v", out.FinalLog)
	}
}

// TestFirstEntryTermBridgeFieldErrorThenValidRecovery 非法衔接请求被拒后节点保持
// 原状态，随后到达的合法请求按原状态继续处理：任期 3、正确匹配索引 2，追加索引
// 3、任期 2 的条目并提交到 3。
func TestFirstEntryTermBridgeFieldErrorThenValidRecovery(t *testing.T) {
	initial := InitialState{CurrentTerm: 2, CommittedIndex: 1, Log: []LogEntry{
		entry(1, 1, "set balance=100"),
		entry(2, 2, "set balance=200"),
	}}
	bad := AppendRequest{Term: 7, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 9,
		Entries: []LogEntry{entry(3, 1, "set evil=1")}}
	legal := AppendRequest{Term: 3, PrevLogIndex: 2, PrevLogTerm: 2, LeaderCommit: 3,
		Entries: []LogEntry{entry(3, 2, "set receipt=ok")}}
	out := run(t, initial, bad, legal)

	first := out.Results[0]
	if first.Accepted || first.Reason != ReasonEntryTermDecreases {
		t.Fatalf("first request should be the term-bridge field error, got %+v", first)
	}
	if first.Conflict != nil || first.Term != 2 || first.CommittedIndex != 1 {
		t.Fatalf("first request changed state: %+v", first)
	}
	second := out.Results[1]
	if !second.Accepted || second.Reason != ReasonOK {
		t.Fatalf("valid follow-up request must be processed from the original state: %+v", second)
	}
	if second.Term != 3 || second.CommittedIndex != 3 {
		t.Fatalf("second result state = term %d ci %d, want term 3 ci 3",
			second.Term, second.CommittedIndex)
	}
	want := []LogEntry{
		entry(1, 1, "set balance=100"),
		entry(2, 2, "set balance=200"),
		entry(3, 2, "set receipt=ok"),
	}
	if !reflect.DeepEqual(out.FinalLog, want) {
		t.Fatalf("final log = %+v, want %+v", out.FinalLog, want)
	}
	if out.FinalTerm != 3 || out.FinalCommittedIndex != 3 {
		t.Fatalf("final state = term %d ci %d, want term 3 ci 3",
			out.FinalTerm, out.FinalCommittedIndex)
	}
}

// conflict 只在前置日志不匹配的结果里出现在 JSON 中，其余结果不输出该键。
func TestConflictHintJSONShape(t *testing.T) {
	out := run(t, InitialState{CurrentTerm: 2, Log: []LogEntry{entry(1, 2, "a")}},
		AppendRequest{Term: 2, PrevLogIndex: 1, PrevLogTerm: 2},
		AppendRequest{Term: 2, PrevLogIndex: 3, PrevLogTerm: 2},
	)
	encoded, err := json.Marshal(out.Results[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "conflict") {
		t.Fatalf("accepted result should omit conflict, got %s", encoded)
	}
	encoded, err = json.Marshal(out.Results[1])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	conflict, ok := decoded["conflict"].(map[string]any)
	if !ok {
		t.Fatalf("mismatch result should carry conflict object, got %s", encoded)
	}
	if conflict["index"] != float64(2) || conflict["term"] != float64(0) {
		t.Fatalf("conflict = %v, want index 2 term 0", conflict)
	}
	// 编解码往返后反馈保持原样。
	var roundTrip AppendResult
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Conflict == nil || *roundTrip.Conflict != (ConflictHint{Index: 2, Term: 0}) {
		t.Fatalf("round trip conflict = %+v, want {2 0}", roundTrip.Conflict)
	}
}
