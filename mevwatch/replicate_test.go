package mevwatch

import (
	"testing"
)

type entrySpec struct {
	term int
	cmd  string
}

func mkEntries(specs ...entrySpec) []AppendEntry {
	out := make([]AppendEntry, len(specs))
	for i, s := range specs {
		out[i] = AppendEntry{Term: s.term, Command: s.cmd}
	}
	return out
}

func mkLog(specs ...entrySpec) []LogEntry {
	out := make([]LogEntry, len(specs))
	for i, s := range specs {
		out[i] = LogEntry{Index: i + 1, Term: s.term, Command: s.cmd}
	}
	return out
}

func runReplicate(t *testing.T, st InitialState, reqs ...ReplicationRequest) ReplicateOutput {
	t.Helper()
	out, err := Replicate(ReplicateInput{InitialState: st, Requests: reqs})
	if err != nil {
		t.Fatalf("Replicate: %v", err)
	}
	return out
}

func logTerms(log []LogEntry) []int {
	out := make([]int, len(log))
	for i, e := range log {
		out[i] = e.Term
	}
	return out
}

func logCmds(log []LogEntry) []string {
	out := make([]string, len(log))
	for i, e := range log {
		out[i] = e.Command
	}
	return out
}

func resultOKs(out ReplicateOutput) []bool {
	out2 := make([]bool, len(out.Results))
	for i, r := range out.Results {
		out2[i] = r.OK
	}
	return out2
}

func TestReplicate_EmptyFollowerAppend(t *testing.T) {
	// Follower at term 0 with no log; leader term 1 sends entries from origin.
	st := InitialState{CurrentTerm: 0, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0,
		Entries: mkEntries(entrySpec{1, "a"}, entrySpec{1, "b"}), LeaderCommit: 2,
	})
	r := out.Results[0]
	if !r.OK || r.Reason != ReasonOK {
		t.Fatalf("result = %+v", r)
	}
	if r.Term != 1 || r.CommitIndex != 2 {
		t.Fatalf("term=%d commit=%d", r.Term, r.CommitIndex)
	}
	if len(out.Log) != 2 || out.Log[0].Index != 1 || out.Log[1].Index != 2 {
		t.Fatalf("log = %+v", out.Log)
	}
}

func TestReplicate_LowerTermRejected(t *testing.T) {
	st := InitialState{CurrentTerm: 3, CommitIndex: 1, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 1, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{2, "b"}), LeaderCommit: 2,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonLowerTerm {
		t.Fatalf("result = %+v", r)
	}
	if r.Term != 3 || r.CommitIndex != 1 {
		t.Fatalf("state changed: term=%d commit=%d", r.Term, r.CommitIndex)
	}
	if len(out.Log) != 2 {
		t.Fatalf("log changed: %+v", out.Log)
	}
}

func TestReplicate_HigherTermPrefixMismatchKeepsTerm(t *testing.T) {
	// Higher term is adopted before the prefix check, so even a rejected
	// request leaves the term update in place.
	st := InitialState{CurrentTerm: 2, CommitIndex: 0, Log: mkLog(entrySpec{1, "a"})}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 4, PrevLogIndex: 5, PrevLogTerm: 0,
		Entries: mkEntries(entrySpec{4, "x"}), LeaderCommit: 1,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonPrevLogMissing {
		t.Fatalf("result = %+v", r)
	}
	if r.Term != 4 {
		t.Fatalf("term not updated on rejection: %d", r.Term)
	}
	if r.CommitIndex != 0 || len(out.Log) != 1 {
		t.Fatalf("log/commit changed: commit=%d log=%+v", r.CommitIndex, out.Log)
	}
}

func TestReplicate_HigherTermAdoptedAndAppended(t *testing.T) {
	st := InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 3, PrevLogIndex: 2, PrevLogTerm: 2,
		Entries: mkEntries(entrySpec{3, "c"}, entrySpec{3, "d"}), LeaderCommit: 4,
	})
	r := out.Results[0]
	if !r.OK || r.Term != 3 || r.CommitIndex != 4 {
		t.Fatalf("result = %+v", r)
	}
	if len(out.Log) != 4 {
		t.Fatalf("log = %+v", out.Log)
	}
}

func TestReplicate_PrevLogTermMismatch(t *testing.T) {
	st := InitialState{CurrentTerm: 2, CommitIndex: 0, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 2, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{2, "b"}), LeaderCommit: 2,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonPrevLogTermMismatch {
		t.Fatalf("result = %+v", r)
	}
	if r.CommitIndex != 0 || len(out.Log) != 2 {
		t.Fatalf("state changed: commit=%d log=%+v", r.CommitIndex, out.Log)
	}
}

func TestReplicate_IndexZeroOnlyMatchesTermZero(t *testing.T) {
	st := InitialState{CurrentTerm: 2, CommitIndex: 0, Log: mkLog(entrySpec{1, "a"})}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 0, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{2, "b"}), LeaderCommit: 1,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonPrevLogTermMismatch {
		t.Fatalf("result = %+v", r)
	}
	if r.CommitIndex != 0 || len(out.Log) != 1 {
		t.Fatalf("state changed: commit=%d log=%+v", r.CommitIndex, out.Log)
	}
}

func TestReplicate_TermConflictReplacesSuffix(t *testing.T) {
	// Follower log [1,1,2,2] commit 2; leader sends from index 2 with term 3.
	// Index 3 is uncommitted, so the conflicting entry and its suffix are
	// replaced.
	st := InitialState{CurrentTerm: 2, CommitIndex: 2, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{1, "b"}, entrySpec{2, "c"}, entrySpec{2, "d"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 3, PrevLogIndex: 2, PrevLogTerm: 1,
		Entries:      mkEntries(entrySpec{3, "c'"}, entrySpec{3, "d'"}),
		LeaderCommit: 4,
	})
	r := out.Results[0]
	if !r.OK {
		t.Fatalf("result = %+v", r)
	}
	want := []int{1, 1, 3, 3}
	if got := logTerms(out.Log); len(got) != len(want) {
		t.Fatalf("log terms = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("log terms = %v, want %v", got, want)
			}
		}
	}
	if got := logCmds(out.Log); got[2] != "c'" || got[3] != "d'" {
		t.Fatalf("log commands = %v", got)
	}
	if r.CommitIndex != 4 {
		t.Fatalf("commit = %d", r.CommitIndex)
	}
}

func TestReplicate_CommittedOverwriteRejected(t *testing.T) {
	// Conflict at index 3 which is already committed: reject atomically.
	st := InitialState{CurrentTerm: 2, CommitIndex: 3, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{1, "b"}, entrySpec{2, "c"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 3, PrevLogIndex: 2, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{3, "x"}), LeaderCommit: 3,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonCommittedOverwrite {
		t.Fatalf("result = %+v", r)
	}
	if r.Term != 3 {
		t.Fatalf("term should still be updated to 3, got %d", r.Term)
	}
	if r.CommitIndex != 3 {
		t.Fatalf("commit changed: %d", r.CommitIndex)
	}
	if len(out.Log) != 3 || logTerms(out.Log)[2] != 2 {
		t.Fatalf("log changed: %+v", out.Log)
	}
}

func TestReplicate_CommandMismatchRejected(t *testing.T) {
	// Same index and term but different command: reject, no state change.
	st := InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 1, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{2, "X"}), LeaderCommit: 2,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonCommandMismatch {
		t.Fatalf("result = %+v", r)
	}
	if r.CommitIndex != 1 || len(out.Log) != 2 {
		t.Fatalf("state changed: commit=%d log=%+v", r.CommitIndex, out.Log)
	}
}

func TestReplicate_AtomicBatchRejectsWithoutAppends(t *testing.T) {
	// Batch: index 2 mismatches (same term, different command) while index 3
	// would be a new append. The whole request must be rejected atomically.
	st := InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 1, PrevLogTerm: 1,
		Entries:      mkEntries(entrySpec{2, "X"}, entrySpec{2, "c"}),
		LeaderCommit: 3,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonCommandMismatch {
		t.Fatalf("result = %+v", r)
	}
	if r.CommitIndex != 1 || len(out.Log) != 2 {
		t.Fatalf("partial change leaked: commit=%d log=%+v", r.CommitIndex, out.Log)
	}
}

func TestReplicate_EmptyBatchCommitsPrevIndex(t *testing.T) {
	// Empty entries: confirmed index is prevLogIndex. Extra local tail is
	// kept but must not be committed.
	st := InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{2, "b"}, entrySpec{2, "c"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 1, PrevLogTerm: 1,
		Entries: nil, LeaderCommit: 10,
	})
	r := out.Results[0]
	if !r.OK {
		t.Fatalf("result = %+v", r)
	}
	if r.CommitIndex != 1 {
		t.Fatalf("commit = %d, want 1 (min(10, prev=1))", r.CommitIndex)
	}
	if len(out.Log) != 3 {
		t.Fatalf("local tail deleted: %+v", out.Log)
	}
}

func TestReplicate_CommitNeverDecreases(t *testing.T) {
	st := InitialState{CurrentTerm: 2, CommitIndex: 3, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{1, "b"}, entrySpec{2, "c"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 3, PrevLogTerm: 2,
		Entries: nil, LeaderCommit: 1,
	})
	r := out.Results[0]
	if !r.OK || r.CommitIndex != 3 {
		t.Fatalf("result = %+v", r)
	}
}

func TestReplicate_CommitCappedByLastConfirmed(t *testing.T) {
	st := InitialState{CurrentTerm: 1, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0,
		Entries:      mkEntries(entrySpec{1, "a"}, entrySpec{1, "b"}, entrySpec{1, "c"}),
		LeaderCommit: 1,
	})
	r := out.Results[0]
	if !r.OK || r.CommitIndex != 1 {
		t.Fatalf("result = %+v", r)
	}
}

func TestReplicate_DuplicateRequestIsIdempotent(t *testing.T) {
	st := InitialState{CurrentTerm: 1, CommitIndex: 0, Log: nil}
	req := ReplicationRequest{
		LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0,
		Entries: mkEntries(entrySpec{1, "a"}, entrySpec{1, "b"}), LeaderCommit: 2,
	}
	out := runReplicate(t, st, req, req)
	if got := resultOKs(out); len(got) != 2 || !got[0] || !got[1] {
		t.Fatalf("results = %v", out.Results)
	}
	if len(out.Log) != 2 {
		t.Fatalf("duplicate entries appended: %+v", out.Log)
	}
	if out.CommitIndex != 2 {
		t.Fatalf("commit = %d", out.CommitIndex)
	}
}

func TestReplicate_ShortRequestKeepsLocalTail(t *testing.T) {
	// Request fully matches a prefix but is shorter than the local log:
	// the extra local tail must survive.
	st := InitialState{CurrentTerm: 2, CommitIndex: 2, Log: mkLog(
		entrySpec{1, "a"}, entrySpec{1, "b"}, entrySpec{2, "c"}, entrySpec{2, "d"},
	)}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 2, PrevLogIndex: 2, PrevLogTerm: 1,
		Entries: mkEntries(entrySpec{2, "c"}), LeaderCommit: 3,
	})
	r := out.Results[0]
	if !r.OK {
		t.Fatalf("result = %+v", r)
	}
	if len(out.Log) != 4 {
		t.Fatalf("local tail deleted: %+v", out.Log)
	}
	if r.CommitIndex != 3 {
		t.Fatalf("commit = %d", r.CommitIndex)
	}
}

func TestReplicate_InvalidRequestRejectedWithoutTermUpdate(t *testing.T) {
	// Higher leader term but entry term exceeds it: field violation, so the
	// node must not adopt the higher term.
	st := InitialState{CurrentTerm: 2, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 3, PrevLogIndex: 0, PrevLogTerm: 0,
		Entries: mkEntries(entrySpec{4, "x"}), LeaderCommit: 1,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonInvalidRequest {
		t.Fatalf("result = %+v", r)
	}
	if r.Term != 2 {
		t.Fatalf("term updated on invalid request: %d", r.Term)
	}
}

func TestReplicate_InvalidRequestNegativeCommit(t *testing.T) {
	st := InitialState{CurrentTerm: 1, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st, ReplicationRequest{
		LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0,
		Entries: nil, LeaderCommit: -1,
	})
	r := out.Results[0]
	if r.OK || r.Reason != ReasonInvalidRequest {
		t.Fatalf("result = %+v", r)
	}
}

func TestReplicate_InvalidRequestDoesNotBlockNext(t *testing.T) {
	// Invalid request is rejected with no state change; the next request is
	// processed normally.
	st := InitialState{CurrentTerm: 1, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st,
		ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{3, "x"}), LeaderCommit: 1},
		ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{2, "a"}), LeaderCommit: 1},
	)
	if out.Results[0].OK || out.Results[0].Reason != ReasonInvalidRequest {
		t.Fatalf("result0 = %+v", out.Results[0])
	}
	if !out.Results[1].OK {
		t.Fatalf("result1 = %+v", out.Results[1])
	}
	if out.Term != 2 || out.CommitIndex != 1 || len(out.Log) != 1 {
		t.Fatalf("final state: term=%d commit=%d log=%+v", out.Term, out.CommitIndex, out.Log)
	}
}

func TestReplicate_Sequence(t *testing.T) {
	// End-to-end: append, commit, conflict replace, idempotent retry.
	st := InitialState{CurrentTerm: 1, CommitIndex: 0, Log: nil}
	out := runReplicate(t, st,
		ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{1, "a"}), LeaderCommit: 1},
		ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 1, PrevLogTerm: 1, Entries: mkEntries(entrySpec{1, "b"}, entrySpec{1, "c"}), LeaderCommit: 3},
		ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 3, PrevLogTerm: 1, Entries: mkEntries(entrySpec{2, "d"}, entrySpec{2, "e"}), LeaderCommit: 5},
		ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 3, PrevLogTerm: 1, Entries: mkEntries(entrySpec{2, "d"}, entrySpec{2, "e"}), LeaderCommit: 5},
	)
	if got := resultOKs(out); len(got) != 4 || !got[0] || !got[1] || !got[2] || !got[3] {
		t.Fatalf("results = %v", out.Results)
	}
	if out.Term != 2 || out.CommitIndex != 5 {
		t.Fatalf("term=%d commit=%d", out.Term, out.CommitIndex)
	}
	if len(out.Log) != 5 {
		t.Fatalf("log = %+v", out.Log)
	}
}

func TestReplicate_Deterministic(t *testing.T) {
	st := InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(entrySpec{1, "a"})}
	reqs := []ReplicationRequest{
		{LeaderTerm: 3, PrevLogIndex: 1, PrevLogTerm: 1, Entries: mkEntries(entrySpec{2, "b"}, entrySpec{3, "c"}), LeaderCommit: 3},
		{LeaderTerm: 3, PrevLogIndex: 3, PrevLogTerm: 3, Entries: nil, LeaderCommit: 3},
	}
	out1 := runReplicate(t, st, reqs...)
	out2 := runReplicate(t, st, reqs...)
	if len(out1.Results) != len(out2.Results) {
		t.Fatalf("length mismatch")
	}
	for i := range out1.Results {
		if out1.Results[i] != out2.Results[i] {
			t.Fatalf("result %d differs: %+v vs %+v", i, out1.Results[i], out2.Results[i])
		}
	}
	if out1.Term != out2.Term || out1.CommitIndex != out2.CommitIndex {
		t.Fatalf("final state differs")
	}
}

func TestValidateInitialState(t *testing.T) {
	tests := []struct {
		name string
		st   InitialState
		want bool
	}{
		{"empty", InitialState{CurrentTerm: 0, CommitIndex: 0, Log: nil}, true},
		{"valid", InitialState{CurrentTerm: 2, CommitIndex: 1, Log: mkLog(
			entrySpec{1, "a"}, entrySpec{2, "b"},
		)}, true},
		{"negative term", InitialState{CurrentTerm: -1, CommitIndex: 0, Log: nil}, false},
		{"negative commit", InitialState{CurrentTerm: 0, CommitIndex: -1, Log: nil}, false},
		{"commit beyond log", InitialState{CurrentTerm: 1, CommitIndex: 2, Log: mkLog(entrySpec{1, "a"})}, false},
		{"gap index", InitialState{CurrentTerm: 1, CommitIndex: 0, Log: []LogEntry{
			{Index: 1, Term: 1, Command: "a"},
			{Index: 3, Term: 1, Command: "b"},
		}}, false},
		{"zero term entry", InitialState{CurrentTerm: 1, CommitIndex: 0, Log: []LogEntry{
			{Index: 1, Term: 0, Command: "a"},
		}}, false},
		{"decreasing terms", InitialState{CurrentTerm: 2, CommitIndex: 0, Log: []LogEntry{
			{Index: 1, Term: 2, Command: "a"},
			{Index: 2, Term: 1, Command: "b"},
		}}, false},
		{"term above current", InitialState{CurrentTerm: 1, CommitIndex: 0, Log: []LogEntry{
			{Index: 1, Term: 2, Command: "a"},
		}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateInitialState(tt.st); (err == nil) != tt.want {
				t.Fatalf("err = %v, want valid=%v", err, tt.want)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {
	tests := []struct {
		name string
		req  ReplicationRequest
		want bool
	}{
		{"empty valid", ReplicationRequest{LeaderTerm: 0, PrevLogIndex: 0, PrevLogTerm: 0, Entries: nil, LeaderCommit: 0}, true},
		{"valid entries", ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 1, PrevLogTerm: 1, Entries: mkEntries(entrySpec{1, "a"}, entrySpec{2, "b"}), LeaderCommit: 3}, true},
		{"negative leader term", ReplicationRequest{LeaderTerm: -1, PrevLogIndex: 0, PrevLogTerm: 0, Entries: nil, LeaderCommit: 0}, false},
		{"negative prev index", ReplicationRequest{LeaderTerm: 1, PrevLogIndex: -1, PrevLogTerm: 0, Entries: nil, LeaderCommit: 0}, false},
		{"negative prev term", ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: -1, Entries: nil, LeaderCommit: 0}, false},
		{"negative commit", ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0, Entries: nil, LeaderCommit: -1}, false},
		{"zero entry term", ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{0, "x"}), LeaderCommit: 1}, false},
		{"decreasing entry terms", ReplicationRequest{LeaderTerm: 2, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{2, "a"}, entrySpec{1, "b"}), LeaderCommit: 2}, false},
		{"entry term above leader", ReplicationRequest{LeaderTerm: 1, PrevLogIndex: 0, PrevLogTerm: 0, Entries: mkEntries(entrySpec{2, "x"}), LeaderCommit: 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateRequest(tt.req); (err == nil) != tt.want {
				t.Fatalf("err = %v, want valid=%v", err, tt.want)
			}
		})
	}
}
