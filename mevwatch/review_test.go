package mevwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Review verdicts on archived risk conclusions. A review object is identified
// by (chain, block hash, victim tx hash, conclusion kind) — never by channel.

// reviewSpec builds one submission document.
func makeReviewSpec(chainID, blockHash, txHash, kind, commitID, operator, reason string, expected int, status string) []byte {
	return []byte(fmt.Sprintf(
		`{"chainId":%q,"blockHash":%q,"txHash":%q,"kind":%q,"commitId":%q,"operator":%q,"reason":%q,"expectedVersion":%d,"status":%q}`,
		chainID, blockHash, txHash, kind, commitID, operator, reason, expected, status))
}

// reviewBlockInput builds a block with a sandwich victim (0xv) and a
// displacement victim (0xd) at the given height/hash.
func reviewBlockInput(hash string, height int64) string {
	return fmt.Sprintf(`{"chainId":"1","blockHash":%q,"blockNumber":%d,"swaps":[`+
		`{"TxHash":"0xf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0xv","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+k","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},`+
		`{"TxHash":"0+w","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":50,"Index":3},`+
		`{"TxHash":"0xd","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4}]}`,
		hash, height)
}

// sandwichOnlyInput builds a block with only a sandwich victim (0xv) at the
// given height/hash. The sandwich is displacement-capable (front gas 90 >
// victim gas 10 * 2), so disabling the sandwich rule re-flags it as
// displacement.
func sandwichOnlyInput(hash string, height int64) string {
	return fmt.Sprintf(`{"chainId":"1","blockHash":%q,"blockNumber":%d,"swaps":[`+
		`{"TxHash":"0xf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0xv","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+k","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2}]}`,
		hash, height)
}

// displacementOnlyInput builds a block with only a displacement victim (0xd)
// at the given height/hash.
func displacementOnlyInput(hash string, height int64) string {
	return fmt.Sprintf(`{"chainId":"1","blockHash":%q,"blockNumber":%d,"swaps":[`+
		`{"TxHash":"0+w","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":50,"Index":0},`+
		`{"TxHash":"0xd","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1}]}`,
		hash, height)
}

// noSandwichSpec disables the sandwich rule; displacement stays enabled.
const noSandwichSpec = `{"id":"noSandwich","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`

// noDisplacementSpec disables the displacement rule; sandwich stays enabled.
const noDisplacementSpec = `{"id":"noDisplacement","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`

// noRulesSpec disables both rules.
const noRulesSpec = `{"id":"noRules","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`

func registerReviewVersion(t *testing.T, dir, spec string) {
	t.Helper()
	if _, _, err := RegisterVersion(dir, []byte(spec)); err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
}

func mustReplayWithVersion(t *testing.T, dir, input, versionID string) {
	t.Helper()
	if _, err := ReplayWithVersion(strings.NewReader(input), dir, versionID); err != nil {
		t.Fatalf("ReplayWithVersion: %v", err)
	}
}

// --- submit + history ---

func TestSubmitReviewFirstRealRisk(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	state, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk))
	if err != nil {
		t.Fatalf("SubmitReview: %v", err)
	}
	if state.Version != 1 {
		t.Fatalf("version = %d, want 1", state.Version)
	}
	if len(state.Revisions) != 1 {
		t.Fatalf("revisions = %d, want 1", len(state.Revisions))
	}
	rev := state.Revisions[0]
	if rev.CommitID != "c1" || rev.Operator != "alice" || rev.Reason != "real victim" ||
		rev.Status != ReviewRealRisk || rev.ExpectedVersion != 0 || rev.Version != 1 {
		t.Fatalf("bad revision: %+v", rev)
	}
}

func TestSubmitReviewFalsePositiveAndWithdrawal(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// False positive.
	state, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "bob", "known bot war", 0, ReviewFalsePositive))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 || state.currentStatus() != ReviewFalsePositive {
		t.Fatalf("after FP: version=%d status=%q", state.Version, state.currentStatus())
	}

	// Withdrawal: a new revision with unreviewed status, version increments.
	state, err = SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "bob", "withdrawn", 1, ReviewUnreviewed))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 {
		t.Fatalf("after withdrawal: version=%d, want 2", state.Version)
	}
	if state.currentStatus() != ReviewUnreviewed {
		t.Fatalf("after withdrawal: status=%q, want unreviewed", state.currentStatus())
	}
	if len(state.Revisions) != 2 {
		t.Fatalf("revisions = %d, want 2 (old records retained)", len(state.Revisions))
	}
}

func TestSubmitReviewOverturn(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "looks real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// Overturn to false positive.
	state, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "alice", "actually a bot war", 1, ReviewFalsePositive))
	if err != nil {
		t.Fatal(err)
	}
	if state.Version != 2 || state.currentStatus() != ReviewFalsePositive {
		t.Fatalf("after overturn: version=%d status=%q", state.Version, state.currentStatus())
	}
	if len(state.Revisions) != 2 {
		t.Fatalf("revisions = %d, want 2", len(state.Revisions))
	}
	// Both revisions retained in order.
	if state.Revisions[0].Status != ReviewRealRisk || state.Revisions[1].Status != ReviewFalsePositive {
		t.Fatalf("revisions not retained in order: %+v", state.Revisions)
	}
}

func TestSubmitReviewIdempotentRetry(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	spec := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk)
	first, err := SubmitReview(dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Retry the exact same submission: returns the original revision, no append.
	again, err := SubmitReview(dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatalf("idempotent retry returned %+v, want %+v", again, first)
	}
	if again.Version != 1 || len(again.Revisions) != 1 {
		t.Fatalf("idempotent retry appended: version=%d revisions=%d", again.Version, len(again.Revisions))
	}

	// Even after a later overturn, retrying the original commit returns the
	// original revision without appending.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "alice", "overturn", 1, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}
	third, err := SubmitReview(dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	if third.Version != 2 || len(third.Revisions) != 2 {
		t.Fatalf("retry after overturn appended: version=%d revisions=%d", third.Version, len(third.Revisions))
	}
	if third.Revisions[0].Status != ReviewRealRisk {
		t.Fatalf("original revision lost: %+v", third.Revisions[0])
	}
}

func TestSubmitReviewSameCommitDifferentContentConflict(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// Same commit ID, different content (status): conflict.
	diff := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 1, ReviewFalsePositive)
	if _, err := SubmitReview(dir, diff); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("got %v, want ErrReviewConflict", err)
	}
	// Same commit ID, different operator: conflict.
	diffOp := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "bob", "real victim", 1, ReviewRealRisk)
	if _, err := SubmitReview(dir, diffOp); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("got %v, want ErrReviewConflict", err)
	}
	// No new revision appended.
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("conflict mutated history: version=%d revisions=%d", hist.Version, len(hist.Revisions))
	}
}

func TestSubmitReviewStaleExpectedVersionConflict(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// Expected version 0 but current is 1: conflict.
	stale := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "alice", "overturn", 0, ReviewFalsePositive)
	if _, err := SubmitReview(dir, stale); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("got %v, want ErrReviewConflict", err)
	}
	// Expected version 2 but current is 1: conflict.
	stale2 := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c3", "alice", "overturn", 2, ReviewFalsePositive)
	if _, err := SubmitReview(dir, stale2); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("got %v, want ErrReviewConflict", err)
	}
	// First submission with expected version 1: conflict (expects 0).
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xd", "displacement", "c9", "alice", "x", 1, ReviewRealRisk)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("first submission with expected=1: got %v, want ErrReviewConflict", err)
	}
}

func TestSubmitReviewNonexistentConclusion(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// Block hash not in archive.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xzz", "0xv", "sandwich", "c1", "alice", "x", 0, ReviewRealRisk)); !errors.Is(err, ErrUnknownConclusion) {
		t.Fatalf("unknown block: got %v, want ErrUnknownConclusion", err)
	}
	// Tx hash not in the block.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xzz", "sandwich", "c1", "alice", "x", 0, ReviewRealRisk)); !errors.Is(err, ErrUnknownConclusion) {
		t.Fatalf("unknown tx: got %v, want ErrUnknownConclusion", err)
	}
	// Kind not on the tx.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "displacement", "c1", "alice", "x", 0, ReviewRealRisk)); !errors.Is(err, ErrUnknownConclusion) {
		t.Fatalf("unknown kind: got %v, want ErrUnknownConclusion", err)
	}
}

func TestSubmitReviewValidation(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	cases := []struct {
		name string
		spec string
	}{
		{"empty commitId", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"","operator":"a","reason":"r","expectedVersion":0,"status":"real-risk"}`},
		{"blank commitId", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"  ","operator":"a","reason":"r","expectedVersion":0,"status":"real-risk"}`},
		{"empty operator", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"","reason":"r","expectedVersion":0,"status":"real-risk"}`},
		{"empty reason", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"","expectedVersion":0,"status":"real-risk"}`},
		{"invalid status", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"r","expectedVersion":0,"status":"maybe"}`},
		{"negative expected", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"r","expectedVersion":-1,"status":"real-risk"}`},
		{"missing expected", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"r","status":"real-risk"}`},
		{"missing status", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"r","expectedVersion":0}`},
		{"unknown field", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","commitId":"c","operator":"a","reason":"r","expectedVersion":0,"status":"real-risk","extra":1}`},
		{"not json", `{not json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SubmitReview(dir, []byte(tc.spec)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSubmitReviewFailureLeavesDataUntouched(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	// A validation failure must not write anything.
	if _, err := SubmitReview(dir, []byte(`{bad`)); err == nil {
		t.Fatal("expected error")
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed submission modified the archive")
	}
}

func TestSubmitReviewConcurrentNoLostUpdates(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			spec := makeReviewSpec("1", "0xa", "0xv", "sandwich",
				fmt.Sprintf("c%d", i), "alice", "concurrent", 0, ReviewRealRisk)
			_, errs[i] = SubmitReview(dir, spec)
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded, busy := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("got %d successful submissions and %d busy, want exactly 1 success", succeeded, busy)
	}
	// The archive holds exactly one review with one revision: no duplicates,
	// no lost updates.
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("history: version=%d revisions=%d, want 1/1", hist.Version, len(hist.Revisions))
	}
}

func TestSubmitReviewRestartConsistency(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	spec := makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk)
	if _, err := SubmitReview(dir, spec); err != nil {
		t.Fatal(err)
	}
	// Simulate a restart: fresh calls against the same on-disk archive.
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || hist.Status != ReviewRealRisk {
		t.Fatalf("after restart: version=%d status=%q", hist.Version, hist.Status)
	}
	// Retry after restart: returns the original revision, no append.
	again, err := SubmitReview(dir, spec)
	if err != nil {
		t.Fatal(err)
	}
	if again.Version != 1 || len(again.Revisions) != 1 {
		t.Fatalf("retry after restart appended: version=%d revisions=%d", again.Version, len(again.Revisions))
	}
	// Overturn after restart: new revision, old retained.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "alice", "overturn", 1, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}
	hist, err = GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("overturn after restart: version=%d revisions=%d", hist.Version, len(hist.Revisions))
	}
}

// --- history ---

func TestGetReviewHistoryUnreviewed(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewUnreviewed || hist.Version != 0 {
		t.Fatalf("unreviewed: status=%q version=%d", hist.Status, hist.Version)
	}
	if hist.Revisions == nil || len(hist.Revisions) != 0 {
		t.Fatalf("revisions = %+v, want []", hist.Revisions)
	}
	// The original conclusion, its version and evidence are still queryable.
	if hist.Finding == nil || hist.Finding.TxHash != "0xv" || hist.Finding.Kind != "sandwich" {
		t.Fatalf("finding = %+v", hist.Finding)
	}
	if hist.RuleVersion == nil || hist.RuleVersion.ID != BuiltinVersionID {
		t.Fatalf("ruleVersion = %+v", hist.RuleVersion)
	}
	if len(hist.Swaps) != 5 {
		t.Fatalf("swaps = %d, want 5", len(hist.Swaps))
	}
}

func TestGetReviewHistoryNonexistentConclusion(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// Conclusion that does not exist: the finding is null, no error. The
	// record's rule version and swaps are still available from the archive.
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xzz", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Finding != nil {
		t.Fatalf("nonexistent conclusion: finding=%+v, want nil", hist.Finding)
	}
	if hist.RuleVersion == nil || hist.RuleVersion.ID != BuiltinVersionID {
		t.Fatalf("ruleVersion = %+v, want builtin (from the archived record)", hist.RuleVersion)
	}
	if hist.Status != ReviewUnreviewed || hist.Version != 0 {
		t.Fatalf("status=%q version=%d", hist.Status, hist.Version)
	}
}

func TestGetReviewHistoryRevisionsSortedAscending(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	submit := func(commit string, expected int, status string) {
		t.Helper()
		if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", commit, "alice", "r", expected, status)); err != nil {
			t.Fatal(err)
		}
	}
	submit("c1", 0, ReviewRealRisk)
	submit("c2", 1, ReviewFalsePositive)
	submit("c3", 2, ReviewUnreviewed)

	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist.Revisions) != 3 {
		t.Fatalf("revisions = %d, want 3", len(hist.Revisions))
	}
	for i, rev := range hist.Revisions {
		if rev.Version != i+1 {
			t.Fatalf("revision %d has version %d", i, rev.Version)
		}
	}
	want := []string{ReviewRealRisk, ReviewFalsePositive, ReviewUnreviewed}
	for i, rev := range hist.Revisions {
		if rev.Status != want[i] {
			t.Fatalf("revision %d status = %q, want %q", i, rev.Status, want[i])
		}
	}
}

func TestGetReviewHistoryOldArchive(t *testing.T) {
	dir := t.TempDir()
	// An archive written before reviews existed: no reviews field.
	data := archiveData{Records: []record{{
		ChainID: "1", BlockHash: "0xa", BlockNumber: 10,
		Swaps: []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}, {TxHash: "0xv", Pool: "p1", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 1}, {TxHash: "0+k", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 80, Index: 2}},
		Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0xv",
			Evidence: []Swap{{TxHash: "0xf"}, {TxHash: "0xv"}, {TxHash: "0+k"}}}},
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatalf("old archive must support review history: %v", err)
	}
	if hist.Status != ReviewUnreviewed || hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("old archive: status=%q version=%d revisions=%d", hist.Status, hist.Version, len(hist.Revisions))
	}
	// Submitting the first review works on an old archive.
	state, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "x", 0, ReviewRealRisk))
	if err != nil {
		t.Fatalf("submit on old archive: %v", err)
	}
	if state.Version != 1 {
		t.Fatalf("version = %d, want 1", state.Version)
	}
}

// --- evaluate ---

func TestEvaluateReviewsEmptyRange(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	got, err := EvaluateReviews(dir, "1", 100, 200, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kept != 0 || got.Missed != 0 || got.StillHit != 0 || got.Eliminated != 0 || got.PendingReview != 0 {
		t.Fatalf("empty range counts: %+v", got)
	}
	if got.Details == nil || len(got.Details) != 0 {
		t.Fatalf("details = %+v, want []", got.Details)
	}
	raw, _ := json.Marshal(got.Details)
	if string(raw) != "[]" {
		t.Fatalf("empty details must serialize as [], got %s", raw)
	}
}

func TestEvaluateReviewsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	if _, err := EvaluateReviews(dir, "1", 0, 100, "nope"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
}

func TestEvaluateReviewsInvertedRange(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	if _, err := EvaluateReviews(dir, "1", 100, 50, BuiltinVersionID); err == nil {
		t.Fatal("expected error for inverted range")
	}
}

func TestEvaluateReviewsCounts(t *testing.T) {
	dir := t.TempDir()
	// Block A (height 10): sandwich on 0xv + displacement on 0xd (builtin).
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	// Block B (height 11): sandwich on 0xv + displacement on 0xd (builtin).
	mustReplay(t, dir, reviewBlockInput("0xb", 11))
	// Block C (height 12): displacement on 0xd, archived under noRules (no
	// original findings), candidate builtin flags it as pending.
	registerReviewVersion(t, dir, noRulesSpec)
	mustReplayWithVersion(t, dir, displacementOnlyInput("0xc", 12), "noRules")
	// Block D (height 13): sandwich on 0xk (displacement-capable).
	mustReplay(t, dir, strings.Replace(sandwichOnlyInput("0xd", 13), `"0xv"`, `"0xk"`, 1))
	// Block E (height 14): sandwich on 0xw, withdrawn after first review.
	mustReplay(t, dir, strings.Replace(sandwichOnlyInput("0xe", 14), `"0xv"`, `"0xw"`, 1))

	// Reviews.
	// A: RR sandwich → builtin still flags sandwich → kept.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// A: FP displacement → builtin still flags displacement → stillHit.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xd", "displacement", "c2", "a", "fp", 0, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}
	// B: RR displacement → noDisplacement drops it → missed.
	registerReviewVersion(t, dir, noDisplacementSpec)
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xb", "0xd", "displacement", "c3", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// B: FP sandwich → builtin still flags sandwich → stillHit.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xb", "0xv", "sandwich", "c4", "a", "fp", 0, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}
	// D: RR sandwich → noSandwich drops sandwich, candidate flags displacement
	// instead → missed (sandwich) + pending (displacement).
	registerReviewVersion(t, dir, noSandwichSpec)
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xd", "0xk", "sandwich", "c5", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// E: RR sandwich then withdrawn → treated as unreviewed → pending.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xe", "0xw", "sandwich", "c6", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xe", "0xw", "sandwich", "c7", "a", "withdrawn", 1, ReviewUnreviewed)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	// With builtin as the candidate:
	//   A: kept (sandwich RR), stillHit (displacement FP)
	//   B: kept (displacement RR), stillHit (sandwich FP)
	//   C: pending (displacement, no original finding)
	//   D: kept (sandwich RR; sandwich takes priority, no displacement flagged)
	//   E: withdrawn → pending
	// So: kept=3 (A sandwich, B displacement, D sandwich), missed=0,
	//     stillHit=2 (A displacement, B sandwich), eliminated=0,
	//     pending=2 (C displacement, E sandwich).
	if got.Kept != 3 {
		t.Fatalf("kept = %d, want 3", got.Kept)
	}
	if got.Missed != 0 {
		t.Fatalf("missed = %d, want 0", got.Missed)
	}
	if got.StillHit != 2 {
		t.Fatalf("stillHit = %d, want 2", got.StillHit)
	}
	if got.Eliminated != 0 {
		t.Fatalf("eliminated = %d, want 0", got.Eliminated)
	}
	if got.PendingReview != 2 {
		t.Fatalf("pending = %d, want 2", got.PendingReview)
	}
}

func TestEvaluateReviewsMissedAndEliminated(t *testing.T) {
	dir := t.TempDir()
	// Block B (height 11): displacement on 0xd (builtin, 50 > 10*2).
	mustReplay(t, dir, reviewBlockInput("0xb", 11))
	registerReviewVersion(t, dir, noDisplacementSpec)

	// RR displacement → noDisplacement drops it → missed.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xb", "0xd", "displacement", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// FP sandwich → noDisplacement keeps sandwich → stillHit.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xb", "0xv", "sandwich", "c2", "a", "fp", 0, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, "noDisplacement")
	if err != nil {
		t.Fatal(err)
	}
	// displacement RR → candidate drops it → missed.
	if got.Missed != 1 {
		t.Fatalf("missed = %d, want 1", got.Missed)
	}
	// sandwich FP → candidate keeps it → stillHit.
	if got.StillHit != 1 {
		t.Fatalf("stillHit = %d, want 1", got.StillHit)
	}
	if got.Kept != 0 || got.Eliminated != 0 || got.PendingReview != 0 {
		t.Fatalf("unexpected counts: kept=%d eliminated=%d pending=%d", got.Kept, got.Eliminated, got.PendingReview)
	}
}

func TestEvaluateReviewsEliminated(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, displacementOnlyInput("0xb", 11))
	registerReviewVersion(t, dir, noDisplacementSpec)

	// FP displacement → noDisplacement drops it → eliminated.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xb", "0xd", "displacement", "c1", "a", "fp", 0, ReviewFalsePositive)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, "noDisplacement")
	if err != nil {
		t.Fatal(err)
	}
	if got.Eliminated != 1 {
		t.Fatalf("eliminated = %d, want 1", got.Eliminated)
	}
	if got.Kept != 0 || got.Missed != 0 || got.StillHit != 0 || got.PendingReview != 0 {
		t.Fatalf("unexpected counts: kept=%d missed=%d stillHit=%d pending=%d", got.Kept, got.Missed, got.StillHit, got.PendingReview)
	}
}

func TestEvaluateReviewsKindChange(t *testing.T) {
	dir := t.TempDir()
	// Block D (height 13): sandwich on 0xk (displacement-capable).
	mustReplay(t, dir, strings.Replace(sandwichOnlyInput("0xd", 13), `"0xv"`, `"0xk"`, 1))
	registerReviewVersion(t, dir, noSandwichSpec)

	// RR sandwich → noSandwich drops sandwich, candidate flags displacement.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xd", "0xk", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, "noSandwich")
	if err != nil {
		t.Fatal(err)
	}
	// Original sandwich RR → candidate no longer flags sandwich → missed.
	if got.Missed != 1 {
		t.Fatalf("missed = %d, want 1 (original kind unmatched)", got.Missed)
	}
	// Candidate displacement (new kind) → no review → pending.
	if got.PendingReview != 1 {
		t.Fatalf("pending = %d, want 1 (new kind unreviewed)", got.PendingReview)
	}
	if got.Kept != 0 || got.StillHit != 0 || got.Eliminated != 0 {
		t.Fatalf("unexpected counts: kept=%d stillHit=%d eliminated=%d", got.Kept, got.StillHit, got.Eliminated)
	}
	// Verify the details: the missed detail has original=sandwich, candidate=nil;
	// the pending detail has original=nil, candidate=displacement.
	var missed, pending *EvalDetail
	for i := range got.Details {
		switch got.Details[i].Category {
		case "missed":
			missed = &got.Details[i]
		case "pending":
			pending = &got.Details[i]
		}
	}
	if missed == nil || missed.Original == nil || missed.Original.Kind != "sandwich" || missed.Candidate != nil {
		t.Fatalf("missed detail wrong: %+v", missed)
	}
	if pending == nil || pending.Original != nil || pending.Candidate == nil || pending.Candidate.Kind != "displacement" {
		t.Fatalf("pending detail wrong: %+v", pending)
	}
}

func TestEvaluateReviewsWithdrawnTreatedAsUnreviewed(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, sandwichOnlyInput("0xa", 10))

	// RR then withdrawn.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "a", "withdrawn", 1, ReviewUnreviewed)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	// Withdrawn: not in the four counts; candidate still flags it → pending.
	if got.Kept != 0 || got.Missed != 0 || got.StillHit != 0 || got.Eliminated != 0 {
		t.Fatalf("withdrawn object in four counts: kept=%d missed=%d stillHit=%d eliminated=%d",
			got.Kept, got.Missed, got.StillHit, got.Eliminated)
	}
	if got.PendingReview != 1 {
		t.Fatalf("pending = %d, want 1 (withdrawn treated as unreviewed)", got.PendingReview)
	}
}

func TestEvaluateReviewsDetailsSorted(t *testing.T) {
	dir := t.TempDir()
	// Two blocks at the same height with different hashes, plus one at a
	// different height. All with sandwich victims.
	mustReplay(t, dir, sandwichOnlyInput("0xb", 5))
	mustReplay(t, dir, sandwichOnlyInput("0xa", 5))
	mustReplay(t, dir, sandwichOnlyInput("0xc", 1))

	// Review all sandwiches as RR.
	for _, id := range []struct{ hash, tx string }{
		{"0xa", "0xv"}, {"0xb", "0xv"}, {"0xc", "0xv"},
	} {
		if _, err := SubmitReview(dir, makeReviewSpec("1", id.hash, id.tx, "sandwich", "c-"+id.hash, "a", "r", 0, ReviewRealRisk)); err != nil {
			t.Fatal(err)
		}
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Details) != 3 {
		t.Fatalf("details = %d, want 3", len(got.Details))
	}
	want := []struct {
		height int64
		hash   string
	}{
		{1, "0xc"},
		{5, "0xa"},
		{5, "0xb"},
	}
	for i, w := range want {
		if got.Details[i].BlockNumber != w.height || got.Details[i].BlockHash != w.hash {
			t.Fatalf("detail %d = height %d hash %s, want %+v", i, got.Details[i].BlockNumber, got.Details[i].BlockHash, w)
		}
	}
}

func TestEvaluateReviewsDetailCarriesVersionsAndEvidence(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	registerReviewVersion(t, dir, strictSpec)

	// RR sandwich → strict version (sev 5) still flags sandwich → kept.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}

	got, err := EvaluateReviews(dir, "1", 0, 100, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kept != 1 {
		t.Fatalf("kept = %d, want 1", got.Kept)
	}
	d := got.Details[0]
	if d.OriginalVersion == nil || d.OriginalVersion.ID != BuiltinVersionID {
		t.Fatalf("originalVersion = %+v", d.OriginalVersion)
	}
	if d.CandidateVersion.ID != "strict" {
		t.Fatalf("candidateVersion = %q, want strict", d.CandidateVersion.ID)
	}
	if d.Original == nil || d.Original.Kind != "sandwich" {
		t.Fatalf("original = %+v", d.Original)
	}
	if d.Candidate == nil || d.Candidate.Kind != "sandwich" || d.Candidate.Severity != 5 {
		t.Fatalf("candidate = %+v", d.Candidate)
	}
	if d.Review == nil || d.Review.CommitID != "c1" {
		t.Fatalf("review = %+v", d.Review)
	}
	// Evidence is carried inside the findings.
	if len(d.Original.Evidence) != 3 || len(d.Candidate.Evidence) != 3 {
		t.Fatalf("evidence: original=%d candidate=%d", len(d.Original.Evidence), len(d.Candidate.Evidence))
	}
}

func TestEvaluateReviewsDoesNotModifyArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("evaluate modified the archive")
	}
}

func TestEvaluateReviewsUsesConsistentSnapshot(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// Evaluate reads the archive once: even if another process holds a
	// conflicting lock, the shared lock serializes without a partial read.
	// This test verifies the function works under the shared lock.
	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version.ID != BuiltinVersionID {
		t.Fatalf("version = %q, want builtin", got.Version.ID)
	}
}

// --- interaction with alerts/reports ---

func TestReviewDoesNotModifyOrGenerateAlerts(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// Generate an alert first.
	alerts, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("precondition: got %d alerts, want 1", len(alerts))
	}

	// Submit a review: must not change the alert or generate new ones.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}

	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 {
		t.Fatalf("review changed alert history: got %d records, want 1", len(hist))
	}
	if hist[0].Status != AlertStatusAlert {
		t.Fatalf("alert status changed to %q", hist[0].Status)
	}

	// Reports are unchanged.
	report, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("report findings = %d, want 2", len(report.Findings))
	}
}

func TestReviewIdentityIndependentOfChannel(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))

	// The review object is identified by (chain, block, tx, kind), not channel.
	// Two channels processing the same conclusion share one review.
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "oncall", 0, 100, 3); err != nil {
		t.Fatal(err)
	}

	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 {
		t.Fatalf("version = %d, want 1 (one review regardless of channels)", hist.Version)
	}
}

func TestReviewSameHeightDifferentBlocksSeparate(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	mustReplay(t, dir, reviewBlockInput("0xb", 10))

	// Review the sandwich in block 0xa.
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// Block 0xb's sandwich is a separate object: still unreviewed.
	hist, err := GetReviewHistory(dir, "1", "0xb", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewUnreviewed || hist.Version != 0 {
		t.Fatalf("same-height different-block: status=%q version=%d, want unreviewed/0", hist.Status, hist.Version)
	}
}

// --- corruption ---

func TestReviewCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "real", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	// Corrupt the archive file.
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich"); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("history: got %v, want corrupted error", err)
	}
	if _, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("evaluate: got %v, want corrupted error", err)
	}
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c2", "a", "x", 1, ReviewFalsePositive)); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("submit: got %v, want corrupted error", err)
	}
}

func TestReviewCorruptedStateLeavesDataUntouched(t *testing.T) {
	dir := t.TempDir()
	// Archive with a structurally invalid review state (version mismatch).
	data := archiveData{
		Records: []record{{
			ChainID: "1", BlockHash: "0xa", BlockNumber: 10,
			Swaps:    []Swap{{TxHash: "0xf"}, {TxHash: "0xv"}, {TxHash: "0+k"}},
			Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0xv"}},
		}},
		Reviews: []ReviewState{{
			ChainID: "1", BlockHash: "0xa", TxHash: "0xv", Kind: "sandwich",
			Version:   2, // mismatch: 0 revisions
			Revisions: []ReviewRevision{},
		}},
	}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "a", "x", 0, ReviewRealRisk)); err == nil {
		t.Fatal("expected corrupted error")
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed submission modified the archive")
	}
}

// --- serialization ---

func TestReviewHistorySerializesComplete(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	if _, err := SubmitReview(dir, makeReviewSpec("1", "0xa", "0xv", "sandwich", "c1", "alice", "real victim", 0, ReviewRealRisk)); err != nil {
		t.Fatal(err)
	}
	hist, err := GetReviewHistory(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(hist)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	// Every required field is present.
	for _, field := range []string{"chainId", "blockHash", "txHash", "kind", "status", "version", "revisions", "finding", "ruleVersion", "swaps"} {
		if _, ok := parsed[field]; !ok {
			t.Fatalf("missing field %q in %s", field, raw)
		}
	}
	if parsed["status"] != "real-risk" || parsed["version"].(float64) != 1 {
		t.Fatalf("bad status/version: %s", raw)
	}
}

func TestEvaluateResultSerializesComplete(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, reviewBlockInput("0xa", 10))
	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"chainId", "startHeight", "endHeight", "version", "kept", "missed", "stillHit", "eliminated", "pendingReview", "details"} {
		if _, ok := parsed[field]; !ok {
			t.Fatalf("missing field %q in %s", field, raw)
		}
	}
}
