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
	"syscall"
	"testing"
)

// twoFindingsInput (from alerts_test.go) archives block 0xa at height 10
// with a sandwich on 0xv (pool p1, sev 3) and a displacement on 0xd (pool
// p2, sev 2) under the built-in rules.
//
// Candidate versions used below:
//   - strict:       sandwich sev 5 on, displacement mult 5 -> only 0xv keeps
//     hitting, with a changed severity; 0xd stops hitting.
//   - mult3:        displacement mult 3 -> 0xd still hits (50 > 30).
//   - noSandwich:   sandwich off, displacement mult 2 -> 0xv flips from
//     sandwich to displacement (a type change); 0xd stays.
const mult3Spec = `{"id":"mult3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
const noSandwichSpec = `{"id":"nosandwich","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`

func reviewSub(chain, block, tx, kind, id, operator, reason, status string, expected int) ReviewSubmission {
	return ReviewSubmission{
		ChainID:         chain,
		BlockHash:       block,
		TxHash:          tx,
		Kind:            kind,
		SubmissionID:    id,
		Operator:        operator,
		Reason:          reason,
		Status:          status,
		ExpectedVersion: expected,
	}
}

func submit(t *testing.T, dir string, sub ReviewSubmission) SubmitReviewResult {
	t.Helper()
	res, err := SubmitReview(dir, sub)
	if err != nil {
		t.Fatalf("SubmitReview(%+v): %v", sub, err)
	}
	return res
}

func mustRegisterVersion(t *testing.T, dir, spec string) string {
	t.Helper()
	v, _, err := RegisterVersion(dir, []byte(spec))
	if err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
	return v.ID
}

func TestSubmitReviewFirstAndRejudgment(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	first := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "confirmed bot", ReviewStatusReal, 0))
	if !first.Created || first.Version != 1 || first.Status != ReviewStatusReal {
		t.Fatalf("first submission = %+v", first)
	}
	if first.Revision.Version != 1 || first.Revision.SubmissionID != "s-1" ||
		first.Revision.Operator != "alice" || first.Revision.Reason != "confirmed bot" ||
		first.Revision.ExpectedVersion != 0 {
		t.Fatalf("revision content not preserved: %+v", first.Revision)
	}

	// A stale expected version is a conflict and appends nothing.
	if _, err := SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "late", ReviewStatusFalsePositive, 0)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("stale expectedVersion: got %v, want ErrReviewConflict", err)
	}

	second := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "actually fp", ReviewStatusFalsePositive, 1))
	if !second.Created || second.Version != 2 || second.Status != ReviewStatusFalsePositive {
		t.Fatalf("second submission = %+v", second)
	}

	// Withdrawal adds another revision and leaves the earlier ones in place.
	withdrawn := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-3", "carol", "reset", ReviewStatusUnreviewed, 2))
	if !withdrawn.Created || withdrawn.Version != 3 || withdrawn.Status != ReviewStatusUnreviewed {
		t.Fatalf("withdrawal = %+v", withdrawn)
	}
}

func TestSubmitReviewIdempotentRetry(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	original := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "r", ReviewStatusReal, 0))
	// The object is rejudged afterwards.
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "r2", ReviewStatusFalsePositive, 1))

	// Retrying the exact original submission (same ID and identical field
	// values, expectedVersion 0 included) returns the original revision even
	// though the object has since moved on, and appends nothing.
	retry := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "r", ReviewStatusReal, 0))
	if retry.Created {
		t.Fatalf("identical retry reported created=true")
	}
	if !reflect.DeepEqual(retry.Revision, original.Revision) {
		t.Fatalf("retry returned %+v, want original %+v", retry.Revision, original.Revision)
	}
	if retry.Version != 2 || retry.Status != ReviewStatusFalsePositive {
		t.Fatalf("retry response must reflect current state, got version %d status %q", retry.Version, retry.Status)
	}
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist.Revisions) != 2 {
		t.Fatalf("identical retry appended a revision: %+v", hist.Revisions)
	}
}

func TestSubmitReviewSubmissionIDConflicts(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "r", ReviewStatusReal, 0))

	// Same ID with different content conflicts, even against another object.
	cases := []ReviewSubmission{
		reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "bob", "r", ReviewStatusReal, 0),
		reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "other", ReviewStatusReal, 0),
		reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "r", ReviewStatusFalsePositive, 0),
		reviewSub("1", "0xa", "0xd", "displacement", "s-1", "alice", "r", ReviewStatusReal, 0),
	}
	for i, sub := range cases {
		if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrSubmissionConflict) {
			t.Fatalf("case %d: got %v, want ErrSubmissionConflict", i, err)
		}
	}
	// Failed conflicts must not change stored data.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("conflict mutated history: %+v", hist)
	}
}

func TestSubmitReviewUnknownConclusion(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	cases := []ReviewSubmission{
		reviewSub("2", "0xa", "0xv", "sandwich", "s", "a", "r", ReviewStatusReal, 0), // other chain
		reviewSub("1", "0xzzz", "0xv", "sandwich", "s", "a", "r", ReviewStatusReal, 0),
		reviewSub("1", "0xa", "0xnomatch", "sandwich", "s", "a", "r", ReviewStatusReal, 0),
		reviewSub("1", "0xa", "0xd", "sandwich", "s", "a", "r", ReviewStatusReal, 0), // 0xd is displacement
	}
	for i, sub := range cases {
		if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrUnknownConclusion) {
			t.Fatalf("case %d: got %v, want ErrUnknownConclusion", i, err)
		}
	}
}

func TestParseReviewSubmissionValidation(t *testing.T) {
	good := `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"alice","reason":"r","status":"real","expectedVersion":0}`
	sub, err := ParseReviewSubmission([]byte(good))
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if sub.ExpectedVersion != 0 || sub.Status != ReviewStatusReal {
		t.Fatalf("bad parse: %+v", sub)
	}
	bad := []struct {
		name string
		spec string
	}{
		{"not json", `{"chainId":`},
		{"trailing garbage", good + ` extra`},
		{"missing chain", `{"blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"blank block", `{"chainId":"1","blockHash":"  ","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"blank tx", `{"chainId":"1","blockHash":"0xa","txHash":"","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"unknown kind", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"rugpull","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"missing kind", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"blank submission id", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"  ","operator":"a","reason":"r","status":"real","expectedVersion":0}`},
		{"blank operator", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"","reason":"r","status":"real","expectedVersion":0}`},
		{"blank reason", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"  ","status":"real","expectedVersion":0}`},
		{"bad status", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"yes","expectedVersion":0}`},
		{"missing status", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","expectedVersion":0}`},
		{"negative expectedVersion", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":-1}`},
		{"missing expectedVersion", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real"}`},
		{"fractional expectedVersion", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":1.5}`},
		{"unknown field", `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"s","operator":"a","reason":"r","status":"real","expectedVersion":0,"extra":1}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseReviewSubmission([]byte(tc.spec)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	// The unreviewed status is a valid first submission too.
	withdraw := strings.Replace(good, `"status":"real"`, `"status":"unreviewed"`, 1)
	if _, err := ParseReviewSubmission([]byte(withdraw)); err != nil {
		t.Fatalf("unreviewed status rejected: %v", err)
	}
}

func TestReviewHistoryQuery(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	// No review data: unreviewed, version 0, empty revisions; the archived
	// original conclusion, detection version and evidence are still present.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusUnreviewed || hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("empty object = %+v", hist)
	}
	raw, _ := json.Marshal(hist.Revisions)
	if string(raw) != "[]" {
		t.Fatalf("empty revisions must serialize as [], got %s", raw)
	}
	if hist.Original == nil || hist.Original.Finding.TxHash != "0xv" || hist.Original.Finding.Severity != 3 {
		t.Fatalf("original conclusion missing: %+v", hist.Original)
	}
	if hist.Original.Version.ID != BuiltinVersionID {
		t.Fatalf("detection version missing: %+v", hist.Original.Version)
	}
	if len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("raw swap evidence missing: %+v", hist.Original.Finding.Evidence)
	}

	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "r1", ReviewStatusReal, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "r2", ReviewStatusFalsePositive, 1))

	hist, err = ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusFalsePositive || hist.Version != 2 {
		t.Fatalf("current state = %q/%d", hist.Status, hist.Version)
	}
	if len(hist.Revisions) != 2 ||
		hist.Revisions[0].Version != 1 || hist.Revisions[0].SubmissionID != "s-1" || hist.Revisions[0].Status != ReviewStatusReal ||
		hist.Revisions[1].Version != 2 || hist.Revisions[1].SubmissionID != "s-2" || hist.Revisions[1].Status != ReviewStatusFalsePositive {
		t.Fatalf("revisions not ascending with content: %+v", hist.Revisions)
	}

	// An identity with no archived conclusion returns null original but
	// still reports review-state defaults.
	missing, err := ReviewHistoryQuery(dir, "1", "0xa", "0xghost", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if missing.Original != nil || missing.Status != ReviewStatusUnreviewed || missing.Version != 0 {
		t.Fatalf("unknown identity = %+v", missing)
	}

	// Absent archive: same defaults, no error.
	absent, err := ReviewHistoryQuery(filepath.Join(t.TempDir(), "none"), "1", "0xa", "0xv", "sandwich")
	if err != nil || absent.Original != nil || absent.Version != 0 {
		t.Fatalf("absent archive: %+v err=%v", absent, err)
	}

	if _, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "rugpull"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("got %v, want ErrUnknownKind", err)
	}
}

func evalBuckets(t *testing.T, dir, versionID string) map[string]ReviewDetail {
	t.Helper()
	got, err := EvaluateReviews(dir, "1", 0, 100, versionID)
	if err != nil {
		t.Fatalf("EvaluateReviews: %v", err)
	}
	byKey := map[string]ReviewDetail{}
	for _, d := range got.Details {
		byKey[d.TxHash+"/"+d.Kind] = d
	}
	return byKey
}

func TestEvaluateRetainedAndEliminated(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)

	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))

	got, err := EvaluateReviews(dir, "1", 0, 100, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if got.Retained != 1 || got.Missed != 0 || got.StillHit != 0 || got.Eliminated != 1 || got.Pending != 0 {
		t.Fatalf("counts = +%d -%d ~%d x%d ?%d, want retained 1, eliminated 1",
			got.Retained, got.Missed, got.StillHit, got.Eliminated, got.Pending)
	}
	details := evalBuckets(t, dir, "strict")
	retained := details["0xv/sandwich"]
	if retained.Bucket != BucketRetained || retained.AppliedRevision == nil || retained.AppliedRevision.SubmissionID != "r" {
		t.Fatalf("retained detail = %+v", retained)
	}
	// Severity changed 3 -> 5 but same tx and kind: still retained.
	if retained.Original.Finding.Severity != 3 || retained.Candidate.Finding.Severity != 5 {
		t.Fatalf("severities not carried: %+v / %+v", retained.Original.Finding, retained.Candidate)
	}
	if retained.Original.Version.ID != BuiltinVersionID || retained.Candidate.Version.ID != "strict" {
		t.Fatalf("rule parameters missing: %+v / %+v", retained.Original.Version, retained.Candidate)
	}
	if len(retained.Original.Finding.Evidence) != 3 || len(retained.Candidate.Finding.Evidence) != 3 {
		t.Fatalf("swap evidence missing: %+v / %+v", retained.Original.Finding.Evidence, retained.Candidate.Finding.Evidence)
	}
	eliminated := details["0xd/displacement"]
	if eliminated.Bucket != BucketEliminated || eliminated.Candidate != nil {
		t.Fatalf("eliminated detail = %+v", eliminated)
	}
}

func TestEvaluateStillHit(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, mult3Spec)
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))

	got, err := EvaluateReviews(dir, "1", 10, 10, "mult3")
	if err != nil {
		t.Fatal(err)
	}
	// 50 > 10*3: the false positive still fires; the unreviewed sandwich is
	// pending.
	if got.StillHit != 1 || got.Pending != 1 || got.Eliminated != 0 {
		t.Fatalf("counts = %+v", got)
	}
}

func TestEvaluateMissedAndTypeChange(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, noSandwichSpec)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))

	got, err := EvaluateReviews(dir, "1", 0, 100, "nosandwich")
	if err != nil {
		t.Fatal(err)
	}
	// Sandwich 0xv (real) no longer fires -> missed. The candidate now flags
	// 0xv as displacement, a new unreviewed type -> pending. The unreviewed
	// original displacement 0xd still hits the same kind -> pending too.
	if got.Missed != 1 || got.Pending != 2 || got.Retained != 0 || got.Eliminated != 0 || got.StillHit != 0 {
		t.Fatalf("counts = %+v", got)
	}
	byKey := map[string]ReviewDetail{}
	for _, d := range got.Details {
		byKey[d.TxHash+"/"+d.Kind] = d
	}
	missed := byKey["0xv/sandwich"]
	if missed.Bucket != BucketMissed || missed.Candidate != nil || missed.AppliedRevision == nil {
		t.Fatalf("missed detail = %+v", missed)
	}
	newType := byKey["0xv/displacement"]
	if newType.Bucket != BucketPending || newType.Original != nil || newType.AppliedRevision != nil {
		t.Fatalf("new-type detail = %+v", newType)
	}
}

func TestEvaluatePendingAndWithdrawal(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)

	// Without reviews, the still-hit sandwich is pending; the displacement
	// that strict stops flagging is not counted anywhere.
	got, err := EvaluateReviews(dir, "1", 0, 100, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if got.Pending != 1 || got.Retained+got.Missed+got.StillHit+got.Eliminated != 0 {
		t.Fatalf("unreviewed counts = %+v", got)
	}

	// A real judgment followed by a withdrawal behaves as unreviewed again.
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "w", "a", "reset", ReviewStatusUnreviewed, 1))
	got, err = EvaluateReviews(dir, "1", 0, 100, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if got.Pending != 1 {
		t.Fatalf("withdrawn object must be pending, counts = %+v", got)
	}
	for _, d := range got.Details {
		if d.TxHash == "0xv" && d.AppliedRevision != nil {
			t.Fatalf("withdrawn object must carry no applied revision: %+v", d)
		}
	}
}

func TestEvaluateEmptyRangeAndDetails(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)

	got, err := EvaluateReviews(dir, "1", 11, 100, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if got.Retained != 0 || got.Missed != 0 || got.StillHit != 0 || got.Eliminated != 0 || got.Pending != 0 {
		t.Fatalf("empty range counts = %+v", got)
	}
	raw, _ := json.Marshal(got.Details)
	if string(raw) != "[]" {
		t.Fatalf("empty details must serialize as [], got %s", raw)
	}

	// Unknown version and an inverted range are errors.
	if _, err := EvaluateReviews(dir, "1", 0, 100, "nope"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
	if _, err := EvaluateReviews(dir, "1", 9, 8, "strict"); err == nil {
		t.Fatal("inverted range must error")
	}
	// Absent archive: builtin yields an empty evaluation; other versions
	// remain unknown.
	absent := filepath.Join(t.TempDir(), "none")
	empty, err := EvaluateReviews(absent, "1", 0, 100, BuiltinVersionID)
	if err != nil || len(empty.Details) != 0 {
		t.Fatalf("absent archive builtin: %+v err=%v", empty, err)
	}
	if _, err := EvaluateReviews(absent, "1", 0, 100, "strict"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("absent archive strict: got %v, want ErrUnknownVersion", err)
	}
}

func TestEvaluateSortingAndDistinctBlockHashes(t *testing.T) {
	dir := t.TempDir()
	// Height 1 hash 0xc: sandwich victim 0+h1.
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xc","blockNumber":1,"swaps":[`+
		`{"TxHash":"0xf1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0+h1","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+z1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":80,"Index":2}]}`)
	// Height 10, two different block hashes: handled independently.
	mustReplay(t, dir, twoFindingsInput)
	mustReplay(t, dir, strings.Replace(twoFindingsInput, `"blockHash":"0xa"`, `"blockHash":"0xb"`, 1))

	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		height int64
		hash   string
		tx     string
		kind   string
	}{
		{1, "0xc", "0+h1", "sandwich"},
		{10, "0xa", "0xd", "displacement"},
		{10, "0xa", "0xv", "sandwich"},
		{10, "0xb", "0xd", "displacement"},
		{10, "0xb", "0xv", "sandwich"},
	}
	if len(got.Details) != len(want) {
		t.Fatalf("got %d details, want %d: %+v", len(got.Details), len(want), got.Details)
	}
	for i, w := range want {
		d := got.Details[i]
		if d.BlockNumber != w.height || d.BlockHash != w.hash || d.TxHash != w.tx || d.Kind != w.kind {
			t.Fatalf("detail %d = %d/%s/%s/%s, want %+v", i, d.BlockNumber, d.BlockHash, d.TxHash, d.Kind, w)
		}
	}
}

func TestEvaluateIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))

	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateReviews(dir, "1", 0, 100, "strict"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("evaluation modified the archive")
	}

	// Review data stays intact and alerts are untouched by reviews.
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Reviews) != 1 || data.EnabledVersion != "" {
		t.Fatalf("evaluation changed reviews or enabled version: %+v", data)
	}
}

func TestReviewsWorkOnOldArchive(t *testing.T) {
	dir := t.TempDir()
	data := archiveData{Records: []record{{
		ChainID:     "1",
		BlockHash:   "0xa",
		BlockNumber: 10,
		Swaps:       []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}, {TxHash: "0xv", Pool: "p1", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 1}, {TxHash: "0+k", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 80, Index: 2}},
		Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0xv",
			Evidence: []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}, {TxHash: "0xv", Pool: "p1", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 1}, {TxHash: "0+k", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 80, Index: 2}}}},
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	res, err := SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich", "s", "a", "r", ReviewStatusReal, 0))
	if err != nil || !res.Created || res.Version != 1 {
		t.Fatalf("old archive review: %+v err=%v", res, err)
	}
	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Retained != 1 {
		t.Fatalf("old archive evaluation = %+v", got)
	}
}

func TestReviewsCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := reviewSub("1", "0xa", "0xv", "sandwich", "s", "a", "r", ReviewStatusReal, 0)
	if _, err := SubmitReview(dir, sub); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("submit: got %v, want corrupted error", err)
	}
	if _, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich"); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("history: got %v, want corrupted error", err)
	}
	if _, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID); err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("evaluate: got %v, want corrupted error", err)
	}
}

func TestReviewsBusyArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	sub := reviewSub("1", "0xa", "0xv", "sandwich", "s", "a", "r", ReviewStatusReal, 0)
	if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrBusy) {
		t.Fatalf("submit: got %v, want ErrBusy", err)
	}
}

func TestSubmitReviewConcurrentNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich",
				fmt.Sprintf("s-%d", i), "op", "r", ReviewStatusReal, 0))
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded, busy, other := 0, 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			other++
			t.Errorf("unexpected error: %v", err)
		}
	}
	if other != 0 {
		t.FailNow()
	}
	if succeeded != 1 {
		t.Fatalf("got %d successes and %d busy, want exactly 1 success", succeeded, busy)
	}
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("concurrent submissions corrupted history: %+v", hist)
	}
	// A follower that based its submission on version 0 now gets a conflict
	// instead of silently overwriting the winner's revision.
	if _, err := SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich", "late", "op", "r", ReviewStatusReal, 0)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("stale follower: got %v, want ErrReviewConflict", err)
	}
}

func TestSubmitReviewSaveFailureAndRetryAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// Existing alert records must survive the failed save untouched.
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3); err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}

	// The object starts at version 1 with a real judgment.
	first := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "confirmed bot", ReviewStatusReal, 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("setup submission = %+v", first)
	}
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	beforeData, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeData.AlertRecords) == 0 {
		t.Fatal("setup must carry existing alert records")
	}

	// Break only the archive save: the atomic-write tmp path is a directory,
	// so writeArchiveAtomic cannot create its temp file. Validation, the
	// lock, the conclusion lookup and the version check all still pass.
	tmp := filepath.Join(dir, archiveFileName+".tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	rejudge := reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "actually fp", ReviewStatusFalsePositive, 1)
	res, err := SubmitReview(dir, rejudge)
	if err == nil {
		t.Fatalf("save failure must return an error, got %+v", res)
	}
	if res.Created {
		t.Fatalf("failed save must not report created=true: %+v", res)
	}
	// The failure is the save itself, not a validation, conflict or busy error.
	for _, sentinel := range []error{ErrUnknownConclusion, ErrReviewConflict, ErrSubmissionConflict, ErrBusy} {
		if errors.Is(err, sentinel) {
			t.Fatalf("got %v, want an archive save error", err)
		}
	}
	if !strings.Contains(err.Error(), archiveFileName) {
		t.Fatalf("error must come from saving the archive, got %v", err)
	}

	// The failed submission leaves no half revision: the object is still
	// real at version 1 with only the original revision, and nothing of the
	// failed attempt (operator, reason, submission id) is stored.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusReal || hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("failed save mutated review state: %+v", hist)
	}
	if !reflect.DeepEqual(hist.Revisions[0], first.Revision) {
		t.Fatalf("original revision changed: got %+v, want %+v", hist.Revisions[0], first.Revision)
	}
	// The whole archive — original conclusion, detection version, swap
	// evidence and the existing alert records — is byte-identical.
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed save modified the archive")
	}

	// Storage recovers: the exact same submission (same submissionId, same
	// expectedVersion, same field values) now succeeds. The failed attempt
	// did not occupy the submission ID.
	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	saved := submit(t, dir, rejudge)
	if !saved.Created || saved.Version != 2 || saved.Status != ReviewStatusFalsePositive {
		t.Fatalf("retry after recovery = %+v", saved)
	}
	if saved.Revision.Version != 2 || saved.Revision.SubmissionID != "s-2" ||
		saved.Revision.Operator != "bob" || saved.Revision.Reason != "actually fp" ||
		saved.Revision.Status != ReviewStatusFalsePositive || saved.Revision.ExpectedVersion != 1 {
		t.Fatalf("revision content not preserved: %+v", saved.Revision)
	}

	// History appends exactly one new revision after the original.
	hist, err = ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusFalsePositive || hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("history after recovery = %+v", hist)
	}
	if !reflect.DeepEqual(hist.Revisions[0], first.Revision) ||
		!reflect.DeepEqual(hist.Revisions[1], saved.Revision) {
		t.Fatalf("revisions = %+v, want original then the retried one", hist.Revisions)
	}

	// Re-sending the now-saved submission is an idempotent retry: the stored
	// revision is returned and nothing is appended.
	again := submit(t, dir, rejudge)
	if again.Created {
		t.Fatal("retry of a saved submission reported created=true")
	}
	if !reflect.DeepEqual(again.Revision, saved.Revision) {
		t.Fatalf("retry returned %+v, want saved revision %+v", again.Revision, saved.Revision)
	}
	hist, err = ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("idempotent retry appended a revision: %+v", hist)
	}
}

func TestSubmitReviewFailureLeavesNoHalfRevision(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	// Unknown conclusion fails validation against archive content and must
	// not append anything.
	if _, err := SubmitReview(dir, reviewSub("1", "0xa", "0xghost", "sandwich", "s", "a", "r", ReviewStatusReal, 0)); !errors.Is(err, ErrUnknownConclusion) {
		t.Fatalf("got %v, want ErrUnknownConclusion", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed submission modified the archive")
	}
}
