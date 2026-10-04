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

// contender describes one racy rejudgment: a distinct submissionId plus
// operator/reason/status values that make its stored fields distinguishable
// from every other contender's, so a winning revision can be checked
// field-by-field for cross-submission mixing.
type contender struct {
	id       string
	operator string
	reason   string
	status   string
}

// contenderSet builds n rejudgments for one object, every field value unique
// to its contender. All share the same target identity and expectedVersion.
func contenderSet(chain, block, tx, kind string, base int, n int) []contender {
	out := make([]contender, n)
	for i := 0; i < n; i++ {
		// Alternate the status too: the stored winner's status must be the
		// winner's own, never blended with another contender's status.
		status := ReviewStatusFalsePositive
		if i%2 == 0 {
			status = ReviewStatusReal
		}
		out[i] = contender{
			id:       fmt.Sprintf("s-%d", base+i),
			operator: fmt.Sprintf("op-%d", i),
			reason:   fmt.Sprintf("reason-%d", i),
			status:   status,
		}
	}
	return out
}

func (c contender) submission(key conclusionKey, expected int) ReviewSubmission {
	return reviewSub(key.chainID, key.blockHash, key.txHash, key.kind,
		c.id, c.operator, c.reason, c.status, expected)
}

// oneConcurrentRace fires every contender at the object in one start-gated
// wave and records each one's result or error. It only drives the race; the
// caller decides which outcomes are legal.
func oneConcurrentRace(t *testing.T, dir string, key conclusionKey, expected int, cs []contender) ([]SubmitReviewResult, []error) {
	t.Helper()
	results := make([]SubmitReviewResult, len(cs))
	errs := make([]error, len(cs))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, c := range cs {
		wg.Add(1)
		go func(i int, c contender) {
			defer wg.Done()
			<-start
			results[i], errs[i] = SubmitReview(dir, c.submission(key, expected))
		}(i, c)
	}
	close(start)
	wg.Wait()
	return results, errs
}

// reviewKey is the shared object identity under test.
var reviewKey = conclusionKey{chainID: "1", blockHash: "0xa", txHash: "0xv", kind: "sandwich"}

func TestSubmitReviewConcurrentNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// The object already carries one archived conclusion and one genuine
	// real-risk judgment: it is at version 1 before the race, and every
	// contender rejudges against that same valid expectedVersion.
	first := submit(t, dir, reviewSub(reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind,
		"base", "alice", "confirmed bot", ReviewStatusReal, 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("setup judgment = %+v", first)
	}

	const n = 12
	cs := contenderSet(reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind, 1, n)
	results, errs := oneConcurrentRace(t, dir, reviewKey, 1, cs)

	// Contenders serialize on the archive's exclusive flock. A contender
	// either:
	//   - wins the lock first and is the single creator, or
	//   - finds the lock still held -> ErrBusy, or
	//   - acquires the lock only after the winner committed, reads the
	//     already-incremented object version and loses on expectedVersion ->
	//     ErrReviewConflict.
	// Busy and conflict are both legal loser outcomes; scheduling decides how
	// many contenders hit each one, so the regression must not assume every
	// loser races the lock at the same instant.
	var winner *contender
	successes := 0
	for i := range cs {
		err := errs[i]
		switch {
		case err == nil:
			successes++
			c := cs[i]
			winner = &c
			res := results[i]
			if !res.Created || res.Version != 2 {
				t.Fatalf("contender %s result = %+v, want created at version 2", c.id, res)
			}
			wantRev := c.submission(reviewKey, 1).revision(2)
			if !reflect.DeepEqual(res.Revision, wantRev) {
				t.Fatalf("winning response revision = %+v, want %+v", res.Revision, wantRev)
			}
		case errors.Is(err, ErrBusy), errors.Is(err, ErrReviewConflict):
			if results[i].Created {
				t.Fatalf("losing contender %s reported created=true: %+v", cs[i].id, results[i])
			}
		default:
			t.Fatalf("contender %s unexpected error: %v", cs[i].id, err)
		}
	}
	if successes != 1 {
		t.Fatalf("got %d successes, want exactly 1 (losers may be busy or conflict)", successes)
	}
	if winner == nil {
		t.Fatal("no winner recorded")
	}

	// The object version advanced exactly once, from 1 to 2, and history is
	// the original revision plus exactly one new revision.
	hist, err := ReviewHistoryQuery(dir, reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("concurrent race corrupted history: %+v", hist)
	}
	if !reflect.DeepEqual(hist.Revisions[0], first.Revision) {
		t.Fatalf("original revision changed: %+v want %+v", hist.Revisions[0], first.Revision)
	}
	// The whole new revision must come from the single winner: no field may
	// be borrowed from a different contender.
	wantRev := winner.submission(reviewKey, 1).revision(2)
	if !reflect.DeepEqual(hist.Revisions[1], wantRev) {
		t.Fatalf("stored revision = %+v, want winner %+v (field mixing?)", hist.Revisions[1], wantRev)
	}
	if hist.Status != winner.status {
		t.Fatalf("current status %q must match winner %q", hist.Status, winner.status)
	}
	// No losing submissionId/operator/reason may appear anywhere in history.
	// Statuses are shared with the base revision, so field mixing on the
	// winning revision is already pinned exactly by the DeepEqual above.
	for _, c := range cs {
		if c.id == winner.id {
			continue
		}
		for _, rev := range hist.Revisions {
			if rev.SubmissionID == c.id || rev.Operator == c.operator || rev.Reason == c.reason {
				t.Fatalf("losing contender %s content leaked into history: %+v", c.id, rev)
			}
		}
	}
	// The original conclusion, its detection parameters and the swap
	// evidence remain exactly as archived.
	if hist.Original == nil || hist.Original.Finding.TxHash != "0xv" ||
		hist.Original.Finding.Kind != "sandwich" || hist.Original.Finding.Severity != 3 ||
		len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("original conclusion/evidence changed: %+v", hist.Original)
	}
	if hist.Original.Version.ID != BuiltinVersionID {
		t.Fatalf("detection version changed: %+v", hist.Original.Version)
	}

	// A contender that lost on busy never completed its rejudgment: once the
	// race is over, re-submitting it with the same original expectedVersion
	// must be a plain version conflict, never a silent overwrite of the
	// winner's judgment.
	loser := cs[0]
	if loser.id == winner.id {
		loser = cs[1]
	}
	if _, err := SubmitReview(dir, loser.submission(reviewKey, 1)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("post-race stale resubmission: got %v, want ErrReviewConflict", err)
	}
	after, err := ReviewHistoryQuery(dir, reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != 2 || len(after.Revisions) != 2 || after.Status != winner.status {
		t.Fatalf("post-race conflict mutated state: %+v", after)
	}
}

// TestSubmitReviewBusyThenConflictAfterWinnerCommits deterministically
// reproduces the legal concurrent ordering the wave test cannot guarantee by
// scheduling: a contender reaches the archive while it is occupied and gets
// busy; the winning contender then commits (through the ordinary submission
// path) and releases the lock; the busy contender retries with the same
// expected version, enters the now-free archive, reads the already
// incremented object version and is rejected with a review version conflict.
// Both loser outcomes therefore come from real SubmitReview calls, and busy
// must never count as a completed rejudgment.
func TestSubmitReviewBusyThenConflictAfterWinnerCommits(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	base := submit(t, dir, reviewSub(reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind,
		"base", "alice", "confirmed bot", ReviewStatusReal, 0))
	if base.Version != 1 {
		t.Fatalf("setup version = %d, want 1", base.Version)
	}

	// Another committer occupies the archive while the contender's first
	// attempt arrives.
	holder, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	loser := contender{id: "late-1", operator: "bob", reason: "arrived while occupied", status: ReviewStatusFalsePositive}
	if _, err := SubmitReview(dir, loser.submission(reviewKey, 1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("occupied archive: got %v, want ErrBusy", err)
	}

	// Occupation ends; the winner goes through the ordinary submission path
	// and is the single rejudgment that lands at version 2.
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	holder.Close()
	winner := contender{id: "win-1", operator: "carol", reason: "committed first", status: ReviewStatusReal}
	won, err := SubmitReview(dir, winner.submission(reviewKey, 1))
	if err != nil {
		t.Fatalf("winner submission: %v", err)
	}
	if !won.Created || won.Version != 2 {
		t.Fatalf("winner = %+v, want created at version 2", won)
	}

	// The contender that only got busy retries verbatim once the race is
	// over. It now enters the archive, sees version 2 and must conflict on
	// its stale expected version 1 rather than overwrite the winner.
	if _, err := SubmitReview(dir, loser.submission(reviewKey, 1)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("post-release retry: got %v, want ErrReviewConflict", err)
	}

	hist, err := ReviewHistoryQuery(dir, reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("history = v%d/%d revs, want v2 with 2 revisions", hist.Version, len(hist.Revisions))
	}
	if !reflect.DeepEqual(hist.Revisions[0], base.Revision) {
		t.Fatalf("original revision changed: %+v want %+v", hist.Revisions[0], base.Revision)
	}
	wantWinner := winner.submission(reviewKey, 1).revision(2)
	if !reflect.DeepEqual(hist.Revisions[1], wantWinner) {
		t.Fatalf("second revision = %+v, want winner %+v", hist.Revisions[1], wantWinner)
	}
	if hist.Status != ReviewStatusReal {
		t.Fatalf("current status %q must follow the winner", hist.Status)
	}
	for _, rev := range hist.Revisions {
		if rev.SubmissionID == loser.id || rev.Operator == loser.operator || rev.Reason == loser.reason {
			t.Fatalf("busy/conflict loser left a revision: %+v", rev)
		}
	}
}

// TestSubmitReviewBusyHeldByOtherCommit keeps the archive occupied with an
// unrelated in-flight commit and proves a legal rejudgment returns busy
// without altering existing review content; once the lock is released the
// same submission still does not blindly succeed — its fate is decided by
// the object's actual version.
func TestSubmitReviewBusyHeldByOtherCommit(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// Version 1 with a real judgment is the existing review content that must
	// not change while the archive is occupied.
	first := submit(t, dir, reviewSub(reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind,
		"base", "alice", "confirmed bot", ReviewStatusReal, 0))

	holder, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	// Even a perfectly valid submission at the current version is busy while
	// another committer holds the archive.
	c := contender{id: "held-1", operator: "bob", reason: "while held", status: ReviewStatusFalsePositive}
	res, err := SubmitReview(dir, c.submission(reviewKey, 1))
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("held archive: got %v, want ErrBusy", err)
	}
	if res.Created {
		t.Fatalf("busy submission reported created=true: %+v", res)
	}
	// The archive must be unchanged while the lock is held. Query it through
	// the unlocked reader: ReviewHistoryQuery takes a blocking shared lock
	// and would deadlock against this test's own held exclusive lock.
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	var heldObj *ReviewObject
	for i := range data.Reviews {
		if data.Reviews[i].key() == reviewKey {
			heldObj = &data.Reviews[i]
		}
	}
	if heldObj == nil || len(heldObj.Revisions) != 1 ||
		!reflect.DeepEqual(heldObj.Revisions[0], first.Revision) ||
		currentReviewStatus(*heldObj) != ReviewStatusReal {
		t.Fatalf("busy submission changed existing content: %+v", heldObj)
	}

	// Simulate the other committer winning a rejudgment of the same object
	// while holding the lock: the busy attempt was NOT a completed
	// rejudgment, and when the lock is released the object's actual version
	// is 2. A caller that treats the earlier busy result as done and simply
	// retries verbatim must now be rejected on version, not overwrite.
	committed := contender{id: "held-win", operator: "carol", reason: "won while holding", status: ReviewStatusFalsePositive}
	committedRev := committed.submission(reviewKey, 1).revision(2)
	for i := range data.Reviews {
		if data.Reviews[i].key() == reviewKey {
			data.Reviews[i].Revisions = append(data.Reviews[i].Revisions, committedRev)
		}
	}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	holder.Close()

	if _, err := SubmitReview(dir, c.submission(reviewKey, 1)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("retry after release against advanced version: got %v, want ErrReviewConflict", err)
	}
	final, err := ReviewHistoryQuery(dir, reviewKey.chainID, reviewKey.blockHash, reviewKey.txHash, reviewKey.kind)
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 2 || len(final.Revisions) != 2 {
		t.Fatalf("post-release state = %+v", final)
	}
	if !reflect.DeepEqual(final.Revisions[0], first.Revision) ||
		!reflect.DeepEqual(final.Revisions[1], committedRev) {
		t.Fatalf("post-release revisions not base+committed: %+v", final.Revisions)
	}

	// Conversely, when the lock is released with the version untouched, the
	// same previously-busy submission at the correct version succeeds: busy
	// itself neither commits nor consumes the submission id.
	dir2 := t.TempDir()
	mustReplay(t, dir2, twoFindingsInput)
	key2 := reviewKey
	submit(t, dir2, reviewSub(key2.chainID, key2.blockHash, key2.txHash, key2.kind,
		"base", "alice", "confirmed bot", ReviewStatusReal, 0))
	holder2, err := os.OpenFile(filepath.Join(dir2, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder2.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	c2 := contender{id: "held-2", operator: "bob", reason: "after release", status: ReviewStatusFalsePositive}
	if _, err := SubmitReview(dir2, c2.submission(key2, 1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("held archive: got %v, want ErrBusy", err)
	}
	if err := syscall.Flock(int(holder2.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	holder2.Close()
	retry, err := SubmitReview(dir2, c2.submission(key2, 1))
	if err != nil {
		t.Fatalf("retry after clean release: %v", err)
	}
	if !retry.Created || retry.Version != 2 {
		t.Fatalf("retry = %+v, want created at version 2", retry)
	}
}

// TestSubmitReviewConcurrentRaceRepeated exercises the race repeatedly to
// pin down both legal loser orderings under scheduling variation: across
// runs the set of failures must be a mix only of busy and version conflict,
// with exactly one creator each round, the object advancing exactly once and
// the stored revision always matching the winner.
func TestSubmitReviewConcurrentRaceRepeated(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	key := conclusionKey{chainID: "1", blockHash: "0xa", txHash: "0xd", kind: "displacement"}

	const rounds = 25
	const n = 8
	for round := 0; round < rounds; round++ {
		// Before this round the object holds 2*round revisions (a base and a
		// race winner per prior round). A fresh base judgment advances it to
		// 2*round+1; the race then advances it once more to 2*round+2.
		baseVersion := 2 * round
		raceVersion := 2*round + 1
		wantVersion := 2*round + 2
		base := submit(t, dir, reviewSub(key.chainID, key.blockHash, key.txHash, key.kind,
			fmt.Sprintf("base-%d", round), "alice", fmt.Sprintf("base-%d", round), ReviewStatusReal, baseVersion))
		if base.Version != raceVersion {
			t.Fatalf("round %d base version = %d, want %d", round, base.Version, raceVersion)
		}
		cs := contenderSet(key.chainID, key.blockHash, key.txHash, key.kind, 1000+round*n, n)
		results, errs := oneConcurrentRace(t, dir, key, raceVersion, cs)

		var winner *contender
		busy, conflict, successes := 0, 0, 0
		for i := range cs {
			switch {
			case errs[i] == nil:
				successes++
				c := cs[i]
				winner = &c
				if !results[i].Created || results[i].Version != wantVersion {
					t.Fatalf("round %d winner %s result = %+v, want version %d",
						round, c.id, results[i], wantVersion)
				}
			case errors.Is(errs[i], ErrBusy):
				busy++
			case errors.Is(errs[i], ErrReviewConflict):
				conflict++
			default:
				t.Fatalf("round %d contender %s: %v", round, cs[i].id, errs[i])
			}
		}
		if successes != 1 {
			t.Fatalf("round %d: %d successes, %d busy, %d conflict, want 1 success", round, successes, busy, conflict)
		}
		if busy+conflict != n-1 {
			t.Fatalf("round %d: losers not fully accounted: %d busy %d conflict", round, busy, conflict)
		}
		hist, err := ReviewHistoryQuery(dir, key.chainID, key.blockHash, key.txHash, key.kind)
		if err != nil {
			t.Fatal(err)
		}
		if hist.Version != wantVersion || len(hist.Revisions) != wantVersion {
			t.Fatalf("round %d history = v%d/%d revs, want v%d/%d",
				round, hist.Version, len(hist.Revisions), wantVersion, wantVersion)
		}
		wantRev := winner.submission(key, raceVersion).revision(wantVersion)
		if !reflect.DeepEqual(hist.Revisions[wantVersion-1], wantRev) {
			t.Fatalf("round %d stored revision = %+v, want winner %+v", round, hist.Revisions[wantVersion-1], wantRev)
		}
		if hist.Status != winner.status {
			t.Fatalf("round %d status %q != winner %q", round, hist.Status, winner.status)
		}
		// Every busy loser, retried verbatim after the round, is now a
		// conflict: busy never completed their rejudgment and must not
		// overwrite the saved winner.
		for i := range cs {
			if !errors.Is(errs[i], ErrBusy) {
				continue
			}
			if _, err := SubmitReview(dir, cs[i].submission(key, raceVersion)); !errors.Is(err, ErrReviewConflict) {
				t.Fatalf("round %d busy loser %s post-race: got %v, want conflict", round, cs[i].id, err)
			}
		}
	}
	// Across many rounds and goroutines, the final history keeps every prior
	// revision in ascending version order, with no revision dropped or
	// duplicated.
	hist, err := ReviewHistoryQuery(dir, key.chainID, key.blockHash, key.txHash, key.kind)
	if err != nil {
		t.Fatal(err)
	}
	wantFinal := 2 * rounds
	if hist.Version != wantFinal || len(hist.Revisions) != wantFinal {
		t.Fatalf("final history = v%d/%d, want v%d", hist.Version, len(hist.Revisions), wantFinal)
	}
	for v, rev := range hist.Revisions {
		if rev.Version != v+1 {
			t.Fatalf("revisions not ascending: position %d holds version %d", v, rev.Version)
		}
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

// breakArchiveSave makes the archive commit fail at the save stage: the
// temporary file the atomic writer creates becomes a directory, so opening
// it as a regular file fails while the lock, the archived conclusion, the
// review object and its revisions are all valid. This is a storage failure
// at persistence time, not a validation, version-conflict or busy error.
func breakArchiveSave(t *testing.T, dir string) {
	t.Helper()
	tmp := filepath.Join(dir, archiveFileName+".tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatalf("break archive save: %v", err)
	}
}

func restoreArchiveSave(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(dir, archiveFileName+".tmp")); err != nil {
		t.Fatalf("restore archive save: %v", err)
	}
}

func TestSubmitReviewSaveFailureRetriedAfterRecovery(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	// A pre-existing alert record must survive the failed and successful
	// submissions byte-for-byte in content.
	alertsBefore, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(alertsBefore) != 2 {
		t.Fatalf("setup: got %d alert records, want 2", len(alertsBefore))
	}

	// Main precondition: the object is at version 1 with a real judgment and
	// one complete revision.
	first := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-1", "alice", "confirmed bot", ReviewStatusReal, 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("setup submission = %+v", first)
	}

	original, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if original.Status != ReviewStatusReal || original.Version != 1 || len(original.Revisions) != 1 {
		t.Fatalf("setup object state = %+v", original)
	}
	archiveBefore, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}

	// Valid target, valid content, valid expected version: the only failure
	// is storage failing while the new revision is being archived.
	breakArchiveSave(t, dir)
	rejudgment := reviewSub("1", "0xa", "0xv", "sandwich", "s-2", "bob", "actually a false positive", ReviewStatusFalsePositive, 1)
	failed, err := SubmitReview(dir, rejudgment)
	if err == nil {
		t.Fatalf("save failure must return an error, got result %+v", failed)
	}
	if errors.Is(err, ErrBusy) || errors.Is(err, ErrReviewConflict) ||
		errors.Is(err, ErrUnknownConclusion) || errors.Is(err, ErrSubmissionConflict) {
		t.Fatalf("failure must happen at the save stage, got %v", err)
	}
	if failed.Created {
		t.Fatalf("failed save must not report created=true: %+v", failed)
	}
	restoreArchiveSave(t, dir)

	// The original judgment is fully retained: still real at version 1, the
	// single original revision with no trace of the failed submission.
	after, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != ReviewStatusReal || after.Version != 1 {
		t.Fatalf("failed save advanced the object: %q/%d, want real/1", after.Status, after.Version)
	}
	if len(after.Revisions) != 1 {
		t.Fatalf("failed save left %d revisions: %+v", len(after.Revisions), after.Revisions)
	}
	if !reflect.DeepEqual(after.Revisions[0], original.Revisions[0]) {
		t.Fatalf("original revision changed: %+v, want %+v", after.Revisions[0], original.Revisions[0])
	}
	for _, rev := range after.Revisions {
		if rev.SubmissionID == "s-2" || rev.Operator == "bob" ||
			rev.Status == ReviewStatusFalsePositive || rev.Reason == "actually a false positive" {
			t.Fatalf("failed submission content leaked into history: %+v", rev)
		}
	}
	// The archived original conclusion, its detection version and the raw
	// swap evidence are untouched, as are the pre-existing alert records.
	if after.Original == nil ||
		after.Original.Finding.TxHash != "0xv" || after.Original.Finding.Kind != "sandwich" ||
		after.Original.Finding.Severity != 3 || len(after.Original.Finding.Evidence) != 3 {
		t.Fatalf("original conclusion/evidence changed: %+v", after.Original)
	}
	if after.Original.Version.ID != BuiltinVersionID {
		t.Fatalf("detection version changed: %+v", after.Original.Version)
	}
	archiveAfter, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(archiveBefore, archiveAfter) {
		t.Fatal("failed save modified the archive file")
	}
	alertsAfter, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(alertsBefore, alertsAfter) {
		t.Fatalf("alert records changed: before %+v after %+v", alertsBefore, alertsAfter)
	}

	// Storage recovered: the exact same submission, same submissionId and
	// still expectedVersion 1, goes through as a fresh create — the failed
	// attempt must neither have consumed the submission id nor count as a
	// stored duplicate.
	retry, err := SubmitReview(dir, rejudgment)
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if !retry.Created || retry.Version != 2 || retry.Status != ReviewStatusFalsePositive {
		t.Fatalf("retry = %+v, want created=true at version 2", retry)
	}
	wantRev := rejudgment.revision(2)
	if !reflect.DeepEqual(retry.Revision, wantRev) {
		t.Fatalf("saved revision = %+v, want %+v", retry.Revision, wantRev)
	}

	saved, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Status != ReviewStatusFalsePositive || saved.Version != 2 || len(saved.Revisions) != 2 {
		t.Fatalf("object after retry = %q/%d with %d revisions", saved.Status, saved.Version, len(saved.Revisions))
	}
	if !reflect.DeepEqual(saved.Revisions[0], original.Revisions[0]) {
		t.Fatalf("original revision not retained first: %+v", saved.Revisions[0])
	}
	if !reflect.DeepEqual(saved.Revisions[1], wantRev) {
		t.Fatalf("appended revision = %+v, want %+v", saved.Revisions[1], wantRev)
	}

	// Sending the now-successful submission verbatim a second time is the
	// ordinary idempotent retry: created:false, the first successfully saved
	// revision returned, history unchanged.
	again, err := SubmitReview(dir, rejudgment)
	if err != nil {
		t.Fatalf("verbatim resend: %v", err)
	}
	if again.Created {
		t.Fatal("verbatim resend of a stored submission must report created=false")
	}
	if !reflect.DeepEqual(again.Revision, wantRev) || again.Version != 2 || again.Status != ReviewStatusFalsePositive {
		t.Fatalf("resend result = %+v", again)
	}
	final, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 2 || len(final.Revisions) != 2 {
		t.Fatalf("verbatim resend changed history: version %d, %d revisions", final.Version, len(final.Revisions))
	}
	if !reflect.DeepEqual(final.Revisions, saved.Revisions) {
		t.Fatalf("verbatim resend appended a revision: %+v", final.Revisions)
	}
}
