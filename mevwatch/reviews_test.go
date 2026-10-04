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

// contenderStatuses gives each racing submitter a status of its own; the
// winner revision can then be proven to carry one submitter's complete
// content with no fields mixed in from another contender.
var contenderStatuses = []string{
	ReviewStatusFalsePositive,
	ReviewStatusReal,
	ReviewStatusUnreviewed,
}

func raceSub(i int) ReviewSubmission {
	return reviewSub("1", "0xa", "0xv", "sandwich",
		fmt.Sprintf("race-%02d", i),
		fmt.Sprintf("operator-%02d", i),
		fmt.Sprintf("reason-%02d", i),
		contenderStatuses[i%len(contenderStatuses)], 1)
}

type raceOutcome struct {
	res SubmitReviewResult
	err error
}

// runRejudgmentRace fires n contenders carrying the same valid
// expectedVersion (1, against an object already at version 1) at the same
// instant, each with a distinct submissionId/operator/reason/status, and
// returns the per-submitter outcomes in submission order.
func runRejudgmentRace(t *testing.T, dir string, n int) []raceOutcome {
	t.Helper()
	outcomes := make([]raceOutcome, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			outcomes[i].res, outcomes[i].err = SubmitReview(dir, raceSub(i))
		}(i)
	}
	close(start)
	wg.Wait()
	return outcomes
}

// verifyRaceSettlement proves the anti-overwrite rules against the history
// actually persisted after a rejudgment race: exactly one contender created
// a revision, the object advanced exactly one version, every stored bit of
// the new revision comes from that winner alone, the original revision and
// the archived conclusion/evidence are untouched, and every loser (busy or
// version conflict) left no content behind.
func verifyRaceSettlement(t *testing.T, dir string, outcomes []raceOutcome, original ReviewRevision) int {
	t.Helper()
	winner := -1
	busyIdx, conflictIdx := -1, -1
	for i, o := range outcomes {
		switch {
		case o.err == nil:
			if !o.res.Created || o.res.Version != 2 {
				t.Fatalf("submitter %d returned %+v, want created at version 2", i, o.res)
			}
			if winner != -1 {
				t.Fatalf("two successful contenders: %d and %d", winner, i)
			}
			winner = i
		case errors.Is(o.err, ErrBusy):
			// The contender hit the lock while another submitter held it.
			busyIdx = i
		case errors.Is(o.err, ErrReviewConflict):
			// The contender entered after the lock was released, read the
			// already-bumped version and was rejected on the version check.
			conflictIdx = i
		default:
			t.Fatalf("submitter %d got an outcome other than success/busy/conflict: %v", i, o.err)
		}
	}
	if winner == -1 {
		t.Fatal("no contender succeeded")
	}
	t.Logf("race settled: winner=%d, busy=%d, version-conflict=%d (either loser outcome is valid)",
		winner, countOutcomes(outcomes, ErrBusy), countOutcomes(outcomes, ErrReviewConflict))

	winSub := raceSub(winner)
	wantRev := winSub.revision(2)
	if !reflect.DeepEqual(outcomes[winner].res.Revision, wantRev) {
		t.Fatalf("winner result revision = %+v, want %+v", outcomes[winner].res.Revision, wantRev)
	}

	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 2 || hist.Status != winSub.Status {
		t.Fatalf("current state = %q/%d, want %q/2 (the winner's rejudgment)",
			hist.Status, hist.Version, winSub.Status)
	}
	if len(hist.Revisions) != 2 {
		t.Fatalf("object holds %d revisions, want exactly 2 (losers must leave none): %+v",
			len(hist.Revisions), hist.Revisions)
	}
	if !reflect.DeepEqual(hist.Revisions[0], original) {
		t.Fatalf("original revision not retained first: %+v, want %+v", hist.Revisions[0], original)
	}
	if !reflect.DeepEqual(hist.Revisions[1], wantRev) {
		t.Fatalf("appended revision = %+v, want the winner's %+v", hist.Revisions[1], wantRev)
	}
	// Defense in depth: no field of any loser may appear in the new
	// revision, and no loser submission id may be stored anywhere. Status is
	// deliberately excluded because only three legal statuses exist so two
	// contenders may legitimately carry the same one; identity/operator/
	// reason are unique per submitter and the full-revision DeepEqual above
	// already pins the winner's status.
	loserIDs := map[string]bool{}
	for i := range outcomes {
		if i == winner {
			continue
		}
		s := raceSub(i)
		loserIDs[s.SubmissionID] = true
		stored := hist.Revisions[1]
		if stored.SubmissionID == s.SubmissionID || stored.Operator == s.Operator ||
			stored.Reason == s.Reason {
			t.Fatalf("loser %d content mixed into the stored revision: %+v", i, stored)
		}
		if reflect.DeepEqual(stored, s.revision(2)) {
			t.Fatalf("stored revision is identical to loser %d's content: %+v", i, stored)
		}
	}
	for _, rev := range hist.Revisions {
		if loserIDs[rev.SubmissionID] {
			t.Fatalf("loser submission id %q left a revision", rev.SubmissionID)
		}
	}
	// The original archived conclusion, its detection parameters and the
	// raw swap evidence stay exactly as archived.
	if hist.Original == nil ||
		hist.Original.Finding.TxHash != "0xv" || hist.Original.Finding.Kind != "sandwich" ||
		hist.Original.Finding.Severity != 3 || len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("original conclusion/evidence changed: %+v", hist.Original)
	}
	if hist.Original.Version.ID != BuiltinVersionID {
		t.Fatalf("detection version changed: %+v", hist.Original.Version)
	}

	// After the race, resubmitting with the stale expected version must be a
	// version conflict regardless of how the contender originally lost: a
	// busy loss is not a completed rejudgment, and neither path may overwrite
	// the winner.
	recheck := func(idx int, label string) {
		if idx < 0 {
			return
		}
		if _, err := SubmitReview(dir, raceSub(idx)); !errors.Is(err, ErrReviewConflict) {
			t.Fatalf("%s loser (submitter %d) replayed with original expected version: got %v, want ErrReviewConflict",
				label, idx, err)
		}
	}
	recheck(busyIdx, "busy")
	recheck(conflictIdx, "conflict")
	if _, err := SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich", "late", "op", "r", ReviewStatusReal, 1)); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("fresh follower with stale base: got %v, want ErrReviewConflict", err)
	}

	// Deterministic late entrants: sequential submissions issued only after
	// the object is provably at version 2 and the race lock is long released.
	// Each acquires the free lock, reads the already-bumped version and must
	// take the version-conflict path (never busy, since submissions are
	// serialized here). This is the legitimate loser outcome the old
	// regression assumed could never happen, and it must append nothing.
	const lateN = 6
	for j := 0; j < lateN; j++ {
		_, err := SubmitReview(dir, reviewSub("1", "0xa", "0xv", "sandwich",
			fmt.Sprintf("late-%02d", j),
			fmt.Sprintf("late-operator-%02d", j),
			fmt.Sprintf("late-reason-%02d", j),
			contenderStatuses[j%len(contenderStatuses)], 1))
		if !errors.Is(err, ErrReviewConflict) {
			t.Fatalf("late entrant %d after lock release: got %v, want ErrReviewConflict", j, err)
		}
	}

	// The follow-up conflict submissions appended nothing either.
	final, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if final.Version != 2 || len(final.Revisions) != 2 || !reflect.DeepEqual(final.Revisions, hist.Revisions) {
		t.Fatalf("post-race conflict replays changed history: %+v", final)
	}
	return winner
}

func countOutcomes(outcomes []raceOutcome, target error) int {
	n := 0
	for _, o := range outcomes {
		if errors.Is(o.err, target) {
			n++
		}
	}
	return n
}

func TestSubmitReviewConcurrentRejudgmentSettlesOnce(t *testing.T) {
	// Repeated races make the regression independent of scheduling: whether a
	// contender hits the held lock or enters after release and loses on the
	// version check, the settled history must be identical in shape. The loop
	// is deterministic (no timing assumptions): every contender starts from a
	// barrier and the settled state is derived from stored data, not from how
	// many contenders reported busy versus conflict.
	const racers, iterations = 12, 25
	for iter := 0; iter < iterations; iter++ {
		dir := t.TempDir()
		mustReplay(t, dir, twoFindingsInput)
		// An object that already carries one real risk judgment: the race is
		// a concurrent rejudgment at expectedVersion 1, not a first submit.
		first := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s-0", "alice", "first real call", ReviewStatusReal, 0))
		if !first.Created || first.Version != 1 {
			t.Fatalf("iter %d setup = %+v", iter, first)
		}
		outcomes := runRejudgmentRace(t, dir, racers)
		verifyRaceSettlement(t, dir, outcomes, first.Revision)
	}
}

// TestSubmitReviewBusyHoldsOffThenActualVersionDecides pins the two-phase
// behavior deterministically (without relying on goroutine interleaving):
// while the archive is occupied, a valid rejudgment returns busy and changes
// nothing; once the lock is released the same submission is accepted or
// rejected by the object's actual version, never because the busy attempt was
// treated as a completed rejudgment.
func TestSubmitReviewBusyHoldsOffThenActualVersionDecides(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	first := submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "hold-1", "alice", "confirmed bot war", ReviewStatusReal, 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("setup = %+v", first)
	}
	archiveBefore, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}

	holder, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	// A legal rejudgment based on version 1: while occupied it must report
	// busy and write nothing.
	contender := reviewSub("1", "0xa", "0xv", "sandwich", "hold-2", "bob", "second look says false positive", ReviewStatusFalsePositive, 1)
	res, err := SubmitReview(dir, contender)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("occupied archive: got %v, want ErrBusy", err)
	}
	if res.Created || res.Version != 0 || res.Revision != (ReviewRevision{}) {
		t.Fatalf("busy submission returned a non-empty result: %+v", res)
	}
	archiveDuring, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(archiveBefore, archiveDuring) {
		t.Fatal("busy submission changed the archive while the lock was held")
	}

	// Release the occupation; existing review content must be intact.
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	held, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if held.Status != ReviewStatusReal || held.Version != 1 || len(held.Revisions) != 1 {
		t.Fatalf("busy loss altered review content: %+v", held)
	}
	if !reflect.DeepEqual(held.Revisions[0], first.Revision) {
		t.Fatalf("original revision changed: %+v, want %+v", held.Revisions[0], first.Revision)
	}

	// Lock released but the object is still at version 1 (busy never
	// completed the rejudgment): the same submission with its original
	// expectedVersion 1 now succeeds as a fresh create — the busy attempt
	// neither consumed the submission id nor counted as a stored revision.
	retry, err := SubmitReview(dir, contender)
	if err != nil {
		t.Fatalf("retry after release: %v", err)
	}
	wantRev := contender.revision(2)
	if !retry.Created || retry.Version != 2 || !reflect.DeepEqual(retry.Revision, wantRev) {
		t.Fatalf("retry = %+v, want created at v2 with %+v", retry, wantRev)
	}
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusFalsePositive || hist.Version != 2 || len(hist.Revisions) != 2 {
		t.Fatalf("object after retry = %q/%d with %d revisions", hist.Status, hist.Version, len(hist.Revisions))
	}
	if !reflect.DeepEqual(hist.Revisions[0], first.Revision) || !reflect.DeepEqual(hist.Revisions[1], wantRev) {
		t.Fatalf("revisions after retry = %+v", hist.Revisions)
	}

	// Independently, if another rejudgment had committed while we waited,
	// releasing the lock would not make the stale submission succeed: with
	// the object now at version 2, a version-1 submission conflicts and
	// leaves no revision.
	late := reviewSub("1", "0xa", "0xv", "sandwich", "hold-3", "carol", "late arrival", ReviewStatusUnreviewed, 1)
	if _, err := SubmitReview(dir, late); !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("stale submission after release: got %v, want ErrReviewConflict", err)
	}
	after, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != 2 || len(after.Revisions) != 2 || !reflect.DeepEqual(after.Revisions, hist.Revisions) {
		t.Fatalf("post-release conflict appended a revision: %+v", after)
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
