package mevwatch

// Regression coverage for `reviews submit` (SubmitReview) against an
// archived report whose saved rule-version declaration has decayed since
// the report was written. A manual review must never change the basis a
// conclusion was produced under and must never launder a damaged report:
// submitting a review used to read the archive through the typed record,
// so a written "version":null decoded into a nil version pointer and was
// explained as the built-in rules — and even stripped from the report on
// the atomic rewrite — while an incomplete declaration decoded into
// silently zeroed parameters. Once the target original conclusion is
// found, the submission must first prove — exactly the way a `report`
// query, a comparison, a history query and a review-range evaluation do —
// that the declaration the report archived still carries a non-empty id,
// both rules with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100. Only an old-format record with no
// version key at all keeps the built-in interpretation. On corruption
// the whole submission fails with ErrCorruptVersion — no revision
// appended, no idempotent created:false retry, no submission-id conflict
// or version conflict — naming the target chain, the block, the readable
// saved version id and the offending rule or field, and leaves the
// archive byte-identical with the new submission id unconsumed.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertSubmitRefused runs one failing SubmitReview and pins the failure
// shape: ErrCorruptVersion wrapping the cause, never an unknown-
// conclusion, version-conflict or submission-conflict misread, naming
// the target chain and block plus every required extra substring,
// returning the zero result and leaving the archive byte-identical. A
// second attempt fails the same way: the declaration is never repaired,
// completed or stripped.
func assertSubmitRefused(t *testing.T, dir string, sub ReviewSubmission, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	res, err := SubmitReview(dir, sub)
	if err == nil {
		t.Fatalf("corrupt declaration accepted a review: %+v", res)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownConclusion) || errors.Is(err, ErrReviewConflict) ||
		errors.Is(err, ErrSubmissionConflict) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt declaration misreported as another submit failure: %v", err)
	}
	if !reflect.DeepEqual(res, SubmitReviewResult{}) {
		t.Fatalf("corrupt declaration returned a partial result: %+v", res)
	}
	msg := err.Error()
	for _, want := range append([]string{sub.ChainID, sub.BlockHash}, want...) {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q must name %q", msg, want)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed submit changed the archive")
	}
	// A retry — same identity, same submission id — fails the proof again.
	if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second submit did not fail the same way: %v", err)
	}
}

// assertSubmissionIDUnstored proves no stored review revision carries the
// given submission id after refused attempts.
func assertSubmissionIDUnstored(t *testing.T, dir, id string) {
	t.Helper()
	var doc rawVersionArchiveDoc
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	for _, obj := range doc.Reviews {
		for _, rev := range obj.Revisions {
			if rev.SubmissionID == id {
				t.Fatalf("refused submission id %q was stored: %+v", id, rev)
			}
		}
	}
}

// repairStoredReportVersion restores the target record's embedded
// declaration to the supplied complete spec, so a submission id a refused
// attempt carried can be proven unconsumed by creating version 1 with it.
func repairStoredReportVersion(t *testing.T, dir, chain, hash, spec string) {
	t.Helper()
	var intact map[string]any
	if err := json.Unmarshal([]byte(spec), &intact); err != nil {
		t.Fatal(err)
	}
	replaceStoredReportVersion(t, dir, chain, hash, intact)
}

// TestSubmitReviewCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the target report (the
// registered versions section stays intact): every way the saved
// document can stop satisfying the registration rules must refuse the
// whole submission, naming chain, block, the readable saved id and the
// offending rule or field. The refused submission id stays free.
func TestSubmitReviewCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
				"s-1", "alice", "r", ReviewStatusReal, 0)
			assertSubmitRefused(t, dir, sub, "candC", tc.wantErr)
			assertSubmissionIDUnstored(t, dir, "s-1")

			// The failed attempt neither stored the id nor advanced the
			// object: once the declaration is repaired, the exact same
			// submission creates version 1 as a first submission.
			repairStoredReportVersion(t, dir, "1", "0xblk", candidateVersionSpec)
			res, err := SubmitReview(dir, sub)
			if err != nil {
				t.Fatalf("submission after repair must be accepted: %v", err)
			}
			if !res.Created || res.Version != 1 || res.Revision.SubmissionID != "s-1" {
				t.Fatalf("repaired resubmit = %+v, want created at version 1", res)
			}
		})
	}
}

// TestSubmitReviewNullAndEmptySavedVersionCorrupt pins the exact misread
// being fixed: version:null used to be explained as the built-in rules
// (and stripped on the rewrite), and {} or an incomplete object used to
// submit under silently zeroed parameters. All of them fail; only a
// wholly missing version key is the legacy built-in shape.
func TestSubmitReviewNullAndEmptySavedVersionCorrupt(t *testing.T) {
	cases := []struct {
		name        string
		value       any
		idReachable bool
	}{
		{"null", nil, false},
		{"empty object", map[string]any{}, false},
		{"incomplete object", map[string]any{"id": "candC"}, true},
		{"non-object number", 5, false},
		{"non-object string", "builtin", false},
		{"array", []any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xblk", tc.value)
			sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
				"s-1", "alice", "r", ReviewStatusReal, 0)
			want := []string{}
			if tc.idReachable {
				want = append(want, "candC")
			}
			assertSubmitRefused(t, dir, sub, want...)
			assertSubmissionIDUnstored(t, dir, "s-1")
		})
	}
}

// TestSubmitReviewBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestSubmitReviewBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-1", "alice", "r", ReviewStatusReal, 0)

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	res, err := SubmitReview(dir, sub)
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must accept a review: %v", err)
	}
	if !res.Created || res.Version != 1 {
		t.Fatalf("builtin-id submit = %+v", res)
	}

	// Damage the embedded declaration while keeping id "builtin": the
	// reserved id cannot bypass the proof, and the already stored s-1
	// retry must not come back as created:false either.
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertSubmitRefused(t, dir, sub, BuiltinVersionID, "multiplier")
}

// TestSubmitReviewDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling
// that name the same field, even when both values agree. The raw bytes
// are patched directly because a JSON map cannot hold two keys.
func TestSubmitReviewDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			path := filepath.Join(dir, archiveFileName)
			text := string(readArchiveFile(t, dir))
			versionsAt := strings.Index(text, `"versions":`)
			if versionsAt < 0 {
				t.Fatal("versions section not found")
			}
			at := strings.Index(text[:versionsAt], `"id": "candC"`)
			if at < 0 {
				t.Fatal("record's embedded candC declaration not found")
			}
			anchor := `"severity": 4,`
			field := strings.Index(text[at:versionsAt], anchor)
			if field < 0 {
				t.Fatal("severity field not found in embedded declaration")
			}
			pos := at + field
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
				"s-1", "alice", "r", ReviewStatusReal, 0)
			res, err := SubmitReview(dir, sub)
			if err == nil {
				t.Fatalf("duplicate-field declaration accepted a review: %+v", res)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed submit repaired the duplicate field")
			}
		})
	}
}

// TestSubmitReviewExplicitlyDisabledRulesAccepted proves enabled:false is
// a legal historical off state, but a disabled rule still has to carry
// complete, in-range parameters before a review is accepted.
func TestSubmitReviewExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-1", "alice", "r", ReviewStatusReal, 0)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	res, err := SubmitReview(dir, sub)
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must accept a review: %v", err)
	}
	if !res.Created || res.Version != 1 {
		t.Fatalf("off-state submit = %+v", res)
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", offBroken)
	assertSubmitRefused(t, dir, sub, "off", "multiplier")
}

// TestSubmitReviewCorruptCheckPrecedesAllDedupAndConflictPaths proves the
// integrity proof runs the moment the target conclusion is found, so it
// cannot be bypassed by any of the other submit branches: an identical
// idempotent retry, a same-id submission with different content (which
// would otherwise be a submission-id conflict) and a fresh id with a
// stale expected version (which would otherwise be a version conflict)
// all fail on the corrupt declaration instead. Existing revisions stay
// exactly as stored.
func TestSubmitReviewCorruptCheckPrecedesAllDedupAndConflictPaths(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	first := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-1", "alice", "r", ReviewStatusReal, 0)
	if res, err := SubmitReview(dir, first); err != nil || !res.Created {
		t.Fatalf("setup submit: %+v %v", res, err)
	}
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	corruptBytes := readArchiveFile(t, dir)

	attempts := []struct {
		name string
		sub  ReviewSubmission
	}{
		{"identical retry", first},
		{"same id different content", reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-1", "bob", "other", ReviewStatusReal, 0)},
		{"fresh id stale expected version", reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-2", "carol", "late", ReviewStatusFalsePositive, 1)},
		{"fresh id at base zero", reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-3", "carol", "late", ReviewStatusFalsePositive, 0)},
		{"withdrawal retry", reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-4", "carol", "withdraw", ReviewStatusUnreviewed, 1)},
	}
	for _, tc := range attempts {
		t.Run(tc.name, func(t *testing.T) {
			res, err := SubmitReview(dir, tc.sub)
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("attempt %q: got %v, want ErrCorruptVersion", tc.name, err)
			}
			if res != (SubmitReviewResult{}) {
				t.Fatalf("attempt %q returned a result: %+v", tc.name, res)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "multiplier") {
				t.Fatalf("attempt %q error must name candC and multiplier: %v", tc.name, err)
			}
		})
	}

	// Nothing moved: the archive is byte-identical, the object still has
	// exactly its first revision, and none of the refused ids was stored.
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatalf("refused submissions changed the archive")
	}
	for _, id := range []string{"s-2", "s-3", "s-4"} {
		assertSubmissionIDUnstored(t, dir, id)
	}
	var doc rawVersionArchiveDoc
	if err := json.Unmarshal(corruptBytes, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Reviews) != 1 || len(doc.Reviews[0].Revisions) != 1 ||
		doc.Reviews[0].Revisions[0].SubmissionID != "s-1" {
		t.Fatalf("existing revision changed: %+v", doc.Reviews)
	}

	// Once repaired, ordinary conventions resume: the identical s-1
	// retry is created:false, and a correctly based rejudgment appends.
	repairStoredReportVersion(t, dir, "1", "0xblk", candidateVersionSpec)
	retry, err := SubmitReview(dir, first)
	if err != nil || retry.Created || retry.Version != 1 {
		t.Fatalf("post-repair idempotent retry: %+v %v", retry, err)
	}
	second := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-2", "carol", "late", ReviewStatusFalsePositive, 1)
	res, err := SubmitReview(dir, second)
	if err != nil || !res.Created || res.Version != 2 {
		t.Fatalf("post-repair rejudgment: %+v %v", res, err)
	}
}

// TestSubmitReviewCorruptSiblingDoesNotBlock proves the proof is scoped
// to the report the target conclusion lives in: a damaged declaration on
// another block never blocks a review of an intact block's conclusion,
// and an identity without a matching conclusion stays unknown-conclusion
// without opening any declaration.
func TestSubmitReviewCorruptSiblingDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	input := cmpBlockLine("1", "0xblk", 7,
		cmpSwap("0xf", "p1", "w", 40, 0),
		cmpSwap("0xv", "p1", "u", 10, 1),
	) + "\n" + cmpBlockLine("1", "0other", 8,
		cmpSwap("0g0", "p2", "w", 40, 2),
		cmpSwap("0g1", "p2", "u", 10, 3),
	) + "\n"
	path := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFileWithVersion(path, dir, "candC"); err != nil {
		t.Fatal(err)
	}

	// Damage only the second block: a review of the first block's
	// conclusion is accepted normally.
	rewriteStoredReportVersion(t, dir, "1", "0other", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	res, err := SubmitReview(dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-1", "alice", "r", ReviewStatusReal, 0))
	if err != nil {
		t.Fatalf("a corrupt sibling block blocked an intact target: %v", err)
	}
	if !res.Created || res.Version != 1 {
		t.Fatalf("intact target submit = %+v", res)
	}
	// The damaged sibling's own conclusion still refuses a review.
	assertSubmitRefused(t, dir,
		reviewSub("1", "0other", "0g1", SuppressDisplacement, "s-2", "bob", "r", ReviewStatusReal, 0),
		"candC", "multiplier")

	// An identity with no matching conclusion stays unknown, and the
	// damaged declaration is never opened on its behalf — even on the
	// damaged block itself.
	for _, target := range []struct{ block, tx, kind string }{
		{"0other", "0ghost", SuppressSandwich},
		{"0ghost", "0xv", SuppressSandwich},
	} {
		if _, err := SubmitReview(dir, reviewSub("1", target.block, target.tx, target.kind,
			"s-9", "op", "r", ReviewStatusReal, 0)); !errors.Is(err, ErrUnknownConclusion) {
			t.Fatalf("target %s/%s: got %v, want ErrUnknownConclusion", target.block, target.tx, err)
		}
	}
}

// TestSubmitReviewUsesSavedParametersNotRegistry proves accepting a
// review never consults the registry for the historical basis: a damaged
// same-id registry entry neither blocks an intact saved report nor
// completes its parameters, an intact registry cannot rescue a corrupt
// report, and a saved id the registry never carried still accepts a
// review on its own.
func TestSubmitReviewUsesSavedParametersNotRegistry(t *testing.T) {
	sub := func(id string) ReviewSubmission {
		return reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			id, "alice", "r", ReviewStatusReal, 0)
	}

	// Damage only the registered candC entry; the report's own embedded
	// copy stays intact, so the review is still accepted.
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	if res, err := SubmitReview(dir, sub("s-1")); err != nil || !res.Created {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %+v %v", res, err)
	}

	// Conversely, an intact registry cannot rescue a corrupt report.
	dir2 := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertSubmitRefused(t, dir2, sub("s-2"), "candC", "multiplier")

	// A complete declaration with an id the registry never carried stands
	// on its own and accepts a review; its id need not be registered.
	dir3 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir3, "1", "0xblk", stray)
	if res, err := SubmitReview(dir3, sub("s-3")); err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	} else if !res.Created {
		t.Fatalf("self-contained declaration submit = %+v", res)
	}
	hist, err := ReviewHistoryQuery(dir3, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Original == nil || hist.Original.Version.ID != "never-registered" ||
		hist.Original.Version.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved historical parameters not carried: %+v", hist.Original)
	}
}

// TestSubmitReviewLegacyRecordStillBuiltin proves the single carve-out:
// a record with no version key at all keeps the built-in explanation and
// still accepts reviews, rejudgments and withdrawals, appending
// revisions while leaving the original conclusion and swap evidence
// untouched.
func TestSubmitReviewLegacyRecordStillBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[` +
		`{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	first := reviewSub("1", "0old", "0v", SuppressSandwich, "s-1", "alice", "r", ReviewStatusReal, 0)
	res, err := SubmitReview(dir, first)
	if err != nil {
		t.Fatalf("legacy record must accept a review under builtin: %v", err)
	}
	if !res.Created || res.Version != 1 {
		t.Fatalf("legacy submit = %+v", res)
	}
	second := reviewSub("1", "0old", "0v", SuppressSandwich, "s-2", "bob", "fp", ReviewStatusFalsePositive, 1)
	if res, err := SubmitReview(dir, second); err != nil || !res.Created || res.Version != 2 {
		t.Fatalf("legacy rejudgment: %+v %v", res, err)
	}
	// The original conclusion and its built-in basis stay exactly as stored.
	hist, err := ReviewHistoryQuery(dir, "1", "0old", "0v", SuppressSandwich)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Original == nil || hist.Original.Version != BuiltinVersion() ||
		hist.Original.Finding.Severity != 3 || len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy original conclusion/evidence damaged: %+v", hist.Original)
	}
}

// TestSubmitReviewCorruptDeclarationLeavesAllSectionsUntouched proves a
// refused submission rewrites neither the damaged report, the other
// records, registered versions, the enabled marker, existing reviews nor
// alert records: the archive bytes stay identical and the stored
// revisions stay reachable after the report is restored.
func TestSubmitReviewCorruptDeclarationLeavesAllSectionsUntouched(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	// Existing revision on the object about to be damaged.
	submit(t, dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-1", "alice", "r", ReviewStatusReal, 0))
	// A pre-existing alert record must survive the refused submission too.
	alerts, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = 0
	})
	corruptBytes := readArchiveFile(t, dir)

	sub := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-2", "bob", "rejudge", ReviewStatusFalsePositive, 1)
	if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("expected ErrCorruptVersion, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatalf("refused submission modified the archive")
	}

	var doc rawVersionArchiveDoc
	if err := json.Unmarshal(corruptBytes, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Reviews) != 1 || len(doc.Reviews[0].Revisions) != 1 ||
		doc.Reviews[0].Revisions[0].SubmissionID != "s-1" {
		t.Fatalf("existing reviews changed: %+v", doc.Reviews)
	}
	gotAlerts, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(alerts, gotAlerts) {
		t.Fatalf("alert records changed: %+v vs %+v", alerts, gotAlerts)
	}

	// Restore the report: the object is still at version 1 with the old
	// revision and the refused submission id remains usable for a fresh
	// create once expectedVersion matches.
	repairStoredReportVersion(t, dir, "1", "0xblk", candidateVersionSpec)
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || len(hist.Revisions) != 1 ||
		hist.Revisions[0].SubmissionID != "s-1" {
		t.Fatalf("object state changed across the refused submit: %+v", hist.Revisions)
	}
}
