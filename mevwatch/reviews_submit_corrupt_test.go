package mevwatch

// Regression coverage for `reviews submit` (SubmitReview) against an
// archived report whose saved rule-version declaration has decayed since
// the report was written. Every other read path — `report`, `compare`,
// `alerts generate`, `reviews history`, `reviews evaluate` and an
// identical-block replay — re-proves the declaration embedded in a report
// before using it; a review submission used to be the one gap. It decoded
// records with the version pointer, so a written "version":null was
// explained as the built-in rules and an incomplete declaration came back
// with silently zeroed parameters, and accepting the submission re-encoded
// that record and stripped the damage out of the archive.
//
// Once a submission finds its target original conclusion it must now first
// prove — exactly the way a `report` query does — that the declaration the
// conclusion's report archived still carries a non-empty id, both rules
// with a boolean enabled and an integer severity 1-5, and a displacement
// multiplier 2-100. Only an old-format record with no version key at all
// keeps the built-in interpretation. On corruption the whole submission
// fails with ErrCorruptVersion: no result, no consumed submission id, no
// revision or object-version change, and an archive left byte for byte —
// including when the submission is an identical retry carrying a
// submissionId already stored.

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
// shape: ErrCorruptVersion wrapping the cause, never an unknown-conclusion,
// version-conflict or submission-id-conflict misread, naming the target
// chain and block plus every required extra substring, returning an empty
// result and leaving the archive byte-identical. A second attempt fails the
// same way: the declaration is neither repaired nor bypassed by a retry.
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
		errors.Is(err, ErrSubmissionConflict) {
		t.Fatalf("corrupt declaration misrouted through another failure: %v", err)
	}
	if !reflect.DeepEqual(res, SubmitReviewResult{}) {
		t.Fatalf("corrupt declaration returned a partial result: %+v", res)
	}
	msg := err.Error()
	for _, subStr := range append([]string{sub.ChainID, sub.BlockHash}, want...) {
		if !strings.Contains(msg, subStr) {
			t.Fatalf("error %q must name %q", msg, subStr)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed submission changed the archive")
	}
	if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second submission did not fail the same way: %v", err)
	}
}

// submitTarget is a legal first-time review against the conclusion
// setupCorruptCompareArchive archives: a displacement on 0xv.
func submitTarget(id string, expected int) ReviewSubmission {
	return reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		id, "alice", "confirmed bot war", ReviewStatusReal, expected)
}

// TestSubmitReviewCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the target report (the
// registered versions stay intact): every way the saved document can stop
// satisfying the registration rules must fail the whole submission, naming
// chain, block, the readable saved id and the offending rule or field — as
// a first submission and as a rejudgment against an object that already
// carries a revision.
func TestSubmitReviewCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertSubmitRefused(t, dir, submitTarget("s-1", 0), "candC", tc.wantErr)
		})
	}

	// The proof is about the original conclusion, not the review state: a
	// rejudgment of an object that already carries a revision, and a
	// withdrawal, fail exactly the same way before the version check can
	// turn either one into a review-version conflict.
	t.Run("with existing review data", func(t *testing.T) {
		dir := setupCorruptCompareArchive(t)
		first := submit(t, dir, submitTarget("s-1", 0))
		if !first.Created || first.Version != 1 {
			t.Fatalf("setup submission = %+v", first)
		}
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		assertSubmitRefused(t, dir, submitTarget("s-2", 1), "candC", "multiplier")

		withdrawn := reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-3", "carol", "reset", ReviewStatusUnreviewed, 1)
		assertSubmitRefused(t, dir, withdrawn, "candC", "multiplier")

		// Even a stale expectedVersion is refused as corruption, never as a
		// review-version conflict: the saved basis is proved first.
		assertSubmitRefused(t, dir, submitTarget("s-4", 0), "candC", "multiplier")
	})
}

// TestSubmitReviewNullAndEmptySavedVersionCorrupt pins the exact misread
// being fixed: version:null used to be explained as the built-in rules and
// to be stripped from the report by the accepting submission's rewrite, and
// {} or an incomplete object used to decode into zeroed parameters. All of
// them fail; only a wholly missing version key is the legacy built-in
// shape.
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
			want := []string{}
			if tc.idReachable {
				want = append(want, "candC")
			}
			assertSubmitRefused(t, dir, submitTarget("s-1", 0), want...)
		})
	}
}

// TestSubmitReviewBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full before a review is accepted, rather than substituting
// the in-code builtin rules.
func TestSubmitReviewBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	res, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err != nil || !res.Created || res.Version != 1 {
		t.Fatalf("a complete builtin-id declaration must accept a review: %+v %v", res, err)
	}

	dir2 := setupCorruptCompareArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", builtinDamaged)
	assertSubmitRefused(t, dir2, submitTarget("s-1", 0), BuiltinVersionID, "multiplier")
}

// TestSubmitReviewDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling that
// name the same field, even when both values agree. The raw bytes are
// patched directly because a JSON map cannot hold two keys.
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
			res, err := SubmitReview(dir, submitTarget("s-1", 0))
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
				t.Fatalf("failed submission repaired the duplicate field")
			}
		})
	}
}

// TestSubmitReviewExplicitlyDisabledRulesAccepted proves enabled:false is
// a legal saved off state for a submitted review, but a disabled rule
// still has to carry complete, in-range parameters.
func TestSubmitReviewExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	res, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err != nil || !res.Created {
		t.Fatalf("an explicitly disabled, complete declaration must accept a review: %+v %v", res, err)
	}

	dir2 := setupCorruptCompareArchive(t)
	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", offBroken)
	assertSubmitRefused(t, dir2, submitTarget("s-1", 0), "off", "multiplier")
}

// TestSubmitReviewUsesSavedParametersNotRegistry proves accepting a review
// never consults the registry for the target's basis: a damaged same-id
// registry entry does not block an intact saved report, an intact registry
// cannot rescue a corrupt report, and a saved id the registry never
// carried still stands on its own.
func TestSubmitReviewUsesSavedParametersNotRegistry(t *testing.T) {
	// Damage only the registered candC entry while the report's own embedded
	// copy stays intact: the submission goes through and borrows nothing.
	dir := setupCorruptCompareArchive(t)
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatal(err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	res, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block a review of an intact report: %v", err)
	}
	if !res.Created || res.Version != 1 {
		t.Fatalf("review against intact report = %+v", res)
	}
	// The corrupt registry entry and the enabled marker are untouched: the
	// submit wrote back the registry byte for byte in content and never
	// tried to complete or strip the damaged sibling.
	var doc replayArchiveDoc
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.EnabledVersion != "twin" || len(doc.Versions) != 2 {
		t.Fatalf("submit rewrote registry/enabled marker: %+v", doc)
	}

	// Conversely, an intact registry cannot rescue a corrupt report.
	dir2 := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertSubmitRefused(t, dir2, submitTarget("s-1", 0), "candC", "multiplier")

	// A complete declaration with an id the registry never carried stands
	// on its own and accepts the review.
	dir3 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir3, "1", "0xblk", stray)
	res3, err := SubmitReview(dir3, submitTarget("s-1", 0))
	if err != nil || !res3.Created {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %+v %v", res3, err)
	}
}

// TestSubmitReviewCorruptSiblingDoesNotBlock proves the integrity proof is
// scoped to the report the submission hits: a damaged declaration on
// another block or another chain, or a damaged registered version, never
// blocks a review of an intact target; and an identity the corrupt report
// does not carry is still an unknown conclusion and never opens that
// report's declaration.
func TestSubmitReviewCorruptSiblingDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	input := cmpBlockLine("1", "0xblk", 7,
		cmpSwap("0xf", "p1", "w", 40, 0),
		cmpSwap("0xv", "p1", "u", 10, 1),
	) + "\n" + cmpBlockLine("1", "0other", 8,
		cmpSwap("0g0", "p2", "w", 40, 2),
		cmpSwap("0g1", "p2", "u", 10, 3),
	) + "\n" + cmpBlockLine("2", "0xblk", 7,
		cmpSwap("0q0", "p3", "w", 40, 4),
		cmpSwap("0q1", "p3", "u", 10, 5),
	) + "\n"
	path := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFileWithVersion(path, dir, "candC"); err != nil {
		t.Fatal(err)
	}
	register(t, dir, twinVersionSpec)

	// Damage only the same-chain sibling block.
	rewriteStoredReportVersion(t, dir, "1", "0other", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	res, err := SubmitReview(dir, reviewSub("1", "0xblk", "0xv", SuppressDisplacement, "s-1", "a", "r", ReviewStatusReal, 0))
	if err != nil || !res.Created {
		t.Fatalf("a corrupt sibling block blocked the intact target: %+v %v", res, err)
	}
	// The damaged sibling itself still refuses, scoped to its own block.
	assertSubmitRefused(t, dir, reviewSub("1", "0other", "0g1", SuppressDisplacement, "s-2", "a", "r", ReviewStatusReal, 0), "candC", "multiplier")

	// Damage the same-hash block on another chain: chain 1's target stays
	// reviewable, chain 2's fails on its own.
	rewriteStoredReportVersion(t, dir, "2", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = 0
	})
	if _, err := SubmitReview(dir, reviewSub("1", "0xblk", "0xv", SuppressDisplacement, "s-3", "a", "r", ReviewStatusFalsePositive, 1)); err != nil {
		t.Fatalf("a corrupt other-chain record blocked the target: %v", err)
	}
	assertSubmitRefused(t, dir, reviewSub("2", "0xblk", "0q1", SuppressDisplacement, "s-4", "a", "r", ReviewStatusReal, 0), "candC", "severity")

	// A damaged registry sibling never blocks an intact saved report.
	rewriteStoredVersion(t, dir, "twin", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 1
	})
	if _, err := SubmitReview(dir, reviewSub("1", "0xblk", "0xv", SuppressDisplacement, "s-5", "a", "r", ReviewStatusReal, 2)); err != nil {
		t.Fatalf("a corrupt registered version blocked the target: %v", err)
	}

	// An identity the corrupt report does not carry is an unknown
	// conclusion: the wrong kind on the damaged block, a ghost tx and a
	// block that was never archived never open the damaged declaration.
	for _, sub := range []ReviewSubmission{
		reviewSub("1", "0other", "0g1", SuppressSandwich, "s-6", "a", "r", ReviewStatusReal, 0),
		reviewSub("1", "0other", "0ghost", SuppressDisplacement, "s-7", "a", "r", ReviewStatusReal, 0),
		reviewSub("1", "0nope", "0g1", SuppressDisplacement, "s-8", "a", "r", ReviewStatusReal, 0),
	} {
		if _, err := SubmitReview(dir, sub); !errors.Is(err, ErrUnknownConclusion) {
			t.Fatalf("sub %+v: got %v, want ErrUnknownConclusion", sub, err)
		}
	}
}

// TestSubmitReviewLegacyRecordStillBuiltin proves the single carve-out: a
// record with no version key at all keeps accepting reviews under the
// built-in interpretation, and appending a revision neither adds a version
// key to the legacy record nor alters its conclusion, evidence or swap
// count.
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
	sub := reviewSub("1", "0old", "0v", SuppressSandwich, "s-1", "alice", "r", ReviewStatusReal, 0)
	res, err := SubmitReview(dir, sub)
	if err != nil {
		t.Fatalf("legacy record must accept a review under builtin: %v", err)
	}
	if !res.Created || res.Version != 1 || res.Status != ReviewStatusReal {
		t.Fatalf("legacy submission result = %+v", res)
	}
	// A rejudgment appends under the same legacy built-in basis.
	res2, err := SubmitReview(dir, reviewSub("1", "0old", "0v", SuppressSandwich, "s-2", "bob", "r2", ReviewStatusFalsePositive, 1))
	if err != nil || !res2.Created || res2.Version != 2 {
		t.Fatalf("legacy rejudgment = %+v %v", res2, err)
	}
	// The report is still queryable exactly as archived: builtin
	// parameters, original findings and evidence, and no version key
	// invented by the review write.
	report, err := Query(dir, "1", "0old")
	if err != nil {
		t.Fatalf("legacy report must still query under builtin: %v", err)
	}
	if report.Version != BuiltinVersion() || len(report.Findings) != 1 ||
		report.Findings[0].Severity != 3 || report.SwapCount != 3 {
		t.Fatalf("legacy report changed across reviews: %+v", report)
	}
	var doc queryArchiveDoc
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Records) != 1 || len(doc.Records[0].Version) != 0 {
		t.Fatalf("review appended a version key to the legacy record: %s", doc.Records[0].Version)
	}
}

// TestSubmitReviewIdempotentRetryCannotBypassCorruption is the heart of
// the fix: the integrity proof runs before submission-id reuse, so
// retrying the exact submission already stored against a report whose
// declaration has since decayed fails as corruption instead of returning
// created:false — and neither a different-content reuse (submission
// conflict) nor a stale expected version (review conflict) can reach its
// old branch either. Once the declaration is restored, the ordinary retry
// and rejudgment conventions apply unchanged.
func TestSubmitReviewIdempotentRetryCannotBypassCorruption(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	first := submit(t, dir, submitTarget("s-1", 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("setup = %+v", first)
	}
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})

	// Identical retry of the stored submission: corruption, not
	// created:false with the original revision.
	res, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err == nil {
		t.Fatalf("identical retry masked corruption: %+v", res)
	}
	if !errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrSubmissionConflict) {
		t.Fatalf("identical retry = %v, want ErrCorruptVersion", err)
	}
	if res.Created || res.Revision != (ReviewRevision{}) {
		t.Fatalf("identical retry returned a result: %+v", res)
	}

	// Same stored id, different content: still corruption rather than a
	// submission-id conflict.
	different := submitTarget("s-1", 0)
	different.Operator = "mallory"
	if _, err := SubmitReview(dir, different); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("different-content reuse = %v, want ErrCorruptVersion", err)
	}

	// A fresh rejudgment with the right current version and one with a
	// stale base both stop at the proof.
	if _, err := SubmitReview(dir, submitTarget("s-2", 1)); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("rejudgment = %v, want ErrCorruptVersion", err)
	}
	if _, err := SubmitReview(dir, submitTarget("s-3", 0)); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("stale rejudgment = %v, want ErrCorruptVersion", err)
	}

	// Restore the declaration: the stored s-1 retry is the ordinary
	// idempotent created:false response again, appending nothing...
	replaceStoredReportVersion(t, dir, "1", "0xblk", map[string]any{
		"id": "candC",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 4, "multiplier": 2},
		},
	})
	retry, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err != nil {
		t.Fatalf("retry after restore: %v", err)
	}
	if retry.Created || retry.Version != 1 || !reflect.DeepEqual(retry.Revision, first.Revision) {
		t.Fatalf("retry = %+v, want original revision at version 1", retry)
	}
	// ...and the rejudgment now appends normally.
	rejudged, err := SubmitReview(dir, submitTarget("s-2", 1))
	if err != nil || !rejudged.Created || rejudged.Version != 2 {
		t.Fatalf("rejudgment after restore = %+v %v", rejudged, err)
	}
}

// TestSubmitReviewCorruptDeclarationConsumesNothing proves a refused
// submission rewrites nothing: the archive bytes stay identical, existing
// revisions and object versions survive, a failed submission id is not
// occupied, and the alert records the archive also carries stay byte
// identical in content.
func TestSubmitReviewCorruptDeclarationConsumesNothing(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	submit(t, dir, submitTarget("s-1", 0))
	// Pre-existing alert records must survive untouched as well.
	alerts, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("setup: want one alert record, got %d", len(alerts))
	}
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	corruptBytes := readArchiveFile(t, dir)

	for i := 0; i < 2; i++ {
		if _, err := SubmitReview(dir, submitTarget("s-new", 1)); !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("attempt %d: got %v, want ErrCorruptVersion", i, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatalf("refused submissions rewrote the archive")
	}
	var doc rawVersionArchiveDoc
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Reviews) != 1 || len(doc.Reviews[0].Revisions) != 1 ||
		doc.Reviews[0].Revisions[0].SubmissionID != "s-1" {
		t.Fatalf("existing review data changed: %+v", doc.Reviews)
	}

	// Restore the basis: the refused id is free and creates version 2
	// against the current object, exactly as if the failed attempts never
	// happened.
	replaceStoredReportVersion(t, dir, "1", "0xblk", map[string]any{
		"id": "candC",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 4, "multiplier": 2},
		},
	})
	res, err := SubmitReview(dir, submitTarget("s-new", 1))
	if err != nil {
		t.Fatalf("refused id must be free after restore: %v", err)
	}
	if !res.Created || res.Version != 2 || res.Revision.SubmissionID != "s-new" {
		t.Fatalf("s-new submission = %+v, want created at version 2", res)
	}
	alertsAfter, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(alerts, alertsAfter) {
		t.Fatalf("alert records changed: before %+v after %+v", alerts, alertsAfter)
	}
}
