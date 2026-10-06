package mevwatch

// Regression coverage for `reviews history` (ReviewHistoryQuery) against
// an archived report whose saved rule-version declaration has decayed
// since the report was written. Once a query hits the archived original
// conclusion it must first prove — exactly the way a `report` query does —
// that the declaration the report archived still carries a non-empty id,
// both rules with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100. A written null used to be explained as
// the built-in rules and an incomplete declaration used to come back with
// silently zeroed parameters. Only an old-format record with no version
// key at all keeps the built-in interpretation. On corruption the whole
// query fails with ErrCorruptVersion — no history JSON, no partial
// original — naming the target chain, the block, the readable saved
// version id and the offending rule or field, and leaves the archive
// untouched.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// historyTarget is the conclusion the setupCorruptCompareArchive block
// carries: under candC (sandwich off, displacement severity 4 multiplier
// 2) swaps 0xf (gas 40) and 0xv (gas 10) produce one displacement hit on
// 0xv — the exact shape that used to decode a decayed zero multiplier as
// a real parameter set.
const (
	historyTargetTx   = "0xv"
	historyTargetKind = SuppressDisplacement
)

// assertHistoryRefused runs one failing ReviewHistoryQuery and pins the
// failure shape: ErrCorruptVersion wrapping the cause, never an
// unknown-conclusion misread, naming the target chain, block and every
// required extra substring, returning no partial history and leaving the
// archive byte-identical.
func assertHistoryRefused(t *testing.T, dir, chain, hash, tx, kind string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	hist, err := ReviewHistoryQuery(dir, chain, hash, tx, kind)
	if err == nil {
		t.Fatalf("corrupt declaration returned history: %+v", hist)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt declaration misreported as an unknown version: %v", err)
	}
	if !reflect.DeepEqual(hist, ReviewHistory{}) {
		t.Fatalf("corrupt declaration returned a partial history: %+v", hist)
	}
	msg := err.Error()
	for _, sub := range append([]string{chain, hash}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed history query changed the archive")
	}
	// No partial repair: a second attempt fails the same way.
	if _, err := ReviewHistoryQuery(dir, chain, hash, tx, kind); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second history query did not fail the same way: %v", err)
	}
}

// TestReviewHistoryCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the target report (the
// registered versions section stays intact): every way the saved document
// can stop satisfying the registration rules must fail the whole history
// query, naming chain, block, the readable saved id and the offending rule
// or field — with or without review data for the object.
func TestReviewHistoryCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertHistoryRefused(t, dir, "1", "0xblk", historyTargetTx, historyTargetKind, "candC", tc.wantErr)
		})
	}

	// The proof is about the original conclusion, not the review data: an
	// object carrying a current review fails exactly the same way.
	t.Run("with review data", func(t *testing.T) {
		dir := setupCorruptCompareArchive(t)
		if _, err := SubmitReview(dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
			"s-1", "alice", "r", ReviewStatusReal, 0)); err != nil {
			t.Fatal(err)
		}
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		assertHistoryRefused(t, dir, "1", "0xblk", historyTargetTx, historyTargetKind, "candC", "multiplier")
	})
}

// TestReviewHistoryNullAndEmptySavedVersionCorrupt pins the exact
// misread being fixed: version:null used to be explained as the built-in
// rules, and {} or an incomplete object used to return zeroed parameters.
// All of them fail; only a wholly missing version key is the legacy
// built-in shape.
func TestReviewHistoryNullAndEmptySavedVersionCorrupt(t *testing.T) {
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
			assertHistoryRefused(t, dir, "1", "0xblk", historyTargetTx, historyTargetKind, want...)
		})
	}
}

// TestReviewHistoryBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestReviewHistoryBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must be returned: %v", err)
	}
	if hist.Original == nil || hist.Original.Version != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin parameters", hist.Original)
	}

	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertHistoryRefused(t, dir, "1", "0xblk", historyTargetTx, historyTargetKind, BuiltinVersionID, "multiplier")
}

// TestReviewHistoryDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling
// that name the same field, even when both values agree. The raw bytes
// are patched directly because a JSON map cannot hold two keys.
func TestReviewHistoryDuplicateFieldsInSavedVersionRefused(t *testing.T) {
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
			hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
			if err == nil {
				t.Fatalf("duplicate-field declaration returned history: %+v", hist)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed history query repaired the duplicate field")
			}
		})
	}
}

// TestReviewHistoryExplicitlyDisabledRulesAccepted proves enabled:false
// is a legal historical off state, but a disabled rule still has to carry
// complete, in-range parameters.
func TestReviewHistoryExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must be returned: %v", err)
	}
	if hist.Original == nil || hist.Original.Version.ID != "off" ||
		hist.Original.Version.Rules.Sandwich.Enabled ||
		hist.Original.Version.Rules.Displacement.Enabled {
		t.Fatalf("historical off state not carried: %+v", hist.Original)
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", offBroken)
	assertHistoryRefused(t, dir, "1", "0xblk", historyTargetTx, historyTargetKind, "off", "multiplier")
}

// TestReviewHistoryUsesSavedParametersNotRegistry proves the original
// conclusion is explained by the declaration the report archived: a
// damaged same-id registry entry neither blocks nor completes the saved
// parameters, the enabled version never leaks in, an intact registry
// cannot rescue a corrupt report, and a saved id the registry never
// carried is still a valid explanation on its own.
func TestReviewHistoryUsesSavedParametersNotRegistry(t *testing.T) {
	// Damage only the registered candC entry while the report's own
	// embedded copy stays intact: the history still shows candC's saved
	// parameters and borrows nothing from the registry.
	dir := setupCorruptCompareArchive(t)
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatal(err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %v", err)
	}
	if hist.Original == nil {
		t.Fatal("original conclusion missing")
	}
	if want := mustRuleVersion(t, candidateVersionSpec); hist.Original.Version != want {
		t.Fatalf("history borrowed registry parameters: %+v, want %+v", hist.Original.Version, want)
	}

	// Conversely, an intact registry cannot rescue a corrupt report:
	// damage only the embedded copy while the same-id registry entry stays
	// intact.
	dir2 := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertHistoryRefused(t, dir2, "1", "0xblk", historyTargetTx, historyTargetKind, "candC", "multiplier")

	// A complete declaration with an id the registry never carried stands
	// on its own.
	dir3 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir3, "1", "0xblk", stray)
	h3, err := ReviewHistoryQuery(dir3, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if h3.Original == nil || h3.Original.Version.ID != "never-registered" ||
		h3.Original.Version.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved historical parameters not carried: %+v", h3.Original)
	}
}

// TestReviewHistoryCorruptSiblingDoesNotBlock proves the integrity proof
// is scoped to the report the query hits: a damaged declaration on
// another block or another chain, or a damaged registered version, never
// blocks the target conclusion's legal history; and an identity without a
// matching conclusion keeps original:null even when the block it names
// carries a damaged declaration.
func TestReviewHistoryCorruptSiblingDoesNotBlock(t *testing.T) {
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
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatalf("a corrupt sibling block blocked the target: %v", err)
	}
	if hist.Original == nil || hist.Original.Version.ID != "candC" {
		t.Fatalf("target original damaged: %+v", hist.Original)
	}
	// The damaged sibling itself still fails, scoped to its own block.
	assertHistoryRefused(t, dir, "1", "0other", "0g1", historyTargetKind, "candC", "multiplier")

	// Damage the same-hash block on another chain: chain 1's target stays
	// queryable, chain 2's fails on its own.
	rewriteStoredReportVersion(t, dir, "2", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = 0
	})
	if _, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind); err != nil {
		t.Fatalf("a corrupt other-chain record blocked the target: %v", err)
	}
	assertHistoryRefused(t, dir, "2", "0xblk", "0q1", historyTargetKind, "candC", "severity")

	// A damaged registry sibling never blocks an intact saved report.
	rewriteStoredVersion(t, dir, "twin", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 1
	})
	if _, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind); err != nil {
		t.Fatalf("a corrupt registered version blocked the target: %v", err)
	}

	// An identity with no matching conclusion keeps original:null even
	// though the named block's own declaration is damaged; its review
	// state defaults remain available.
	ghost, err := ReviewHistoryQuery(dir, "1", "0other", "0ghost", SuppressSandwich)
	if err != nil {
		t.Fatalf("a non-matching identity must not open the block declaration: %v", err)
	}
	if ghost.Original != nil || ghost.Status != ReviewStatusUnreviewed || ghost.Version != 0 ||
		len(ghost.Revisions) != 0 {
		t.Fatalf("no-conclusion identity = %+v", ghost)
	}
}

// TestReviewHistoryLegacyRecordStillBuiltin proves the single carve-out:
// a record with no version key at all is still explained by the built-in
// rules, with the original conclusion, findings and swap evidence intact.
func TestReviewHistoryLegacyRecordStillBuiltin(t *testing.T) {
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
	hist, err := ReviewHistoryQuery(dir, "1", "0old", "0v", SuppressSandwich)
	if err != nil {
		t.Fatalf("legacy record must be explained under builtin: %v", err)
	}
	if hist.Original == nil {
		t.Fatal("original conclusion missing")
	}
	if hist.Original.Version != BuiltinVersion() {
		t.Fatalf("version = %+v, want builtin", hist.Original.Version)
	}
	if hist.Original.Finding.TxHash != "0v" || hist.Original.Finding.Kind != SuppressSandwich ||
		hist.Original.Finding.Severity != 3 || len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy conclusion/evidence damaged: %+v", hist.Original.Finding)
	}
	if hist.Status != ReviewStatusUnreviewed || hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("legacy default review state wrong: %+v", hist)
	}
}

// TestReviewHistorySuccessContentPreserved proves a healthy history keeps
// the current review status, the review version, every revision in
// ascending order, the original conclusion with its saved detection
// parameters and the complete swap evidence — with no re-detection —
// whether or not review data exists.
func TestReviewHistorySuccessContentPreserved(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	// No review data yet: defaults plus the full original under builtin.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xd", SuppressDisplacement)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusUnreviewed || hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("default review state wrong: %+v", hist)
	}
	if hist.Original == nil {
		t.Fatal("original conclusion missing")
	}
	if hist.Original.BlockNumber != 10 ||
		hist.Original.Finding.TxHash != "0xd" || hist.Original.Finding.Kind != SuppressDisplacement ||
		hist.Original.Finding.Severity != 2 || len(hist.Original.Finding.Evidence) != 2 {
		t.Fatalf("original conclusion/evidence wrong: %+v", hist.Original)
	}
	if hist.Original.Version != BuiltinVersion() {
		t.Fatalf("detection version wrong: %+v", hist.Original.Version)
	}

	submit(t, dir, reviewSub("1", "0xa", "0xd", SuppressDisplacement, "s-1", "alice", "fp", ReviewStatusFalsePositive, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xd", SuppressDisplacement, "s-2", "bob", "keep", ReviewStatusReal, 1))
	hist, err = ReviewHistoryQuery(dir, "1", "0xa", "0xd", SuppressDisplacement)
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusReal || hist.Version != 2 {
		t.Fatalf("current state = %q/%d", hist.Status, hist.Version)
	}
	if len(hist.Revisions) != 2 ||
		hist.Revisions[0].Version != 1 || hist.Revisions[0].SubmissionID != "s-1" || hist.Revisions[0].Status != ReviewStatusFalsePositive ||
		hist.Revisions[1].Version != 2 || hist.Revisions[1].SubmissionID != "s-2" || hist.Revisions[1].Status != ReviewStatusReal {
		t.Fatalf("revisions not ascending with full content: %+v", hist.Revisions)
	}
	if hist.Original.Finding.Severity != 2 ||
		hist.Original.Version != BuiltinVersion() ||
		len(hist.Original.Finding.Evidence) != 2 {
		t.Fatalf("original conclusion changed across reviews: %+v", hist.Original)
	}

	// A non-builtin saved declaration is carried with its own parameters.
	dir2 := setupCorruptCompareArchive(t)
	h2, err := ReviewHistoryQuery(dir2, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil {
		t.Fatal(err)
	}
	if h2.Original == nil {
		t.Fatal("original conclusion missing")
	}
	if want := mustRuleVersion(t, candidateVersionSpec); h2.Original.Version != want {
		t.Fatalf("saved parameters wrong: %+v want %+v", h2.Original.Version, want)
	}
	if h2.Original.Finding.Severity != 4 {
		t.Fatalf("conclusion severity must stay the archived 4, got %d", h2.Original.Finding.Severity)
	}
}

// TestReviewHistoryCorruptDeclarationReadOnly proves a refused history
// query rewrites neither reports, reviews, the enabled marker nor the
// archive bytes, and the stored revisions stay reachable once the report
// is restored.
func TestReviewHistoryCorruptDeclarationReadOnly(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	submit(t, dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind, "s-1", "alice", "r", ReviewStatusReal, 0))
	corruptBytes := func() []byte {
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		return readArchiveFile(t, dir)
	}()
	if _, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("expected ErrCorruptVersion")
	}
	after := readArchiveFile(t, dir)
	if !reflect.DeepEqual(corruptBytes, after) {
		t.Fatalf("failed history query modified the archive")
	}
	// The review object itself is untouched: the query rewrote nothing.
	var doc rawVersionArchiveDoc
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Reviews) != 1 || len(doc.Reviews[0].Revisions) != 1 ||
		doc.Reviews[0].Revisions[0].SubmissionID != "s-1" {
		t.Fatalf("review data changed: %+v", doc.Reviews)
	}
}
