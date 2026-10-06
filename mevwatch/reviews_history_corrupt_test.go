package mevwatch

// Regression coverage for `reviews history` (ReviewHistoryQuery) against an
// archived report whose saved rule-version declaration has decayed since
// the report was written. Once the query hits the original conclusion, the
// declaration that conclusion's report archived must first pass the exact
// integrity proof a `report` query enforces — a non-empty id, sandwich and
// displacement each with a boolean enabled and an integer severity 1-5, and
// a displacement multiplier 2-100 — re-validated from the raw stored bytes.
// Until that proof succeeds no history is returned: a written null used to
// be explained as the built-in rules and an incomplete declaration used to
// return the original under silently zeroed parameters. Only an old-format
// record with no version key at all keeps the built-in interpretation. On
// corruption the whole query fails with ErrCorruptVersion naming the target
// chain and block, the readable saved id and the offending rule or field —
// no partial history — and a corrupt sibling record or registered version
// never blocks the target's intact history. The query is read-only either
// way.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// setupHistoryCorruptArchive archives the two-findings block (a sandwich on
// 0xv and a displacement on 0xd under builtin) and records one real review
// on the sandwich, so every query below has a stored history worth
// protecting alongside the original conclusion.
func setupHistoryCorruptArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s1", "op", "looks real", ReviewStatusReal, 0))
	return dir
}

// assertHistoryRefused runs one failing ReviewHistoryQuery and pins the
// failure shape: ErrCorruptVersion wrapping the cause, never an
// unknown-block, unknown-version or unknown-conclusion misread, naming the
// target chain and block plus every required extra substring, leaving the
// archive byte-identical, and failing identically on a second attempt.
func assertHistoryRefused(t *testing.T, dir, chain, hash, tx, kind string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	hist, err := ReviewHistoryQuery(dir, chain, hash, tx, kind)
	if err == nil {
		t.Fatalf("corrupt historical declaration returned history: %+v", hist)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrUnknownConclusion) {
		t.Fatalf("corrupt historical declaration misreported as unknown block/version/conclusion: %v", err)
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
	// No partial history is ever returned, and a second attempt fails the
	// same way: the declaration is not repaired or completed.
	if _, err := ReviewHistoryQuery(dir, chain, hash, tx, kind); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second history query did not fail the same way: %v", err)
	}
}

// TestReviewHistoryCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the targeted report (the
// reviews and every other archive section stay intact): every way the saved
// document can stop satisfying the registration rules must fail the whole
// history query, naming chain, block, the readable saved id and the
// offending rule or field.
func TestReviewHistoryCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupHistoryCorruptArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			// The block was archived under builtin; the saved id stays
			// readable and is named rather than bypassed.
			assertHistoryRefused(t, dir, "1", "0xa", "0xv", "sandwich", BuiltinVersionID, tc.wantErr)
		})
	}
}

// TestReviewHistoryNullAndEmptySavedVersionCorrupt pins the exact misread
// being fixed: version:null used to leave the decoded version pointer nil
// and be explained as the built-in rules, and {} or an incomplete object
// returned the original under zeroed parameters. All of these fail; only a
// wholly missing version key is the legacy built-in shape.
func TestReviewHistoryNullAndEmptySavedVersionCorrupt(t *testing.T) {
	cases := []struct {
		name  string
		value any
		// idReachable says whether the error can still name a saved id.
		idReachable bool
	}{
		{"null", nil, false},
		{"empty object", map[string]any{}, false},
		{"incomplete object", map[string]any{"id": "builtin"}, true},
		{"non-object number", 5, false},
		{"non-object string", "builtin", false},
		{"array", []any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupHistoryCorruptArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xa", tc.value)
			want := []string{}
			if tc.idReachable {
				want = append(want, BuiltinVersionID)
			}
			assertHistoryRefused(t, dir, "1", "0xa", "0xv", "sandwich", want...)
		})
	}
}

// TestReviewHistoryDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling that
// name the same field, even when both values agree.
func TestReviewHistoryDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 3, `},
		{"case variant", `"Severity": 3, `},
		{"escaped", "\"se\\u0076erity\": 3, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupHistoryCorruptArchive(t)
			path := filepath.Join(dir, archiveFileName)
			text := string(readArchiveFile(t, dir))
			at := strings.Index(text, `"id": "builtin"`)
			if at < 0 {
				t.Fatal("record's embedded builtin declaration not found")
			}
			anchor := `"severity": 2,`
			field := strings.Index(text[at:], anchor)
			if field < 0 {
				t.Fatal("severity field not found in embedded declaration")
			}
			pos := at + field
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
			if err == nil {
				t.Fatalf("duplicate-field declaration returned history")
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), BuiltinVersionID) || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name builtin and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed history query repaired the duplicate field")
			}
		})
	}
}

// TestReviewHistoryExplicitlyDisabledRulesAccepted proves enabled:false is
// a legal historical off state — the history comes back with the saved off
// parameters — but a disabled rule still has to carry complete, in-range
// parameters.
func TestReviewHistoryExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupHistoryCorruptArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", off)
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must return history: %v", err)
	}
	if hist.Original == nil || hist.Original.Version.ID != "off" ||
		hist.Original.Version.Rules.Sandwich.Enabled ||
		hist.Original.Version.Rules.Displacement.Enabled {
		t.Fatalf("historical off state not carried: %+v", hist.Original)
	}
	if hist.Status != ReviewStatusReal || hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("review history damaged: %+v", hist)
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", offBroken)
	assertHistoryRefused(t, dir, "1", "0xa", "0xv", "sandwich", "off", "severity")
}

// TestReviewHistoryCorruptSiblingAndRegistryDoNotBlock proves only the
// target record's declaration is judged: a corrupt declaration on another
// block and a corrupt registered version — even one so damaged a whole-
// archive decode would fail — never block the target conclusion's intact
// history.
func TestReviewHistoryCorruptSiblingAndRegistryDoNotBlock(t *testing.T) {
	t.Run("corrupt registered version", func(t *testing.T) {
		dir := setupHistoryCorruptArchive(t)
		mustRegisterVersion(t, dir, mult3Spec)
		// A wrong-typed field in the registry entry used to fail the
		// whole-archive decode and with it the history query.
		rewriteStoredVersion(t, dir, "mult3", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = "3"
		})
		hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
		if err != nil {
			t.Fatalf("a corrupt registry entry must not block an intact history: %v", err)
		}
		if hist.Original == nil || hist.Original.Version != BuiltinVersion() ||
			hist.Status != ReviewStatusReal || hist.Version != 1 || len(hist.Revisions) != 1 {
			t.Fatalf("intact history not returned: %+v", hist)
		}
	})

	t.Run("corrupt sibling record", func(t *testing.T) {
		dir := setupHistoryCorruptArchive(t)
		other := `{"chainId":"1","blockHash":"0xb","blockNumber":11,"swaps":[` +
			`{"TxHash":"0g0","Pool":"p9","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":0},` +
			`{"TxHash":"0g1","Pool":"p9","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`
		mustReplay(t, dir, other)
		rewriteStoredReportVersion(t, dir, "1", "0xb", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = "2"
		})
		hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
		if err != nil {
			t.Fatalf("a corrupt sibling record must not block an intact history: %v", err)
		}
		if hist.Original == nil || hist.Original.Version != BuiltinVersion() ||
			hist.Status != ReviewStatusReal || len(hist.Revisions) != 1 {
			t.Fatalf("intact history not returned: %+v", hist)
		}
		// The sibling's own conclusions are refused on their own.
		assertHistoryRefused(t, dir, "1", "0xb", "0g1", "displacement", BuiltinVersionID, "multiplier")
	})
}

// TestReviewHistoryUsesSavedParametersNotRegistry proves the original
// conclusion is explained by the declaration its report archived: a same-id
// registry entry is neither consulted nor able to complete the saved
// parameters, and a saved id the registry never carried is still a valid
// explanation on its own.
func TestReviewHistoryUsesSavedParametersNotRegistry(t *testing.T) {
	// A complete declaration with an id the registry never carried is
	// valid on its own and needs no registry backing.
	dir := setupHistoryCorruptArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", stray)
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if hist.Original == nil || hist.Original.Version.ID != "never-registered" ||
		hist.Original.Version.Rules.Displacement.Multiplier != 9 ||
		hist.Original.Version.Rules.Sandwich.Severity != 5 {
		t.Fatalf("saved historical parameters not carried: %+v", hist.Original)
	}

	// Damage the same-id registry entry while the report's own embedded
	// copy stays intact: the history still explains the original with the
	// saved parameters and borrows nothing from the registry.
	dir2 := t.TempDir()
	mustRegisterVersion(t, dir2, mult3Spec)
	if _, err := ReplayWithVersion(strings.NewReader(twoFindingsInput), dir2, "mult3"); err != nil {
		t.Fatal(err)
	}
	submit(t, dir2, reviewSub("1", "0xa", "0xd", "displacement", "s1", "op", "fp", ReviewStatusFalsePositive, 0))
	rewriteStoredVersion(t, dir2, "mult3", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	hist2, err := ReviewHistoryQuery(dir2, "1", "0xa", "0xd", "displacement")
	if err != nil {
		t.Fatalf("a corrupt same-id registry entry must not block an intact saved report: %v", err)
	}
	if want := mustRuleVersion(t, mult3Spec); hist2.Original == nil || hist2.Original.Version != want {
		t.Fatalf("history borrowed registry parameters: %+v", hist2.Original)
	}
}

// TestReviewHistoryUnmatchedConclusionKeepsOriginalNull proves the
// declaration proof only runs once the query hits an original conclusion:
// an identity no archived finding matches keeps its existing behavior —
// original:null, unreviewed, version 0, an empty revision list — even when
// the block's own saved declaration is damaged.
func TestReviewHistoryUnmatchedConclusionKeepsOriginalNull(t *testing.T) {
	dir := setupHistoryCorruptArchive(t)
	rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xghost", "sandwich")
	if err != nil {
		t.Fatalf("an unmatched conclusion must not open the declaration: %v", err)
	}
	if hist.Original != nil || hist.Status != ReviewStatusUnreviewed ||
		hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("unmatched identity changed shape: %+v", hist)
	}
}

// TestReviewHistoryLegacyRecordStillBuiltin proves the single carve-out is
// unchanged by the fix: a record with no version key at all explains its
// original under the built-in rules, with the review history and the swap
// evidence intact.
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
	submit(t, dir, reviewSub("1", "0old", "0v", "sandwich", "s1", "op", "real", ReviewStatusReal, 0))
	hist, err := ReviewHistoryQuery(dir, "1", "0old", "0v", "sandwich")
	if err != nil {
		t.Fatalf("legacy record must return history under builtin: %v", err)
	}
	if hist.Original == nil || hist.Original.Version != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin", hist.Original)
	}
	if len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy swap evidence damaged: %+v", hist.Original.Finding)
	}
	if hist.Status != ReviewStatusReal || hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("legacy review history damaged: %+v", hist)
	}
}

// TestReviewHistoryFailureThenRepairKeepsHistory proves a refused query is
// fully read-only: once the declaration is whole again the exact stored
// history — current status, version, every revision in ascending order and
// the original conclusion with its evidence — comes back unchanged, so the
// failure neither dropped nor rewrote any archived content.
func TestReviewHistoryFailureThenRepairKeepsHistory(t *testing.T) {
	dir := setupHistoryCorruptArchive(t)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s2", "op2", "withdrew", ReviewStatusUnreviewed, 1))
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "s3", "op3", "false alarm", ReviewStatusFalsePositive, 2))

	rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertHistoryRefused(t, dir, "1", "0xa", "0xv", "sandwich", BuiltinVersionID, "multiplier")

	// Restore the declaration to exactly what the report archived.
	rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 2
	})
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatalf("repaired declaration must return history: %v", err)
	}
	if hist.Status != ReviewStatusFalsePositive || hist.Version != 3 || len(hist.Revisions) != 3 {
		t.Fatalf("stored history changed across the failed query: %+v", hist)
	}
	for i, rev := range hist.Revisions {
		if rev.Version != i+1 {
			t.Fatalf("revisions not in ascending version order: %+v", hist.Revisions)
		}
	}
	if hist.Original == nil || hist.Original.Version != BuiltinVersion() ||
		hist.Original.Finding.TxHash != "0xv" || len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("original conclusion or evidence changed: %+v", hist.Original)
	}
}
