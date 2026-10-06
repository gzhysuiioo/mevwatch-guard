package mevwatch

// Regression coverage for `compare` (Compare) against an archived block
// whose saved rule-version declaration has decayed since the report was
// written. Comparing a block must first prove the complete version
// declaration the block archived — the same integrity check a standalone
// report query runs — before any comparison result is returned. A legal
// candidate version cannot carry a damaged historical declaration into the
// comparison: a missing or null parameter must never come back as a zero
// value, a null or missing id must never be explained as the built-in
// rules, and historical parameters must never be completed from the
// currently enabled or a same-id registered version. Only an old-format
// record with no version key at all keeps the built-in interpretation.
// The compare is read-only: success or failure leaves the archive exactly
// as it was, an unknown block stays ErrUnknownBlock, and an unknown or
// corrupt candidate version keeps its existing error behaviour.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertCompareRefused runs one failing Compare against an intact candidate
// and pins the failure shape the compare command relies on:
// ErrCorruptVersion wrapping the cause, never an unknown-block or
// unknown-version misread, naming the target chain and block plus every
// required extra substring (the readable saved id and the offending rule
// or field), returning no result and leaving the archive byte-identical.
func assertCompareRefused(t *testing.T, dir, chain, hash, candidate string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	result, err := Compare(dir, chain, hash, candidate)
	if err == nil {
		t.Fatalf("corrupt historical declaration compared successfully: %+v", result)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt historical declaration misreported as unknown block/version: %v", err)
	}
	msg := err.Error()
	for _, sub := range append([]string{chain, hash}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed compare changed the archive")
	}
	// Failing again fails the same way: the refusal never repairs the
	// declaration, and no comparison JSON is ever produced.
	if _, err := Compare(dir, chain, hash, candidate); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second compare did not fail the same way: %v", err)
	}
}

// TestCompareCorruptHistoricalVersionRefused runs the full corruption
// matrix against the declaration embedded in the archived block (the
// registered versions section is left intact): every way the saved
// document can stop satisfying the registration rules must fail the whole
// compare with ErrCorruptVersion — even though the requested candidate
// "twin" is intact and the registry copy of the same id is intact too —
// naming chain, block, the saved id and the offending rule or field.
func TestCompareCorruptHistoricalVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			// The candidate is intact on purpose: a legal candidate must not
			// let the damaged historical declaration take part.
			assertCompareRefused(t, dir, "1", "0xblk", "twin", "candC", tc.wantErr)
		})
	}
}

// TestCompareNullAndEmptyHistoricalVersionCorrupt pins the exact misread
// being fixed: a written version:null used to decode into the built-in
// explanation, and {} or an incomplete object decoded into silently zeroed
// parameters. All must fail as corruption even when the candidate is
// legal; only a wholly missing version key is the legacy built-in shape.
func TestCompareNullAndEmptyHistoricalVersionCorrupt(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"null", nil},
		{"empty object", map[string]any{}},
		{"incomplete object", map[string]any{"id": "candC"}},
		{"non-object number", 5},
		{"non-object string builtin", "builtin"},
		{"array", []any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xblk", tc.value)
			assertCompareRefused(t, dir, "1", "0xblk", "twin")
		})
	}
}

// TestCompareBuiltinHistoricalIDDoesNotBypassValidation proves an
// embedded id of "builtin" names the same saved declaration as any other
// id and is validated in full: a complete built-in declaration is
// compared normally, while a damaged one is refused as corruption rather
// than auto-replaced by the in-code built-in rules.
func TestCompareBuiltinHistoricalIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	result, err := Compare(dir, "1", "0xblk", "twin")
	if err != nil {
		t.Fatalf("a complete builtin-id historical declaration must compare: %v", err)
	}
	if result.OriginalVersion != BuiltinVersion() {
		t.Fatalf("original version = %+v, want builtin parameters", result.OriginalVersion)
	}

	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertCompareRefused(t, dir, "1", "0xblk", "twin", BuiltinVersionID, "multiplier")
}

// TestCompareDuplicateFieldsInHistoricalVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling
// that name the same field. The compare must refuse even when both values
// agree; the raw bytes are patched directly because a JSON map cannot
// hold two keys.
func TestCompareDuplicateFieldsInHistoricalVersionRefused(t *testing.T) {
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
			// The first candC declaration in the file is the one embedded in
			// the record (records precede the versions registry).
			versionsAt := strings.Index(text, `"versions":`)
			if versionsAt < 0 {
				t.Fatal("versions section not found")
			}
			at := strings.Index(text[:versionsAt], `"id": "candC"`)
			if at < 0 {
				t.Fatal("record's embedded candC declaration not found")
			}
			anchor := `"severity": 4,`
			fieldAt := strings.Index(text[at:versionsAt], anchor)
			if fieldAt < 0 {
				t.Fatal("severity field not found in embedded declaration")
			}
			pos := at + fieldAt
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			result, err := Compare(dir, "1", "0xblk", "twin")
			if err == nil {
				t.Fatalf("duplicate-field historical declaration compared: %+v", result)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed compare repaired the duplicate field")
			}
		})
	}
}

// TestCompareExplicitlyDisabledHistoricalRulesAccepted proves
// enabled:false is a legal saved off state on the historical side too: a
// report archived with both rules off but carrying complete parameters is
// compared normally, while a disabled rule that lost a parameter is still
// corrupt.
func TestCompareExplicitlyDisabledHistoricalRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	result, err := Compare(dir, "1", "0xblk", "twin")
	if err != nil {
		t.Fatalf("an explicitly disabled, complete historical declaration must compare: %v", err)
	}
	if result.OriginalVersion.ID != "off" ||
		result.OriginalVersion.Rules.Sandwich.Enabled ||
		result.OriginalVersion.Rules.Displacement.Enabled {
		t.Fatalf("saved off state not returned: %+v", result.OriginalVersion)
	}
	// The stored original conclusions are exactly the archived ones; the
	// historical side is never re-detected.
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "displacement" {
		t.Fatalf("archived original conclusions damaged: %+v", result.OriginalFindings)
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", offBroken)
	assertCompareRefused(t, dir, "1", "0xblk", "twin", "off", "severity")
}

// TestCompareHistoricalParametersComeOnlyFromReport proves the historical
// side is explained by the declaration the report archived: damaging the
// same-id registry entry or enabling another version neither changes nor
// blocks an intact saved report, and a complete declaration whose id was
// never registered needs no registry backing. Conversely an intact
// registry cannot rescue a corrupt report copy (covered by the matrix
// above).
func TestCompareHistoricalParametersComeOnlyFromReport(t *testing.T) {
	// Records archived under archA, liveB enabled; damage only the
	// registered archA entry. The report's own intact embedded declaration
	// must still drive the historical side byte for byte.
	dir := setupCompareArchive(t)
	rewriteStoredVersion(t, dir, "archA", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	result, err := Compare(dir, "1", "0xblk", "candC")
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %v", err)
	}
	if want := mustRuleVersion(t, archivedVersionSpec); result.OriginalVersion != want {
		t.Fatalf("historical side borrowed registry parameters: %+v, want %+v", result.OriginalVersion, want)
	}

	// A complete report-only id the registry never carried compares too.
	dir2 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", stray)
	r2, err := Compare(dir2, "1", "0xblk", "twin")
	if err != nil {
		t.Fatalf("a complete self-contained historical declaration must not need registry backing: %v", err)
	}
	if r2.OriginalVersion.ID != "never-registered" ||
		r2.OriginalVersion.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved historical parameters not returned: %+v", r2.OriginalVersion)
	}
	if _, err := GetVersion(dir2, "never-registered"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("the report-only id must not have been inserted into the registry: %v", err)
	}
}

// TestCompareCorruptHistoryRefusedWithNoSwapsOrFindings proves validation
// cannot be skipped by returning an empty comparison: a block with no
// swaps, and a block whose swaps produce no original conclusion, both
// fail the whole compare when their saved declaration is damaged, instead
// of coming back as an empty success.
func TestCompareCorruptHistoryRefusedWithNoSwapsOrFindings(t *testing.T) {
	// No swaps at all.
	emptyDir := t.TempDir()
	register(t, emptyDir, candidateVersionSpec)
	register(t, emptyDir, twinVersionSpec)
	emptyInput := `{"chainId":"1","blockHash":"0xempty","blockNumber":3,"swaps":[]}`
	if _, err := ReplayWithVersion(strings.NewReader(emptyInput), emptyDir, "candC"); err != nil {
		t.Fatal(err)
	}
	replaceStoredReportVersion(t, emptyDir, "1", "0xempty", map[string]any{"id": "candC"})
	assertCompareRefused(t, emptyDir, "1", "0xempty", "twin")

	// Swaps present but no conclusion under either declaration: 11 vs 10
	// beats neither candC's multiplier 2 nor twin's.
	flatDir := t.TempDir()
	register(t, flatDir, candidateVersionSpec)
	register(t, flatDir, twinVersionSpec)
	flatInput := cmpBlockLine("1", "0flat", 4,
		cmpSwap("0f", "p1", "w", 11, 0),
		cmpSwap("0v", "p1", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(flatInput), flatDir, "candC"); err != nil {
		t.Fatal(err)
	}
	damaged := map[string]any{
		"id": "candC",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 4},
		},
	}
	replaceStoredReportVersion(t, flatDir, "1", "0flat", damaged)
	assertCompareRefused(t, flatDir, "1", "0flat", "twin", "candC", "multiplier")
}

// TestCompareCorruptHistoryCandidateAndBlockErrorsDistinct pins the
// boundaries once the historical side is validated: a corrupt historical
// declaration is reported even against an unknown-block-free intact
// candidate; an unknown block and an unknown/corrupt candidate keep their
// existing behaviour, including when a different record in the archive is
// corrupt.
func TestCompareCorruptHistoryCandidateAndBlockErrorsDistinct(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	// The target block fails as corruption against every intact candidate.
	for _, id := range []string{"twin", BuiltinVersionID} {
		if _, err := Compare(dir, "1", "0xblk", id); !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("Compare under intact %s error = %v, want ErrCorruptVersion", id, err)
		}
	}
	// The historical declaration is proved first, before the candidate is
	// even resolved: with the history corrupt, an unknown candidate cannot
	// mask that as a plain unknown-version failure either.
	if _, err := Compare(dir, "1", "0xblk", "ghost"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt history checked first, error = %v, want ErrCorruptVersion", err)
	}
	// ...while an unknown block is settled before the record is read and
	// stays an unknown-block failure.
	if _, err := Compare(dir, "1", "0xghost", "twin"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block error = %v, want ErrUnknownBlock", err)
	}

	// With the historical declaration intact, an unknown candidate keeps
	// exactly its existing unknown-version behaviour.
	intact := setupCorruptCompareArchive(t)
	if _, err := Compare(intact, "1", "0xblk", "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown candidate against intact history error = %v, want ErrUnknownVersion", err)
	}
}

// TestCompareLegacyRecordStillBuiltinAfterFix re-pins the one carve-out
// end to end through Compare's raw-record path: a record with no version
// key at all is still explained by the built-in rules, with stored
// conclusions and swap evidence intact.
func TestCompareLegacyRecordStillBuiltinAfterFix(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[` +
		`{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"u","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"u","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	register(t, dir, twinVersionSpec)
	result, err := Compare(dir, "1", "0old", "twin")
	if err != nil {
		t.Fatalf("legacy record must compare under builtin: %v", err)
	}
	if !reflect.DeepEqual(result.OriginalVersion, BuiltinVersion()) {
		t.Fatalf("original version = %+v, want builtin", result.OriginalVersion)
	}
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "sandwich" {
		t.Fatalf("legacy findings damaged: %+v", result.OriginalFindings)
	}
	if len(result.Swaps) != 3 {
		t.Fatalf("legacy swap evidence damaged: %+v", result.Swaps)
	}
}
