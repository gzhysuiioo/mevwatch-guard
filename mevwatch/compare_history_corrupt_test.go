package mevwatch

// Regression coverage for the historical side of `compare`: when a user
// compares an archived block against a candidate rule version, the
// declaration the block archived must first pass the exact integrity
// proof a `report` query enforces before any comparison is returned. A
// legal candidate can never make a damaged historical declaration
// participate: a written null used to be explained as the built-in rules
// and an incomplete declaration used to compare under silently zeroed
// parameters. Only an old-format record with no version key at all keeps
// the built-in interpretation. On corruption the whole comparison fails
// with ErrCorruptVersion — no partial result, even when the block has no
// swaps or an empty findings array. The check is read-only.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertCompareRefused runs one failing Compare and pins the failure
// shape: ErrCorruptVersion wrapping the cause, never an unknown-block or
// unknown-version misread, naming the target chain and block plus every
// required extra substring, leaving the archive byte-identical.
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
	// No partial result is ever returned, and a second attempt fails the
	// same way: the declaration is not repaired or completed.
	if _, err := Compare(dir, chain, hash, candidate); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second compare did not fail the same way: %v", err)
	}
}

// TestCompareCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the compared report (the
// registered versions section and the candidate stay intact): every way
// the saved document can stop satisfying the registration rules must
// fail the whole comparison, naming chain, block, the readable saved id
// and the offending rule or field.
func TestCompareCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			// The candidate (twin) is itself intact; its legality must not
			// rescue the damaged historical declaration.
			assertCompareRefused(t, dir, "1", "0xblk", "twin", "candC", tc.wantErr)
		})
	}
}

// TestCompareNullAndEmptySavedVersionCorrupt pins the exact misread
// being fixed: version:null used to leave the decoded version pointer
// nil and be explained as the built-in rules, and {} or an incomplete
// object compared under zeroed parameters. All of these fail; only a
// wholly missing version key is the legacy built-in shape.
func TestCompareNullAndEmptySavedVersionCorrupt(t *testing.T) {
	cases := []struct {
		name  string
		value any
		// idReachable says whether the error can still name a saved id.
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
			assertCompareRefused(t, dir, "1", "0xblk", "twin", want...)
		})
	}
}

// TestCompareBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestCompareBuiltinIDDoesNotBypassValidation(t *testing.T) {
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
		t.Fatalf("a complete builtin-id declaration must compare: %v", err)
	}
	if result.OriginalVersion != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin parameters", result.OriginalVersion)
	}

	// The same id with a missing field is corrupt and names "builtin"
	// rather than silently substituting it.
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

// TestCompareDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the
// saved declaration, including an escaped spelling and a case-only
// spelling that name the same field, even when both values agree. The
// two rules each declaring their own enabled/severity is not a repeat.
func TestCompareDuplicateFieldsInSavedVersionRefused(t *testing.T) {
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
			result, err := Compare(dir, "1", "0xblk", "twin")
			if err == nil {
				t.Fatalf("duplicate-field declaration compared: %+v", result)
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

// TestCompareExplicitlyDisabledRulesAccepted proves enabled:false is a
// legal historical off state, but a disabled rule still has to carry
// complete, in-range parameters.
func TestCompareExplicitlyDisabledRulesAccepted(t *testing.T) {
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
		t.Fatalf("an explicitly disabled, complete declaration must compare: %v", err)
	}
	if result.OriginalVersion.ID != "off" ||
		result.OriginalVersion.Rules.Sandwich.Enabled ||
		result.OriginalVersion.Rules.Displacement.Enabled {
		t.Fatalf("historical off state not carried: %+v", result.OriginalVersion)
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

// TestCompareCorruptSavedVersionEmptyAndNoSwapBlocks proves the
// historical proof cannot be skipped by an empty comparison: a block
// with no swaps and a block whose findings are empty both still fail
// outright when their saved declaration is damaged, never returning an
// empty diff.
func TestCompareCorruptSavedVersionEmptyAndNoSwapBlocks(t *testing.T) {
	t.Run("no swaps", func(t *testing.T) {
		dir := t.TempDir()
		register(t, dir, candidateVersionSpec)
		input := `{"chainId":"1","blockHash":"0empty","blockNumber":3,"swaps":[]}`
		if _, err := ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
			t.Fatal(err)
		}
		replaceStoredReportVersion(t, dir, "1", "0empty", nil)
		assertCompareRefused(t, dir, "1", "0empty", "candC")
	})

	t.Run("empty findings under both-off version", func(t *testing.T) {
		dir := t.TempDir()
		bothOff := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
		register(t, dir, bothOff)
		input := cmpBlockLine("1", "0quiet", 4,
			cmpSwap("0g0", "p", "w", 15, 0),
			cmpSwap("0g1", "p", "u", 10, 1),
		)
		if _, err := ReplayWithVersion(strings.NewReader(input), dir, "off"); err != nil {
			t.Fatal(err)
		}
		// Damage the declaration of the no-conclusion block.
		replaceStoredReportVersion(t, dir, "1", "0quiet", map[string]any{"id": "off"})
		assertCompareRefused(t, dir, "1", "0quiet", "off")
	})
}

// TestCompareUsesSavedParametersNotRegistry proves the historical side
// is explained by the declaration the report archived: a same-id
// registry entry is neither consulted nor able to complete the saved
// parameters, the enabled version never leaks in, and a saved id the
// registry never carried is still a valid explanation on its own.
func TestCompareUsesSavedParametersNotRegistry(t *testing.T) {
	// Damage the registered archA entry while the report's own embedded
	// copy stays intact: the comparison still shows archA's saved
	// parameters and borrows nothing from the registry.
	dir := setupCompareArchive(t)
	rewriteStoredVersion(t, dir, "archA", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	result, err := Compare(dir, "1", "0xblk", "twin")
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %v", err)
	}
	if want := mustRuleVersion(t, archivedVersionSpec); result.OriginalVersion != want {
		t.Fatalf("historical side borrowed registry parameters: %+v", result.OriginalVersion)
	}

	// Conversely, an intact registry cannot rescue a corrupt report:
	// damage only the report's own copy while the same-id registry entry
	// stays intact, and compare under a completely different intact
	// candidate.
	dir2 := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertCompareRefused(t, dir2, "1", "0xblk", "twin", "candC", "multiplier")

	// A complete declaration with an id the registry never carried is
	// valid on its own and needs no registry backing.
	dir3 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir3, "1", "0xblk", stray)
	r3, err := Compare(dir3, "1", "0xblk", "twin")
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if r3.OriginalVersion.ID != "never-registered" ||
		r3.OriginalVersion.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved historical parameters not carried: %+v", r3.OriginalVersion)
	}
}

// TestCompareHistoricalProofRunsBeforeCandidateResolution pins the
// ordering guarantee: with both the historical declaration and the
// candidate damaged, the failure is about the target block's historical
// declaration (chain, block and saved id named), not about the
// candidate — the stored report is proved before the candidate side is
// re-judged.
func TestCompareHistoricalProofRunsBeforeCandidateResolution(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = 0
	})
	_, err := Compare(dir, "1", "0xblk", "candC")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if !strings.Contains(err.Error(), "archived report for chain 1 block 0xblk") ||
		!strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "multiplier") {
		t.Fatalf("failure must identify the historical declaration, got %v", err)
	}
}

// TestCompareLegacyRecordStillBuiltin proves the single carve-out is
// unchanged by the fix: a record with no version key at all compares
// with the built-in rules on the historical side and its stored
// conclusions and swap evidence intact.
func TestCompareLegacyRecordStillBuiltin(t *testing.T) {
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
	register(t, dir, candidateVersionSpec)
	result, err := Compare(dir, "1", "0old", "candC")
	if err != nil {
		t.Fatalf("legacy record must compare under builtin: %v", err)
	}
	if result.OriginalVersion != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin", result.OriginalVersion)
	}
	if len(result.OriginalFindings) != 1 ||
		result.OriginalFindings[0].Kind != "sandwich" ||
		result.OriginalFindings[0].Severity != 3 {
		t.Fatalf("legacy findings damaged: %+v", result.OriginalFindings)
	}
	if len(result.Swaps) != 3 {
		t.Fatalf("legacy swap evidence damaged: %+v", result.Swaps)
	}
}
