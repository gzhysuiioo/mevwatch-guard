package mevwatch

// Regression coverage for re-importing a block whose content is identical
// to the archived record. Such a run used to hand back the archived report
// without the integrity proof a standalone report query (Query) performs:
// a saved "version":null decoded into the built-in explanation and an
// incomplete declaration decoded into silently zeroed parameters, as long
// as the version this replay selected was itself legal. An identical
// reimport must now hold every old report it returns to exactly the
// standard of Query: prove the saved declaration from its raw bytes, fail
// the whole batch as ErrCorruptVersion (never unknown block or unknown
// version) with no reports, no new records and no change to the archive,
// while an intact old report comes back exactly as saved — not
// re-detected, not completed from the enabled or same-id registered
// version, and not requiring its historical id to stay registered.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// reimportCorruptLine is the exact line archived by
// setupCorruptCompareArchive (chain 1, block 0xblk, height 7, the two
// same-pool swaps), so importing it is an identical re-import of the one
// archived record rather than a content conflict.
var reimportCorruptLine = cmpBlockLine("1", "0xblk", 7,
	cmpSwap("0xf", "p1", "w", 40, 0),
	cmpSwap("0xv", "p1", "u", 10, 1),
)

// assertReimportRefused runs one identical re-import and pins the failure
// shape: a LineError carrying the input line, wrapping ErrCorruptVersion
// (never an unknown block/version), naming the chain and block plus every
// required extra substring, returning no reports and leaving the archive
// byte-identical; a second attempt fails the same read-only way.
func assertReimportRefused(t *testing.T, dir, input string, line int, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	reports, err := ReplayWithVersion(strings.NewReader(input), dir, "candC")
	if err == nil {
		t.Fatalf("corrupt old report returned successfully: %+v", reports)
	}
	if reports != nil {
		t.Fatalf("a refused replay must return no reports, got %+v", reports)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt old report misreported as unknown block/version: %v", err)
	}
	var le *LineError
	if !errors.As(err, &le) {
		t.Fatalf("error %v is not a LineError", err)
	}
	if le.Line != line {
		t.Fatalf("error line = %d, want %d (%v)", le.Line, line, err)
	}
	msg := err.Error()
	for _, sub := range append([]string{"1", "0xblk"}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused replay changed the archive:\nbefore=%s\nafter =%s", before, after)
	}
	if _, rerr := ReplayWithVersion(strings.NewReader(input), dir, "candC"); !errors.Is(rerr, ErrCorruptVersion) {
		t.Fatalf("second reimport did not fail the same way: %v", rerr)
	}
}

// TestReimportCorruptSavedVersionRefused runs the full corruption matrix
// against the version declaration embedded in the identical re-imported
// record while the same-id registered entry stays intact: every way the
// saved document can stop satisfying the registration rules must fail the
// whole replay as corruption of that report, naming the readable saved id
// and the offending rule or field — the legality of this run's selected
// version (candC, intact in the registry) cannot pardon it.
func TestReimportCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertReimportRefused(t, dir, reimportCorruptLine, 1, "candC", tc.wantErr)

			// The damaged copy belongs to the record: the intact registered
			// candC neither rescues the report nor gets damaged itself.
			if _, err := GetVersion(dir, "candC"); err != nil {
				t.Fatalf("registry candC must stay intact: %v", err)
			}
			if _, err := Query(dir, "1", "0xblk"); !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("standalone report query must refuse the same record: %v", err)
			}
		})
	}
}

// TestReimportNullAndEmptySavedVersionCorrupt pins the exact misread being
// fixed: version:null used to come back from a reimport explained as the
// built-in rules, and {} or an incomplete object as zeroed parameters.
// Everything actually saved fails; only a wholly missing version key is
// the legacy built-in shape (covered separately).
func TestReimportNullAndEmptySavedVersionCorrupt(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"null", nil},
		{"empty object", map[string]any{}},
		{"incomplete object", map[string]any{"id": "candC"}},
		{"non-object number", 5},
		{"non-object string", "builtin"},
		{"array", []any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xblk", tc.value)
			// The id may be unreadable for null/{}/scalars; the message must
			// still name the input line, chain and block and never call this
			// an unknown block/version.
			assertReimportRefused(t, dir, reimportCorruptLine, 1)
		})
	}
}

// TestReimportBuiltinIDDoesNotBypassValidation proves an id of "builtin"
// names the same saved declaration as any other id and is validated in
// full on reimport: a complete built-in declaration is returned, a damaged
// one is refused as corruption rather than auto-replaced by the in-code
// builtin.
func TestReimportBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	reports, err := ReplayWithVersion(strings.NewReader(reimportCorruptLine), dir, "candC")
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must return on reimport: %v", err)
	}
	if len(reports) != 1 || reports[0].Version != BuiltinVersion() {
		t.Fatalf("version = %+v, want builtin parameters", reports)
	}

	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertReimportRefused(t, dir, reimportCorruptLine, 1, BuiltinVersionID, "multiplier")
}

// patchRecordVersionDuplicate inserts a repeated field into the archived
// record's embedded version declaration by patching raw bytes (a JSON map
// cannot hold two keys), the same way the standalone query test does. The
// record precedes the versions registry in the archive file.
func patchRecordVersionDuplicate(t *testing.T, dir, repeated string) {
	t.Helper()
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
	patched := text[:pos] + repeated + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestReimportDuplicateFieldsInSavedVersionRefused covers decay the writer
// could never have produced: a repeated field in the saved declaration,
// including an escaped spelling and a case-only spelling that name the
// same field, even with identical values.
func TestReimportDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			patchRecordVersionDuplicate(t, dir, dup.field)
			before := readArchiveFile(t, dir)

			reports, err := ReplayWithVersion(strings.NewReader(reimportCorruptLine), dir, "candC")
			if err == nil {
				t.Fatalf("duplicate-field declaration returned: %+v", reports)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if reports != nil {
				t.Fatalf("refused replay returned reports: %+v", reports)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused replay repaired the duplicate field")
			}
		})
	}
}

// TestReimportExplicitlyDisabledRulesAccepted proves enabled:false is a
// legal saved off state for a reimported report, while a disabled rule
// that lost a parameter is still corrupt.
func TestReimportExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	reports, err := ReplayWithVersion(strings.NewReader(reimportCorruptLine), dir, "candC")
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must return: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != "off" ||
		reports[0].Version.Rules.Sandwich.Enabled || reports[0].Version.Rules.Displacement.Enabled {
		t.Fatalf("saved off state not returned: %+v", reports[0].Version)
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", offBroken)
	assertReimportRefused(t, dir, reimportCorruptLine, 1, "off", "severity")
}

// TestReimportCorruptOldBlockFailsBatchBothOrders is the all-or-nothing
// guarantee: with a corrupt old block and a genuinely new block in the
// same file, the whole replay fails wherever the old block sits — no
// reports at all, the new block is never archived, and the existing
// archive stays byte-identical. The LineError names the old block's input
// line in either ordering.
func TestReimportCorruptOldBlockFailsBatchBothOrders(t *testing.T) {
	cases := []struct {
		name  string
		input string
		line  int
	}{
		{"old block then new block", reimportCorruptLine + "\n" + replayCorruptInput, 1},
		{"new block then old block", replayCorruptInput + "\n" + reimportCorruptLine, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				delete(storedRule(t, ver, "displacement"), "multiplier")
			})
			before := readArchiveFile(t, dir)

			reports, err := ReplayWithVersion(strings.NewReader(tc.input), dir, "candC")
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if reports != nil {
				t.Fatalf("partial success leaked reports: %+v", reports)
			}
			var le *LineError
			if !errors.As(err, &le) || le.Line != tc.line {
				t.Fatalf("error = %v, want LineError at line %d", err, tc.line)
			}
			if !strings.Contains(err.Error(), "0xblk") || !strings.Contains(err.Error(), "multiplier") {
				t.Fatalf("error must name the old block and field: %v", err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed batch changed the archive")
			}
			if _, err := Query(dir, "1", "0xnew"); !errors.Is(err, ErrUnknownBlock) {
				t.Fatalf("new block archived by a refused batch: %v", err)
			}
		})
	}
}

// TestReimportIntactReportReturnedAsSaved proves the legitimate reimport
// contract survives the new proof: the original conclusions, evidence,
// swap count and full version parameters come back unchanged, the block is
// not re-detected, nothing is borrowed from the currently enabled or a
// same-id registered version, and the historical id need not even remain
// registered.
func TestReimportIntactReportReturnedAsSaved(t *testing.T) {
	// Fixture: record archived under archA while liveB is enabled.
	dir := setupCompareArchive(t)
	identical := strings.SplitN(compareFixtureInput(), "\n", 2)[0]
	want, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}

	reports, rerr := Replay(strings.NewReader(identical), dir)
	if rerr != nil {
		t.Fatalf("identical reimport failed: %v", rerr)
	}
	if len(reports) != 1 || !reflect.DeepEqual(reports[0], want) {
		t.Fatalf("reimport report = %+v, want the archived report %+v", reports, want)
	}
	if reports[0].Version.ID != "archA" || reports[0].SwapCount != 13 || len(reports[0].Findings) != 3 {
		t.Fatalf("reimport did not return the saved report: %+v", reports[0])
	}

	// The enabled liveB must not leak into the reimported report.
	if _, enabled, err := ListVersions(dir); err != nil || enabled != "liveB" {
		t.Fatalf("setup: enabled = %q err=%v", enabled, err)
	}

	// Damage the same-id registry entry: the record's own intact embedded
	// declaration is unaffected and still returned, with no parameters
	// pulled from the registry.
	rewriteStoredVersion(t, dir, "archA", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	reports2, rerr := Replay(strings.NewReader(identical), dir)
	if rerr != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %v", rerr)
	}
	if !reflect.DeepEqual(reports2[0], want) {
		t.Fatalf("reimport borrowed registry parameters: %+v\nwant %+v", reports2[0], want)
	}

	// A complete self-contained declaration whose id was never registered
	// is returned as saved rather than refused.
	dir2 := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", stray)
	reports3, rerr := ReplayWithVersion(strings.NewReader(reimportCorruptLine), dir2, "candC")
	if rerr != nil {
		t.Fatalf("a complete report-only declaration must not need registry backing: %v", rerr)
	}
	if reports3[0].Version.ID != "never-registered" ||
		reports3[0].Version.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved parameters not returned: %+v", reports3[0].Version)
	}
	// The original findings are the stored candC displacement severity 4,
	// not re-judged under the stray declaration.
	if len(reports3[0].Findings) != 1 || reports3[0].Findings[0].Kind != "displacement" ||
		reports3[0].Findings[0].Severity != 4 {
		t.Fatalf("old report was re-detected under the saved parameters: %+v", reports3[0].Findings)
	}
}

// TestReimportAppendingNewBlockPreservesOldRecordBytes proves the raw-record
// read/write path keeps an already stored record byte for byte when the
// batch also commits a genuinely new block; only the one new record is
// appended.
func TestReimportAppendingNewBlockPreservesOldRecordBytes(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := mustReplayDoc(t, filepath.Join(dir, archiveFileName))

	reports, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "candC")
	if err != nil {
		t.Fatalf("new block replay failed: %v", err)
	}
	if len(reports) != 1 || reports[0].BlockHash != "0xnew" {
		t.Fatalf("unexpected reports: %+v", reports)
	}

	after := mustReplayDoc(t, filepath.Join(dir, archiveFileName))
	if !reflect.DeepEqual(before.Records, after.Records[:len(before.Records)]) {
		t.Fatalf("existing record rewritten:\nbefore=%s\nafter =%s", before.Records, after.Records)
	}
	if len(after.Records) != len(before.Records)+1 {
		t.Fatalf("records = %d, want exactly one appended", len(after.Records))
	}
}

// TestReimportLegacyRecordWithoutVersionUsesBuiltin proves the one legacy
// carve-out on the reimport path: a record with no version key at all
// returns under the built-in rules with its stored conclusions, evidence
// and swap count, stays byte-identical, and a new block appended in the
// same run never retrofits a version onto it.
func TestReimportLegacyRecordWithoutVersionUsesBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacyLine := cmpBlockLine("1", "0old", 5,
		cmpSwap("0f", "p1", "bot", 90, 0),
		cmpSwap("0v", "p1", "user", 10, 1),
		cmpSwap("0b", "p1", "bot", 80, 2),
	)
	// In/Out differ from the string fixture below, so write the record by
	// hand with the exact swaps the line carries.
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[{"TxHash":"0f","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)

	reports, err := Replay(strings.NewReader(legacyLine), dir)
	if err != nil {
		t.Fatalf("legacy reimport failed: %v", err)
	}
	if len(reports) != 1 || reports[0].Version != BuiltinVersion() {
		t.Fatalf("legacy reimport must return builtin: %+v", reports)
	}
	if reports[0].SwapCount != 3 || len(reports[0].Findings) != 1 ||
		reports[0].Findings[0].Kind != "sandwich" || reports[0].Findings[0].Severity != 3 ||
		len(reports[0].Findings[0].Evidence) != 3 {
		t.Fatalf("legacy report damaged: %+v", reports[0])
	}
	// Identical-only replay writes nothing.
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("legacy-only replay rewrote the archive:\nbefore=%s\nafter =%s", before, after)
	}

	// Appending a new block leaves the legacy record exactly as stored.
	if _, err := Replay(strings.NewReader(replayCorruptInput), dir); err != nil {
		t.Fatalf("appending after legacy record failed: %v", err)
	}
	doc := mustReplayDoc(t, filepath.Join(dir, archiveFileName))
	if len(doc.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(doc.Records))
	}
	var first queryRecord
	if err := json.Unmarshal(doc.Records[0], &first); err != nil {
		t.Fatal(err)
	}
	if len(first.Version) != 0 {
		t.Fatalf("legacy record was retrofitted with a version: %s", first.Version)
	}
}
