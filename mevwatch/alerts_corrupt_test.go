package mevwatch

// Regression coverage for alert generation over archived reports whose
// saved rule-version declaration has decayed. Generation must prove every
// in-range report's declaration with the same integrity rules a report
// query applies — before any processing record is produced — and fail the
// whole run with ErrCorruptVersion otherwise: no partial result, no new
// records for the intact blocks, no change to reports, existing records
// or suppressions. Only a record with no version key at all keeps the
// legacy built-in interpretation.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertGenerateRefused runs one failing GenerateAlerts over the whole
// archive and pins the shape the command relies on: ErrCorruptVersion
// wrapping the cause, naming the target chain and block plus every
// required extra substring, no records returned, and the archive
// byte-identical afterwards.
func assertGenerateRefused(t *testing.T, dir, chain string, start, end uint64, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	records, err := GenerateAlerts(dir, chain, "ops", start, end, 1)
	if err == nil {
		t.Fatalf("corrupt archive generated records: %+v", records)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt report misreported as unknown block/version: %v", err)
	}
	msg := err.Error()
	for _, sub := range want {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if records != nil {
		t.Fatalf("failed generation returned records: %+v", records)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed generation changed the archive")
	}
	// The failure is not a write-side repair: generating again fails the
	// same way.
	if _, err := GenerateAlerts(dir, chain, "ops", start, end, 1); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second generation did not fail the same way: %v", err)
	}
}

// TestGenerateCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the archived report: every way the
// saved document can stop satisfying the registration rules must fail the
// whole generation with ErrCorruptVersion, naming chain, block, the saved
// id and the offending rule or field.
func TestGenerateCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertGenerateRefused(t, dir, "1", 0, 100, "1", "0xblk", "candC", tc.wantErr)
		})
	}
}

// TestGenerateNullAndEmptySavedVersionCorrupt pins the exact misread being
// fixed: version:null used to decode into the built-in explanation, and {}
// or an incomplete object decoded into silently zeroed parameters. All of
// them must fail as corruption; only a wholly missing version key is the
// legacy built-in shape.
func TestGenerateNullAndEmptySavedVersionCorrupt(t *testing.T) {
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
			assertGenerateRefused(t, dir, "1", 0, 100, "1", "0xblk")
		})
	}
}

// TestGenerateCorruptReportWithoutMatchingFindingsStillFails proves the
// integrity check is not tied to whether the decayed report would have
// produced a record: a corrupt declaration fails the whole generation even
// when the report has no conclusions at all, when every conclusion is
// below the threshold, or when every conclusion was already processed —
// and the intact block's new records are not saved either.
func TestGenerateCorruptReportWithoutMatchingFindingsStillFails(t *testing.T) {
	// secondBlock is a clean block on the same chain at height 20 whose
	// sandwich conclusion would produce a record if generation succeeded.
	const secondBlock = `{"chainId":"1","blockHash":"0xok","blockNumber":20,` +
		`"swaps":[` +
		`{"TxHash":"0xf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xv","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0+k","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2}]}`

	setup := func(t *testing.T) string {
		dir := setupCorruptCompareArchive(t) // 0xblk at height 7, displacement severity 4
		mustReplay(t, dir, secondBlock)
		return dir
	}
	corrupt := func(t *testing.T, dir string) {
		t.Helper()
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
	}
	assertNoRecords := func(t *testing.T, dir string) {
		t.Helper()
		history, err := AlertHistory(dir, "1", "ops", 0, 100)
		if err != nil {
			t.Fatalf("AlertHistory: %v", err)
		}
		if len(history) != 0 {
			t.Fatalf("failed generation saved records: %+v", history)
		}
	}

	t.Run("no findings in corrupt report", func(t *testing.T) {
		dir := setup(t)
		// Strip the conclusions off the report before corrupting it: even
		// with nothing to process, the decayed declaration fails the run.
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(map[string]any) {})
		stripFindings(t, dir, "0xblk")
		corrupt(t, dir)
		assertGenerateRefused(t, dir, "1", 0, 100, "0xblk")
		assertNoRecords(t, dir)
	})

	t.Run("findings below threshold", func(t *testing.T) {
		dir := setup(t)
		corrupt(t, dir)
		// Threshold 5 is above the archived displacement severity 4, so the
		// decayed report would produce no record — the run still fails.
		before := readArchiveFile(t, dir)
		if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 5); !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("got %v, want ErrCorruptVersion", err)
		}
		if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatal("failed generation changed the archive")
		}
		assertNoRecords(t, dir)
	})

	t.Run("findings already processed", func(t *testing.T) {
		dir := setup(t)
		// Process every conclusion while the declarations are intact, then
		// corrupt one report: a repeated generation has nothing new to do,
		// but the decayed declaration still fails it.
		if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
			t.Fatalf("initial GenerateAlerts: %v", err)
		}
		corrupt(t, dir)
		assertGenerateRefused(t, dir, "1", 0, 100, "0xblk")
		history, err := AlertHistory(dir, "1", "ops", 0, 100)
		if err != nil {
			t.Fatalf("AlertHistory: %v", err)
		}
		if len(history) != 2 {
			t.Fatalf("pre-existing records changed: %+v", history)
		}
	})

	t.Run("intact block records not committed", func(t *testing.T) {
		dir := setup(t)
		corrupt(t, dir)
		// 0xok's sandwich meets the threshold and was never processed, but
		// the run fails on 0xblk first and commits nothing.
		assertGenerateRefused(t, dir, "1", 0, 100, "0xblk")
		assertNoRecords(t, dir)
	})
}

// stripFindings removes the conclusions of one archived report without
// touching anything else.
func stripFindings(t *testing.T, dir, hash string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["records"].([]any) {
		rec := r.(map[string]any)
		if rec["blockHash"] == hash {
			rec["findings"] = []any{}
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("record %s not found", hash)
}

// TestGenerateLegacyRecordWithoutVersionKey proves only a wholly absent
// version key keeps the built-in interpretation: the generation succeeds
// and the record carries the built-in parameters.
func TestGenerateLegacyRecordWithoutVersionKey(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	dropVersionKey(t, dir, "0xblk")
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("legacy record must generate: %v", err)
	}
	if len(got) != 1 || got[0].Version != BuiltinVersion() {
		t.Fatalf("legacy record not explained as builtin: %+v", got)
	}
}

// dropVersionKey removes the version key from one archived record
// entirely, producing the legacy pre-version shape.
func dropVersionKey(t *testing.T, dir, hash string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["records"].([]any) {
		rec := r.(map[string]any)
		if rec["blockHash"] == hash {
			delete(rec, "version")
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("record %s not found", hash)
}

// TestGenerateBuiltinIDDoesNotBypassValidation proves an id of "builtin"
// is validated like any other saved declaration: a complete one generates
// normally, a damaged one fails as corruption rather than being replaced
// by the in-code builtin.
func TestGenerateBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatalf("a complete builtin-id declaration must generate: %v", err)
	}

	dir = setupCorruptCompareArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertGenerateRefused(t, dir, "1", 0, 100, BuiltinVersionID, "multiplier")
}

// TestGenerateDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including a case-only spelling and an escaped spelling
// that name the same field — rejected even when both values agree. The
// raw bytes are patched directly because a JSON map cannot hold two keys.
func TestGenerateDuplicateFieldsInSavedVersionRefused(t *testing.T) {
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
			// The first candC declaration in the file is the one embedded
			// in the record (records precede the versions registry).
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
			_, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
			if err == nil {
				t.Fatal("duplicate-field declaration generated records")
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatal("failed generation repaired the duplicate field")
			}
		})
	}
}

// TestGenerateDisabledAndUnregisteredDeclarationsAccepted proves a legal
// declaration is used exactly as saved: an explicit enabled:false is a
// legal off state, and the saved id need not still be registered — the
// record carries the declaration's own complete parameters, never values
// pulled from the enabled or a same-id registered version.
func TestGenerateDisabledAndUnregisteredDeclarationsAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	ghost := map[string]any{
		"id": "ghost",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", ghost)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("unregistered but complete declaration must generate: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	v := got[0].Version
	if v.ID != "ghost" || v.Rules.Sandwich.Enabled ||
		!v.Rules.Displacement.Enabled || v.Rules.Displacement.Severity != 5 ||
		v.Rules.Displacement.Multiplier != 100 {
		t.Fatalf("record must carry the saved declaration's own parameters: %+v", v)
	}

	// The same-id registered version's parameters are never substituted
	// for the saved ones: rewrite the embedded declaration's displacement
	// severity and confirm the record keeps the saved value.
	dir = setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = 2
	})
	got, err = GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("saved declaration must generate: %v", err)
	}
	if len(got) != 1 || got[0].Version.Rules.Displacement.Severity != 2 {
		t.Fatalf("record must use the saved parameters, not the registry's: %+v", got)
	}
}

// TestGenerateCorruptVersionOutsideRangeIgnored proves the integrity check
// covers exactly the reports the generation draws on: a decayed
// declaration outside the height range or on another chain does not block
// the run, and the corrupt document is written back byte for byte.
func TestGenerateCorruptVersionOutsideRangeIgnored(t *testing.T) {
	dir := setupCorruptCompareArchive(t) // 0xblk at height 7
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)

	// A range below the corrupt report sees an empty result, not a failure.
	got, err := GenerateAlerts(dir, "1", "ops", 8, 100, 1)
	if err != nil {
		t.Fatalf("out-of-range corrupt report must not block generation: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want no records", got)
	}
	// Another chain's range is equally unaffected.
	if _, err := GenerateAlerts(dir, "2", "ops", 0, 100, 1); err != nil {
		t.Fatalf("other chain must not see the corrupt report: %v", err)
	}
	// The corrupt declaration survived the successful runs untouched.
	text := string(readArchiveFile(t, dir))
	if !strings.Contains(text, `"version": null`) {
		t.Fatal("successful generation rewrote the corrupt declaration")
	}
}
