package mevwatch

// Regression coverage for offline alert generation against an archived
// report whose saved rule-version declaration has decayed since the report
// was written. `alerts generate` must prove every in-range report's
// complete version declaration — a non-empty id, sandwich and displacement
// each with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100 — from its raw bytes before any conclusion
// is turned into a processing record, using the same proof registration,
// report queries, comparison, evaluation and replay demand. A missing or
// null parameter must never produce a zero-valued record, a null or missing
// id must never be explained as the built-in rules, and parameters must
// never be completed from the registered or currently enabled version.
// Only an old-format record with no version key at all keeps the built-in
// interpretation. Any corrupt report in range fails the whole generation —
// even when it has no findings, all its findings are below the threshold or
// were already processed — creates no records for any block and leaves the
// archive byte-identical.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertGenerateRefused runs one failing GenerateAlerts and pins the shape
// the command relies on: ErrCorruptVersion (never an unknown-version
// misread), naming the target chain and block plus every required extra
// substring, creating no processing records, and leaving the archive
// byte-identical.
func assertGenerateRefused(t *testing.T, dir, chain, channel string, start, end uint64, sev int, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	records, err := GenerateAlerts(dir, chain, channel, start, end, sev)
	if err == nil {
		t.Fatalf("corrupt report generated successfully: %+v", records)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt report misreported as unknown version: %v", err)
	}
	msg := err.Error()
	for _, sub := range append([]string{chain}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	// No partial success: no records are returned and none are stored.
	if len(records) != 0 {
		t.Fatalf("failed generation returned %d records: %+v", len(records), records)
	}
	after := readArchiveFile(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed generation changed the archive")
	}
	// No new processing records were stored. AlertHistory is deliberately not
	// used for this check: it decodes the archive through the fully typed
	// reader, which a wrong-typed version field makes fail wholesale (the
	// pre-existing shape a report query already worked around); read the
	// alerts section independently instead.
	var doc generateArchiveDoc
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.AlertRecords) != 0 {
		t.Fatalf("failed generation left processing records: %+v", doc.AlertRecords)
	}
	// Re-running fails the same way rather than repairing the declaration.
	if _, err := GenerateAlerts(dir, chain, channel, start, end, sev); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second generation did not fail the same way: %v", err)
	}
}

// TestGenerateCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the in-range archived report (the
// registered versions section is left intact): every way the saved
// document can stop satisfying the registration rules must fail the whole
// generation with ErrCorruptVersion, naming chain, block, the saved id and
// the offending rule or field.
func TestGenerateCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertGenerateRefused(t, dir, "1", "ops", 0, 100, 1, "0xblk", "candC", tc.wantErr)
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
			// The id may be unreadable for null/{}/scalars; the message must
			// still name the chain and block and never call this an unknown
			// version.
			assertGenerateRefused(t, dir, "1", "ops", 0, 100, 1, "0xblk")
		})
	}
}

// TestGenerateBuiltinIDDoesNotBypassValidation proves an id of "builtin"
// names the same saved declaration as any other id and is validated in
// full: a complete built-in declaration generates with the built-in
// parameters, a damaged one is refused as corruption (never auto-replaced
// by the in-code builtin).
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
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must generate: %v", err)
	}
	if len(got) != 1 || got[0].Version != BuiltinVersion() {
		t.Fatalf("record version = %+v, want builtin parameters", got)
	}

	// The same id with a missing field is corrupt, and the failure points at
	// "builtin" rather than silently substituting it.
	dir2 := setupCorruptCompareArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", builtinDamaged)
	assertGenerateRefused(t, dir2, "1", "ops", 0, 100, 1, "0xblk", BuiltinVersionID, "multiplier")
}

// TestGenerateDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling that
// name the same field, even with identical values. The raw bytes are
// patched directly because a JSON map cannot hold two keys; the report
// record precedes the versions array.
func TestGenerateDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		// "v" written via its JSON escape (v) decodes to the same key.
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
			field := strings.Index(text[at:versionsAt], anchor)
			if field < 0 {
				t.Fatal("severity field not found in embedded declaration")
			}
			pos := at + field
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			before := readArchiveFile(t, dir)

			records, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
			if err == nil {
				t.Fatalf("duplicate-field declaration generated: %+v", records)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed generation repaired the duplicate field")
			}
		})
	}
}

// TestGenerateExplicitlyDisabledRulesAccepted proves enabled:false is a
// legal saved off state, not a missing field: a report archived with both
// rules off but complete parameters is processed normally (the archived
// conclusion is reused, never re-judged), while a disabled rule that lost a
// parameter is still corrupt.
func TestGenerateExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must be accepted: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want the one archived conclusion", len(got))
	}
	v := got[0].Version
	if v.ID != "off" || v.Rules.Sandwich.Enabled || v.Rules.Displacement.Enabled ||
		v.Rules.Sandwich.Severity != 1 || v.Rules.Displacement.Severity != 1 ||
		v.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("saved off state not carried in full: %+v", v)
	}
	// The archived conclusion is reused despite both rules being off now.
	if got[0].Finding.Kind != "displacement" || got[0].Finding.Severity != 4 {
		t.Fatalf("record re-judged under the off rules: %+v", got[0].Finding)
	}

	// Disabled does not pardon a missing severity: the rule still has to be
	// declared completely.
	dir2 := setupCorruptCompareArchive(t)
	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir2, "1", "0xblk", offBroken)
	assertGenerateRefused(t, dir2, "1", "ops", 0, 100, 1, "0xblk", "off", "severity")
}

// TestGenerateCorruptEvenWhenNothingWouldBeProcessed proves the declaration
// proof does not depend on the run having work to do for the report: a
// report with no findings, one whose findings are all below the threshold,
// and one whose findings were all processed before still make the whole
// generation fail when their declaration decayed.
func TestGenerateCorruptEvenWhenNothingWouldBeProcessed(t *testing.T) {
	t.Run("no findings", func(t *testing.T) {
		dir := t.TempDir()
		register(t, dir, candidateVersionSpec)
		input := `{"chainId":"1","blockHash":"0xempty","blockNumber":3,"swaps":[]}`
		if _, err := ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
			t.Fatal(err)
		}
		rewriteStoredReportVersion(t, dir, "1", "0xempty", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		assertGenerateRefused(t, dir, "1", "ops", 0, 100, 1, "0xempty", "candC", "multiplier")
	})

	t.Run("all findings below threshold", func(t *testing.T) {
		dir := setupCorruptCompareArchive(t) // sole finding is displacement severity 4
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		// Threshold 5 skips the severity-4 finding, yet the report must still
		// be proven first.
		assertGenerateRefused(t, dir, "1", "ops", 0, 100, 5, "0xblk", "candC", "multiplier")
	})

	t.Run("all findings already processed", func(t *testing.T) {
		dir := setupCorruptCompareArchive(t)
		first, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(first) != 1 {
			t.Fatalf("precondition: got %d records, want 1", len(first))
		}
		// Decay the declaration after the conclusion was already processed.
		rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		before := readArchiveFile(t, dir)

		records, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
		if !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("already-processed corrupt report error = %v, want ErrCorruptVersion", err)
		}
		if len(records) != 0 {
			t.Fatalf("failed run returned records: %+v", records)
		}
		// The existing record survives and the damaged archive is not repaired.
		if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("failed generation changed the archive")
		}
		hist, err := AlertHistory(dir, "1", "ops", 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(hist) != 1 || hist[0].BlockHash != "0xblk" {
			t.Fatalf("existing processing record damaged: %+v", hist)
		}
	})
}

// TestGenerateCorruptReportFailsWholeRange builds two in-range reports, one
// intact and one damaged, and proves the run is all-or-nothing: no record
// for the healthy block is returned or stored, and the archive is
// untouched. A damaged report outside the requested range is never judged
// and does not block the healthy one.
func TestGenerateCorruptReportFailsWholeRange(t *testing.T) {
	setup := func(t *testing.T) string {
		dir := setupCorruptCompareArchive(t) // chain 1, 0xblk at height 7
		second := cmpBlockLine("1", "0xblk2", 8,
			cmpSwap("0xf2", "p1", "w", 40, 0),
			cmpSwap("0xv2", "p1", "u", 10, 1),
		)
		if _, err := ReplayWithVersion(strings.NewReader(second), dir, "candC"); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	// Control: intact, both reports produce one record each.
	control := setup(t)
	got, err := GenerateAlerts(control, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("control: got %d records, want 2", len(got))
	}

	// Damage only the height-7 report: the healthy height-8 report must not
	// be partially processed.
	dir := setup(t)
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	assertGenerateRefused(t, dir, "1", "ops", 0, 100, 1, "0xblk", "candC", "multiplier")

	// A range covering only the healthy block succeeds: out-of-range damage
	// is never judged.
	later, err := GenerateAlerts(dir, "1", "ops", 8, 8, 1)
	if err != nil {
		t.Fatalf("out-of-range corrupt report blocked a healthy range: %v", err)
	}
	if len(later) != 1 || later[0].BlockHash != "0xblk2" {
		t.Fatalf("healthy-range generation wrong: %+v", later)
	}
	// The successful narrow run stored exactly its own record and never
	// repaired or completed the damaged height-7 declaration.
	if _, gerr := GenerateAlerts(dir, "1", "ops", 7, 7, 1); !errors.Is(gerr, ErrCorruptVersion) {
		t.Fatalf("damaged declaration was repaired: %v", gerr)
	}
}

// TestGenerateLegacyRecordWithoutVersionUsesBuiltin proves the one legacy
// carve-out for alerting: a record with no version key at all is processed
// under the built-in rules, and a generation that writes new records keeps
// the keyless record keyless rather than turning the absence into an
// explicit null (which would itself be corruption).
func TestGenerateLegacyRecordWithoutVersionUsesBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatalf("legacy report must generate under builtin: %v", err)
	}
	if len(got) != 1 || got[0].Version != BuiltinVersion() {
		t.Fatalf("record version = %+v, want builtin", got)
	}
	if got[0].Finding.Kind != "sandwich" || got[0].Finding.Severity != 3 || len(got[0].Finding.Evidence) != 3 {
		t.Fatalf("legacy conclusion/evidence damaged: %+v", got[0].Finding)
	}

	// The write-back kept the legacy record without a version key.
	var doc struct {
		Records []map[string]json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(doc.Records))
	}
	if raw, present := doc.Records[0]["version"]; present {
		t.Fatalf("legacy record gained a version key on write-back: %s", raw)
	}
	// It still reads as a legacy built-in report afterwards.
	r, err := Query(dir, "1", "0old")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != BuiltinVersion() {
		t.Fatalf("post-write report version = %+v, want builtin", r.Version)
	}
	// Idempotent.
	again, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil || len(again) != 0 {
		t.Fatalf("legacy generation not idempotent: %+v %v", again, err)
	}
}

// TestGenerateUsesSavedParametersNotRegistry proves a valid in-range
// declaration is explained by itself: an id the registry never carried
// still generates with the saved parameters, and a corrupt same-id entry in
// the versions registry neither changes nor blocks an intact embedded
// declaration.
func TestGenerateUsesSavedParametersNotRegistry(t *testing.T) {
	// A complete self-contained declaration whose id was never registered.
	dir := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", stray)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	v := got[0].Version
	if v.ID != "never-registered" || v.Rules.Displacement.Multiplier != 9 || v.Rules.Sandwich.Severity != 5 {
		t.Fatalf("record borrowed registry parameters: %+v", v)
	}
	if _, err := GetVersion(dir, "never-registered"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("the report-only id must not have been inserted into the registry: %v", err)
	}

	// A corrupt registry sibling cannot contaminate an intact embedded
	// declaration.
	dir2 := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir2, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	got2, err := GenerateAlerts(dir2, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("an intact embedded declaration must not be blocked by registry damage: %v", err)
	}
	if len(got2) != 1 {
		t.Fatalf("got %d records, want 1", len(got2))
	}
	if want := mustRuleVersion(t, candidateVersionSpec); got2[0].Version != want {
		t.Fatalf("record version = %+v, want the embedded candC parameters %+v", got2[0].Version, want)
	}
	// The successful run wrote the archive back but kept the corrupt
	// registered entry as-is: it is still refused through the registry and
	// was neither repaired nor stripped.
	if _, err := GetVersion(dir2, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt registry entry was rewritten by generation: %v", err)
	}

	// Conversely, an intact registry does not rescue a corrupt embedded
	// declaration.
	dir3 := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir3, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	if _, err := GenerateAlerts(dir3, "1", "ops", 0, 100, 1); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt embedded declaration accepted via the registry: %v", err)
	}
}

// TestGeneratePreservesEveryOtherSection proves a successful write-back
// round-trips every section generation does not judge: the registered
// versions in stored order, the enabled marker, suppressions and reviews
// keep their exact content (a generation never repairs, completes or
// rewrites them), alongside the new alert records.
func TestGeneratePreservesEveryOtherSection(t *testing.T) {
	dir := setupCompareArchive(t) // versions archA/liveB/candC/twin, liveB enabled, 3 records
	if _, _, err := RegisterSuppression(dir, []byte(
		`{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":100,"reason":"r"}`,
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, ReviewSubmission{
		ChainID: "1", BlockHash: "0xblk", TxHash: "0xa0v", Kind: "sandwich",
		SubmissionID: "rev-1", Operator: "alice", Reason: "confirmed",
		Status: ReviewStatusReal, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	beforeRaw := readArchiveFile(t, dir)
	var before struct {
		Versions       []json.RawMessage  `json:"versions"`
		EnabledVersion string             `json:"enabledVersion"`
		Suppressions   []Suppression      `json:"suppressions"`
		Reviews        []ReviewObject     `json:"reviews"`
		AlertRecords   []ProcessingRecord `json:"alerts"`
	}
	if err := json.Unmarshal(beforeRaw, &before); err != nil {
		t.Fatal(err)
	}

	got, err := GenerateAlerts(dir, "1", "ops", 100, 100, 1)
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want 3", len(got))
	}

	var after struct {
		Versions       []json.RawMessage  `json:"versions"`
		EnabledVersion string             `json:"enabledVersion"`
		Suppressions   []Suppression      `json:"suppressions"`
		Reviews        []ReviewObject     `json:"reviews"`
		AlertRecords   []ProcessingRecord `json:"alerts"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Versions) != len(before.Versions) {
		t.Fatalf("versions changed: %d -> %d", len(before.Versions), len(after.Versions))
	}
	for i := range before.Versions {
		// Whitespace may be re-indented by the atomic writer; the JSON value
		// must be identical.
		var bv, av any
		if err := json.Unmarshal(before.Versions[i], &bv); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(after.Versions[i], &av); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(bv, av) {
			t.Fatalf("version %d rewritten:\nbefore=%s\nafter =%s", i, before.Versions[i], after.Versions[i])
		}
	}
	if after.EnabledVersion != before.EnabledVersion || after.EnabledVersion != "liveB" {
		t.Fatalf("enabled marker changed: %q", after.EnabledVersion)
	}
	if !reflect.DeepEqual(after.Suppressions, before.Suppressions) {
		t.Fatalf("suppressions rewritten:\nbefore=%+v\nafter =%+v", before.Suppressions, after.Suppressions)
	}
	if !reflect.DeepEqual(after.Reviews, before.Reviews) {
		t.Fatalf("reviews rewritten:\nbefore=%+v\nafter =%+v", before.Reviews, after.Reviews)
	}
	if len(after.AlertRecords) != 3 {
		t.Fatalf("alerts = %d, want the 3 new records", len(after.AlertRecords))
	}
}

// TestGenerateUsesArchivedParamsRegardlessOfEnabled proves a successful run
// carries the report's own archived parameters even when a different
// version is enabled, and the archived conclusion is not re-detected.
func TestGenerateUsesArchivedParamsRegardlessOfEnabled(t *testing.T) {
	dir := setupCompareArchive(t) // records archived under archA, liveB enabled
	got, err := GenerateAlerts(dir, "1", "ops", 100, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d records, want the three archived conclusions", len(got))
	}
	want := mustRuleVersion(t, archivedVersionSpec)
	for _, r := range got {
		if r.Version != want {
			t.Fatalf("record version = %+v, want archived archA %+v", r.Version, want)
		}
	}
}
