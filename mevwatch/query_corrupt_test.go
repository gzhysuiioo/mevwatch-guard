package mevwatch

// Regression coverage for `report` (Query) against an archived report
// whose saved rule-version declaration has decayed since the report was
// written. Querying a report must first prove the complete version
// declaration the report archived — a non-empty id, sandwich and
// displacement each with a boolean enabled and an integer severity 1-5,
// and a displacement multiplier 2-100 — still satisfies every
// registration rule, using the same raw-document proof registration,
// enabling, comparison, evaluation and replay already demand. Until that
// proof succeeds no report is returned: a missing or null parameter must
// never be shown as a zero value, a null or missing id must never be
// explained as the built-in rules, and parameters must never be completed
// from the registered or currently enabled version. Only an old-format
// record with no version key at all keeps the built-in interpretation.
// The query is read-only: success or failure leaves the archive exactly
// as it was, and a block that was never archived stays ErrUnknownBlock.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// rewriteStoredReportVersion rewrites the version declaration embedded in
// one archived record (not the same-id entry in the versions registry)
// through mutate.
func rewriteStoredReportVersion(t *testing.T, dir, chain, hash string, mutate func(ver map[string]any)) {
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
	records, ok := doc["records"].([]any)
	if !ok {
		t.Fatalf("no records array in archive: %s", raw)
	}
	found := false
	for _, r := range records {
		rec, ok := r.(map[string]any)
		if !ok || rec["chainId"] != chain || rec["blockHash"] != hash {
			continue
		}
		ver, ok := rec["version"].(map[string]any)
		if !ok {
			t.Fatalf("record %s/%s has no object version to rewrite: %v", chain, hash, rec["version"])
		}
		mutate(ver)
		found = true
	}
	if !found {
		t.Fatalf("record %s/%s not found in archive", chain, hash)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// replaceStoredReportVersion replaces the embedded version declaration of
// one record wholesale — used for null, an empty object, a reserved-id
// declaration and versions the registry does not carry.
func replaceStoredReportVersion(t *testing.T, dir, chain, hash string, value any) {
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
		if rec["chainId"] == chain && rec["blockHash"] == hash {
			rec["version"] = value
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
	t.Fatalf("record %s/%s not found in archive", chain, hash)
}

// assertQueryRefused runs one failing Query and pins the shape the report
// command relies on: ErrCorruptVersion wrapping the cause, never an
// unknown-block or unknown-version misread, naming the target chain and
// block plus every required extra substring, and leaving the archive
// byte-identical.
func assertQueryRefused(t *testing.T, dir, chain, hash string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	report, err := Query(dir, chain, hash)
	if err == nil {
		t.Fatalf("corrupt report returned successfully: %+v", report)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt report misreported as unknown block/version: %v", err)
	}
	msg := err.Error()
	for _, sub := range append([]string{chain, hash}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed report query changed the archive")
	}
	// The failure is not a write-side repair: querying again fails the same
	// way, and no report JSON is ever produced.
	if _, err := Query(dir, chain, hash); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second query did not fail the same way: %v", err)
	}
}

// TestQueryCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the archived report (the registered
// versions section is left intact): every way the saved document can stop
// satisfying the registration rules must fail Query with
// ErrCorruptVersion, naming chain, block, the saved id and the offending
// rule or field.
func TestQueryCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})

			assertQueryRefused(t, dir, "1", "0xblk", "candC", tc.wantErr)

			// The report's damage lives in its own saved declaration; the
			// refusal is read-only, so no missing parameter is completed or
			// fixed (assertQueryRefused compares the archive bytes and
			// re-queries). Registry independence for structural damage is
			// covered separately in TestQueryUsesSavedParametersNotRegistry;
			// a JSON type mismatch in the embedded copy is intentionally not
			// read back through the registry, whose whole-archive typed
			// decode predates and is outside this fix.
		})
	}
}

// TestQueryNullAndEmptySavedVersionCorrupt pins the exact misread being
// fixed: version:null used to decode into the built-in explanation, and
// {} or an incomplete object decoded into silently zeroed parameters. All
// three must fail as corruption; only a wholly missing version key is the
// legacy built-in shape.
func TestQueryNullAndEmptySavedVersionCorrupt(t *testing.T) {
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
			// block/version.
			assertQueryRefused(t, dir, "1", "0xblk")
		})
	}
}

// TestQueryBuiltinIDDoesNotBypassValidation proves an id of "builtin"
// names the same saved declaration as any other id and is validated in
// full: a complete built-in declaration is shown, a damaged one is
// refused as corruption (never auto-replaced by the in-code builtin).
func TestQueryBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupCorruptCompareArchive(t)

	// A complete declaration carrying the reserved id stands on its own.
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must be shown: %v", err)
	}
	if r.Version != BuiltinVersion() {
		t.Fatalf("version = %+v, want builtin parameters", r.Version)
	}

	// The same id with a missing field is corrupt, and the failure points
	// at "builtin" rather than silently substituting it.
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertQueryRefused(t, dir, "1", "0xblk", BuiltinVersionID, "multiplier")
}

// TestQueryDuplicateFieldsInSavedVersionRefused covers decay registration
// could never have produced: a repeated field in the saved declaration,
// including an escaped spelling and a case-only spelling that name the
// same field. The raw bytes are patched directly because a JSON map
// cannot hold two keys; the report record precedes the versions array.
func TestQueryDuplicateFieldsInSavedVersionRefused(t *testing.T) {
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
			report, err := Query(dir, "1", "0xblk")
			if err == nil {
				t.Fatalf("duplicate-field declaration shown: %+v", report)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed query repaired the duplicate field")
			}
		})
	}
}

// TestQueryExplicitlyDisabledRulesAccepted proves enabled:false is a legal
// saved off state, not a missing field: a report archived with both rules
// off but complete parameters is returned normally, while a disabled rule
// that lost a parameter is still corrupt.
func TestQueryExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", off)
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must be accepted: %v", err)
	}
	if r.Version.ID != "off" || r.Version.Rules.Sandwich.Enabled || r.Version.Rules.Displacement.Enabled {
		t.Fatalf("saved off state not returned: %+v", r.Version)
	}

	// Disabled does not pardon a missing severity: the rule still has to be
	// declared completely.
	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", offBroken)
	assertQueryRefused(t, dir, "1", "0xblk", "off", "severity")
}

// TestQueryUsesSavedParametersNotRegistry proves the report is explained
// by the declaration it archived: enabling another version, damaging the
// same-id registry entry, or pointing at an id the registry never carried
// neither changes nor blocks an intact saved report, and no parameters are
// pulled back out of the registry.
func TestQueryUsesSavedParametersNotRegistry(t *testing.T) {
	dir := setupCompareArchive(t) // records archived under archA, liveB enabled

	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if want := mustRuleVersion(t, archivedVersionSpec); r.Version != want {
		t.Fatalf("report must show its saved archA parameters regardless of the enabled version: %+v", r.Version)
	}

	// Damage the registered archA entry; the report's own intact embedded
	// declaration is unaffected and still returned byte for byte, with no
	// parameters pulled from the registry.
	rewriteStoredVersion(t, dir, "archA", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	r2, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved report: %v", err)
	}
	if want := mustRuleVersion(t, archivedVersionSpec); r2.Version != want {
		t.Fatalf("report borrowed registry parameters: %+v, want %+v", r2.Version, want)
	}

	// Conversely, an intact registry does not rescue a corrupt report:
	// damage only the report's own copy while the same-id registry entry
	// stays intact.
	dir2 := setupCompareArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertQueryRefused(t, dir2, "1", "0xblk", "archA", "multiplier")
}

// TestQueryUnknownVersionIDInReportStillValid proves the saved declaration
// is self-contained: even an id the archive's registry never registered is
// a valid explanation as long as the document itself is complete.
func TestQueryUnknownVersionIDInReportStillValid(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", stray)
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if r.Version.ID != "never-registered" || r.Version.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved parameters not returned: %+v", r.Version)
	}
	if _, err := GetVersion(dir, "never-registered"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("the report-only id must not have been inserted into the registry: %v", err)
	}
}

// TestQueryLegacyArchiveWithoutVersionUsesBuiltin proves the one legacy
// carve-out: a record with no version key at all is still explained by the
// built-in rules, with identity, height, swap count, conclusions and
// evidence unchanged.
func TestQueryLegacyArchiveWithoutVersionUsesBuiltin(t *testing.T) {
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
	before := readArchiveFile(t, dir)
	r, err := Query(dir, "1", "0old")
	if err != nil {
		t.Fatalf("legacy report must query under builtin: %v", err)
	}
	if r.Version != BuiltinVersion() {
		t.Fatalf("version = %+v, want builtin", r.Version)
	}
	if r.ChainID != "1" || r.BlockHash != "0old" || r.BlockNumber != 5 || r.SwapCount != 3 {
		t.Fatalf("identity/height/swap count damaged: %+v", r)
	}
	if len(r.Findings) != 1 || r.Findings[0].Kind != "sandwich" || r.Findings[0].Severity != 3 ||
		len(r.Findings[0].Evidence) != 3 {
		t.Fatalf("legacy findings/evidence damaged: %+v", r.Findings)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("legacy query rewrote the archive")
	}
}

// TestQueryUnknownBlockUnchanged proves block existence still governs the
// query: a never-archived block returns ErrUnknownBlock even when a
// different record in the same archive is corrupt, and the missing-dir
// case stays ErrUnknownBlock.
func TestQueryUnknownBlockUnchanged(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	// The corrupt record fails as corruption...
	if _, err := Query(dir, "1", "0xblk"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt record error = %v, want ErrCorruptVersion", err)
	}
	// ...but an absent block is still an unknown-block failure, not a
	// spillover corruption error.
	for _, id := range [][2]string{{"1", "0xother"}, {"9", "0xblk"}} {
		if _, err := Query(dir, id[0], id[1]); !errors.Is(err, ErrUnknownBlock) {
			t.Fatalf("Query(%s,%s) = %v, want ErrUnknownBlock", id[0], id[1], err)
		}
	}
	if _, err := Query(filepath.Join(dir, "missing"), "1", "0xblk"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("missing directory must stay ErrUnknownBlock")
	}
}

// TestQuerySuccessContentUnchanged proves a healthy report still carries
// exactly the original block identity, height, swap count, the original
// conclusions in their stored order with all swap evidence, and the saved
// parameters — with no re-detection.
func TestQuerySuccessContentUnchanged(t *testing.T) {
	dir := setupCompareArchive(t)
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if r.ChainID != "1" || r.BlockHash != "0xblk" || r.BlockNumber != 100 || r.SwapCount != 13 {
		t.Fatalf("identity/height/swap count wrong: %+v", r)
	}
	if want := mustRuleVersion(t, archivedVersionSpec); r.Version != want {
		t.Fatalf("version = %+v, want archA", r.Version)
	}
	wantFindings := []struct {
		tx       string
		kind     string
		severity int
		evidence int
	}{
		{"0xa0v", "sandwich", 4, 3},
		{"0xe0v", "sandwich", 4, 3},
		{"0xb0v", "displacement", 1, 2},
	}
	if len(r.Findings) != len(wantFindings) {
		t.Fatalf("findings = %+v", r.Findings)
	}
	for i, w := range wantFindings {
		got := r.Findings[i]
		if got.TxHash != w.tx || got.Kind != w.kind || got.Severity != w.severity ||
			len(got.Evidence) != w.evidence {
			t.Fatalf("findings[%d] = %+v, want %+v", i, got, w)
		}
	}
	if r.Findings[0].Evidence[0] != (Swap{TxHash: "0xa0f", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0}) {
		t.Fatalf("raw swap evidence damaged: %+v", r.Findings[0].Evidence[0])
	}
	// Deterministic across reads.
	again, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r, again) {
		t.Fatalf("repeated query differs:\n%+v\n%+v", r, again)
	}
}
