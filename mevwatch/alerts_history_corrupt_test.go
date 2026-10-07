package mevwatch

// Regression coverage for `alerts history` (AlertHistory) against saved
// processing records whose detection-version declaration has decayed since
// the record was written. A history query draws on the record's own saved
// declaration — never on the block report's, the enabled version's or a
// same-id registry entry's — and must first prove, exactly the way a
// `report` query does, that the declaration still carries a non-empty id,
// both rules with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100. A written null used to be explained as the
// built-in rules and a missing severity or multiplier used to come back as
// 0; processing records postdate rule versions, so unlike a pre-version
// block report an alert record without a version key is damage too, not the
// legacy built-in shape. On any one corrupt hit record the whole query
// fails with ErrCorruptVersion — no partial history — naming the record's
// chain, block hash, victim tx, conclusion kind, conclusion type and
// channel, the readable saved id and the offending rule or field. Records
// outside the chain/channel/range, decayed block reports and decayed
// registry versions never block it. The query is read-only.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// editStoredAlert runs edit against every alert entry in the archive that
// matches the processing-record identity.
func editStoredAlert(t *testing.T, dir, chain, hash, tx, kind, channel string, edit func(rec map[string]any)) {
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
	alerts, ok := doc["alerts"].([]any)
	if !ok {
		t.Fatalf("no alerts array in archive: %s", raw)
	}
	found := false
	for _, a := range alerts {
		rec := a.(map[string]any)
		finding := rec["finding"].(map[string]any)
		if rec["chainId"] != chain || rec["blockHash"] != hash ||
			finding["txHash"] != tx || finding["kind"] != kind || rec["channel"] != channel {
			continue
		}
		edit(rec)
		found = true
	}
	if !found {
		t.Fatalf("alert record %s/%s %s/%s ch=%s not found", chain, hash, tx, kind, channel)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// rewriteStoredAlertVersion rewrites the version declaration embedded in
// one saved processing record through mutate.
func rewriteStoredAlertVersion(t *testing.T, dir, chain, hash, tx, kind, channel string, mutate func(ver map[string]any)) {
	t.Helper()
	editStoredAlert(t, dir, chain, hash, tx, kind, channel, func(rec map[string]any) {
		ver, ok := rec["version"].(map[string]any)
		if !ok {
			t.Fatalf("alert record has no object version to rewrite: %v", rec["version"])
		}
		mutate(ver)
	})
}

// replaceStoredAlertVersion replaces one record's version declaration
// wholesale — used for null, an empty object or a self-contained
// never-registered declaration.
func replaceStoredAlertVersion(t *testing.T, dir, chain, hash, tx, kind, channel string, value any) {
	t.Helper()
	editStoredAlert(t, dir, chain, hash, tx, kind, channel, func(rec map[string]any) {
		rec["version"] = value
	})
}

// dropStoredAlertVersionKey removes the version key from one saved
// processing record — processing records have no legacy no-version shape.
func dropStoredAlertVersionKey(t *testing.T, dir, chain, hash, tx, kind, channel string) {
	t.Helper()
	editStoredAlert(t, dir, chain, hash, tx, kind, channel, func(rec map[string]any) {
		delete(rec, "version")
	})
}

const (
	alertHistoryChain   = "1"
	alertHistoryBlock   = "0xblk"
	alertHistoryTx      = "0xv"
	alertHistoryKind    = SuppressDisplacement
	alertHistoryChannel = "ops"
)

// setupAlertHistoryCorruptArchive archives the setupCorruptCompareArchive
// block under candC (one displacement conclusion on 0xv at height 7) and
// processes it for channel ops without any suppression, leaving one alert
// record carrying a complete candC declaration.
func setupAlertHistoryCorruptArchive(t *testing.T) string {
	t.Helper()
	dir := setupCorruptCompareArchive(t)
	got, err := GenerateAlerts(dir, alertHistoryChain, alertHistoryChannel, 0, 100, 1)
	if err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}
	if len(got) != 1 || got[0].Status != AlertStatusAlert {
		t.Fatalf("precondition: want one alert record, got %+v", got)
	}
	return dir
}

// setupSuppressedAlertHistoryArchive does the same with a suppression
// covering the conclusion, so the single record is stored as suppressed
// with its hit reason.
func setupSuppressedAlertHistoryArchive(t *testing.T) string {
	t.Helper()
	dir := setupCorruptCompareArchive(t)
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":7,"endHeight":7,"reason":"known bot war"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, alertHistoryChain, alertHistoryChannel, 0, 100, 1)
	if err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}
	if len(got) != 1 || got[0].Status != AlertStatusSuppressed ||
		len(got[0].Suppressions) != 1 || got[0].Suppressions[0].ID != "s1" {
		t.Fatalf("precondition: want one suppressed record, got %+v", got)
	}
	return dir
}

// assertAlertHistoryRefused runs one failing AlertHistory and pins the
// failure shape the command relies on: ErrCorruptVersion wrapping the
// cause, never an unknown-version misread, no partial records, an error
// naming every required substring (chain, block, victim tx, kind,
// conclusion type and channel among them), and the archive byte-identical.
func assertAlertHistoryRefused(t *testing.T, dir, chain, channel string, start, end uint64, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	records, err := AlertHistory(dir, chain, channel, start, end)
	if err == nil {
		t.Fatalf("corrupt alert record returned history: %+v", records)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt declaration misreported as an unknown version: %v", err)
	}
	if records != nil {
		t.Fatalf("failed history returned partial records: %+v", records)
	}
	msg := err.Error()
	for _, sub := range want {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed history query changed the archive")
	}
	// No write-side repair: a second query fails the same way.
	if _, err := AlertHistory(dir, chain, channel, start, end); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second history query did not fail the same way: %v", err)
	}
}

// TestAlertHistoryCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the saved processing record:
// every way the saved document can stop satisfying the registration rules
// must fail the whole history query, naming chain, block, victim tx, kind,
// conclusion type, channel, the readable saved id and the offending field.
func TestAlertHistoryCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			rewriteStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				func(ver map[string]any) { tc.mutate(t, ver) })
			assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind,
				AlertStatusAlert, alertHistoryChannel, "candC", tc.wantErr)
		})
	}
}

// TestAlertHistoryCorruptSuppressedRecordNamesType proves the suppressed
// conclusion type and its channel are named just like an alert's: a
// damaged suppressed record fails the query and identifies itself as a
// suppressed record on the channel, never silently losing the suppression.
func TestAlertHistoryCorruptSuppressedRecordNamesType(t *testing.T) {
	dir := setupSuppressedAlertHistoryArchive(t)
	rewriteStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
		func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
	assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind,
		AlertStatusSuppressed, alertHistoryChannel, "candC", "multiplier")
}

// TestAlertHistoryNullEmptyAndMissingVersionCorrupt pins the exact
// misread being fixed: a null or incomplete declaration used to display
// with zeroed parameters and be queried successfully, and a record whose
// version key is missing must not be explained as the built-in rules —
// processing records postdate rule versions. All fail; only archives with
// no alert data at all stay an empty result.
func TestAlertHistoryNullEmptyAndMissingVersionCorrupt(t *testing.T) {
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
			dir := setupAlertHistoryCorruptArchive(t)
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, tc.value)
			want := []string{
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind,
				AlertStatusAlert, alertHistoryChannel,
			}
			if tc.idReachable {
				want = append(want, "candC")
			}
			assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100, want...)
		})
	}

	t.Run("missing version key is not legacy builtin", func(t *testing.T) {
		dir := setupAlertHistoryCorruptArchive(t)
		dropStoredAlertVersionKey(t, dir,
			alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel)
		before := readArchiveFile(t, dir)
		records, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
		if !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("missing version key = %v / %+v, want ErrCorruptVersion", err, records)
		}
		if records != nil {
			t.Fatalf("missing-version record returned: %+v", records)
		}
		msg := err.Error()
		for _, sub := range []string{
			alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind,
			AlertStatusAlert, alertHistoryChannel, "version is required",
		} {
			if !strings.Contains(msg, sub) {
				t.Fatalf("error %q must name %q", msg, sub)
			}
		}
		if strings.Contains(msg, BuiltinVersionID) {
			t.Fatalf("missing version must not be explained as builtin: %v", err)
		}
		if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatal("failed query rewrote the archive")
		}
	})
}

// TestAlertHistoryBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestAlertHistoryBuiltinIDDoesNotBypassValidation(t *testing.T) {
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	dir := setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, builtinFull)
	got, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must query: %v", err)
	}
	if len(got) != 1 || got[0].Version != BuiltinVersion() {
		t.Fatalf("record = %+v, want builtin parameters", got)
	}

	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	dir = setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, builtinDamaged)
	assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100,
		BuiltinVersionID, "multiplier")
}

// TestAlertHistoryDuplicateFieldsInSavedRecordRefused covers decay
// registration could never have produced: a repeated field in the record's
// saved declaration, including an exact repeat with the same value, a
// case-only spelling and an escaped spelling that name the same field. The
// raw bytes are patched directly because a JSON map cannot hold two keys.
func TestAlertHistoryDuplicateFieldsInSavedRecordRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact same value", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			path := filepath.Join(dir, archiveFileName)
			text := string(readArchiveFile(t, dir))
			// The alert record's declaration lives in the alerts section,
			// which follows the records and versions sections.
			alertsAt := strings.Index(text, `"alerts":`)
			if alertsAt < 0 {
				t.Fatal("alerts section not found")
			}
			at := strings.Index(text[alertsAt:], `"id": "candC"`)
			if at < 0 {
				t.Fatal("alert record's candC declaration not found")
			}
			at += alertsAt
			anchor := `"severity": 4,`
			field := strings.Index(text[at:], anchor)
			if field < 0 {
				t.Fatal("severity field not found in the alert record's declaration")
			}
			pos := at + field
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			records, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
			if err == nil {
				t.Fatalf("duplicate-field declaration returned history: %+v", records)
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatal("failed history repaired the duplicate field")
			}
		})
	}
}

// TestAlertHistoryDisabledAndUnregisteredDeclarationsAccepted proves a
// legal record is used exactly as saved: an explicit enabled:false is a
// legal off state as long as the disabled rule keeps complete, in-range
// parameters, and the saved id need not still be registered — parameters
// are never pulled from the enabled or a same-id registered version.
func TestAlertHistoryDisabledAndUnregisteredDeclarationsAccepted(t *testing.T) {
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	dir := setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, off)
	got, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must query: %v", err)
	}
	if len(got) != 1 || got[0].Version.ID != "off" ||
		got[0].Version.Rules.Sandwich.Enabled || got[0].Version.Rules.Displacement.Enabled {
		t.Fatalf("saved off state not carried: %+v", got)
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
	dir = setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, offBroken)
	assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100, "off", "severity")

	// A complete declaration with an id the registry never carried stands
	// on its own.
	ghost := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
		},
	}
	dir = setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, ghost)
	got, err = AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	v := got[0].Version
	if v.ID != "never-registered" || v.Rules.Displacement.Severity != 5 || v.Rules.Displacement.Multiplier != 100 {
		t.Fatalf("saved parameters not carried: %+v", v)
	}
	if _, err := GetVersion(dir, "never-registered"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("the record-only id must not be taken from the registry: %v", err)
	}
}

// TestAlertHistoryProofUsesRecordNotReportOrRegistry proves the proof reads
// the record's own declaration: a damaged same-id registry version and a
// damaged declaration on the block's own report neither block nor complete
// an intact saved record, and the saved id need not be registered.
func TestAlertHistoryProofUsesRecordNotReportOrRegistry(t *testing.T) {
	// Damage the registered candC entry while every saved record stays
	// intact: the history still shows the record with its own parameters.
	dir := setupAlertHistoryCorruptArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	got, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact alert record: %v", err)
	}
	if want := mustRuleVersion(t, candidateVersionSpec); len(got) != 1 || got[0].Version != want {
		t.Fatalf("history borrowed registry parameters: %+v want %+v", got, want)
	}

	// Damage the block report's own embedded declaration while the alert
	// record stays intact: the history is unaffected and never re-proves or
	// borrows from the report.
	dir = setupAlertHistoryCorruptArchive(t)
	rewriteStoredReportVersion(t, dir, alertHistoryChain, alertHistoryBlock, func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	got, err = AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatalf("a corrupt block report must not block an intact alert record: %v", err)
	}
	if len(got) != 1 || got[0].Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("alert record parameters must come from the record, not the damaged report: %+v", got)
	}

	// Conversely, an intact registry cannot rescue a corrupt record: damage
	// only the alert record's own copy while the registry stays intact.
	dir = setupAlertHistoryCorruptArchive(t)
	rewriteStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
		func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
	assertAlertHistoryRefused(t, dir, alertHistoryChain, alertHistoryChannel, 0, 100, "candC", "multiplier")
}

// TestAlertHistoryCorruptSiblingDoesNotBlock proves the integrity proof is
// scoped to the records the query actually returns: a damaged declaration
// on another channel, another chain or outside the height range does not
// block the query, while the damaged record fails a query that hits it.
func TestAlertHistoryCorruptSiblingDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	// Block 0xa at height 10 on chain 1 with two conclusions; every
	// conclusion is processed for both ops and audit, and the same block is
	// archived on chain 2 for ops as well.
	mustReplay(t, dir, twoFindingsInput)
	other := strings.Replace(twoFindingsInput, `"chainId":"1"`, `"chainId":"2"`, 1)
	mustReplay(t, dir, other)
	for _, ch := range []string{"ops", "audit"} {
		if _, err := GenerateAlerts(dir, "1", ch, 0, 100, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := GenerateAlerts(dir, "2", "ops", 0, 100, 1); err != nil {
		t.Fatal(err)
	}

	// Corrupt only the chain-1 ops sandwich record (0xv): the audit copy,
	// the chain-1 ops displacement copy (0xd), and the chain-2 copies stay
	// intact.
	rewriteStoredAlertVersion(t, dir, "1", "0xa", "0xv", SuppressSandwich, "ops", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})

	// Hitting the damaged record fails the whole query — no partial
	// history, the intact displacement record on the same channel is not
	// returned either.
	assertAlertHistoryRefused(t, dir, "1", "ops", 0, 100, "1", "0xa", "0xv", SuppressSandwich, "ops")

	// The other channel's identical conclusions stay queryable.
	audit, err := AlertHistory(dir, "1", "audit", 0, 100)
	if err != nil {
		t.Fatalf("other channel must stay queryable: %v", err)
	}
	if len(audit) != 2 {
		t.Fatalf("audit history = %+v, want both conclusions", audit)
	}

	// The other chain's records stay queryable.
	chain2, err := AlertHistory(dir, "2", "ops", 0, 100)
	if err != nil {
		t.Fatalf("other chain must stay queryable: %v", err)
	}
	if len(chain2) != 2 {
		t.Fatalf("chain 2 history = %+v, want both conclusions", chain2)
	}

	// A range that excludes height 10 never opens the damaged record.
	above, err := AlertHistory(dir, "1", "ops", 11, 100)
	if err != nil {
		t.Fatalf("out-of-range query must not open the damaged record: %v", err)
	}
	if len(above) != 0 {
		t.Fatalf("out-of-range history = %+v, want []", above)
	}

	// The damaged record still fails under every scope that includes it,
	// and the corrupt declaration is written back verbatim.
	if _, err := AlertHistory(dir, "1", "ops", 10, 10); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("inclusive single-height query must fail: %v", err)
	}
	if !strings.Contains(string(readArchiveFile(t, dir)), `"multiplier": 0`) {
		t.Fatal("failed history query repaired the corrupt record")
	}
}

// TestAlertHistorySuccessContentAndOrderPreserved proves healthy records
// keep their full JSON content — conclusion, swap evidence, generation
// threshold, suppression hits, saved parameters — in the height, block
// hash, tx hash and kind ascending order generation uses, with [] for an
// empty result.
func TestAlertHistorySuccessContentAndOrderPreserved(t *testing.T) {
	dir := setupSuppressedAlertHistoryArchive(t)
	got, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 7, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v, want one record", got)
	}
	r := got[0]
	if r.ChainID != alertHistoryChain || r.BlockHash != alertHistoryBlock || r.BlockNumber != 7 ||
		r.Channel != alertHistoryChannel || r.Pool != "p1" {
		t.Fatalf("identity wrong: %+v", r)
	}
	if r.Finding.Kind != alertHistoryKind || r.Finding.TxHash != alertHistoryTx ||
		r.Finding.Severity != 4 || len(r.Finding.Evidence) != 2 {
		t.Fatalf("conclusion/evidence wrong: %+v", r.Finding)
	}
	if r.MinSeverity != 1 || r.Status != AlertStatusSuppressed {
		t.Fatalf("threshold/status wrong: %+v", r)
	}
	if len(r.Suppressions) != 1 || r.Suppressions[0].ID != "s1" ||
		r.Suppressions[0].Reason != "known bot war" {
		t.Fatalf("suppression hits wrong: %+v", r.Suppressions)
	}
	if want := mustRuleVersion(t, candidateVersionSpec); r.Version != want {
		t.Fatalf("saved detection version wrong: %+v want %+v", r.Version, want)
	}

	// Deterministic across reads, no re-detection.
	again, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("repeated query differs:\n%+v\n%+v", got, again)
	}

	// Ordering matches generation's height/hash/tx/kind order on a
	// multi-block archive.
	dir2 := t.TempDir()
	mustReplay(t, dir2, `{"chainId":"1","blockHash":"0xc","blockNumber":1,"swaps":[`+
		`{"TxHash":"0xf1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0+h1","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+z1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":80,"Index":2}]}`)
	mustReplay(t, dir2, twoFindingsInput) // 0xa at height 10
	created, err := GenerateAlerts(dir2, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	hist, err := AlertHistory(dir2, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hist, created) {
		t.Fatalf("history order/content differs from generation:\n%+v\n%+v", hist, created)
	}
}

// TestAlertHistoryEmptyAndOldArchives proves the empty shapes stay empty:
// a missing directory, an old-format archive without an alerts section, an
// explicit empty alerts array and a range with no matching record all
// return []; none of them is reinterpreted using a missing declaration.
func TestAlertHistoryEmptyAndOldArchives(t *testing.T) {
	emptyCases := func(t *testing.T, dir string) {
		t.Helper()
		for _, scope := range []struct {
			chain, channel string
			start, end     uint64
		}{
			{"1", "ops", 0, 100},
			{"2", "ops", 0, 100},
			{"1", "audit", 0, 100},
			{"1", "ops", 100, 200},
		} {
			got, err := AlertHistory(dir, scope.chain, scope.channel, scope.start, scope.end)
			if err != nil {
				t.Fatalf("scope %+v: %v", scope, err)
			}
			raw, _ := json.Marshal(got)
			if string(raw) != "[]" {
				t.Fatalf("scope %+v = %s, want []", scope, raw)
			}
		}
	}

	t.Run("missing directory", func(t *testing.T) {
		emptyCases(t, filepath.Join(t.TempDir(), "absent"))
	})

	t.Run("old archive without alerts section", func(t *testing.T) {
		dir := t.TempDir()
		data := archiveData{Records: []record{{
			ChainID: "1", BlockHash: "0old", BlockNumber: 5,
			Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0v"}},
		}}}
		if err := writeArchiveAtomic(dir, data); err != nil {
			t.Fatal(err)
		}
		emptyCases(t, dir)
		text := string(readArchiveFile(t, dir))
		if strings.Contains(text, "alerts") {
			t.Fatalf("old archive must carry no alerts section: %s", text)
		}
	})

	t.Run("explicit empty alerts array", func(t *testing.T) {
		dir := setupAlertHistoryCorruptArchive(t)
		editStoredAlert(t, dir,
			alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
			func(rec map[string]any) {})
		// Remove every alert entry by rewriting the section wholesale.
		path := filepath.Join(dir, archiveFileName)
		raw, _ := os.ReadFile(path)
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["alerts"] = []any{}
		out, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		emptyCases(t, dir)
	})
}

// TestAlertHistoryCorruptedArchiveFailsClearly proves a wholly unreadable
// archive is still an archive-corruption error, never [] or a version
// error, and the failed query does not rewrite the file.
func TestAlertHistoryCorruptedArchiveFailsClearly(t *testing.T) {
	dir := setupAlertHistoryCorruptArchive(t)
	corrupt := []byte("{not json")
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	records, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err == nil || !strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("got %v / %+v, want corrupted-archive error", err, records)
	}
	if errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("whole-archive JSON damage must not masquerade as one record's corrupt version: %v", err)
	}
	if after, rerr := os.ReadFile(filepath.Join(dir, archiveFileName)); rerr != nil || !reflect.DeepEqual(after, corrupt) {
		t.Fatalf("failed query changed the archive: %q %v", after, rerr)
	}
}
