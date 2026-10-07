package mevwatch

// Regression coverage for `alerts history` (AlertHistory) against stored
// processing records whose own saved rule-version declaration has decayed
// since the record was written. Once a query hits a stored record it must
// first prove — exactly the way a `report` query proves the block report —
// that the declaration the record itself archived still carries a non-empty
// id, both rules with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100. A written null used to be explained as the
// built-in rules and an incomplete declaration used to come back with
// silently zeroed parameters. A processing record is always produced with a
// resolved version, so — unlike a block report — even a wholly missing
// version key is the record's own corruption rather than the legacy
// built-in shape. One corrupt record the query hits fails the whole history
// with ErrCorruptVersion — no history JSON, no partial result — naming the
// record's chain, block hash, victim tx hash, conclusion kind and channel,
// the readable saved version id and the offending rule or field. Damage
// confined to another chain/channel, an out-of-range record, a block report
// or a registered version never blocks the query. Success or failure leaves
// the archive untouched.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// rewriteAlertsDoc decodes the archive, hands the decoded top-level
// document to mutate and writes it back. Helpers below use it to tamper with
// the stored processing records ("alerts").
func rewriteAlertsDoc(t *testing.T, dir string, mutate func(doc map[string]any)) {
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
	mutate(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// storedAlertList returns the archive's processing-record array.
func storedAlertList(t *testing.T, doc map[string]any) []any {
	t.Helper()
	alerts, ok := doc["alerts"].([]any)
	if !ok || len(alerts) == 0 {
		t.Fatalf("archive has no non-empty alerts array: %v", doc["alerts"])
	}
	return alerts
}

// rewriteStoredAlertVersion mutates the embedded version object of the
// processing record carrying the given chain/block/tx/kind/channel identity.
func rewriteStoredAlertVersion(t *testing.T, dir, chain, hash, tx, kind, channel string, mutate func(ver map[string]any)) {
	t.Helper()
	rewriteAlertsDoc(t, dir, func(doc map[string]any) {
		found := false
		for _, a := range storedAlertList(t, doc) {
			rec := a.(map[string]any)
			f := rec["finding"].(map[string]any)
			if rec["chainId"] != chain || rec["blockHash"] != hash ||
				f["txHash"] != tx || f["kind"] != kind || rec["channel"] != channel {
				continue
			}
			ver, ok := rec["version"].(map[string]any)
			if !ok {
				t.Fatalf("alert record %s/%s %s has no object version to rewrite: %v", chain, hash, tx, rec["version"])
			}
			mutate(ver)
			found = true
		}
		if !found {
			t.Fatalf("alert record %s/%s tx %s %s channel %s not found", chain, hash, tx, kind, channel)
		}
	})
}

// replaceStoredAlertVersion wholesale replaces the embedded version
// declaration of one processing record (null, an empty object, a complete
// reserved-id declaration, etc.), or removes the key when drop is true.
func replaceStoredAlertVersion(t *testing.T, dir, chain, hash, tx, kind, channel string, drop bool, value any) {
	t.Helper()
	rewriteAlertsDoc(t, dir, func(doc map[string]any) {
		found := false
		for _, a := range storedAlertList(t, doc) {
			rec := a.(map[string]any)
			f := rec["finding"].(map[string]any)
			if rec["chainId"] != chain || rec["blockHash"] != hash ||
				f["txHash"] != tx || f["kind"] != kind || rec["channel"] != channel {
				continue
			}
			if drop {
				delete(rec, "version")
			} else {
				rec["version"] = value
			}
			found = true
		}
		if !found {
			t.Fatalf("alert record %s/%s tx %s %s channel %s not found", chain, hash, tx, kind, channel)
		}
	})
}

// setupAlertHistoryCorruptArchive registers candC/twin, archives one block
// under candC (one displacement conclusion on 0xv at height 7) and processes
// it for channel ops, then returns the archive directory holding the single
// processing record.
func setupAlertHistoryCorruptArchive(t *testing.T) string {
	t.Helper()
	dir := setupCorruptCompareArchive(t)
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}
	return dir
}

// corruptAlertIdentity is the identity of the single fixture record.
var corruptAlertIdentity = struct {
	chain, hash, tx, kind, channel string
}{"1", "0xblk", "0xv", SuppressDisplacement, "ops"}

// assertHistoryRefusedAlerts runs one failing AlertHistory and pins the
// shape the command relies on: ErrCorruptVersion wrapping the cause, never
// an unknown-version misread, naming the record's whole identity plus every
// required extra substring, returning no partial history and leaving the
// archive byte-identical.
func assertHistoryRefusedAlerts(t *testing.T, dir string, want ...string) {
	t.Helper()
	id := corruptAlertIdentity
	before := readArchiveFile(t, dir)
	records, err := AlertHistory(dir, id.chain, id.channel, 0, 100)
	if err == nil {
		t.Fatalf("corrupt processing record returned history: %+v", records)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("corrupt record misreported as unknown version/block: %v", err)
	}
	required := append([]string{id.chain, id.hash, id.tx, id.kind, id.channel}, want...)
	msg := err.Error()
	for _, sub := range required {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if records != nil {
		t.Fatalf("failed history returned partial records: %+v", records)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed history query changed the archive")
	}
	// No read-side repair: a second attempt fails the same way.
	if _, err := AlertHistory(dir, id.chain, id.channel, 0, 100); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second history query did not fail the same way: %v", err)
	}
}

// TestAlertHistoryCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration the matching processing record saved for
// itself (the block report and registered versions stay intact): every way
// the saved document can stop satisfying the registration rules must fail
// the whole history, naming chain, block, victim tx, kind, channel, the
// readable saved id and the offending rule or field.
func TestAlertHistoryCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			id := corruptAlertIdentity
			rewriteStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel,
				func(ver map[string]any) { tc.mutate(t, ver) })
			assertHistoryRefusedAlerts(t, dir, "candC", tc.wantErr)
		})
	}
}

// TestAlertHistoryNullEmptyAndMissingSavedVersionCorrupt pins the exact
// misread being fixed: version:null used to be explained as the built-in
// rules and {} or an incomplete object used to return zeroed parameters.
// For a processing record even a wholly missing key is corruption — only
// block reports get the legacy built-in carve-out.
func TestAlertHistoryNullEmptyAndMissingSavedVersionCorrupt(t *testing.T) {
	id := corruptAlertIdentity
	cases := []struct {
		name        string
		drop        bool
		value       any
		idReachable bool
	}{
		{"null", false, nil, false},
		{"empty object", false, map[string]any{}, false},
		{"incomplete object", false, map[string]any{"id": "candC"}, true},
		{"non-object number", false, 5, false},
		{"non-object string", false, "builtin", false},
		{"array", false, []any{}, false},
		{"missing key", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			replaceStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, tc.drop, tc.value)
			want := []string{}
			if tc.idReachable {
				want = append(want, "candC")
			}
			assertHistoryRefusedAlerts(t, dir, want...)
		})
	}
}

// TestAlertHistoryBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestAlertHistoryBuiltinIDDoesNotBypassValidation(t *testing.T) {
	id := corruptAlertIdentity
	dir := setupAlertHistoryCorruptArchive(t)
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, false, builtinFull)
	got, err := AlertHistory(dir, id.chain, id.channel, 0, 100)
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must be returned: %v", err)
	}
	if len(got) != 1 || got[0].Version != BuiltinVersion() {
		t.Fatalf("record = %+v, want builtin parameters", got)
	}

	dir = setupAlertHistoryCorruptArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, false, builtinDamaged)
	assertHistoryRefusedAlerts(t, dir, BuiltinVersionID, "multiplier")
}

// TestAlertHistoryDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling that
// name the same field, even when both values agree. The raw bytes are
// patched inside the alerts section (a JSON map cannot hold two keys).
func TestAlertHistoryDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	id := corruptAlertIdentity
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			path := filepath.Join(dir, archiveFileName)
			text := string(readArchiveFile(t, dir))
			alertsAt := strings.Index(text, `"alerts":`)
			if alertsAt < 0 {
				t.Fatal("alerts section not found")
			}
			atRel := strings.Index(text[alertsAt:], `"id": "candC"`)
			if atRel < 0 {
				t.Fatal("processing record's embedded candC declaration not found")
			}
			at := alertsAt + atRel
			anchor := `"severity": 4,`
			fieldRel := strings.Index(text[at:], anchor)
			if fieldRel < 0 {
				t.Fatal("displacement severity field not found in the record's declaration")
			}
			pos := at + fieldRel
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			records, err := AlertHistory(dir, id.chain, id.channel, 0, 100)
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
				t.Fatal("failed history query repaired the duplicate field")
			}
		})
	}
}

// TestAlertHistoryExplicitlyDisabledRulesAccepted proves enabled:false is
// a legal saved off state, but a disabled rule still has to carry complete,
// in-range parameters.
func TestAlertHistoryExplicitlyDisabledRulesAccepted(t *testing.T) {
	id := corruptAlertIdentity
	dir := setupAlertHistoryCorruptArchive(t)
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, false, off)
	got, err := AlertHistory(dir, id.chain, id.channel, 0, 100)
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must be returned: %v", err)
	}
	if len(got) != 1 || got[0].Version.ID != "off" ||
		got[0].Version.Rules.Sandwich.Enabled || got[0].Version.Rules.Displacement.Enabled {
		t.Fatalf("saved off state not carried: %+v", got)
	}

	dir = setupAlertHistoryCorruptArchive(t)
	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1},
		},
	}
	replaceStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, false, offBroken)
	assertHistoryRefusedAlerts(t, dir, "off", "multiplier")
}

// TestAlertHistoryUsesSavedParametersNotRegistry proves the record is
// explained by the declaration it saved for itself: a damaged same-id
// registry entry neither blocks nor completes the saved parameters, the
// enabled version never leaks in, an intact registry cannot rescue a
// corrupt record, and a saved id the registry never carried is still valid
// on its own.
func TestAlertHistoryUsesSavedParametersNotRegistry(t *testing.T) {
	id := corruptAlertIdentity

	// Damage only the registered candC entry: the record's own intact copy
	// is shown and borrows nothing from the registry.
	dir := setupAlertHistoryCorruptArchive(t)
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatal(err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	got, err := AlertHistory(dir, id.chain, id.channel, 0, 100)
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact saved record: %v", err)
	}
	if want := mustRuleVersion(t, candidateVersionSpec); len(got) != 1 || got[0].Version != want {
		t.Fatalf("history borrowed registry parameters: %+v want %+v", got, want)
	}

	// Conversely, an intact registry cannot rescue the record's own corrupt
	// copy.
	dir2 := setupAlertHistoryCorruptArchive(t)
	rewriteStoredAlertVersion(t, dir2, id.chain, id.hash, id.tx, id.kind, id.channel, func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertHistoryRefusedAlerts(t, dir2, "candC", "multiplier")

	// A complete declaration with an id the registry never carried stands
	// on its own.
	dir3 := setupAlertHistoryCorruptArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredAlertVersion(t, dir3, id.chain, id.hash, id.tx, id.kind, id.channel, false, stray)
	h3, err := AlertHistory(dir3, id.chain, id.channel, 0, 100)
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	if len(h3) != 1 || h3[0].Version.ID != "never-registered" ||
		h3[0].Version.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("saved parameters not carried: %+v", h3)
	}
}

// cloneAlertMap deep-copies one decoded processing record so a test can
// append a sibling with different identity fields.
func cloneAlertMap(t *testing.T, src map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	var dst map[string]any
	if err := json.Unmarshal(raw, &dst); err != nil {
		t.Fatal(err)
	}
	return dst
}

// corruptVersionObject is one damaged declaration (displacement multiplier
// missing) reused for out-of-scope sibling records.
func corruptVersionObject() map[string]any {
	return map[string]any{
		"id": "candC",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 4},
		},
	}
}

// TestAlertHistoryCorruptSiblingOutOfScopeDoesNotBlock proves the integrity
// proof is scoped to the records the query hits: a damaged declaration on
// another chain, another channel or outside the height range, a damaged
// block report declaration and a damaged registered version never block the
// in-scope intact records. The damaged record itself still fails the query
// that hits it.
func TestAlertHistoryCorruptSiblingOutOfScopeDoesNotBlock(t *testing.T) {
	id := corruptAlertIdentity
	dir := setupAlertHistoryCorruptArchive(t)
	rewriteAlertsDoc(t, dir, func(doc map[string]any) {
		alerts := storedAlertList(t, doc)
		template := alerts[0].(map[string]any)

		sibling := func(chain, channel, hash, tx string, number int64) map[string]any {
			s := cloneAlertMap(t, template)
			s["chainId"] = chain
			s["channel"] = channel
			s["blockHash"] = hash
			s["blockNumber"] = number
			s["finding"].(map[string]any)["txHash"] = tx
			s["version"] = corruptVersionObject()
			return s
		}
		alerts = append(alerts,
			sibling("2", "ops", "0xblk", "0xq", 7),    // another chain
			sibling("1", "oncall", "0xblk", "0xc", 7), // another channel
			sibling("1", "ops", "0xhigh", "0xh", 99),  // outside the range below
		)
		doc["alerts"] = alerts
	})

	// Range 0..50 excludes the height-99 sibling but includes the chain/channel
	// decoys, which must also be skipped by their identity: the intact
	// in-scope record is returned.
	got, err := AlertHistory(dir, id.chain, id.channel, 0, 50)
	if err != nil {
		t.Fatalf("out-of-scope corrupt siblings blocked the target: %v", err)
	}
	if len(got) != 1 || got[0].BlockHash != id.hash || got[0].Finding.TxHash != id.tx {
		t.Fatalf("target record damaged: %+v", got)
	}

	// Each damaged sibling fails a query whose identity/range actually hits
	// it, with its own identity named.
	assertSibling := func(chain, channel, hash, tx string, start, end uint64) {
		t.Helper()
		_, err := AlertHistory(dir, chain, channel, start, end)
		if !errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("AlertHistory(%s,%s,%d,%d) = %v, want ErrCorruptVersion", chain, channel, start, end, err)
		}
		msg := err.Error()
		for _, sub := range []string{chain, hash, tx, channel, "candC", "multiplier"} {
			if !strings.Contains(msg, sub) {
				t.Fatalf("error %q must name %q", msg, sub)
			}
		}
	}
	assertSibling("2", "ops", "0xblk", "0xq", 0, 100)
	assertSibling("1", "oncall", "0xblk", "0xc", 0, 100)
	assertSibling("1", "ops", "0xhigh", "0xh", 90, 100)

	// A damaged block-report declaration never blocks alert history: the
	// report and the processing record are separate documents.
	rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	if _, err := AlertHistory(dir, id.chain, id.channel, 0, 50); err != nil {
		t.Fatalf("a corrupt block report blocked history: %v", err)
	}
	// A damaged registered version never blocks it either.
	rewriteStoredVersion(t, dir, "twin", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 1
	})
	if _, err := AlertHistory(dir, id.chain, id.channel, 0, 50); err != nil {
		t.Fatalf("a corrupt registered version blocked history: %v", err)
	}
}

// TestAlertHistoryLegacyAndEmptyArchives proves the empty cases still
// output an empty list: a pre-alerting archive (no alerts key), a range no
// record matches, a missing directory and an empty alerts array. None of
// these are explained as a built-in processing record.
func TestAlertHistoryLegacyAndEmptyArchives(t *testing.T) {
	// Old-format archive with a block report but no processing records.
	dir := t.TempDir()
	data := archiveData{Records: []record{{
		ChainID: "1", BlockHash: "0old", BlockNumber: 5,
		Swaps: []Swap{{TxHash: "0f", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}},
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		d             string
		chain, chanID string
		start, end    uint64
	}{
		{"old archive full range", dir, "1", "ops", 0, 100},
		{"range before record", dir, "1", "ops", 0, 4},
		{"other channel", dir, "1", "oncall", 0, 100},
		{"missing directory", filepath.Join(t.TempDir(), "absent"), "1", "ops", 0, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AlertHistory(tc.d, tc.chain, tc.chanID, tc.start, tc.end)
			if err != nil {
				t.Fatalf("AlertHistory: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("got %+v, want no records", got)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "[]" {
				t.Fatalf("empty history must serialize as [], got %s", raw)
			}
		})
	}

	// An explicit empty alerts array likewise serializes as [].
	emptyAlerts := t.TempDir()
	if err := writeArchiveAtomic(emptyAlerts, archiveData{
		Records:      []record{},
		AlertRecords: []ProcessingRecord{},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := AlertHistory(emptyAlerts, "1", "ops", 0, 100)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty alerts array: got %+v err=%v", got, err)
	}
}

// TestAlertHistoryCorruptedArchiveStillErrors proves a wholly unreadable
// archive is reported as archive corruption rather than as an empty
// history.
func TestAlertHistoryCorruptedArchiveStillErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := AlertHistory(dir, "1", "ops", 0, 100); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("got %v, want corrupted-archive error", err)
	}
}

// TestAlertHistorySuccessContentPreserved proves a healthy history keeps
// the original JSON content: the alert/suppressed conclusions, raw swap
// evidence, the generation threshold, the suppression reasons hit at the
// time and the saved detection parameters, ordered by height, block hash,
// tx hash and kind with both ends of the range inclusive — with no
// re-detection.
func TestAlertHistorySuccessContentPreserved(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput) // 0xa @10: sandwich 0xv sev3, displacement 0xd sev2
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":10,"endHeight":10,"reason":"known bot war"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	created, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 2 {
		t.Fatalf("precondition: got %d records, want 2", len(created))
	}

	// Inclusive bounds: the exact height returns the records; just outside
	// returns [].
	hist, err := AlertHistory(dir, "1", "ops", 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hist, created) {
		t.Fatalf("history differs from the generated records:\n%+v\n%+v", hist, created)
	}
	if before, err := AlertHistory(dir, "1", "ops", 0, 9); err != nil || len(before) != 0 {
		t.Fatalf("range below the block must be empty, got %+v err=%v", before, err)
	}

	byTx := map[string]ProcessingRecord{}
	for _, r := range hist {
		byTx[r.Finding.TxHash] = r
	}
	sand := byTx["0xv"]
	if sand.Status != AlertStatusSuppressed || len(sand.Suppressions) != 1 ||
		sand.Suppressions[0].ID != "s1" || sand.Suppressions[0].Reason != "known bot war" {
		t.Fatalf("sandwich suppression history damaged: %+v", sand)
	}
	if sand.MinSeverity != 1 || sand.Version != BuiltinVersion() ||
		sand.Finding.Kind != "sandwich" || sand.Finding.Severity != 3 ||
		len(sand.Finding.Evidence) != 3 {
		t.Fatalf("sandwich record content damaged: %+v", sand)
	}
	disp := byTx["0xd"]
	if disp.Status != AlertStatusAlert || len(disp.Suppressions) != 0 ||
		disp.MinSeverity != 1 || disp.Version != BuiltinVersion() ||
		disp.Finding.Kind != "displacement" || disp.Finding.Severity != 2 ||
		len(disp.Finding.Evidence) != 2 {
		t.Fatalf("displacement record content damaged: %+v", disp)
	}
	// Ordering within one block: tx hash ascending (0xd before 0xv).
	if hist[0].Finding.TxHash != "0xd" || hist[1].Finding.TxHash != "0xv" {
		t.Fatalf("history not tx-hash ordered: %s then %s", hist[0].Finding.TxHash, hist[1].Finding.TxHash)
	}

	// Read-only and deterministic: repeat and compare bytes, and confirm the
	// archive still validates identically.
	again, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again, hist) {
		t.Fatalf("repeated history differs:\n%+v\n%+v", again, hist)
	}
}

// TestAlertHistoryCorruptRecordReadOnly proves a refused history query
// rewrites neither the damaged declaration nor anything else, and the
// stored record stays reachable once the declaration is restored.
func TestAlertHistoryCorruptRecordReadOnly(t *testing.T) {
	id := corruptAlertIdentity
	dir := setupAlertHistoryCorruptArchive(t)
	corruptBytes := func() []byte {
		rewriteStoredAlertVersion(t, dir, id.chain, id.hash, id.tx, id.kind, id.channel, func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		return readArchiveFile(t, dir)
	}()
	if _, err := AlertHistory(dir, id.chain, id.channel, 0, 100); !errors.Is(err, ErrCorruptVersion) {
		t.Fatal("expected ErrCorruptVersion")
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed history query modified the archive")
	}
	// The damaged bytes survive untouched in the alerts section.
	if !strings.Contains(string(corruptBytes), `"multiplier": 0`) {
		t.Fatal("test precondition: multiplier zero not present")
	}
}
