package mevwatch

// Regression coverage for `suppressions revoke` over an archive whose
// stored reports carry decayed rule-version declarations. Revoking a
// registered condition rewrites the archive, so every report's saved
// declaration must first be proved with the same integrity rules a report
// query applies — a report on another chain, outside the condition's
// coverage or without conclusions is never skipped. One corrupt
// declaration fails the whole revocation with ErrCorruptVersion before
// anything is written: no result, no flipped revoked flag, and the damaged
// declaration itself left byte for byte in place — a written null must
// never resurface as a missing version key. Only a record with no version
// key at all keeps the legacy built-in interpretation.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// setupRevokeCorruptArchive archives one block on chain "1" (0xblk at
// height 7 under candC) and registers the revocation fixture condition s1
// (heights 100-200, so the block is outside the condition's coverage).
func setupRevokeCorruptArchive(t *testing.T) string {
	t.Helper()
	dir := setupCorruptCompareArchive(t)
	registerRevocationSpec(t, dir)
	return dir
}

// assertRevokeRefused runs one failing RevokeSuppression and pins the shape
// the command relies on: ErrCorruptVersion wrapping the cause, never an
// unknown-suppression misread, naming the target chain and block plus every
// required extra substring, the archive byte-identical afterwards and the
// condition's revoked flag still wantRevoked.
func assertRevokeRefused(t *testing.T, dir, id string, wantRevoked bool, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	cond, changed, err := RevokeSuppression(dir, id)
	if err == nil {
		t.Fatalf("corrupt archive revoked %q: changed=%v %+v", id, changed, cond)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownSuppression) || errors.Is(err, ErrUnknownBlock) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt report misreported as unknown suppression/block/version: %v", err)
	}
	msg := err.Error()
	for _, sub := range want {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if changed {
		t.Fatal("failed revocation reported a state change")
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed revocation changed the archive")
	}
	// The condition kept its revoked flag. ListSuppressions cannot be
	// asked here — its typed decode of the records trips over the corrupt
	// declaration — so the flag is read off the raw archive document.
	var doc struct {
		Suppressions []Suppression `json:"suppressions"`
	}
	if err := json.Unmarshal(before, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Suppressions {
		if c.ID == id && c.Revoked != wantRevoked {
			t.Fatalf("failed revocation flipped the condition: %+v", c)
		}
	}
	// The failure is not a write-side repair: revoking again fails the
	// same way.
	if _, _, err := RevokeSuppression(dir, id); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second revoke did not fail the same way: %v", err)
	}
}

// TestRevokeCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the archived report: every way the
// saved document can stop satisfying the registration rules must fail the
// whole revocation with ErrCorruptVersion, naming chain, block, the saved
// id and the offending rule or field.
func TestRevokeCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupRevokeCorruptArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertRevokeRefused(t, dir, "s1", false, "1", "0xblk", "candC", tc.wantErr)
		})
	}
}

// TestRevokeNullAndEmptySavedVersionCorrupt pins the exact misread being
// fixed: a saved version:null used to decode into a nil pointer the save
// then dropped, rewriting the corrupt report into the legacy no-version
// shape a report query reads as built-in. Null, {}, an incomplete object
// and non-object declarations must all fail as corruption, and the failed
// revocation must leave the damaged declaration exactly as it was.
func TestRevokeNullAndEmptySavedVersionCorrupt(t *testing.T) {
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
			dir := setupRevokeCorruptArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xblk", tc.value)
			assertRevokeRefused(t, dir, "s1", false, "1", "0xblk")
			if tc.name == "null" {
				// The written null survived the failed revocation as a
				// null, not as a dropped version key.
				text := string(readArchiveFile(t, dir))
				if !strings.Contains(text, `"version": null`) {
					t.Fatalf("failed revocation rewrote the null declaration:\n%s", text)
				}
			}
		})
	}
}

// TestRevokeCorruptReportNeverSkipped proves the integrity proof covers
// every report in the archive: a decayed declaration fails the revocation
// even when the report sits on another chain, outside the condition's
// height coverage, or carries no conclusions at all.
func TestRevokeCorruptReportNeverSkipped(t *testing.T) {
	t.Run("outside condition coverage", func(t *testing.T) {
		// s1 covers heights 100-200; 0xblk sits at height 7 and its pool,
		// kind and channel never match either — the decayed declaration
		// still fails the revocation.
		dir := setupRevokeCorruptArchive(t)
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		assertRevokeRefused(t, dir, "s1", false, "1", "0xblk")
	})

	t.Run("report on another chain", func(t *testing.T) {
		dir := setupRevokeCorruptArchive(t)
		mustReplay(t, dir, `{"chainId":"2","blockHash":"0xother","blockNumber":5,"swaps":[]}`)
		replaceStoredReportVersion(t, dir, "2", "0xother", nil)
		assertRevokeRefused(t, dir, "s1", false, "2", "0xother")
	})

	t.Run("report without conclusions", func(t *testing.T) {
		dir := setupRevokeCorruptArchive(t)
		stripFindings(t, dir, "0xblk")
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		assertRevokeRefused(t, dir, "s1", false, "1", "0xblk")
	})
}

// TestRevokeAlreadyRevokedStillProvesReports proves an idempotent
// re-revoke cannot mask existing damage: once the condition is registered
// the declarations are proved before the already-revoked state is
// reported, so a second revoke over a since-decayed report fails as
// corruption instead of returning changed:false.
func TestRevokeAlreadyRevokedStillProvesReports(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("first revoke: changed=%v err=%v", changed, err)
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
	assertRevokeRefused(t, dir, "s1", true, "1", "0xblk")
}

// TestRevokeUnknownConditionOnCorruptArchive proves an id that was never
// registered keeps its existing error even when a stored report is
// corrupt: the declaration proof only runs for a registered condition.
func TestRevokeUnknownConditionOnCorruptArchive(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
	before := readArchiveFile(t, dir)
	if _, _, err := RevokeSuppression(dir, "nope"); !errors.Is(err, ErrUnknownSuppression) {
		t.Fatalf("got %v, want ErrUnknownSuppression", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed revocation changed the archive")
	}
}

// TestRevokeLegacyRecordWithoutVersionKey proves only a wholly absent
// version key keeps the built-in interpretation: the revocation succeeds
// and the legacy record is written back without growing a version key.
func TestRevokeLegacyRecordWithoutVersionKey(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	dropVersionKey(t, dir, "0xblk")
	cond, changed, err := RevokeSuppression(dir, "s1")
	if err != nil || !changed {
		t.Fatalf("legacy record must not block revocation: changed=%v err=%v", changed, err)
	}
	if !cond.Revoked {
		t.Fatalf("revoked condition must carry revoked:true, got %+v", cond)
	}
	var doc struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	for _, rec := range doc.Records {
		if rec["blockHash"] == "0xblk" {
			if _, ok := rec["version"]; ok {
				t.Fatalf("legacy record grew a version key: %v", rec)
			}
		}
	}
}

// TestRevokeBuiltinIDDoesNotBypassValidation proves an id of "builtin" is
// validated like any other saved declaration: a complete one revokes
// normally, a damaged one fails as corruption rather than being replaced
// by the in-code builtin.
func TestRevokeBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("a complete builtin-id declaration must not block revocation: changed=%v err=%v", changed, err)
	}

	dir = setupRevokeCorruptArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertRevokeRefused(t, dir, "s1", false, BuiltinVersionID, "multiplier")
}

// TestRevokeDuplicateFieldsInSavedVersionRefused covers decay registration
// could never have produced: a repeated field in the saved declaration,
// including a case-only spelling and an escaped spelling that name the
// same field — rejected even when both values agree. The raw bytes are
// patched directly because a JSON map cannot hold two keys.
func TestRevokeDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupRevokeCorruptArchive(t)
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
			_, _, err := RevokeSuppression(dir, "s1")
			if err == nil {
				t.Fatal("duplicate-field declaration allowed the revocation")
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatal("failed revocation repaired the duplicate field")
			}
		})
	}
}

// TestRevokeDisabledAndUnregisteredDeclarationsAccepted proves a legal
// declaration never blocks the revocation: an explicit enabled:false is a
// legal off state, and the saved id need not still be registered — the
// declaration is used exactly as saved, never completed from the enabled
// or a same-id registered version.
func TestRevokeDisabledAndUnregisteredDeclarationsAccepted(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	ghost := map[string]any{
		"id": "ghost",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", ghost)
	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("unregistered but complete declaration must not block revocation: changed=%v err=%v", changed, err)
	}
	// The saved declaration survived the commit with its own parameters,
	// never values pulled from the enabled or a same-id registered version.
	text := string(readArchiveFile(t, dir))
	if !strings.Contains(text, `"ghost"`) || !strings.Contains(text, `"multiplier": 100`) {
		t.Fatalf("saved declaration was rewritten:\n%s", text)
	}
}

// TestRevokeSuccessChangesOnlyTheCondition proves a successful revocation
// touches nothing but the target condition's revoked flag: reports and
// their swap evidence, the versions registry, other conditions, existing
// processing records and reviews all survive byte for byte.
func TestRevokeSuccessChangesOnlyTheCondition(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	// A second condition and a processed alert give the commit something to
	// preserve beyond the target condition.
	spec2 := `{"id":"a2","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"r2"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec2)); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatal(err)
	}

	decode := func() map[string]any {
		var doc map[string]any
		if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
	before := decode()
	cond, changed, err := RevokeSuppression(dir, "s1")
	if err != nil || !changed || !cond.Revoked {
		t.Fatalf("revoke: changed=%v cond=%+v err=%v", changed, cond, err)
	}
	after := decode()

	for _, section := range []string{"records", "versions", "enabledVersion", "alerts"} {
		if !reflect.DeepEqual(before[section], after[section]) {
			t.Fatalf("revocation rewrote the %s section", section)
		}
	}
	condsBefore, okB := before["suppressions"].([]any)
	condsAfter, okA := after["suppressions"].([]any)
	if !okB || !okA || len(condsBefore) != len(condsAfter) {
		t.Fatalf("suppressions section changed shape: %v -> %v", before["suppressions"], after["suppressions"])
	}
	for i, cb := range condsBefore {
		ca := condsAfter[i].(map[string]any)
		cbm := cb.(map[string]any)
		if cbm["id"] == "s1" {
			if cbm["revoked"] != false || ca["revoked"] != true {
				t.Fatalf("target condition's flag did not flip: %v -> %v", cbm, ca)
			}
			delete(cbm, "revoked")
			delete(ca, "revoked")
		}
		if !reflect.DeepEqual(cbm, ca) {
			t.Fatalf("condition %v changed beyond the revoked flag: %v", cbm, ca)
		}
	}
}
