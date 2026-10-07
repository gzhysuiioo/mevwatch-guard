package mevwatch

// Regression coverage for `suppressions register` over an archive whose
// stored reports carry decayed rule-version declarations. Registering a
// condition rewrites the archive, so every report's saved declaration must
// first be proved with the same integrity rules a report query applies —
// a report on another chain, outside the new condition's pool/height
// coverage or without conclusions is never skipped. One corrupt declaration
// fails the whole registration with ErrCorruptVersion before anything is
// written: no result, no new condition, and the damaged declaration itself
// left byte for byte in place — a written null must never resurface as a
// missing version key a later report query explains as the built-in rules.
// Only a record with no version key at all keeps the legacy built-in
// interpretation.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// registerNewSuppressionSpec is a legal condition the fixtures never carry:
// it shares the archived block's chain, pool and displacement kind and
// covers its height, so a run that wrongly skipped the integrity proof
// because the new condition "did not touch" the block could not pass by
// accident.
const registerNewSuppressionSpec = `{"id":"s2","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"new maintenance window"}`

// assertRegisterRefused runs one failing RegisterSuppression and pins the
// shape the command relies on: ErrCorruptVersion wrapping the cause, never
// an idempotent no-op or a conflict misread, naming chain and block plus
// every required extra substring, the archive byte-identical afterwards and
// the submitted condition absent from the stored condition list.
func assertRegisterRefused(t *testing.T, dir, spec, id string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	cond, created, err := RegisterSuppression(dir, []byte(spec))
	if err == nil {
		t.Fatalf("corrupt archive accepted the registration: created=%v %+v", created, cond)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrSuppressionConflict) || errors.Is(err, ErrUnknownKind) {
		t.Fatalf("corrupt report misreported as a spec/conflict failure: %v", err)
	}
	msg := err.Error()
	for _, sub := range want {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if created {
		t.Fatal("failed registration reported creation")
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed registration changed the archive")
	}
	var doc struct {
		Suppressions []Suppression `json:"suppressions"`
	}
	if err := json.Unmarshal(before, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Suppressions {
		if c.ID == id {
			t.Fatalf("failed registration left condition %q in the archive", id)
		}
	}
	// The failure is not a write-side repair: registering again fails the
	// same way.
	if _, _, err := RegisterSuppression(dir, []byte(spec)); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second registration did not fail the same way: %v", err)
	}
}

// TestRegisterSuppressionCorruptSavedVersionRefused runs the full corruption
// matrix against the declaration embedded in the archived report: every way
// the saved document can stop satisfying the registration rules must fail
// the whole registration with ErrCorruptVersion, naming chain, block, the
// saved id and the offending rule or field.
func TestRegisterSuppressionCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupRevokeCorruptArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertRegisterRefused(t, dir, registerNewSuppressionSpec, "s2",
				"1", "0xblk", "candC", tc.wantErr)
		})
	}
}

// TestRegisterSuppressionNullAndEmptySavedVersionCorrupt pins the exact
// misread being fixed: a saved version:null used to decode into a typed
// record the save then dropped, rewriting the corrupt report into the
// legacy no-version shape a report query reads as built-in. Null, {}, an
// incomplete object and non-object declarations must all fail as
// corruption, and the failed registration must leave the damaged
// declaration exactly as it was.
func TestRegisterSuppressionNullAndEmptySavedVersionCorrupt(t *testing.T) {
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
			assertRegisterRefused(t, dir, registerNewSuppressionSpec, "s2", "1", "0xblk")
			if tc.name == "null" {
				// The written null survived the failed registration as a
				// null, not as a dropped version key.
				text := string(readArchiveFile(t, dir))
				if !strings.Contains(text, `"version": null`) {
					t.Fatalf("failed registration rewrote the null declaration:\n%s", text)
				}
			}
		})
	}
}

// TestRegisterSuppressionCorruptReportNeverSkipped proves the integrity
// proof covers every report in the archive, regardless of the new
// condition's coverage: a decayed declaration fails the registration even
// when the report sits on another chain, outside the condition's chain/
// pool/height window, or carries no conclusions at all.
func TestRegisterSuppressionCorruptReportNeverSkipped(t *testing.T) {
	t.Run("outside new condition coverage", func(t *testing.T) {
		// The fixture condition s1 spans heights 100-200 and the block sits
		// at height 7; register a fresh condition that also misses it.
		dir := setupRevokeCorruptArchive(t)
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		misses := `{"id":"s9","chainId":"9","pool":"other","kind":"sandwich","channel":"other","startHeight":1000,"endHeight":2000,"reason":"far away"}`
		assertRegisterRefused(t, dir, misses, "s9", "1", "0xblk")
	})

	t.Run("report on another chain", func(t *testing.T) {
		dir := setupRevokeCorruptArchive(t)
		mustReplay(t, dir, `{"chainId":"2","blockHash":"0xother","blockNumber":5,"swaps":[]}`)
		replaceStoredReportVersion(t, dir, "2", "0xother", nil)
		assertRegisterRefused(t, dir, registerNewSuppressionSpec, "s2", "2", "0xother")
	})

	t.Run("report without conclusions", func(t *testing.T) {
		dir := setupRevokeCorruptArchive(t)
		stripFindings(t, dir, "0xblk")
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		assertRegisterRefused(t, dir, registerNewSuppressionSpec, "s2", "1", "0xblk")
	})
}

// TestRegisterSuppressionCorruptArchiveBlocksRetryAndConflict proves the
// declarations are proved before id reuse is judged: over a corrupt archive
// an identical-content retry must not return created:false and a different
// document must not return a conflict — both fail as corruption and change
// nothing, so neither path can mask the damaged report.
func TestRegisterSuppressionCorruptArchiveBlocksRetryAndConflict(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)

	// Same id, same content: normally an idempotent no-op success.
	if _, created, err := RegisterSuppression(dir, []byte(revocationSpec)); err == nil || created {
		t.Fatalf("identical retry over a corrupt archive: created=%v err=%v", created, err)
	} else if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("identical retry error = %v, want ErrCorruptVersion", err)
	}

	// Same id, different content: normally a conflict.
	conflicting := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"changed reason"}`
	if _, _, err := RegisterSuppression(dir, []byte(conflicting)); !errors.Is(err, ErrCorruptVersion) ||
		errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("different-content retry error = %v, want ErrCorruptVersion (not a conflict)", err)
	}
}

// TestRegisterSuppressionLegacyRecordWithoutVersionKey proves only a wholly
// absent version key keeps the built-in interpretation: the registration
// succeeds and the legacy record is written back without growing a version
// key.
func TestRegisterSuppressionLegacyRecordWithoutVersionKey(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	dropVersionKey(t, dir, "0xblk")
	cond, created, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("legacy record must not block registration: created=%v err=%v", created, err)
	}
	if cond.ID != "s2" || cond.Revoked {
		t.Fatalf("new condition returned wrong: %+v", cond)
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

// TestRegisterSuppressionBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" is validated like any other saved declaration: a complete one
// registers normally, a damaged one fails as corruption rather than being
// replaced by the in-code builtin.
func TestRegisterSuppressionBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	if _, created, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec)); err != nil || !created {
		t.Fatalf("a complete builtin-id declaration must not block registration: created=%v err=%v", created, err)
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
	assertRegisterRefused(t, dir, registerNewSuppressionSpec, "s2", BuiltinVersionID, "multiplier")
}

// TestRegisterSuppressionDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including a case-only spelling and an escaped spelling that
// name the same field — rejected even when both values agree. The raw bytes
// are patched directly because a JSON map cannot hold two keys.
func TestRegisterSuppressionDuplicateFieldsInSavedVersionRefused(t *testing.T) {
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
			_, _, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec))
			if err == nil {
				t.Fatal("duplicate-field declaration allowed the registration")
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); after == nil || !strings.Contains(string(after), dup.field) {
				t.Fatal("failed registration repaired the duplicate field")
			}
		})
	}
}

// TestRegisterSuppressionDisabledAndUnregisteredDeclarationsAccepted proves
// a legal declaration never blocks the registration: an explicit
// enabled:false is a legal off state, and the saved id need not still be
// registered — the declaration is used exactly as saved, never completed
// from the enabled or a same-id registered version.
func TestRegisterSuppressionDisabledAndUnregisteredDeclarationsAccepted(t *testing.T) {
	dir := setupRevokeCorruptArchive(t)
	ghost := map[string]any{
		"id": "ghost",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", ghost)
	if _, created, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec)); err != nil || !created {
		t.Fatalf("unregistered but complete declaration must not block registration: created=%v err=%v", created, err)
	}
	// The saved declaration survived the commit with its own parameters,
	// never values pulled from the enabled or a same-id registered version.
	text := string(readArchiveFile(t, dir))
	if !strings.Contains(text, `"ghost"`) || !strings.Contains(text, `"multiplier": 100`) {
		t.Fatalf("saved declaration was rewritten:\n%s", text)
	}
}

// TestRegisterSuppressionSuccessAppendsOnlyTheCondition proves a healthy
// archive still only gains the one new condition: reports (kept as raw
// stored documents), the versions registry, the enabled marker, existing
// processing records and reviews are all written back unchanged, and the
// normal idempotent-retry and conflict behaviors survive.
func TestRegisterSuppressionSuccessAppendsOnlyTheCondition(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	if _, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatal(err)
	}
	// s1 pre-exists, with one alert already generated against it. Under
	// candC the sandwich rule is off, so the archived conclusion on
	// 0xvictim is a displacement.
	if _, _, err := RegisterSuppression(dir, []byte(
		`{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"r"}`,
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, ReviewSubmission{
		ChainID: "1", BlockHash: "0xa", TxHash: "0xvictim", Kind: "displacement",
		SubmissionID: "rev-1", Operator: "alice", Reason: "looks fine",
		Status: ReviewStatusFalsePositive, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	before := mustReplayDoc(t, filepath.Join(dir, archiveFileName))

	cond, created, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("register s2: created=%v cond=%+v err=%v", created, cond, err)
	}
	if cond.Revoked {
		t.Fatalf("newly registered condition must carry revoked:false, got %+v", cond)
	}

	after := mustReplayDoc(t, filepath.Join(dir, archiveFileName))
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatal("registration rewrote stored reports")
	}
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatal("registration rewrote registered versions")
	}
	if before.EnabledVersion != after.EnabledVersion {
		t.Fatalf("enabled marker changed: %q -> %q", before.EnabledVersion, after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.AlertRecords, after.AlertRecords) {
		t.Fatal("registration rewrote processing records")
	}
	if !reflect.DeepEqual(before.Reviews, after.Reviews) {
		t.Fatal("registration rewrote reviews")
	}
	if len(after.Suppressions) != len(before.Suppressions)+1 {
		t.Fatalf("suppression count = %d, want %d (append only)",
			len(after.Suppressions), len(before.Suppressions)+1)
	}

	// Same id, same content stays an idempotent no-op after the fix.
	if again, created2, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec)); err != nil || created2 {
		t.Fatalf("identical retry: created=%v err=%v", created2, err)
	} else if again.ID != "s2" {
		t.Fatalf("identical retry returned %+v", again)
	}
	// Same id, different content stays a conflict that writes nothing.
	conflict := `{"id":"s2","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"other"}`
	if _, _, err := RegisterSuppression(dir, []byte(conflict)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("conflict error = %v, want ErrSuppressionConflict", err)
	}
}

// TestRegisterSuppressionEmptyArchiveUnchanged proves an archive without
// reports still registers normally: the all-reports proof has nothing to
// open, and it must not invent a failure for the no-records case.
func TestRegisterSuppressionEmptyArchiveUnchanged(t *testing.T) {
	dir := t.TempDir()
	cond, created, err := RegisterSuppression(dir, []byte(registerNewSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("empty archive registration: created=%v cond=%+v err=%v", created, cond, err)
	}
	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != "s2" || listed[0].Revoked {
		t.Fatalf("listed conditions = %+v", listed)
	}
}
