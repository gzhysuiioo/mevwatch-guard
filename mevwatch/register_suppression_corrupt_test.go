package mevwatch

// Regression coverage for `suppressions register` over an archive whose
// stored reports carry decayed rule-version declarations. Registering a
// suppression condition rewrites the archive, so every report's saved
// declaration must first be proved with the same integrity rules a report
// query applies — a report on another chain, outside the new condition's
// coverage or without conclusions is never skipped. One corrupt declaration
// fails the whole registration with ErrCorruptVersion before anything is
// decided about the submitted condition (an append, an identical-retry
// no-op or a conflict): no condition is added, and the damaged declaration
// itself is left byte for byte in place — a written null must never
// resurface as a missing version key. Only a record with no version key at
// all keeps the legacy built-in interpretation.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// registerSuppressionSpec is a legal condition the fixture archive does not
// yet carry. It targets a sandwich on heights 100-200, while the fixture
// block 0xblk sits at height 7 with a displacement conclusion — the new
// condition covers none of it, which is exactly the case that must still
// open the report.
const registerSuppressionSpec = `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"known bot war"}`

// setupRegisterCorruptArchive archives the compare fixture block (chain "1",
// 0xblk at height 7 under candC) and registers no conditions yet: the
// registration under test is the one that adds one.
func setupRegisterCorruptArchive(t *testing.T) string {
	t.Helper()
	return setupCorruptCompareArchive(t)
}

// assertRegisterRefused runs one failing RegisterSuppression and pins the
// shape the command relies on: ErrCorruptVersion wrapping the cause, never a
// conflict or unknown misread, naming the target chain and block plus every
// required extra substring, the archive byte-identical afterwards and the
// submitted condition absent (and still absent after a retry).
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
		t.Fatalf("corrupt report misreported as a suppression conflict/spec error: %v", err)
	}
	msg := err.Error()
	for _, sub := range want {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if created {
		t.Fatal("failed registration reported created:true")
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed registration changed the archive")
	}
	// The condition was not added: the raw archive carries no suppression
	// with its id.
	var doc struct {
		Suppressions []Suppression `json:"suppressions"`
	}
	if err := json.Unmarshal(before, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Suppressions {
		if c.ID == id {
			t.Fatalf("failed registration added condition %+v", c)
		}
	}
	// The failure is not a write-side repair: registering again fails the
	// same way, and still adds nothing.
	if _, _, err := RegisterSuppression(dir, []byte(spec)); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second register did not fail the same way: %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed re-registration changed the archive")
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
			dir := setupRegisterCorruptArchive(t)
			rewriteStoredReportVersion(t, dir, "1", "0xblk", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			assertRegisterRefused(t, dir, registerSuppressionSpec, "s1",
				"1", "0xblk", "candC", tc.wantErr)
		})
	}
}

// TestRegisterSuppressionNullAndEmptySavedVersionCorrupt pins the exact
// misread being fixed: a saved version:null used to decode into a nil
// pointer the save then dropped, turning the corrupt report into the legacy
// no-version shape a report query reads as built-in, and a successful
// registration used to mask it. Null, {}, an incomplete object and
// non-object declarations must all fail as corruption and survive the
// failed registration exactly as stored.
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
			dir := setupRegisterCorruptArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xblk", tc.value)
			assertRegisterRefused(t, dir, registerSuppressionSpec, "s1", "1", "0xblk")
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
// proof covers every report in the archive, not just ones the new condition
// could match: a decayed declaration fails the registration even when the
// report sits on another chain, outside the condition's height coverage, or
// carries no conclusions at all.
func TestRegisterSuppressionCorruptReportNeverSkipped(t *testing.T) {
	t.Run("outside condition coverage", func(t *testing.T) {
		// The submitted condition covers heights 100-200 for a sandwich;
		// 0xblk sits at height 7 with a displacement in pool p1 and never
		// matches — its decayed declaration still fails the registration.
		dir := setupRegisterCorruptArchive(t)
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		assertRegisterRefused(t, dir, registerSuppressionSpec, "s1", "1", "0xblk")
	})

	t.Run("report on another chain", func(t *testing.T) {
		dir := setupRegisterCorruptArchive(t)
		mustReplay(t, dir, `{"chainId":"2","blockHash":"0xother","blockNumber":5,"swaps":[]}`)
		replaceStoredReportVersion(t, dir, "2", "0xother", nil)
		assertRegisterRefused(t, dir, registerSuppressionSpec, "s1", "2", "0xother")
	})

	t.Run("report without conclusions", func(t *testing.T) {
		dir := setupRegisterCorruptArchive(t)
		stripFindings(t, dir, "0xblk")
		replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
		assertRegisterRefused(t, dir, registerSuppressionSpec, "s1", "1", "0xblk")
	})
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
			dir := setupRegisterCorruptArchive(t)
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
			_, _, err := RegisterSuppression(dir, []byte(registerSuppressionSpec))
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
	dir := setupRegisterCorruptArchive(t)
	ghost := map[string]any{
		"id": "ghost",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", ghost)
	cond, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("unregistered but complete declaration must not block registration: created=%v err=%v", created, err)
	}
	if cond.ID != "s1" || cond.Revoked {
		t.Fatalf("registered condition wrong: %+v", cond)
	}
	// The saved declaration survived the commit with its own parameters,
	// never values pulled from the enabled or a same-id registered version.
	text := string(readArchiveFile(t, dir))
	if !strings.Contains(text, `"ghost"`) || !strings.Contains(text, `"multiplier": 100`) {
		t.Fatalf("saved declaration was rewritten:\n%s", text)
	}
	// The report still queries under its own saved parameters.
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("report must still query under its saved declaration: %v", err)
	}
	if r.Version.ID != "ghost" || r.Version.Rules.Sandwich.Enabled {
		t.Fatalf("saved off state not returned: %+v", r.Version)
	}
}

// TestRegisterSuppressionBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" is validated like any other saved declaration: a complete one
// registers normally, a damaged one fails as corruption rather than being
// replaced by the in-code builtin.
func TestRegisterSuppressionBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupRegisterCorruptArchive(t)
	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinFull)
	if _, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec)); err != nil || !created {
		t.Fatalf("a complete builtin-id declaration must not block registration: created=%v err=%v", created, err)
	}

	dir = setupRegisterCorruptArchive(t)
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", builtinDamaged)
	assertRegisterRefused(t, dir, registerSuppressionSpec, "s1", BuiltinVersionID, "multiplier")
}

// TestRegisterSuppressionLegacyRecordWithoutVersionKey proves only a wholly
// absent version key keeps the built-in interpretation: the registration
// succeeds, the legacy record is written back without growing a version key
// and the new condition is appended.
func TestRegisterSuppressionLegacyRecordWithoutVersionKey(t *testing.T) {
	dir := setupRegisterCorruptArchive(t)
	dropVersionKey(t, dir, "0xblk")
	cond, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("legacy record must not block registration: created=%v err=%v", created, err)
	}
	if cond.ID != "s1" {
		t.Fatalf("unexpected condition: %+v", cond)
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
	// The legacy report still queries under the built-in rules.
	r, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatalf("legacy report must still query: %v", err)
	}
	if r.Version != BuiltinVersion() {
		t.Fatalf("legacy report version = %+v, want builtin", r.Version)
	}
}

// TestRegisterSuppressionOverCorruptArchiveMasksNoOutcome proves the
// integrity proof runs before any judgment about the submitted condition:
// an identical retry and a different-content conflict against an existing
// id, and an idempotent retry of an already revoked condition, all fail as
// corruption rather than returning created:false, a conflict or silently
// re-enabling the revoked condition.
func TestRegisterSuppressionOverCorruptArchiveMasksNoOutcome(t *testing.T) {
	dir := setupRegisterCorruptArchive(t)
	if _, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec)); err != nil || !created {
		t.Fatalf("setup register: created=%v err=%v", created, err)
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
	before := readArchiveFile(t, dir)

	// Identical content would be a created:false no-op on an intact
	// archive; over a corrupt report it is refused first.
	if _, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec)); err == nil || created {
		t.Fatalf("identical retry over a corrupt report: created=%v err=%v", created, err)
	} else if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("identical retry error = %v, want ErrCorruptVersion", err)
	}

	// Different content would be a conflict; corruption wins instead and is
	// never misreported as ErrSuppressionConflict.
	conflict := strings.Replace(registerSuppressionSpec, `"known bot war"`, `"other reason"`, 1)
	_, _, cerr := RegisterSuppression(dir, []byte(conflict))
	if !errors.Is(cerr, ErrCorruptVersion) || errors.Is(cerr, ErrSuppressionConflict) {
		t.Fatalf("conflict over a corrupt report: %v, want ErrCorruptVersion (not a conflict)", cerr)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("refused registrations changed the archive")
	}

	// A revoked condition keeps its flag: the failed retries never wrote.
	var doc struct {
		Suppressions []Suppression `json:"suppressions"`
	}
	if err := json.Unmarshal(before, &doc); err != nil {
		t.Fatal(err)
	}
	for _, c := range doc.Suppressions {
		if c.ID == "s1" && c.Revoked {
			t.Fatalf("condition was revoked by a failed registration: %+v", c)
		}
	}
}

// TestRegisterSuppressionRevokedConditionNotReenabledOverCorruption proves
// the fixed post-revocation behavior — an identical retry never re-enables
// a revoked condition — cannot be masked or triggered across a corrupt
// report: the retry fails as corruption and the revoked flag survives.
func TestRegisterSuppressionRevokedConditionNotReenabledOverCorruption(t *testing.T) {
	dir := setupRegisterCorruptArchive(t)
	registerRevocationSpec(t, dir)
	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("setup revoke: changed=%v err=%v", changed, err)
	}
	replaceStoredReportVersion(t, dir, "1", "0xblk", nil)
	before := readArchiveFile(t, dir)

	cond, created, err := RegisterSuppression(dir, []byte(revocationSpec))
	if err == nil {
		t.Fatalf("retry over a corrupt report succeeded: created=%v %+v", created, cond)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("failed retry changed the archive")
	}
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range conds {
		if c.ID == "s1" && !c.Revoked {
			t.Fatal("failed retry re-enabled the revoked condition")
		}
	}
}

// TestRegisterSuppressionSuccessAppendsOnlyCondition proves a healthy
// archive still accepts new conditions and a successful registration touches
// nothing but the suppressions section: report conclusions and swap
// evidence, the versions registry and enabled marker, existing processing
// records and review history survive byte for byte, the new condition is
// appended last with revoked:false and a second condition still registers.
func TestRegisterSuppressionSuccessAppendsOnlyCondition(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	if _, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatal(err)
	}
	spec0 := `{"id":"s0","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":50,"reason":"old"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec0)); err != nil {
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
	// Revoke s0 so the archive also carries a revoked condition that must be
	// preserved as-is.
	if _, changed, err := RevokeSuppression(dir, "s0"); err != nil || !changed {
		t.Fatalf("revoke s0: changed=%v err=%v", changed, err)
	}
	before := readEnableSkeleton(t, dir)

	cond, created, err := RegisterSuppression(dir, []byte(registerSuppressionSpec))
	if err != nil || !created {
		t.Fatalf("register s1: created=%v err=%v", created, err)
	}
	if cond.ID != "s1" || cond.Revoked || cond.StartHeight != 100 || cond.EndHeight != 200 {
		t.Fatalf("registered condition wrong: %+v", cond)
	}

	after := readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatal("historical reports changed on registration")
	}
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatal("version declarations changed on registration")
	}
	if after.EnabledVersion != before.EnabledVersion {
		t.Fatalf("enabled marker changed on registration: %q -> %q", before.EnabledVersion, after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.AlertRecords, after.AlertRecords) {
		t.Fatal("alert processing records changed on registration")
	}
	if !reflect.DeepEqual(before.Reviews, after.Reviews) {
		t.Fatal("manual reviews changed on registration")
	}
	if len(after.Suppressions) != len(before.Suppressions)+1 {
		t.Fatalf("suppressions count = %d, want %d (append only)", len(after.Suppressions), len(before.Suppressions)+1)
	}
	if !reflect.DeepEqual(before.Suppressions, after.Suppressions[:len(before.Suppressions)]) {
		t.Fatal("existing conditions changed on registration")
	}
	if after.Suppressions[len(after.Suppressions)-1] != cond {
		t.Fatalf("appended condition = %+v, want %+v", after.Suppressions[len(after.Suppressions)-1], cond)
	}

	// A second new condition still registers, and the appended order holds.
	spec2 := `{"id":"s2","chainId":"2","pool":"p2","kind":"displacement","channel":"ops","startHeight":0,"endHeight":9,"reason":"r2"}`
	if _, created, err := RegisterSuppression(dir, []byte(spec2)); err != nil || !created {
		t.Fatalf("register s2: created=%v err=%v", created, err)
	}
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(conds) != 3 || conds[0].ID != "s0" || !conds[0].Revoked ||
		conds[1].ID != "s1" || conds[1].Revoked || conds[2].ID != "s2" {
		t.Fatalf("conditions after appends = %+v", conds)
	}
	// Report conclusions, evidence and review history are still intact.
	r, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatalf("report query after registration: %v", err)
	}
	if len(r.Findings) != 1 || r.Findings[0].TxHash != "0xvictim" ||
		r.Findings[0].Kind != "displacement" || r.Findings[0].Severity != 4 ||
		len(r.Findings[0].Evidence) != 2 {
		t.Fatalf("report conclusions/evidence changed: %+v", r.Findings)
	}
}
