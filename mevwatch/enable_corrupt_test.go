package mevwatch

// Regression coverage for enabling a corrupt archived rule version.
// `rules enable` chooses the version later replays run under, so a
// successful enable must prove the selected version's stored archive
// document still satisfies every registration rule — exactly the way a
// replay, a single-block comparison and a review-range evaluation prove
// theirs. A registered-but-corrupt version must fail with
// ErrCorruptVersion (naming the version and the offending rule or field)
// even when it is already the enabled marker; it is never misreported as
// unknown and never replaced by the current version, the built-in rules or
// defaults. A corrupt sibling neither blocks an intact choice (or builtin)
// nor is repaired, reordered or dropped, and a refused enable leaves the
// whole archive — reports, rules, the marker, suppressions, alert records
// and reviews — byte for byte untouched.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestEnableCorruptVersionRefused runs the full stored-document corruption
// matrix against `rules enable`: every way a registered version document
// can stop satisfying the registration rules must fail the enable with
// ErrCorruptVersion, never success and never ErrUnknownVersion.
func TestEnableCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, err := EnableVersion(dir, "candC")
			if err == nil {
				t.Fatalf("corrupt version enabled successfully: %+v", v)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("registered corruption misreported as unknown version: %v", err)
			}
			if v != (RuleVersion{}) {
				t.Fatalf("a refused enable must return no parameters, got %+v", v)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the selected version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused enable changed the archive")
			}
		})
	}
}

// TestEnableCorruptAlreadyEnabledVersionRefused pins the rule that
// re-selecting the current marker is not a reputation-based no-op: the
// already-enabled version is damaged after it was selected, and enabling
// it again must still inspect its stored declaration and fail. The marker
// keeps naming the corrupt version rather than silently switching.
func TestEnableCorruptAlreadyEnabledVersionRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatalf("EnableVersion while intact: %v", err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	v, err := EnableVersion(dir, "candC")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("re-enabling the corrupt marker: v=%+v err=%v, want ErrCorruptVersion", v, err)
	}
	if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "multiplier") {
		t.Fatalf("error must name version candC and the multiplier, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused enable changed the archive")
	}
	var s struct {
		EnabledVersion string `json:"enabledVersion"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &s); err != nil {
		t.Fatal(err)
	}
	if s.EnabledVersion != "candC" {
		t.Fatalf("enabled marker changed on refusal: %q", s.EnabledVersion)
	}
}

// TestEnableIntactVersionIgnoresCorruptSibling proves a damaged sibling
// neither blocks switching to an intact registered version (or builtin)
// nor gets completed, fixed, reordered or dropped along the way: version
// documents survive as raw bytes, only the enabled marker changes.
func TestEnableIntactVersionIgnoresCorruptSibling(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	type skeleton struct {
		Versions       []json.RawMessage `json:"versions"`
		EnabledVersion string            `json:"enabledVersion"`
	}
	read := func() skeleton {
		var s skeleton
		if err := json.Unmarshal(readArchiveFile(t, dir), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := read()

	twin, err := EnableVersion(dir, "twin")
	if err != nil {
		t.Fatalf("enabling intact twin past a corrupt sibling failed: %v", err)
	}
	if twin.ID != "twin" || twin.Rules.Displacement.Multiplier != 2 ||
		!twin.Rules.Sandwich.Enabled || twin.Rules.Sandwich.Severity != 3 {
		t.Fatalf("enable must return the selected version's full parameters: %+v", twin)
	}

	after := read()
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatalf("stored version documents rewritten:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
	// Registration order and the corrupt entry itself are preserved.
	var ids []string
	for _, raw := range after.Versions {
		var meta struct {
			ID    string         `json:"id"`
			Rules map[string]any `json:"rules"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, meta.ID)
		if meta.ID == "candC" {
			disp := meta.Rules["displacement"].(map[string]any)
			if m, ok := disp["multiplier"]; !ok || m.(float64) != 0 {
				t.Fatalf("corrupt sibling repaired instead of preserved: %v", disp)
			}
		}
	}
	if !reflect.DeepEqual(ids, []string{"candC", "twin"}) {
		t.Fatalf("version order changed: %v", ids)
	}
	if after.EnabledVersion != "twin" {
		t.Fatalf("enabled marker = %q, want twin", after.EnabledVersion)
	}

	// builtin needs no registration and stays usable beside the damage.
	b, err := EnableVersion(dir, BuiltinVersionID)
	if err != nil {
		t.Fatalf("enabling builtin failed: %v", err)
	}
	if b != BuiltinVersion() {
		t.Fatalf("builtin parameters wrong: %+v", b)
	}
	if got := read().EnabledVersion; got != BuiltinVersionID {
		t.Fatalf("enabled marker = %q, want builtin", got)
	}
}

// TestEnableSwitchedVersionDrivesLaterReplay proves a successful switch is
// what later replays without --version actually use, while the corrupt
// sibling stays on disk untouched.
func TestEnableSwitchedVersionDrivesLaterReplay(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("EnableVersion twin: %v", err)
	}
	input := cmpBlockLine("1", "0xnew", 9,
		cmpSwap("0xn1", "p1", "w", 40, 0),
		cmpSwap("0xn2", "p1", "u", 10, 1),
	)
	reports, err := Replay(strings.NewReader(input), dir)
	if err != nil {
		t.Fatalf("plain replay under twin failed: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != "twin" {
		t.Fatalf("replay did not use the newly enabled version: %+v", reports)
	}
	// The corrupt sibling was neither repaired nor dropped by the replay
	// write: it still cannot be enabled.
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling changed after replay: %v", err)
	}
}

// TestEnableExplicitFalseIsLegalButParamsRequired pins the enabled:false
// semantics: an explicitly disabled rule is a legal off state on enable,
// but its severity (and the displacement multiplier) must still be present
// and in range.
func TestEnableExplicitFalseIsLegalButParamsRequired(t *testing.T) {
	dir := t.TempDir()
	off := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":false,"severity":2,"multiplier":2}}}`
	register(t, dir, off)
	v, err := EnableVersion(dir, "off")
	if err != nil {
		t.Fatalf("enabling both-rules-off version failed: %v", err)
	}
	if v.Rules.Sandwich.Enabled || v.Rules.Displacement.Enabled {
		t.Fatalf("disabled state must survive enable: %+v", v)
	}
	// Damage one parameter of the disabled displacement rule: still corrupt.
	rewriteStoredVersion(t, dir, "off", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	if _, err := EnableVersion(dir, "off"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("disabled rule with a missing multiplier: %v, want ErrCorruptVersion", err)
	}
}

// TestEnableUnknownVersionStaysUnknownWithCorruptSibling pins the boundary
// in an archive that also holds a corrupt version: an identifier that was
// never registered stays an unknown-version failure, never corruption.
func TestEnableUnknownVersionStaysUnknownWithCorruptSibling(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)
	for _, id := range []string{"ghost", ""} {
		_, err := EnableVersion(dir, id)
		if !errors.Is(err, ErrUnknownVersion) && id != "" {
			t.Fatalf("enable %q: %v, want ErrUnknownVersion", id, err)
		}
		if id == "" && err == nil {
			t.Fatalf("empty id must fail")
		}
		if errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("unknown id %q misreported corrupt: %v", id, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed enables changed the archive")
	}
}

// TestEnableDuplicateFieldInStoredDocumentCorrupt covers corruption the
// map-based mutator cannot express: a repeated field inside a stored
// version document. Duplicate keys (including case-folded spellings the
// decoder treats as the same field) were illegal at registration, so the
// stored document is corrupt; a plain map round-trip would hide the
// repeat, hence the document is written as raw JSON.
func TestEnableDuplicateFieldInStoredDocumentCorrupt(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	doc := `{
  "records": [],
  "versions": [
    {"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3,"Severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}},
    {"id":"twin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}
  ]
}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := EnableVersion(dir, "candC")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("duplicate field enable error = %v, want ErrCorruptVersion", err)
	}
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("error must wrap ErrDuplicateField: %v", err)
	}
	if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("error must name version and field: %v", err)
	}
	// The intact twin in the same raw document still enables.
	twin, err := EnableVersion(dir, "twin")
	if err != nil {
		t.Fatalf("intact twin beside the duplicate-field document: %v", err)
	}
	if twin.ID != "twin" {
		t.Fatalf("wrong version returned: %+v", twin)
	}
}

// TestEnableCorruptJSONArchiveFails proves a whole archive that is not
// legal JSON fails cleanly without touching anything.
func TestEnableCorruptJSONArchiveFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{"records":[`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "anything"); err == nil ||
		!strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("broken JSON archive: %v, want a corruption error", err)
	}
	if after := readArchiveFile(t, dir); string(after) != `{"records":[` {
		t.Fatalf("failed enable rewrote the archive: %q", after)
	}
}

// TestEnableSaveFailureReported forces the atomic commit to fail (read-only
// directory) and checks the error surfaces instead of a false success.
func TestEnableSaveFailureReported(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := EnableVersion(dir, "twin"); err == nil {
		t.Fatal("enable into an unwritable archive reported success")
	}
}

// TestEnableLegacyAndEmptyArchives proves pre-version archives still run
// builtin: enabling builtin succeeds without registration and writes
// nothing, while any other identifier stays unknown.
func TestEnableLegacyAndEmptyArchives(t *testing.T) {
	t.Run("legacy records without versions", func(t *testing.T) {
		dir := t.TempDir()
		legacy := `{"records":[]}`
		if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := EnableVersion(dir, BuiltinVersionID)
		if err != nil {
			t.Fatalf("enable builtin on legacy archive: %v", err)
		}
		if v != BuiltinVersion() {
			t.Fatalf("builtin parameters wrong: %+v", v)
		}
		if after := readArchiveFile(t, dir); string(after) != legacy {
			t.Fatalf("enabling builtin rewrote a legacy archive: %q", after)
		}
		if _, err := EnableVersion(dir, "strict"); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("unknown id on legacy archive: %v, want ErrUnknownVersion", err)
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		v, err := EnableVersion(dir, BuiltinVersionID)
		if err != nil {
			t.Fatalf("enable builtin on empty archive: %v", err)
		}
		if v != BuiltinVersion() {
			t.Fatalf("builtin parameters wrong: %+v", v)
		}
		if _, err := os.Stat(filepath.Join(dir, archiveFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("no-op builtin enable created an archive file: %v", err)
		}
		if _, err := EnableVersion(dir, "strict"); !errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("unknown id on empty archive: %v, want ErrUnknownVersion", err)
		}
	})
}

// TestEnableCorruptVersionPreservesFullState builds an archive holding
// every kind of state, then proves a refused enable leaves it byte
// identical and a successful switch changes nothing but the marker:
// reports, suppressions, alert records and reviews survive as they were,
// and no historical conclusion is re-detected.
func TestEnableCorruptVersionPreservesFullState(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	register(t, dir, twinVersionSpec)
	if _, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterSuppression(dir, []byte(
		`{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":1,"endHeight":100,"reason":"r"}`,
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

	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("refusal error = %v, want ErrCorruptVersion", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused enable changed a full-state archive")
	}

	// Switching to the intact twin changes only the marker.
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("enable twin: %v", err)
	}
	report, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" || report.Findings[0].Severity != 4 {
		t.Fatalf("historical report changed after enable switch: %+v", report)
	}
	history, err := ReviewHistoryQuery(dir, "1", "0xa", "0xvictim", "displacement")
	if err != nil {
		t.Fatal(err)
	}
	if history.Status != ReviewStatusFalsePositive || history.Version != 1 {
		t.Fatalf("review history changed: %+v", history)
	}
	alerts, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Status != AlertStatusSuppressed {
		t.Fatalf("alert records changed: %+v", alerts)
	}
	if conds, err := ListSuppressions(dir); err != nil || len(conds) != 1 || conds[0].ID != "s1" {
		t.Fatalf("suppressions changed: %+v %v", conds, err)
	}
	// The corrupt document is still on disk and still refused.
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt version repaired by the successful sibling switch: %v", err)
	}
}
