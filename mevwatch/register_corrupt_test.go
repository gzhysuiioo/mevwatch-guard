package mevwatch

// Regression coverage for registering a rule version while the archive
// already holds versions whose stored documents have decayed. Registration
// only appends the submitted version: every other declaration is written
// back as its exact stored document (fields, values and order preserved,
// corrupt and intact siblings alike), so a missing or null field is never
// completed, a wrong-typed or out-of-range value never fixed, and unknown
// or repeated fields never dropped. When the submitted id already exists,
// its stored declaration must still satisfy the registration rules in
// full; a decayed one fails with ErrCorruptVersion — never created:false,
// never a parameter conflict, and the submitted parameters never replace
// it. The newly appended version must not make a corrupt sibling usable:
// enabling, replaying or comparing under it still fails as corruption.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// registerSkeleton reads the archive with each version kept as its raw
// stored document, the shape registration writes, so the sections can be
// compared entry for entry across a successful append.
type registerSkeleton struct {
	Records        []record           `json:"records"`
	Versions       []json.RawMessage  `json:"versions"`
	EnabledVersion string             `json:"enabledVersion"`
	Suppressions   []Suppression      `json:"suppressions"`
	AlertRecords   []ProcessingRecord `json:"alerts"`
	Reviews        []ReviewObject     `json:"reviews"`
}

func readRegisterSkeleton(t *testing.T, dir string) registerSkeleton {
	t.Helper()
	var s registerSkeleton
	if err := json.Unmarshal(readArchiveFile(t, dir), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestRegisterCorruptExistingIDRefused runs the full corruption matrix
// against re-registering an existing id: every way its stored document can
// stop satisfying the registration rules must fail with
// ErrCorruptVersion, name the version and the offending rule or field,
// never come back created:false (an "identical retry") or as a parameter
// conflict, and leave the archive byte for byte untouched — even when the
// resubmitted spec is the version's original, fully valid declaration.
func TestRegisterCorruptExistingIDRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, created, err := RegisterVersion(dir, []byte(candidateVersionSpec))
			if err == nil {
				t.Fatalf("corrupt existing id accepted: v=%+v created=%v", v, created)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrVersionConflict) {
				t.Fatalf("corruption misreported as a parameter conflict: %v", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("registered-but-corrupt version misreported as unknown: %v", err)
			}
			if created {
				t.Fatalf("refused registration reported created: %+v", v)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the existing version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused registration changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestRegisterCorruptExistingIDDifferentParamsStillCorruption proves the
// integrity verdict wins over the parameter comparison even when the
// resubmission differs from the stored declaration: it is corruption, not
// ErrVersionConflict, and the new parameters never overwrite the stored
// ones.
func TestRegisterCorruptExistingIDDifferentParamsStillCorruption(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	different := `{"id":"candC","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":false,"severity":1,"multiplier":99}}}`
	v, created, err := RegisterVersion(dir, []byte(different))
	if !errors.Is(err, ErrCorruptVersion) || created {
		t.Fatalf("resubmission over a corrupt id: v=%+v created=%v err=%v", v, created, err)
	}
	if errors.Is(err, ErrVersionConflict) {
		t.Fatalf("corruption misreported as a conflict: %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("resubmission overwrote the corrupt declaration:\nbefore=%s\nafter =%s", before, after)
	}
}

// TestRegisterNewVersionAppendsPastCorruptSiblings proves the main fix:
// submitting an unregistered id only appends the new valid version after
// the existing ones. Every corrupt or intact sibling survives entry for
// entry in order, the enabled marker and every other section stay put, and
// the damaged sibling is still afterwards refused on its own merits by
// enable, replay and compare — the new registration never heals it.
func TestRegisterNewVersionAppendsPastCorruptSiblings(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	// One sibling missing a field and one carrying an unknown field: both
	// are corrupt in ways a typed-struct round-trip used to silently
	// repair (zero value) or drop.
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
		ver["mystery"] = 42
	})
	before := readRegisterSkeleton(t, dir)

	newSpec := `{"id":"fresh","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":5,"multiplier":9}}}`
	v, created, err := RegisterVersion(dir, []byte(newSpec))
	if err != nil || !created || v.ID != "fresh" {
		t.Fatalf("new registration: v=%+v created=%v err=%v", v, created, err)
	}

	after := readRegisterSkeleton(t, dir)
	if len(after.Versions) != len(before.Versions)+1 {
		t.Fatalf("version count = %d, want %d (one appended)", len(after.Versions), len(before.Versions)+1)
	}
	if !reflect.DeepEqual(before.Versions, after.Versions[:len(before.Versions)]) {
		t.Fatalf("existing declarations rewritten or reordered:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
	if !entryDeclaresID(after.Versions[len(after.Versions)-1], "fresh") {
		t.Fatalf("new version not appended last: %s", after.Versions)
	}
	// The damaged document still lacks the multiplier and still carries
	// the unknown field: registration neither completed nor cleaned it.
	var damaged map[string]any
	if err := json.Unmarshal(after.Versions[0], &damaged); err != nil {
		t.Fatal(err)
	}
	if _, has := damaged["mystery"]; !has {
		t.Fatalf("unknown field dropped from the corrupt sibling: %s", after.Versions[0])
	}
	disp := damaged["rules"].(map[string]any)["displacement"].(map[string]any)
	if _, has := disp["multiplier"]; has {
		t.Fatalf("missing multiplier was filled in: %s", after.Versions[0])
	}
	if after.EnabledVersion != before.EnabledVersion {
		t.Fatalf("enabled marker changed: %q -> %q", before.EnabledVersion, after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("historical reports changed on registration")
	}

	// The intact twin remains usable; the corrupt candC is still refused
	// by every selection path, so the new version never restored it.
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("intact twin no longer enableable: %v", err)
	}
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling became enableable after registration: %v", err)
	}
	if _, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling became replayable after registration: %v", err)
	}
	if _, err := Compare(dir, "1", "0xblk", "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling became comparable after registration: %v", err)
	}
	// The freshly appended version is itself usable end to end.
	fresh, err := GetVersion(dir, "fresh")
	if err != nil || fresh.Rules.Displacement.Multiplier != 9 {
		t.Fatalf("new version not stored intact: %+v %v", fresh, err)
	}
}

// TestRegisterDuplicateFieldSiblingPreservedVerbatim covers a decay the
// registration decoder itself could never emit: a repeated field inside a
// stored declaration. The raw bytes are patched directly because a JSON
// map cannot hold two keys; the duplicate must survive a later append byte
// for byte and keep the entry corrupt.
func TestRegisterDuplicateFieldSiblingPreservedVerbatim(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	if vsec < 0 {
		t.Fatal("versions section not found")
	}
	at := strings.Index(text[vsec:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("candC entry not found")
	}
	at += vsec
	anchor := `"severity": 4,`
	field := strings.Index(text[at:], anchor)
	if field < 0 {
		t.Fatal("candC severity field not found")
	}
	pos := at + field
	patched := text[:pos] + `"severity": 4, ` + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readRegisterSkeleton(t, dir)

	if _, created, err := RegisterVersion(dir, []byte(
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
	)); err != nil || !created {
		t.Fatalf("registration past a duplicate-field sibling: created=%v err=%v", created, err)
	}

	after := readRegisterSkeleton(t, dir)
	// Compare each entry with whitespace compacted: the hand-patched input
	// has ad-hoc indentation that one MarshalIndent normalises, but its
	// tokens — including the repeated key — must survive exactly.
	compact := func(t *testing.T, b json.RawMessage) string {
		t.Helper()
		var out bytes.Buffer
		if err := json.Compact(&out, b); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	for i := range before.Versions {
		if compact(t, before.Versions[i]) != compact(t, after.Versions[i]) {
			t.Fatalf("duplicate-field declaration was rewritten:\nbefore=%s\nafter =%s", before.Versions[i], after.Versions[i])
		}
	}
	// The entry is still corrupt on its own merits, now via the duplicate.
	var cand json.RawMessage
	for _, entry := range after.Versions {
		if entryDeclaresID(entry, "candC") {
			cand = entry
		}
	}
	if cand == nil {
		t.Fatal("candC entry missing")
	}
	if _, err := ParseRuleVersion(cand); !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate-field entry parses cleanly after registration: %v", err)
	}
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) ||
		!errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate-field sibling became usable: %v", err)
	}
}

// TestRegisterPreservesAllOtherState builds an archive holding every kind
// of state, then appends a new version past a corrupt sibling and proves
// nothing but the versions section moved: the enabled marker, historical
// reports (with their own version parameters), suppressions, alert
// processing records and manual reviews keep their exact content.
func TestRegisterPreservesAllOtherState(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
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
	// Damage the only registered version after all state exists; the new
	// registration must leave both the damage and every other section put.
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readRegisterSkeleton(t, dir)

	if _, created, err := RegisterVersion(dir, []byte(
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
	)); err != nil || !created {
		t.Fatalf("registration: created=%v err=%v", created, err)
	}

	after := readRegisterSkeleton(t, dir)
	if after.EnabledVersion != "candC" {
		t.Fatalf("enabled marker changed to %q", after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.Versions, after.Versions[:len(before.Versions)]) {
		t.Fatalf("stored versions rewritten:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("historical reports changed")
	}
	if !reflect.DeepEqual(before.Suppressions, after.Suppressions) {
		t.Fatalf("suppressions changed")
	}
	if !reflect.DeepEqual(before.AlertRecords, after.AlertRecords) {
		t.Fatalf("alert records changed")
	}
	if !reflect.DeepEqual(before.Reviews, after.Reviews) {
		t.Fatalf("manual reviews changed")
	}
	report, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" || report.Findings[0].Severity != 4 {
		t.Fatalf("archived report changed: %+v", report)
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
}

// TestRegisterIntactRetrySemanticsUnchanged pins the two intact-id
// outcomes that must survive the fix: same id and same parameters returns
// the existing version with created:false, same id and different
// parameters is a conflict; neither writes the archive. Explicitly
// disabled rules are a legal complete declaration for both.
func TestRegisterIntactRetrySemanticsUnchanged(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := readArchiveFile(t, dir)

	got, created, err := RegisterVersion(dir, []byte(candidateVersionSpec))
	if err != nil || created {
		t.Fatalf("identical retry: v=%+v created=%v err=%v", got, created, err)
	}
	want := mustRuleVersion(t, candidateVersionSpec)
	if got != want {
		t.Fatalf("identical retry returned %+v, want %+v", got, want)
	}

	conflict := `{"id":"twin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":3,"multiplier":2}}}`
	if _, created, err := RegisterVersion(dir, []byte(conflict)); !errors.Is(err, ErrVersionConflict) || created {
		t.Fatalf("different params: created=%v err=%v", created, err)
	}

	// A complete, explicitly disabled version registers and retries.
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	if _, created, err := RegisterVersion(dir, []byte(offSpec)); err != nil || !created {
		t.Fatalf("disabled version register: created=%v err=%v", created, err)
	}
	if _, created, err := RegisterVersion(dir, []byte(offSpec)); err != nil || created {
		t.Fatalf("disabled version retry: created=%v err=%v", created, err)
	}
	if after := readArchiveFile(t, dir); reflect.DeepEqual(before, after) {
		t.Fatal("successful registration did not write the archive")
	}
}

// TestRegisterInvalidAndBusyArchiveReported covers the environment-level
// failures: an archive whose whole file is not valid JSON, or one locked by
// another process, must error clearly and leave the file alone — no
// partial registration.
func TestRegisterInvalidAndBusyArchiveReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	if _, created, err := RegisterVersion(dir, []byte(strictSpec)); err == nil || created {
		t.Fatalf("invalid-JSON archive accepted: created=%v err=%v", created, err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed registration rewrote an invalid archive")
	}

	busyDir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(busyDir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterVersion(busyDir, []byte(strictSpec)); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy archive error = %v, want ErrBusy", err)
	}
}

// TestRegisterNewSpecStillFullyValidated proves the submitted document
// goes through every existing check even while corrupt siblings sit in the
// archive: a single object, complete fields, no duplicates, in-range
// parameters. The built-in id stays reserved and cannot be registered past
// corrupt data either.
func TestRegisterNewSpecStillFullyValidated(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readRegisterSkeleton(t, dir)
	bad := []string{
		``,
		`null`,
		`[]`,
		`{"id":"fresh"}`,
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}} extra`,
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3,"severity":4},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":6},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":1}}}`,
		`{"id":"builtin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
	}
	for i, spec := range bad {
		if v, created, err := RegisterVersion(dir, []byte(spec)); err == nil {
			t.Fatalf("bad spec %d accepted: %+v created=%v", i, v, created)
		}
	}
	after := readRegisterSkeleton(t, dir)
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatalf("rejected specs changed the versions section:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
}
