package mevwatch

// Regression coverage for registering a rule version into an archive whose
// stored declarations have decayed. Registration only ever adds the version
// it was asked to add: a corrupt sibling — a missing or null field, a wrong
// type, an out-of-range number, an unknown or duplicate field — neither
// blocks a legal new registration nor gets repaired, completed, reordered
// or dropped by one (a missing enabled must not come back as an explicit
// false). And when the submitted ID is already taken by a corrupt
// declaration, the failure is ErrCorruptVersion naming the version and the
// offending rule or field — never created:false against the decayed
// parameters, never an overwrite, never a parameter conflict.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// freshVersionSpec is a legal registration that shares no ID with the
// corrupt-archive fixture.
const freshVersionSpec = `{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":2},"displacement":{"enabled":true,"severity":3,"multiplier":3}}}`

// mustReplayDoc reads the archive at path into the raw-version document
// shape registration and replay use, leaving every stored version as its
// raw document.
func mustReplayDoc(t *testing.T, path string) replayArchiveDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc replayArchiveDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestRegisterNewVersionPreservesCorruptSiblings runs the full corruption
// matrix against the siblings of a new registration: a legal spec for an
// unregistered ID must succeed (created:true) and be appended after the
// existing versions, while every corrupt stored declaration survives byte
// for byte, in order — and stays corrupt for enable, replay and compare.
func TestRegisterNewVersionPreservesCorruptSiblings(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readEnableSkeleton(t, dir)

			v, created, err := RegisterVersion(dir, []byte(freshVersionSpec))
			if err != nil || !created {
				t.Fatalf("registering a legal version past a corrupt sibling: v=%+v created=%v err=%v", v, created, err)
			}
			if want := mustRuleVersion(t, freshVersionSpec); v != want {
				t.Fatalf("registered version = %+v, want %+v", v, want)
			}

			after := readEnableSkeleton(t, dir)
			if len(after.Versions) != len(before.Versions)+1 {
				t.Fatalf("version count = %d, want %d (append only)", len(after.Versions), len(before.Versions)+1)
			}
			if !reflect.DeepEqual(before.Versions, after.Versions[:len(before.Versions)]) {
				t.Fatalf("existing declarations changed on registration:\nbefore=%s\nafter =%s",
					before.Versions, after.Versions[:len(before.Versions)])
			}
			if after.EnabledVersion != before.EnabledVersion {
				t.Fatalf("enabled marker changed on registration: %q -> %q", before.EnabledVersion, after.EnabledVersion)
			}
			if !reflect.DeepEqual(before.Records, after.Records) {
				t.Fatalf("historical reports changed on registration")
			}

			// The new version is stored exactly as submitted and is usable;
			// the corrupt sibling was not repaired by the registration and
			// is still refused on its own merits. (GetVersion/ListVersions
			// decode every stored version, so the wrong-typed sibling cases
			// are read back through the raw document instead.)
			stored, err := ParseRuleVersion(after.Versions[len(after.Versions)-1])
			if err != nil || stored != v {
				t.Fatalf("appended declaration = %+v, %v; want %+v", stored, err, v)
			}
			if _, err := EnableVersion(dir, "fresh"); err != nil {
				t.Fatalf("newly registered version not enableable: %v", err)
			}
			if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("corrupt sibling silently repaired by registration: %v", err)
			}
			if _, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("replay under corrupt sibling: %v, want ErrCorruptVersion", err)
			}
			if _, err := Compare(dir, "1", "0xblk", "candC"); !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("compare under corrupt sibling: %v, want ErrCorruptVersion", err)
			}
		})
	}
}

// TestRegisterCorruptExistingIDRefused runs the full corruption matrix
// against re-registration of the corrupt version's own ID: a legal
// resubmission must fail with ErrCorruptVersion naming the version and the
// offending rule or field — never created:false, never ErrVersionConflict —
// and must leave the stored declaration untouched.
func TestRegisterCorruptExistingIDRefused(t *testing.T) {
	resubmit := `{"id":"candC","rules":{"sandwich":{"enabled":true,"severity":2},"displacement":{"enabled":true,"severity":3,"multiplier":3}}}`
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, created, err := RegisterVersion(dir, []byte(resubmit))
			if err == nil {
				t.Fatalf("corrupt existing declaration accepted: v=%+v created=%v", v, created)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrVersionConflict) {
				t.Fatalf("corruption misreported as a parameter conflict: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the existing version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused re-registration changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestRegisterCorruptExistingNotTreatedAsIdentical pins the core regression:
// a stored declaration whose enabled field went missing decodes as
// enabled:false, so a resubmission of the original parameters — which
// declare enabled:false — used to hit the identical-retry path and report
// created:false, blessing the decayed document as a legal version. The
// stored declaration must be validated first, so the retry fails as
// corruption instead.
func TestRegisterCorruptExistingNotTreatedAsIdentical(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	// candC declares sandwich enabled:false; deleting the field leaves a
	// document that decodes to exactly the registered parameters.
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "sandwich"), "enabled")
	})
	before := readArchiveFile(t, dir)

	v, created, err := RegisterVersion(dir, []byte(candidateVersionSpec))
	if err == nil || created {
		t.Fatalf("retry against a decayed declaration: v=%+v created=%v err=%v", v, created, err)
	}
	if !errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrVersionConflict) {
		t.Fatalf("error = %v, want ErrCorruptVersion (not a conflict)", err)
	}
	if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "enabled") {
		t.Fatalf("error must name candC and the enabled field, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused retry changed the archive")
	}
}

// TestRegisterCorruptDuplicateFieldSibling proves a stored document carrying
// a repeated field — damage registration could never have produced — is
// preserved byte for byte when another version registers, and is judged
// corrupt (never unknown, never conflicting) when its own ID is resubmitted.
func TestRegisterCorruptDuplicateFieldSibling(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	if vsec < 0 {
		t.Fatal("versions section not found in archive")
	}
	at := strings.Index(text[vsec:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("candC entry not found in versions section")
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
	// Normalize the hand-patched file through the same raw-version document
	// shape registration rewrites, so the byte comparison below is not
	// defeated by the patch's own whitespace; the duplicate field itself
	// survives the round trip because versions stay raw stored documents.
	normalized, err := json.MarshalIndent(mustReplayDoc(t, path), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, normalized, 0o644); err != nil {
		t.Fatal(err)
	}
	before := readEnableSkeleton(t, dir)

	// A legal new registration succeeds and leaves the duplicate-field
	// document exactly as stored.
	if _, created, err := RegisterVersion(dir, []byte(freshVersionSpec)); err != nil || !created {
		t.Fatalf("registering past a duplicate-field sibling: created=%v err=%v", created, err)
	}
	after := readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(before.Versions, after.Versions[:len(before.Versions)]) {
		t.Fatalf("duplicate-field declaration changed on registration")
	}

	// Resubmitting its own ID reports the corruption, naming the field.
	_, _, rerr := RegisterVersion(dir, []byte(candidateVersionSpec))
	if !errors.Is(rerr, ErrCorruptVersion) || !errors.Is(rerr, ErrDuplicateField) {
		t.Fatalf("duplicate-field resubmission: err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", rerr)
	}
	if !strings.Contains(rerr.Error(), "candC") || !strings.Contains(rerr.Error(), "severity") {
		t.Fatalf("error must name candC and severity, got %v", rerr)
	}
}

// TestRegisterAppendsAfterExistingVersions pins the ordering guarantee: a
// new version lands after every existing one, and an intact existing ID
// keeps its established outcomes — identical parameters return created:false
// and different parameters report ErrVersionConflict, neither rewriting the
// archive.
func TestRegisterAppendsAfterExistingVersions(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := readArchiveFile(t, dir)

	if _, created, err := RegisterVersion(dir, []byte(freshVersionSpec)); err != nil || !created {
		t.Fatalf("register fresh: created=%v err=%v", created, err)
	}
	versions, _, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 4 || versions[1].ID != "candC" || versions[2].ID != "twin" || versions[3].ID != "fresh" {
		t.Fatalf("version order = %+v, want builtin, candC, twin, fresh", versions)
	}

	// Intact existing ID: identical parameters are a no-op success.
	if v, created, err := RegisterVersion(dir, []byte(candidateVersionSpec)); err != nil || created ||
		v != mustRuleVersion(t, candidateVersionSpec) {
		t.Fatalf("identical retry: v=%+v created=%v err=%v", v, created, err)
	}
	// Intact existing ID: different parameters are a conflict.
	conflicting := `{"id":"candC","rules":{"sandwich":{"enabled":true,"severity":1},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
	if _, _, err := RegisterVersion(dir, []byte(conflicting)); !errors.Is(err, ErrVersionConflict) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("different parameters: err = %v, want ErrVersionConflict", err)
	}
	// Neither the retry nor the conflict rewrote anything but the one append.
	after := readEnableSkeleton(t, dir)
	if len(after.Versions) != 3 {
		t.Fatalf("version count changed by retry/conflict: %d", len(after.Versions))
	}
	var beforeSkel enableSkeleton
	if err := json.Unmarshal(before, &beforeSkel); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeSkel.Versions, after.Versions[:len(beforeSkel.Versions)]) {
		t.Fatalf("existing declarations changed by retry/conflict")
	}
}

// TestRegisterPreservesAllPriorState builds an archive holding every kind of
// state, then registers a new version and proves only the versions section
// grew: the enabled marker, historical reports, suppressions, alert
// processing records and manual reviews are all untouched.
func TestRegisterPreservesAllPriorState(t *testing.T) {
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
	before := readEnableSkeleton(t, dir)

	if _, created, err := RegisterVersion(dir, []byte(freshVersionSpec)); err != nil || !created {
		t.Fatalf("register fresh: created=%v err=%v", created, err)
	}

	after := readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(before.Versions, after.Versions[:len(before.Versions)]) {
		t.Fatalf("existing declarations changed on registration")
	}
	if after.EnabledVersion != "candC" {
		t.Fatalf("enabled marker changed on registration: %q", after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("historical reports changed on registration")
	}
	if !reflect.DeepEqual(before.Suppressions, after.Suppressions) {
		t.Fatalf("suppressions changed on registration")
	}
	if !reflect.DeepEqual(before.AlertRecords, after.AlertRecords) {
		t.Fatalf("alert records changed on registration")
	}
	if !reflect.DeepEqual(before.Reviews, after.Reviews) {
		t.Fatalf("manual reviews changed on registration")
	}
}

// TestRegisterInvalidArchiveReported covers the environment-level failures:
// an archive whose whole file is not valid JSON must error clearly and be
// left alone — no partial registration.
func TestRegisterInvalidArchiveReported(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	if _, _, err := RegisterVersion(dir, []byte(freshVersionSpec)); err == nil ||
		errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrVersionConflict) {
		t.Fatalf("invalid-JSON archive error = %v, want a whole-archive corruption error", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed registration rewrote an invalid archive")
	}
}
