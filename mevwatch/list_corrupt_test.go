package mevwatch

// Regression coverage for `rules list` (ListVersions) against an archive
// holding a registered version whose stored document has decayed since
// registration. Listing must prove every stored declaration still
// satisfies the registration rules — the same proof showing, enabling,
// comparing, evaluating and replaying already demand — so a corrupt
// registered version fails the whole query with ErrCorruptVersion (never
// listed with silently zeroed or defaulted parameters, never skipped,
// never substituted with the enabled, built-in or default parameters),
// even when it is not the currently enabled version. An explicit
// enabled:false stays a legal off state, intact archives keep their exact
// output shape, and the query never rewrites the archive.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestListCorruptVersionRefused runs the full corruption matrix against
// listing an archive whose non-enabled registered version has decayed:
// every way its stored document can stop satisfying the registration rules
// must fail the whole query with ErrCorruptVersion, name the version and
// the offending rule or field, return no partial list, and leave the
// archive untouched.
func TestListCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			versions, enabled, err := ListVersions(dir)
			if err == nil {
				t.Fatalf("corrupt version listed successfully: %+v (enabled %q)", versions, enabled)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("registered-but-corrupt version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the corrupt version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if versions != nil {
				t.Fatalf("a failed list must return no partial version list, got %+v", versions)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused list changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestListCorruptEnabledVersionRefused pins that the integrity check also
// runs when the corrupt version is the currently enabled one: the whole
// list still fails rather than presenting the enabled version with zeroed
// parameters.
func TestListCorruptEnabledVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			if _, err := EnableVersion(dir, "candC"); err != nil {
				t.Fatalf("setup: EnableVersion candC: %v", err)
			}
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			versions, _, err := ListVersions(dir)
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("listing with a corrupt enabled version: versions=%+v err=%v, want ErrCorruptVersion", versions, err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corrupt enabled version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name version candC and field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused list changed the archive")
			}
		})
	}
}

// TestListCorruptDuplicateFieldRefused covers a decay registration could
// never have produced: a repeated field in a stored version document,
// including spellings the decoder folds onto the same field. The raw bytes
// are patched directly because a JSON map cannot hold two keys.
func TestListCorruptDuplicateFieldRefused(t *testing.T) {
	for _, dup := range []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", `"se\u0076erity": 4, `},
	} {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			path := filepath.Join(dir, archiveFileName)
			text := string(readArchiveFile(t, dir))
			// Records precede the versions array and embed a full copy of
			// candC in their "version" field, so anchor past "versions".
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
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			before := readArchiveFile(t, dir)

			_, _, err := ListVersions(dir)
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("duplicate-field document: err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused list changed the archive")
			}
		})
	}
}

// TestListCorruptUnidentifiableVersionRefused covers a stored document
// whose own identity decayed away: with no string id to name, the failure
// still reports version corruption and points at the entry's position in
// the versions array rather than falling back to a zeroed list entry.
func TestListCorruptUnidentifiableVersionRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver, "id")
	})
	before := readArchiveFile(t, dir)

	_, _, err := ListVersions(dir)
	if !errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("id-less corrupt version: err = %v, want ErrCorruptVersion", err)
	}
	if !strings.Contains(err.Error(), "versions[0]") || !strings.Contains(err.Error(), "id") {
		t.Fatalf("error must point at the entry and its missing id, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused list changed the archive")
	}
}

// TestListIntactVersionsUnchanged proves the fix does not alter the
// successful shape: builtin first, registered versions in stored order
// with their id strings verbatim and full parameters, the enabled marker
// reported as stored, and an explicitly disabled version (both rules off)
// listed like any other intact one.
func TestListIntactVersionsUnchanged(t *testing.T) {
	dir := t.TempDir()
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, candidateVersionSpec)
	register(t, dir, offSpec)
	register(t, dir, twinVersionSpec)
	if _, err := EnableVersion(dir, "off"); err != nil {
		t.Fatalf("EnableVersion off: %v", err)
	}
	before := readArchiveFile(t, dir)

	versions, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatalf("listing intact versions failed: %v", err)
	}
	want := []RuleVersion{
		BuiltinVersion(),
		mustRuleVersion(t, candidateVersionSpec),
		mustRuleVersion(t, offSpec),
		mustRuleVersion(t, twinVersionSpec),
	}
	if !reflect.DeepEqual(versions, want) {
		t.Fatalf("versions = %+v, want %+v", versions, want)
	}
	if enabled != "off" {
		t.Fatalf("enabled = %q, want off", enabled)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("successful list changed the archive")
	}
}

// TestListInvalidArchiveReported covers a whole archive file that is not
// valid JSON: the query must report whole-archive corruption, never
// version corruption and never an empty version list.
func TestListInvalidArchiveReported(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	versions, _, err := ListVersions(dir)
	if err == nil || errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("invalid-JSON archive: versions=%+v err=%v, want a whole-archive corruption error", versions, err)
	}
	if !strings.Contains(err.Error(), "archive is corrupted") {
		t.Fatalf("invalid-JSON archive error = %v, want the archive corruption wording", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed list rewrote an invalid archive")
	}
}

// TestListMissingAndLegacyArchive pins the boundaries that must keep
// working: a missing archive directory and a pre-version legacy archive
// both list the built-in version alone with its original parameters.
func TestListMissingAndLegacyArchive(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	versions, enabled, err := ListVersions(missing)
	if err != nil || enabled != BuiltinVersionID ||
		len(versions) != 1 || versions[0] != BuiltinVersion() {
		t.Fatalf("missing directory: versions=%+v enabled=%q err=%v", versions, enabled, err)
	}

	legacy := t.TempDir()
	legacyDoc := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[],"findings":[]}]}`
	if err := os.WriteFile(filepath.Join(legacy, archiveFileName), []byte(legacyDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	versions, enabled, err = ListVersions(legacy)
	if err != nil || enabled != BuiltinVersionID ||
		len(versions) != 1 || versions[0] != BuiltinVersion() {
		t.Fatalf("legacy archive: versions=%+v enabled=%q err=%v", versions, enabled, err)
	}
}

// TestListCorruptSiblingDoesNotBlockShow pins the asymmetry the fix must
// preserve: the same corrupt entry that fails the whole list still does
// not block showing an intact sibling on its own.
func TestListCorruptSiblingDoesNotBlockShow(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	if _, _, err := ListVersions(dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("list past a corrupt sibling: %v, want ErrCorruptVersion", err)
	}
	twin, err := GetVersion(dir, "twin")
	if err != nil {
		t.Fatalf("showing intact twin blocked by corrupt sibling: %v", err)
	}
	if want := mustRuleVersion(t, twinVersionSpec); twin != want {
		t.Fatalf("twin = %+v, want %+v", twin, want)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("queries changed the archive")
	}
}
