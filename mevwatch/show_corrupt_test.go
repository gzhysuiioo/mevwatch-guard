package mevwatch

// Regression coverage for `rules show` (GetVersion) against a registered
// version whose stored archive document has decayed since registration.
// Showing a version must prove its actual stored declaration still
// satisfies the registration rules — the same proof registration,
// enabling, comparison, evaluation and replay already demand — so a
// corrupt registered version is refused with ErrCorruptVersion (never
// shown with silently zeroed or defaulted parameters, never substituted
// with the enabled, built-in or default parameters, never reported
// unknown), even when it is the currently enabled version. The check
// covers only the requested version: a corrupt sibling never blocks
// showing an intact one, and the query never rewrites the archive.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestShowCorruptVersionRefused runs the full corruption matrix against
// showing a registered version: every way its stored document can stop
// satisfying the registration rules must fail with ErrCorruptVersion, name
// the version and the offending rule or field, and leave the archive
// untouched.
func TestShowCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, err := GetVersion(dir, "candC")
			if err == nil {
				t.Fatalf("corrupt version shown successfully: %+v", v)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("registered-but-corrupt version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the requested version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused show changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestShowCorruptEnabledVersionRefused pins the core regression: the
// integrity check runs even when the requested id is the currently enabled
// version, and a corrupt enabled version blocks neither showing an intact
// sibling nor showing builtin.
func TestShowCorruptEnabledVersionRefused(t *testing.T) {
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

			v, err := GetVersion(dir, "candC")
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("showing the corrupt enabled version: v=%+v err=%v, want ErrCorruptVersion", v, err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corrupt enabled version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name version candC and field %q, got %v", tc.wantErr, err)
			}

			// The corrupt enabled version does not contaminate intact
			// versions: twin and builtin still show their full parameters.
			twin, err := GetVersion(dir, "twin")
			if err != nil {
				t.Fatalf("intact twin blocked by corrupt enabled sibling: %v", err)
			}
			if want := mustRuleVersion(t, twinVersionSpec); twin != want {
				t.Fatalf("twin = %+v, want %+v", twin, want)
			}
			b, err := GetVersion(dir, BuiltinVersionID)
			if err != nil || b != BuiltinVersion() {
				t.Fatalf("builtin blocked by corrupt enabled sibling: %+v, %v", b, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("show changed the archive")
			}
		})
	}
}

// TestShowCorruptSiblingDoesNotBlock proves damage in one registered
// version neither blocks showing an intact sibling nor gets repaired,
// completed or dropped by the successful query: the corrupt entry is still
// refused on its own merits afterwards.
func TestShowCorruptSiblingDoesNotBlock(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	twin, err := GetVersion(dir, "twin")
	if err != nil {
		t.Fatalf("showing intact twin past a corrupt sibling failed: %v", err)
	}
	if want := mustRuleVersion(t, twinVersionSpec); twin != want {
		t.Fatalf("twin = %+v, want %+v", twin, want)
	}
	// The corrupt entry was not repaired or completed by the query.
	if _, err := GetVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling was silently repaired: %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("show changed the archive")
	}
}

// TestShowUnknownVersionExactMatch pins the boundary: an id no stored
// declaration carries stays an unknown-version failure (never corruption),
// and the id string is matched exactly — no case folding, no trimming.
func TestShowUnknownVersionExactMatch(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := readArchiveFile(t, dir)
	for _, id := range []string{"ghost", "CANDC", "Candc", " candC", "candC ", ""} {
		if _, err := GetVersion(dir, id); !errors.Is(err, ErrUnknownVersion) ||
			errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("id %q: error = %v, want ErrUnknownVersion", id, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("unknown-version query changed the archive")
	}
}

// TestShowCorruptDuplicateFieldRefused covers a decay registration could
// never have produced: a repeated field in the stored document, including
// spellings the decoder folds onto the same field. The raw bytes are
// patched directly because a JSON map cannot hold two keys.
func TestShowCorruptDuplicateFieldRefused(t *testing.T) {
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

			_, err := GetVersion(dir, "candC")
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("duplicate-field document: err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name candC and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused show changed the archive")
			}
		})
	}
}

// TestShowCorruptDuplicateIDRefused covers a decayed document that also
// repeats its identity key: "id":"other" arrives last and a plain
// unmarshal would fold the entry onto "other", hiding candC behind an
// unknown-version error. The query must still attribute the entry to the
// registered version and refuse it as corruption, under either spelling.
func TestShowCorruptDuplicateIDRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	at := strings.Index(text[vsec:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("candC entry not found in versions section")
	}
	pos := vsec + at
	patched := text[:pos] + `"id": "candC", "id": "other", ` + text[pos+len(`"id": "candC",`):]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)

	for _, asked := range []string{"candC", "other"} {
		if _, err := GetVersion(dir, asked); !errors.Is(err, ErrCorruptVersion) ||
			errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("showing %q against a duplicate-id document: %v", asked, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused show changed the archive")
	}
	// The intact twin is unaffected by the unidentifiable sibling.
	if _, err := GetVersion(dir, "twin"); err != nil {
		t.Fatalf("intact twin blocked by corrupt sibling: %v", err)
	}
}

// TestShowInvalidArchiveReported covers a whole archive file that is not
// valid JSON: a non-builtin query must report whole-archive corruption
// (neither unknown version nor version corruption), while builtin stays
// queryable.
func TestShowInvalidArchiveReported(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	if _, err := GetVersion(dir, "candC"); err == nil ||
		errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("invalid-JSON archive error = %v, want a whole-archive corruption error", err)
	}
	if _, err := GetVersion(dir, BuiltinVersionID); err != nil {
		t.Fatalf("builtin must stay queryable on an invalid archive: %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed show rewrote an invalid archive")
	}
}

// TestShowBuiltinAlwaysAvailable proves builtin needs no archive at all:
// a missing directory, a legacy archive without any versions section, and
// an archive holding a corrupt sibling all still show the built-in
// parameters, and a legacy archive offers no other version.
func TestShowBuiltinAlwaysAvailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if b, err := GetVersion(missing, BuiltinVersionID); err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin on a missing directory: %+v, %v", b, err)
	}
	if _, err := GetVersion(missing, "strict"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("missing directory, unregistered id: %v, want ErrUnknownVersion", err)
	}

	legacy := t.TempDir()
	legacyDoc := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[],"findings":[]}]}`
	if err := os.WriteFile(filepath.Join(legacy, archiveFileName), []byte(legacyDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := GetVersion(legacy, BuiltinVersionID); err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin on a legacy archive: %+v, %v", b, err)
	}
	if _, err := GetVersion(legacy, "strict"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("legacy archive, unregistered id: %v, want ErrUnknownVersion", err)
	}
}

// TestShowExplicitlyDisabledRulesAccepted proves enabled:false is a legal
// off state, not corruption: a version with both rules disabled still carries
// complete parameters, and showing it returns the full declaration.
func TestShowExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := t.TempDir()
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, offSpec)
	v, err := GetVersion(dir, "off")
	if err != nil {
		t.Fatalf("an explicitly disabled version must show: %v", err)
	}
	if want := mustRuleVersion(t, offSpec); v != want {
		t.Fatalf("shown version = %+v, want %+v", v, want)
	}
}
