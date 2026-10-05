package mevwatch

// Regression coverage for viewing one registered rule version with
// GetVersion (`rules show`). A view must prove the named version's stored
// archive document still satisfies every registration rule before it
// returns a single parameter — the same proof a comparison, a review-range
// evaluation, a replay and an enable already demand — so a version whose
// declaration decayed is refused with ErrCorruptVersion instead of coming
// back under zeroed fields (a missing enabled looked like an explicit
// false; a missing severity or multiplier looked like 0), defaults, the
// currently enabled version or the built-in rules. The check targets only
// the named version: a corrupt sibling, even one that is currently enabled,
// neither blocks an intact candidate nor the built-in version, and a
// refused view leaves the archive byte for byte untouched.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestGetVersionCorruptRefused runs the full corruption matrix against a
// single-version view: every way a stored version document can stop
// satisfying the registration rules must fail with ErrCorruptVersion,
// name the version and the offending rule or field, return no parameters,
// and never masquerade as an unknown version.
func TestGetVersionCorruptRefused(t *testing.T) {
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
				t.Fatalf("corruption misreported as unknown version: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the requested version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if v != (RuleVersion{}) {
				t.Fatalf("a refused view must return no parameters, got %+v", v)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused view changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestGetVersionCorruptEnabledSiblingDoesNotBlock pins the scoping rule:
// the integrity check targets only the version the user named. A corrupt
// version currently enabled does not damage viewing an intact sibling, and
// the built-in version stays viewable with no registration.
func TestGetVersionCorruptEnabledSiblingDoesNotBlock(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	// The corrupt, currently-enabled version still fails on its own merits.
	if _, err := GetVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("viewing the corrupt enabled version: %v, want ErrCorruptVersion", err)
	}

	// The intact sibling is returned with its full, exact parameters.
	twin, err := GetVersion(dir, "twin")
	if err != nil {
		t.Fatalf("viewing intact twin past a corrupt enabled sibling: %v", err)
	}
	if want := mustRuleVersion(t, twinVersionSpec); twin != want {
		t.Fatalf("twin = %+v, want %+v", twin, want)
	}

	// Builtin needs no registration and is immune to the damaged sibling.
	b, err := GetVersion(dir, BuiltinVersionID)
	if err != nil {
		t.Fatalf("viewing builtin past a corrupt sibling: %v", err)
	}
	if b != BuiltinVersion() {
		t.Fatalf("builtin parameters wrong: %+v", b)
	}

	// The enabled marker and the damaged declaration survive the views.
	skeleton := readEnableSkeleton(t, dir)
	if skeleton.EnabledVersion != "candC" {
		t.Fatalf("enabled marker changed to %q", skeleton.EnabledVersion)
	}
}

// TestGetVersionIntactReturnsFullDeclaration proves the success path keeps
// the documented JSON shape and values, including an explicitly disabled
// rule: enabled:false is a normal off state, but its severity and the
// displacement multiplier still come back in full.
func TestGetVersionIntactReturnsFullDeclaration(t *testing.T) {
	dir := t.TempDir()
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":5,"multiplier":100}}}`
	register(t, dir, offSpec)
	v, err := GetVersion(dir, "off")
	if err != nil {
		t.Fatalf("viewing an intact disabled-rules version: %v", err)
	}
	if want := mustRuleVersion(t, offSpec); !reflect.DeepEqual(v, want) {
		t.Fatalf("GetVersion = %+v, want %+v", v, want)
	}
	if v.Rules.Sandwich.Enabled || v.Rules.Sandwich.Severity != 1 ||
		v.Rules.Displacement.Enabled || v.Rules.Displacement.Severity != 5 ||
		v.Rules.Displacement.Multiplier != 100 {
		t.Fatalf("disabled-rule parameters zeroed or substituted: %+v", v)
	}
}

// TestGetVersionDuplicateFieldRefused covers damage registration could
// never have produced: a repeated parameter field in the stored document,
// including an escaped or case-only spelling. The raw bytes are patched
// directly because a JSON map cannot hold two keys.
func TestGetVersionDuplicateFieldRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	raw := readArchiveFile(t, dir)
	text := string(raw)
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

	_, err := GetVersion(dir, "candC")
	if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate-field document: err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
	}
	if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("error must name candC and severity, got %v", err)
	}
}

// TestGetVersionDuplicateIDRefused covers a decayed document that repeats
// its identity key: "id":"other" arrives last and a plain unmarshal would
// fold the entry onto "other", hiding candC behind an unknown-version
// error. Viewing either spelling must attribute the entry to the requested
// id and refuse it as corruption, never treat the later value as an
// override and report the version unregistered.
func TestGetVersionDuplicateIDRefused(t *testing.T) {
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
		v, err := GetVersion(dir, asked)
		if !errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("viewing %q against a duplicate-id document: v=%+v err=%v", asked, v, err)
		}
		if !strings.Contains(err.Error(), asked) {
			t.Fatalf("error must name the requested version %q, got %v", asked, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused views changed the archive")
	}
	// The intact twin is unaffected by the unidentifiable sibling.
	if _, err := GetVersion(dir, "twin"); err != nil {
		t.Fatalf("intact twin blocked by corrupt sibling: %v", err)
	}
}

// TestGetVersionUnknownVersionExactMatch pins the boundary with
// ErrUnknownVersion: an id that was never registered stays unknown, the id
// is matched exactly (no case folding, no trimming), and a corrupt sibling
// changes none of this.
func TestGetVersionUnknownVersionExactMatch(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	for _, asked := range []string{"ghost", "candc", "CANDC", " candC", "candC ", "candC\n"} {
		v, err := GetVersion(dir, asked)
		if !errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrCorruptVersion) {
			t.Fatalf("GetVersion(%q) = %+v, %v; want ErrUnknownVersion only", asked, v, err)
		}
		if !strings.Contains(err.Error(), asked) {
			t.Fatalf("error must quote the requested id %q, got %v", asked, err)
		}
	}

	// No archive directory at all: only builtin exists.
	empty := t.TempDir()
	if _, err := GetVersion(filepath.Join(empty, "missing"), "anything"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("absent dir, non-builtin id: %v, want ErrUnknownVersion", err)
	}
}

// TestGetVersionBuiltinAlwaysAvailable proves the built-in version is
// queryable with no archive directory, against a pre-version legacy
// archive, and alongside a corrupt sibling or an unparseable whole archive:
// it is constructed in code and never read out of the file.
func TestGetVersionBuiltinAlwaysAvailable(t *testing.T) {
	// No directory.
	b, err := GetVersion(t.TempDir(), BuiltinVersionID)
	if err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin without a directory: %+v, %v", b, err)
	}

	// Pre-version archive with no versions section.
	legacyDir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,"swaps":[],"findings":[]}]}`
	if err := os.WriteFile(filepath.Join(legacyDir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err = GetVersion(legacyDir, BuiltinVersionID)
	if err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin on a legacy archive: %+v, %v", b, err)
	}
	// Such an archive can only resolve the built-in version.
	if _, err := GetVersion(legacyDir, "strict"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("legacy archive, registered id: %v, want ErrUnknownVersion", err)
	}
	// Registering a version into the legacy archive makes just that version
	// additionally queryable.
	register(t, legacyDir, strictSpec)
	if got, err := GetVersion(legacyDir, "strict"); err != nil || got != mustRuleVersion(t, strictSpec) {
		t.Fatalf("registered version not viewable in a legacy archive: %+v, %v", got, err)
	}

	// Corrupt sibling present.
	corruptDir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, corruptDir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = nil
	})
	if b, err := GetVersion(corruptDir, BuiltinVersionID); err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin next to a corrupt sibling: %+v, %v", b, err)
	}

	// Whole archive no longer parseable: builtin is still answered from
	// code without touching the file.
	path := filepath.Join(corruptDir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := GetVersion(corruptDir, BuiltinVersionID); err != nil || b != BuiltinVersion() {
		t.Fatalf("builtin against an unparseable archive: %+v, %v", b, err)
	}
}

// TestGetVersionUnparseableArchiveReportsArchiveCorruption proves that
// when the whole archive cannot be parsed, a non-builtin view fails as a
// whole-archive corruption error — distinct from a corrupt version and
// from an unknown version — rather than pretending the id is unregistered.
func TestGetVersionUnparseableArchiveReportsArchiveCorruption(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := GetVersion(dir, "twin")
	if err == nil {
		t.Fatal("unparseable archive produced a version")
	}
	if errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("whole-archive failure misreported as a corrupt version: %v", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("whole-archive failure misreported as an unknown version: %v", err)
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error must describe the corrupt archive, got %v", err)
	}
}

// TestGetVersionIsReadOnly proves successful and failed views change
// nothing: the versions section, enabled marker, reports and history all
// survive a mix of intact and corrupt single-version queries.
func TestGetVersionIsReadOnly(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	for _, id := range []string{"twin", BuiltinVersionID, "candC", "ghost"} {
		_, _ = GetVersion(dir, id)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("views changed the archive:\nbefore=%s\nafter =%s", before, after)
	}
	report, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 {
		t.Fatalf("archived report changed: %+v", report)
	}
	if _, enabled, err := ListVersions(dir); err != nil || enabled != "twin" {
		t.Fatalf("enabled marker changed: enabled=%q err=%v", enabled, err)
	}
}
