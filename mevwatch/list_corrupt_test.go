package mevwatch

// Regression coverage for listing rule versions (ListVersions, the
// `rules list` backend) when a registered version's stored archive document
// has decayed since registration. Showing one version already proved that
// version's stored declaration still satisfies the registration rules, but
// the list used to decode every entry straight into structs: a missing
// enabled rendered as an explicit false and a missing multiplier as 0, so a
// damaged version was displayed with normal-looking zero values, and a
// wrong-typed field blew the read up as whole-archive corruption.
//
// Listing must instead judge every registered document with the same
// parser registration, enabling, comparison, replay and show use, and fail
// the whole query — no full or partial list — when a single entry is
// corrupt, even when it is not the enabled one and wherever it sits in the
// archive. The corrupt entry is never skipped, repaired, completed or
// replaced with the enabled version, builtin or defaults; an explicitly
// declared enabled:false is still a legal off state and lists normally.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestListCorruptVersionRefused runs the full corruption matrix against
// listing an archive whose first registered version (candC, which is not
// enabled — the marker defaults to builtin) has decayed. Every kind of
// damage must fail the whole list with ErrCorruptVersion naming the
// version and the offending rule or field, return no versions, and leave
// the archive byte for byte untouched.
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
				t.Fatalf("corrupt version listed successfully: %+v", versions)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corrupt registered version misreported as unknown: %v", err)
			}
			if versions != nil {
				t.Fatalf("a refused list must return no versions, not even a partial one: %+v", versions)
			}
			if enabled != "" {
				t.Fatalf("a refused list must not report an enabled version: %q", enabled)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the corrupt version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused list changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
		})
	}
}

// TestListCorruptEnabledVersionRefused proves the check also runs when the
// damaged entry is the currently enabled version.
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

			versions, _, err := ListVersions(dir)
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("listing a corrupt enabled version: versions=%+v err=%v, want ErrCorruptVersion", versions, err)
			}
			if versions != nil {
				t.Fatalf("refused list leaked versions: %+v", versions)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name version candC and field %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestListCorruptLastVersionRefused proves position does not matter: the
// damaged entry sitting after intact entries (twin is stored after candC)
// fails the whole list just as an early one does — nothing is listed up to
// the corrupt point.
func TestListCorruptLastVersionRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "twin", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	versions, _, err := ListVersions(dir)
	if !errors.Is(err, ErrCorruptVersion) || versions != nil {
		t.Fatalf("corrupt trailing version: versions=%+v err=%v", versions, err)
	}
	if !strings.Contains(err.Error(), "twin") || !strings.Contains(err.Error(), "multiplier") {
		t.Fatalf("error must name twin and multiplier, got %v", err)
	}
}

// TestListCorruptDuplicateFieldRefused covers damage registration could
// never have produced: a repeated field in the stored document, including
// case-only and escaped spellings the decoder folds onto the same field.
// The raw bytes are patched directly because a JSON map cannot hold two
// keys; two equal occurrences are still a duplicate.
func TestListCorruptDuplicateFieldRefused(t *testing.T) {
	for _, dup := range []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"identical value", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", `"se\u0076erity": 4, `},
		{"long-s variant", `"ſeverity": 4, `},
	} {
		t.Run(dup.name, func(t *testing.T) {
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
			patched := text[:pos] + dup.field + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			before := readArchiveFile(t, dir)

			versions, _, err := ListVersions(dir)
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("duplicate-field document: versions=%+v err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", versions, err)
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

// patchDuplicateID rewrites the stored version's raw document in place so
// its object opens with two id keys: the registered id first and secondID
// last. A JSON map cannot hold two keys, so the bytes are patched the same
// way the duplicate-field show tests do.
func patchDuplicateID(t *testing.T, dir, registeredID, secondID string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	if vsec < 0 {
		t.Fatal("versions section not found in archive")
	}
	at := strings.Index(text[vsec:], `"id": "`+registeredID+`"`)
	if at < 0 {
		t.Fatalf("%s entry not found in versions section", registeredID)
	}
	pos := vsec + at
	patched := text[:pos] + `"id": "` + registeredID + `", "id": "` + secondID + `", ` +
		text[pos+len(`"id": "`+registeredID+`",`):]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
}

// nullifyFirstVersionEntry replaces the versions array's first object with
// a JSON null entry by locating the first "{" after "versions" and finding
// its matching "}" with a brace scan.
func nullifyFirstVersionEntry(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	if vsec < 0 {
		t.Fatal("versions section not found in archive")
	}
	open := strings.Index(text[vsec:], "{")
	if open < 0 {
		t.Fatal("no version object in versions section")
	}
	open += vsec
	depth := 0
	close := -1
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				close = i
			}
		}
		if close >= 0 {
			break
		}
	}
	if close < 0 {
		t.Fatal("unterminated version object")
	}
	patched := text[:open] + "null" + text[close+1:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestListCorruptDuplicateIDNamesIdentifiableVersion covers a decayed
// document that also repeats its identity key. The list must still fail as
// corruption and name an identifiable version — the id a reader sees in
// the decoded document (the last occurrence, which unmarshal folds onto) —
// never report success or mislabel it an unknown version.
func TestListCorruptDuplicateIDNamesIdentifiableVersion(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	patchDuplicateID(t, dir, "candC", "other")
	before := readArchiveFile(t, dir)

	_, _, err := ListVersions(dir)
	if !errors.Is(err, ErrCorruptVersion) || errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("duplicate-id document: %v, want ErrCorruptVersion", err)
	}
	// The surviving id (last occurrence, what an unmarshal shows) is the
	// identifiable marker; the registered id is named in the document too.
	if !strings.Contains(err.Error(), "other") {
		t.Fatalf("error must name the identifiable version, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused list changed the archive")
	}
}

// TestListCorruptUnidentifiableVersionStillRefused proves a stored entry
// that carries no string id at all still fails the whole list as version
// corruption (with the parse reason) rather than panicking or being
// skipped; the failure simply cannot invent a version name.
func TestListCorruptUnidentifiableVersionStillRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver, "id")
	})
	versions, _, err := ListVersions(dir)
	if !errors.Is(err, ErrCorruptVersion) || versions != nil {
		t.Fatalf("id-less document: versions=%+v err=%v", versions, err)
	}
	if !strings.Contains(err.Error(), "id") {
		t.Fatalf("error must carry the parser reason about id, got %v", err)
	}

	// A null entry is likewise unidentifiable corruption, not a skipped one.
	dir2 := setupCorruptCompareArchive(t)
	nullifyFirstVersionEntry(t, dir2)
	if versions, _, err := ListVersions(dir2); !errors.Is(err, ErrCorruptVersion) || versions != nil {
		t.Fatalf("null entry: versions=%+v err=%v", versions, err)
	}
}

// TestListInvalidArchiveReported proves a wholly unparseable archive keeps
// its whole-archive corruption error: it is neither treated as "no
// registered versions" nor mislabelled as one corrupt version.
func TestListInvalidArchiveReported(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	versions, _, err := ListVersions(dir)
	if err == nil {
		t.Fatalf("invalid-JSON archive listed: %+v", versions)
	}
	if errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("whole-archive failure misreported as version corruption: %v", err)
	}
	if !strings.Contains(err.Error(), "archive is corrupted") {
		t.Fatalf("error must report archive corruption, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed list rewrote an invalid archive")
	}
}

// TestListIntactVersionsShape pins the successful behaviour: builtin first,
// registered versions in stored order with full parameters, every id string
// preserved verbatim, and the enabled marker reported accurately.
func TestListIntactVersionsShape(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := readArchiveFile(t, dir)

	versions, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("a successful list must be read-only")
	}
	if enabled != BuiltinVersionID {
		t.Fatalf("enabled = %q, want builtin before any enable", enabled)
	}
	want := []RuleVersion{
		BuiltinVersion(),
		mustRuleVersion(t, candidateVersionSpec),
		mustRuleVersion(t, twinVersionSpec),
	}
	if !reflect.DeepEqual(versions, want) {
		t.Fatalf("versions = %+v\nwant %+v", versions, want)
	}
	// Explicit zero/false parameters survive: candC has sandwich explicitly
	// disabled, and that must show as false with its real severity, never as
	// corruption or a dropped rule.
	candC := versions[1]
	if candC.Rules.Sandwich.Enabled || candC.Rules.Sandwich.Severity != 3 {
		t.Fatalf("explicitly disabled sandwich distorted: %+v", candC.Rules.Sandwich)
	}
	// Each listed version matches what a single-version show returns.
	for _, w := range want {
		got, err := GetVersion(dir, w.ID)
		if err != nil || got != w {
			t.Fatalf("list/show disagree for %s: %+v %v", w.ID, got, err)
		}
	}

	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatal(err)
	}
	listBefore := readArchiveFile(t, dir)
	_, enabled, err = ListVersions(dir)
	if err != nil || enabled != "twin" {
		t.Fatalf("enabled marker after enable: %q, %v", enabled, err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(listBefore, after) {
		t.Fatalf("a successful list must be read-only")
	}
}

// TestListExplicitlyDisabledRulesAccepted proves enabled:false on both
// rules is a normal version: the list shows it with complete parameters,
// distinguishing a real off state from a lost enabled field.
func TestListExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := t.TempDir()
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, offSpec)
	versions, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatalf("an explicitly disabled version must list: %v", err)
	}
	if enabled != BuiltinVersionID || len(versions) != 2 {
		t.Fatalf("list shape wrong: enabled=%q versions=%+v", enabled, versions)
	}
	if want := mustRuleVersion(t, offSpec); versions[1] != want {
		t.Fatalf("listed off version = %+v, want %+v", versions[1], want)
	}
	if versions[1].Rules.Sandwich.Enabled || versions[1].Rules.Displacement.Enabled ||
		versions[1].Rules.Displacement.Multiplier != 2 {
		t.Fatalf("false flags and real multiplier must both be shown: %+v", versions[1].Rules)
	}
}

// TestListVersionIDsVerbatim pins that listing never case-folds, trims or
// otherwise rewrites the stored id strings.
func TestListVersionIDsVerbatim(t *testing.T) {
	dir := t.TempDir()
	specs := []string{
		`{"id":" StRiCt ","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
		`{"id":"Caps","rules":{"sandwich":{"enabled":false,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":7}}}`,
	}
	for _, spec := range specs {
		register(t, dir, spec)
	}
	versions, _, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, v := range versions {
		ids = append(ids, v.ID)
	}
	wantIDs := []string{BuiltinVersionID, " StRiCt ", "Caps"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("ids = %q, want %q", ids, wantIDs)
	}
}

// TestListMissingAndLegacyArchives pins the empty-state behaviour: a
// missing directory and a pre-version archive (no versions section and no
// enabled marker, records present) both return builtin with its original
// parameters.
func TestListMissingAndLegacyArchives(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	versions, enabled, err := ListVersions(missing)
	if err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	if enabled != BuiltinVersionID || !reflect.DeepEqual(versions, []RuleVersion{BuiltinVersion()}) {
		t.Fatalf("missing directory list = %+v enabled=%q", versions, enabled)
	}

	legacy := t.TempDir()
	legacyDoc := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[],"findings":[]}]}`
	if err := os.WriteFile(filepath.Join(legacy, archiveFileName), []byte(legacyDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	versions, enabled, err = ListVersions(legacy)
	if err != nil {
		t.Fatalf("legacy archive: %v", err)
	}
	if enabled != BuiltinVersionID || !reflect.DeepEqual(versions, []RuleVersion{BuiltinVersion()}) {
		t.Fatalf("legacy list = %+v enabled=%q", versions, enabled)
	}
}

// TestListCorruptSiblingDoesNotBlockShow pins the asymmetry the task
// keeps: a corrupt sibling fails the list, but showing one intact legal
// version stays unaffected by the other damaged entry.
func TestListCorruptSiblingDoesNotBlockShow(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	if _, _, err := ListVersions(dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("list must fail: %v", err)
	}
	twin, err := GetVersion(dir, "twin")
	if err != nil {
		t.Fatalf("showing intact twin must be unaffected: %v", err)
	}
	if want := mustRuleVersion(t, twinVersionSpec); twin != want {
		t.Fatalf("twin = %+v, want %+v", twin, want)
	}
}
