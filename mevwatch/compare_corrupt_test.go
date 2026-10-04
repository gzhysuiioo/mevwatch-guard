package mevwatch

// Coverage for compare's handling of a registered version whose stored
// declaration is damaged. Registration validates every spec, so a corrupt
// document can only reach the archive out of band; these tests hand-edit
// archive.json to produce each defect shape. A compare naming such a
// version must refuse the comparison with ErrCorruptVersion naming the
// version and the bad field — never substituting zero values, the
// built-in rules, the enabled version or any default — and must leave the
// archive byte-identical. An explicitly disabled rule with all fields
// present stays valid, and the refusal is identical for a block with no
// swaps even though no conclusion could ever be produced.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// adjacentSwapInput has same-pool adjacent swaps whose only possible hit
// is displacement: front 30 vs victim 10. Sandwich cannot fire (there is
// no back swap), so with displacement enabled and multiplier 0 this is
// exactly the shape that used to panic (MaxInt64/0) and otherwise
// produces false conclusions from zero-valued parameters.
const adjacentSwapInput = `{"chainId":"1","blockHash":"0adj","blockNumber":4,"swaps":[` +
	`{"TxHash":"0f","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":30,"Index":0},` +
	`{"TxHash":"0v","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`

const emptySwapInput = `{"chainId":"1","blockHash":"0empty","blockNumber":1,"swaps":[]}`

// setupCorruptArchive registers a good archiving version archA, the
// enabled version liveB and a valid "damaged" version, archives input
// under archA and enables liveB; it then replaces only the stored
// document of "damaged" with corruptRaw. Passing tests therefore prove
// neither the enabled version nor the built-in rules are substituted for
// the requested damaged one.
func setupCorruptArchive(t *testing.T, input, corruptRaw string) string {
	t.Helper()
	dir := t.TempDir()
	const (
		archSpec = `{"id":"archA","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":1,"multiplier":3}}}`
		liveSpec = `{"id":"liveB","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":5,"multiplier":4}}}`
		damaged  = `{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
	)
	register(t, dir, archSpec)
	register(t, dir, liveSpec)
	register(t, dir, damaged)
	if _, err := ReplayWithVersion(strings.NewReader(input), dir, "archA"); err != nil {
		t.Fatalf("ReplayWithVersion: %v", err)
	}
	if _, err := EnableVersion(dir, "liveB"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	patchStoredSpec(t, dir, "damaged", corruptRaw)
	return dir
}

// patchStoredSpec replaces the stored registration document whose id is
// targetID with raw (which may itself be invalid), simulating out-of-band
// damage to archive.json without touching the other versions.
func patchStoredSpec(t *testing.T, dir, targetID, raw string) {
	t.Helper()
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	replaced := false
	for i, spec := range data.VersionSpecs {
		if specVersionID(spec) == targetID {
			data.VersionSpecs[i] = json.RawMessage(raw)
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatalf("stored spec %q not found", targetID)
	}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
}

func TestCompareRejectsCorruptVersions(t *testing.T) {
	cases := []struct {
		name      string
		corrupt   string
		wantField string
	}{
		{
			"multiplier zero (would divide by zero)",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":0}}}`,
			"multiplier",
		},
		{
			"multiplier missing",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2}}}`,
			"multiplier",
		},
		{
			"multiplier null",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":null}}}`,
			"multiplier",
		},
		{
			"multiplier out of range high",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":101}}}`,
			"multiplier",
		},
		{
			"multiplier wrong type",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":"2"}}}`,
			"multiplier",
		},
		{
			"displacement severity missing",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"multiplier":2}}}`,
			"displacement.severity",
		},
		{
			"displacement severity null",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":null,"multiplier":2}}}`,
			"displacement.severity",
		},
		{
			"sandwich severity out of range",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":6},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich.severity",
		},
		{
			"sandwich severity wrong type",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":"3"},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich.severity",
		},
		{
			"sandwich enabled missing",
			`{"id":"damaged","rules":{"sandwich":{"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich.enabled",
		},
		{
			"sandwich enabled null",
			`{"id":"damaged","rules":{"sandwich":{"enabled":null,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich.enabled",
		},
		{
			"sandwich enabled wrong type",
			`{"id":"damaged","rules":{"sandwich":{"enabled":"yes","severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich.enabled",
		},
		{
			"displacement object missing",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3}}}`,
			"displacement",
		},
		{
			"displacement object null",
			`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":null}}`,
			"displacement",
		},
		{
			"sandwich object missing",
			`{"id":"damaged","rules":{"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
			"sandwich",
		},
		{
			"rules object missing",
			`{"id":"damaged"}`,
			"rules",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptArchive(t, adjacentSwapInput, tc.corrupt)
			_, err := Compare(dir, "1", "0adj", "damaged")
			if err == nil {
				t.Fatal("Compare with corrupt version succeeded")
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("err = %v, want ErrCorruptVersion", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, `"damaged"`) {
				t.Fatalf("error must name the requested version: %v", err)
			}
			if !strings.Contains(msg, tc.wantField) {
				t.Fatalf("error %q must name the bad field %q", msg, tc.wantField)
			}
		})
	}
}

// A block with no swaps and therefore no possible conclusion must still
// refuse the corrupt version deterministically before any detection runs.
func TestCompareCorruptVersionFailsEvenWithEmptySwaps(t *testing.T) {
	corrupt := `{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2}}}`
	dir := setupCorruptArchive(t, emptySwapInput, corrupt)
	_, err := Compare(dir, "1", "0empty", "damaged")
	if err == nil || !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("err = %v, want ErrCorruptVersion even with no swaps", err)
	}
}

// Explicit false is a complete, valid off state for either rule, and a
// closed rule still has to carry its full parameters: the disabled-but-
// complete version compares successfully (with no candidate findings),
// while a disabled rule missing its own severity is still corrupt.
func TestCompareExplicitFalseIsValidOffState(t *testing.T) {
	dir := t.TempDir()
	const (
		damaged = `{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
		bothOff = `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":false,"severity":2,"multiplier":2}}}`
	)
	register(t, dir, damaged)
	register(t, dir, bothOff)
	if _, err := ReplayWithVersion(strings.NewReader(adjacentSwapInput), dir, "damaged"); err != nil {
		t.Fatalf("ReplayWithVersion: %v", err)
	}
	result, err := Compare(dir, "1", "0adj", "off")
	if err != nil {
		t.Fatalf("fully declared disabled rules must compare: %v", err)
	}
	if len(result.ComparedFindings) != 0 {
		t.Fatalf("both rules off must yield no conclusions, got %+v", result.ComparedFindings)
	}

	// Disabled displacement that omits severity and multiplier is still
	// corrupt: the closed rule is not excused from declaring parameters.
	bad := setupCorruptArchive(t, adjacentSwapInput,
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":false}}}`)
	if _, err := Compare(bad, "1", "0adj", "damaged"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("err = %v, want ErrCorruptVersion for disabled rule with missing params", err)
	}
}

// Corruption never substitutes the built-in, enabled or any default
// rules: liveB and builtin remain usable on the same archive, and the
// failed comparison is an error rather than an inconclusive success.
// Unknown version and unknown block keep their distinct error behavior.
func TestCompareCorruptVersionDoesNotSubstitute(t *testing.T) {
	dir := setupCorruptArchive(t, adjacentSwapInput,
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":0}}}`)
	if _, err := Compare(dir, "1", "0adj", "damaged"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt compare: %v", err)
	}
	if _, err := Compare(dir, "1", "0adj", "liveB"); err != nil {
		t.Fatalf("enabled liveB compare must still work: %v", err)
	}
	if _, err := Compare(dir, "1", "0adj", BuiltinVersionID); err != nil {
		t.Fatalf("builtin compare must still work: %v", err)
	}
	if _, err := Compare(dir, "1", "0adj", "ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("unknown version err = %v, want ErrUnknownVersion", err)
	}
	if _, err := Compare(dir, "1", "0ghost", "damaged"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block err = %v, want ErrUnknownBlock", err)
	}
}

// Failed and successful comparisons leave every byte of the archive
// untouched: the corrupt document, the original report, swap evidence,
// enabled marker and other records all stay as they were.
func TestCompareCorruptVersionIsReadOnly(t *testing.T) {
	dir := setupCorruptArchive(t, adjacentSwapInput,
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":0}}}`)
	path := filepath.Join(dir, archiveFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = Compare(dir, "1", "0adj", "damaged")
	_, _ = Compare(dir, "1", "0adj", "liveB")
	_, _ = Compare(dir, "1", "0adj", BuiltinVersionID)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("compare rewrote the archive:\nbefore=%s\nafter =%s", before, after)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if data.EnabledVersion != "liveB" {
		t.Fatalf("enabled marker changed to %q", data.EnabledVersion)
	}
	report, err := Query(dir, "1", "0adj")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "archA" {
		t.Fatalf("archived report version changed: %+v", report.Version)
	}
}

// Other version entry points surface the same identifiable corruption
// rather than handing out zero-valued parameters, and a failed enable
// never moves the enabled marker.
func TestOtherVersionEntryPointsRejectCorruptVersion(t *testing.T) {
	dir := setupCorruptArchive(t, adjacentSwapInput,
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2}}}`)
	if _, err := GetVersion(dir, "damaged"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("GetVersion err = %v, want ErrCorruptVersion", err)
	}
	if _, err := EnableVersion(dir, "damaged"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("EnableVersion err = %v, want ErrCorruptVersion", err)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if data.EnabledVersion != "liveB" {
		t.Fatalf("failed enable moved the marker to %q", data.EnabledVersion)
	}
	if _, _, err := ListVersions(dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("ListVersions err = %v, want ErrCorruptVersion", err)
	}
}

// Old-format archives that stored parsed versions (the pre-spec
// "versions" array) keep comparing without any upgrade or rewrite.
func TestCompareOldFormatVersionStorageStillWorks(t *testing.T) {
	dir := t.TempDir()
	s := func(tx, trader string, gas int64, index int) Swap {
		return Swap{TxHash: tx, Pool: "p1", Trader: trader, In: 1, Out: 1, GasPrice: gas, Index: index}
	}
	swaps := []Swap{s("0f", "bot", 90, 0), s("0v", "user", 10, 1), s("0b", "bot", 80, 2)}
	old := archiveData{
		Records: []record{{
			ChainID: "1", BlockHash: "0old", BlockNumber: 5, Swaps: swaps,
			Findings: []ReportFinding{{
				Kind: "sandwich", Severity: 3, TxHash: "0v", Evidence: swaps,
			}},
		}},
		// Old storage layout: parsed versions, no spec documents.
		Versions: []RuleVersion{{
			ID: "candC",
			Rules: RuleSet{
				Sandwich:     SandwichRule{Enabled: false, Severity: 3},
				Displacement: DisplacementRule{Enabled: true, Severity: 4, Multiplier: 2},
			},
		}},
	}
	if err := writeArchiveAtomic(dir, old); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, archiveFileName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), `"versions"`) ||
		strings.Contains(string(before), `"versionSpecs"`) {
		t.Fatalf("fixture is not in the old storage layout:\n%s", before)
	}
	result, err := Compare(dir, "1", "0old", "candC")
	if err != nil {
		t.Fatalf("old-format version must compare: %v", err)
	}
	if result.ComparedVersion.ID != "candC" ||
		result.ComparedVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("migrated parameters wrong: %+v", result.ComparedVersion)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("compare rewrote an old-format archive:\nbefore=%s\nafter =%s", before, after)
	}
}

// A damaged value in the old parsed layout is still caught after
// migration: the struct cannot express a missing field but a hand-edited
// zero multiplier is marshalled back as "multiplier":0 and rejected.
func TestCompareOldFormatCorruptVersionRejected(t *testing.T) {
	dir := t.TempDir()
	if err := writeArchiveAtomic(dir, archiveData{
		Records: []record{{
			ChainID: "1", BlockHash: "0old", BlockNumber: 5,
			Swaps:    []Swap{{TxHash: "0f", Pool: "p1", Trader: "w", In: 1, Out: 1, GasPrice: 30, Index: 0}},
			Findings: []ReportFinding{},
		}},
		Versions: []RuleVersion{{
			ID: "bad",
			Rules: RuleSet{
				Sandwich:     SandwichRule{Enabled: true, Severity: 3},
				Displacement: DisplacementRule{Enabled: true, Severity: 2, Multiplier: 0},
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	_, err := Compare(dir, "1", "0old", "bad")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("err = %v, want ErrCorruptVersion from migrated old layout", err)
	}
}

// Registering a fresh, unrelated version stays usable even while a
// different version in the archive is damaged.
func TestRegisterUnrelatedVersionWithCorruptArchive(t *testing.T) {
	dir := setupCorruptArchive(t, adjacentSwapInput,
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":0}}}`)
	if _, created, err := RegisterVersion(dir, []byte(
		`{"id":"fresh","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
	)); err != nil || !created {
		t.Fatalf("registering unrelated version: v-created=%v err=%v", created, err)
	}
	// Re-registering the corrupt id cannot silently overwrite or repair it.
	if _, _, err := RegisterVersion(dir, []byte(
		`{"id":"damaged","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`,
	)); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("re-registering over a corrupt id: err=%v, want ErrCorruptVersion", err)
	}
	if _, err := Compare(dir, "1", "0adj", "fresh"); err != nil {
		t.Fatalf("fresh version must compare on the same archive: %v", err)
	}
}
