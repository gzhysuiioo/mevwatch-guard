package mevwatch

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const strictSpec = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`

func register(t *testing.T, dir, spec string) (RuleVersion, bool) {
	t.Helper()
	v, created, err := RegisterVersion(dir, []byte(spec))
	if err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
	return v, created
}

func TestParseRuleVersionValidation(t *testing.T) {
	bad := []struct {
		name string
		spec string
	}{
		{"not json", `{"id":`},
		{"trailing garbage", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}} extra`},
		{"missing id", `{"rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"empty id", `{"id":"","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"missing rules", `{"id":"v"}`},
		{"missing sandwich", `{"id":"v","rules":{"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"missing displacement", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3}}}`},
		{"missing enabled", `{"id":"v","rules":{"sandwich":{"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"missing severity", `{"id":"v","rules":{"sandwich":{"enabled":true},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"missing multiplier", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2}}}`},
		{"severity zero", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":0},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"severity six", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":6},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"severity string", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":"3"},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"severity fractional", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":2.5},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"enabled string", `{"id":"v","rules":{"sandwich":{"enabled":"yes","severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
		{"multiplier one", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":1}}}`},
		{"multiplier 101", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":101}}}`},
		{"multiplier fractional", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2.5}}}`},
		{"unknown rule", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2},"frontrun":{"enabled":true,"severity":1}}}`},
		{"unknown field", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}},"extra":1}`},
		{"sandwich with multiplier", `{"id":"v","rules":{"sandwich":{"enabled":true,"severity":3,"multiplier":2},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseRuleVersion([]byte(tc.spec)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	v, err := ParseRuleVersion([]byte(strictSpec))
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if v.ID != "strict" || !v.Rules.Sandwich.Enabled || v.Rules.Sandwich.Severity != 5 ||
		!v.Rules.Displacement.Enabled || v.Rules.Displacement.Severity != 4 || v.Rules.Displacement.Multiplier != 5 {
		t.Fatalf("parsed version wrong: %+v", v)
	}
}

func TestRegisterVersionLifecycle(t *testing.T) {
	dir := t.TempDir()
	v, created := register(t, dir, strictSpec)
	if !created {
		t.Fatal("first registration must report created")
	}
	// Same ID and identical parameters: success, no new version.
	if _, created := register(t, dir, strictSpec); created {
		t.Fatal("identical re-registration must not create a version")
	}
	versions, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].ID != BuiltinVersionID || versions[1] != v {
		t.Fatalf("versions = %+v", versions)
	}
	if enabled != BuiltinVersionID {
		t.Fatalf("enabled = %q, want builtin before any enable", enabled)
	}
	// Same ID, different parameters: rejected.
	different := `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	if _, _, err := RegisterVersion(dir, []byte(different)); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("got %v, want ErrVersionConflict", err)
	}
	// The built-in ID is reserved.
	builtinSpec := `{"id":"builtin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
	if _, _, err := RegisterVersion(dir, []byte(builtinSpec)); err == nil {
		t.Fatal("registering over the built-in id must fail")
	}
	// Enable persists and is visible to a fresh reader.
	if _, err := EnableVersion(dir, "strict"); err != nil {
		t.Fatal(err)
	}
	_, enabled, err = ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "strict" {
		t.Fatalf("enabled = %q, want strict", enabled)
	}
	got, err := GetVersion(dir, "strict")
	if err != nil || got != v {
		t.Fatalf("GetVersion = %+v, %v", got, err)
	}
	// Enabling an unknown version fails and changes nothing.
	if _, err := EnableVersion(dir, "nope"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
	_, enabled, _ = ListVersions(dir)
	if enabled != "strict" {
		t.Fatalf("failed enable changed enabled version to %q", enabled)
	}
	// The built-in version is queryable without registration.
	b, err := GetVersion(dir, BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if b.Rules.Sandwich != (SandwichRule{Enabled: true, Severity: 3}) ||
		b.Rules.Displacement != (DisplacementRule{Enabled: true, Severity: 2, Multiplier: 2}) {
		t.Fatalf("builtin params wrong: %+v", b)
	}
}

func TestRegisterVersionBusy(t *testing.T) {
	dir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterVersion(dir, []byte(strictSpec)); !errors.Is(err, ErrBusy) {
		t.Fatalf("register: got %v, want ErrBusy", err)
	}
	if _, err := EnableVersion(dir, "strict"); !errors.Is(err, ErrBusy) {
		t.Fatalf("enable: got %v, want ErrBusy", err)
	}
}

func TestConcurrentRegisterDistinctVersions(t *testing.T) {
	dir := t.TempDir()
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			spec := fmt.Sprintf(`{"id":"v%d","rules":{"sandwich":{"enabled":true,"severity":%d},"displacement":{"enabled":true,"severity":2,"multiplier":%d}}}`,
				i, i%5+1, i%99+2)
			// A busy archive is a valid answer to a concurrent writer; retry
			// until the registration commits.
			for {
				_, _, err := RegisterVersion(dir, []byte(spec))
				if errors.Is(err, ErrBusy) {
					continue
				}
				done <- err
				return
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent register: %v", err)
		}
	}
	versions, _, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 9 { // builtin + 8 registered
		t.Fatalf("got %d versions, want 9; concurrent writes lost data", len(versions))
	}
}

// displacementInput: front gas 40 is 4x the victim's 10 — flagged under
// multiplier 2 (builtin) but not under multiplier 5 (strict).
const displacementInput = `{"chainId":"1","blockHash":"0xd1","blockNumber":1,"swaps":[{"TxHash":"0xfront","Pool":"p1","Trader":"whale","In":1,"Out":1,"GasPrice":40,"Index":0},{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1}]}`

func TestReplayWithExplicitVersion(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, strictSpec)
	reports, err := ReplayWithVersion(strings.NewReader(displacementInput), dir, "strict")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Findings) != 0 {
		t.Fatalf("multiplier 5 must not flag 4x front gas: %+v", reports[0].Findings)
	}
	if reports[0].Version.ID != "strict" || reports[0].Version.Rules.Displacement.Multiplier != 5 {
		t.Fatalf("report does not carry the version used: %+v", reports[0].Version)
	}
	// The archived report keeps its version even though builtin would flag it.
	got, err := Query(dir, "1", "0xd1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version.ID != "strict" || len(got.Findings) != 0 {
		t.Fatalf("queried report wrong: %+v", got)
	}
}

func TestReplayUsesEnabledVersion(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, strictSpec)
	if _, err := EnableVersion(dir, "strict"); err != nil {
		t.Fatal(err)
	}
	reports := replay(t, dir, displacementInput)
	if len(reports[0].Findings) != 0 || reports[0].Version.ID != "strict" {
		t.Fatalf("enabled version not applied: %+v", reports[0])
	}
}

func TestReplayUnknownVersionLeavesArchiveUntouched(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReplayWithVersion(strings.NewReader(displacementInput), dir, "ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
	if _, err := Query(dir, "1", "0xd1"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("failed replay archived a block: %v", err)
	}
	if _, err := ReplayWithVersion(strings.NewReader(displacementInput), dir, ""); err == nil {
		t.Fatal("empty version id must fail")
	}
}

func TestReplaySandwichDisabledFallsToDisplacement(t *testing.T) {
	dir := t.TempDir()
	// Sandwich off: the same bracketing pattern is re-judged as displacement.
	spec := `{"id":"nosand","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	register(t, dir, spec)
	reports, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "nosand")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(reports[0].Findings))
	}
	f := reports[0].Findings[0]
	if f.Kind != "displacement" || f.Severity != 4 || f.TxHash != "0xvictim" {
		t.Fatalf("bad finding: %+v", f)
	}
}

func TestReplayBothRulesDisabled(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, spec)
	reports, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "off")
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].Findings == nil || len(reports[0].Findings) != 0 {
		t.Fatalf("both rules off must yield an empty findings array: %+v", reports[0].Findings)
	}
}

func TestReplayMultiplierOverflowSafe(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"big","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":2,"multiplier":100}}}`
	register(t, dir, spec)
	input := fmt.Sprintf(`{"chainId":"1","blockHash":"0xov","blockNumber":1,"swaps":[{"TxHash":"0xf1","Pool":"p","Trader":"a","In":0,"Out":0,"GasPrice":%[1]d,"Index":0},{"TxHash":"0xv1","Pool":"p","Trader":"b","In":0,"Out":0,"GasPrice":%[1]d,"Index":1},{"TxHash":"0xf2","Pool":"q","Trader":"a","In":0,"Out":0,"GasPrice":%[1]d,"Index":2},{"TxHash":"0xv2","Pool":"q","Trader":"b","In":0,"Out":0,"GasPrice":100000000000000000,"Index":3}]}`, math.MaxInt64)
	reports, err := ReplayWithVersion(strings.NewReader(input), dir, "big")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range reports[0].Findings {
		got[f.TxHash] = f.Kind
	}
	// victim MaxInt64: 100x would overflow, must not flag.
	if _, flagged := got["0xv1"]; flagged {
		t.Fatal("0xv1 must not be flagged (overflow)")
	}
	// victim 1e17, front MaxInt64 ~ 92x: not strictly above 100x, must not flag.
	if _, flagged := got["0xv2"]; flagged {
		t.Fatal("0xv2 must not be flagged (92x < 100x)")
	}
}

func TestReimportReturnsOriginalReportAfterVersionChange(t *testing.T) {
	dir := t.TempDir()
	first := replay(t, dir, sandwichInput)
	if first[0].Version.ID != BuiltinVersionID {
		t.Fatalf("default replay must use builtin, got %+v", first[0].Version)
	}
	register(t, dir, strictSpec)
	if _, err := EnableVersion(dir, "strict"); err != nil {
		t.Fatal(err)
	}
	second := replay(t, dir, sandwichInput)
	if second[0].Version.ID != BuiltinVersionID {
		t.Fatalf("reimport must return the original report, got version %+v", second[0].Version)
	}
	if len(second[0].Findings) != 1 || second[0].Findings[0].Severity != 3 {
		t.Fatalf("reimport findings changed: %+v", second[0].Findings)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Records) != 1 {
		t.Fatalf("reimport added records: %d", len(data.Records))
	}
}

func TestCompareVersions(t *testing.T) {
	dir := t.TempDir()
	// 0xza/0xzb: displacement under builtin (99 > 2*10), gone under strict (99 < 5*10... wait 5*10=50, 99>50 flagged).
	// Use front gas 40 vs victim 10: flagged by builtin (40>20), not by strict (40<50).
	input := `{"chainId":"1","blockHash":"0xcmp","blockNumber":7,"swaps":[` +
		`{"TxHash":"0xfa","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":0},` +
		`{"TxHash":"0xva","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xfb","Pool":"p2","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":2},` +
		`{"TxHash":"0xvb","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":3},` +
		`{"TxHash":"0xbb","Pool":"p2","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":4}]}`
	original := replay(t, dir, input)
	if len(original[0].Findings) != 2 {
		t.Fatalf("setup: got %d findings, want 2", len(original[0].Findings))
	}
	register(t, dir, strictSpec)

	result, err := Compare(dir, "1", "0xcmp", "strict")
	if err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion != BuiltinVersion() {
		t.Fatalf("original version wrong: %+v", result.OriginalVersion)
	}
	if result.ComparedVersion.ID != "strict" || result.ComparedVersion.Rules.Displacement.Multiplier != 5 {
		t.Fatalf("compared version wrong: %+v", result.ComparedVersion)
	}
	if len(result.Swaps) != 5 {
		t.Fatalf("raw swap evidence missing: %+v", result.Swaps)
	}
	// 0xva: displacement under builtin, nothing under strict -> removed.
	if len(result.Removed) != 1 || result.Removed[0].TxHash != "0xva" {
		t.Fatalf("removed = %+v", result.Removed)
	}
	// 0xvb: sandwich under both, severity 3 -> 5: changed only, not added+removed.
	if len(result.Changed) != 1 || result.Changed[0].TxHash != "0xvb" {
		t.Fatalf("changed = %+v", result.Changed)
	}
	if result.Changed[0].Original.Severity != 3 || result.Changed[0].Compared.Severity != 5 {
		t.Fatalf("change detail wrong: %+v", result.Changed[0])
	}
	if len(result.Added) != 0 {
		t.Fatalf("added = %+v", result.Added)
	}
	// Both full conclusion sets are present.
	if len(result.OriginalFindings) != 2 || len(result.ComparedFindings) != 1 {
		t.Fatalf("findings sets wrong: %+v / %+v", result.OriginalFindings, result.ComparedFindings)
	}
	// Compare must not modify the archived report or the enabled version.
	after, err := Query(dir, "1", "0xcmp")
	if err != nil {
		t.Fatal(err)
	}
	if after.Version.ID != BuiltinVersionID || len(after.Findings) != 2 || after.Findings[1].Severity != 2 {
		t.Fatalf("compare modified the archived report: %+v", after)
	}
	_, enabled, _ := ListVersions(dir)
	if enabled != BuiltinVersionID {
		t.Fatalf("compare changed enabled version to %q", enabled)
	}
}

func TestCompareAddedAndSorted(t *testing.T) {
	dir := t.TempDir()
	// Builtin flags nothing (front gas 15 < 2*10? no: 15 > 20 false... 15 < 20, no displacement).
	// A looser version (multiplier 1 not allowed; use severity-only change via multiplier 2 with
	// front 25 > 20 for 0xvc, and front 21 > 20 for 0xva) — instead register a version with
	// multiplier 2 but higher sandwich severity to also produce a change; keep it simple:
	// builtin: no findings; strict2 (multiplier 2, but front 25/21 flagged): two added, hash-sorted.
	input := `{"chainId":"1","blockHash":"0xadd","blockNumber":3,"swaps":[` +
		`{"TxHash":"0xfz","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":25,"Index":0},` +
		`{"TxHash":"0xvz","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xfa","Pool":"p2","Trader":"w","In":1,"Out":1,"GasPrice":21,"Index":2},` +
		`{"TxHash":"0xva","Pool":"p2","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":3}]}`
	reports := replay(t, dir, input)
	if len(reports[0].Findings) != 2 {
		t.Fatalf("setup: builtin should flag both (25>20, 21>20): %+v", reports[0].Findings)
	}
	// Compare against a version with multiplier 3: 25 > 30 false, 21 > 30 false -> both removed, sorted.
	spec := `{"id":"x3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	register(t, dir, spec)
	result, err := Compare(dir, "1", "0xadd", "x3")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 || result.Removed[0].TxHash != "0xva" || result.Removed[1].TxHash != "0xvz" {
		t.Fatalf("removed not sorted by tx hash: %+v", result.Removed)
	}
	// Reverse direction: comparing a no-finding record against builtin adds them.
	// Use the same block under x3 archived in a second archive for the added case.
	dir2 := t.TempDir()
	register(t, dir2, spec)
	if _, err := ReplayWithVersion(strings.NewReader(input), dir2, "x3"); err != nil {
		t.Fatal(err)
	}
	result2, err := Compare(dir2, "1", "0xadd", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(result2.Added) != 2 || result2.Added[0].TxHash != "0xva" || result2.Added[1].TxHash != "0xvz" {
		t.Fatalf("added not sorted by tx hash: %+v", result2.Added)
	}
	if result2.OriginalVersion.ID != "x3" {
		t.Fatalf("original version wrong: %+v", result2.OriginalVersion)
	}
}

func TestCompareUnknown(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	if _, err := Compare(dir, "1", "0xmissing", BuiltinVersionID); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("got %v, want ErrUnknownBlock", err)
	}
	if _, err := Compare(dir, "1", "0xa", "ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("got %v, want ErrUnknownVersion", err)
	}
	if _, err := Compare(filepath.Join(dir, "nope"), "1", "0xa", BuiltinVersionID); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("got %v, want ErrUnknownBlock", err)
	}
}

func TestLegacyArchiveUsesBuiltinVersion(t *testing.T) {
	dir := t.TempDir()
	// Hand-write an archive in the pre-version format: no versions, no
	// enabledVersion, records without a version field.
	legacy := `{"records":[{"chainId":"1","blockHash":"0xleg","blockNumber":5,` +
		`"swaps":[{"TxHash":"0xfront","Pool":"p1","Trader":"bot","In":500,"Out":480,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xback","Pool":"p1","Trader":"bot","In":480,"Out":505,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0xvictim","evidence":[` +
		`{"TxHash":"0xfront","Pool":"p1","Trader":"bot","In":500,"Out":480,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xback","Pool":"p1","Trader":"bot","In":480,"Out":505,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	// Query: conclusions and evidence unchanged, version reported as builtin.
	r, err := Query(dir, "1", "0xleg")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != BuiltinVersion() {
		t.Fatalf("legacy record version = %+v, want builtin", r.Version)
	}
	if len(r.Findings) != 1 || r.Findings[0].Kind != "sandwich" || r.Findings[0].Severity != 3 ||
		len(r.Findings[0].Evidence) != 3 {
		t.Fatalf("legacy findings damaged: %+v", r.Findings)
	}
	// Compare against a registered version works on the legacy record.
	register(t, dir, strictSpec)
	result, err := Compare(dir, "1", "0xleg", "strict")
	if err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion != BuiltinVersion() || len(result.OriginalFindings) != 1 {
		t.Fatalf("legacy compare wrong: %+v", result)
	}
	// Continued import judges new blocks under the enabled (builtin) rules
	// and leaves the legacy record untouched.
	reports := replay(t, dir, displacementInput)
	if len(reports) != 1 || reports[0].Version.ID != BuiltinVersionID || len(reports[0].Findings) != 1 {
		t.Fatalf("continued import wrong: %+v", reports)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(data.Records))
	}
	if data.Records[0].Version != nil {
		t.Fatalf("legacy record was rewritten with a version: %+v", data.Records[0].Version)
	}
	if len(data.Records[0].Findings) != 1 || data.Records[0].Findings[0].Severity != 3 {
		t.Fatalf("legacy findings modified: %+v", data.Records[0].Findings)
	}
}
