package mevwatch

// Regression coverage for the single-block rule comparison behind the
// `compare` entry. These tests pin behaviour end to end on the in-package
// API: the archived side keeps the version that judged it at archive time,
// the candidate side is judged strictly under the version named in the
// call (never the currently enabled one), diffs are split per victim
// transaction, ordering and evidence are preserved, the query is read
// only, and pre-version legacy archives are interpreted as builtin.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const (
	// archivedVersion is the version under which the fixture block is
	// archived: sandwich severity 4, displacement severity 1 with
	// multiplier 3.
	archivedVersionSpec = `{"id":"archA","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":1,"multiplier":3}}}`
	// enabledVersion is enabled in the archive afterwards but must never
	// leak into either side of a comparison. Its judgments are markedly
	// different: sandwich severity 5, displacement severity 5 with
	// multiplier 4.
	enabledVersionSpec = `{"id":"liveB","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":5,"multiplier":4}}}`
	// candidateVersion is the version named at compare time: sandwich
	// disabled, displacement severity 4 with the builtin multiplier 2.
	candidateVersionSpec = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	// twinVersion carries the builtin parameters under another id, so a
	// comparison produces identical conclusions and an empty diff.
	twinVersionSpec = `{"id":"twin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
)

// cmpSwap builds one swap record map; In and Out are fixed because the
// detection rules never read them, while every numeric field is explicit.
func cmpSwap(tx, pool, trader string, gas int64, index int) map[string]any {
	return map[string]any{
		"TxHash": tx, "Pool": pool, "Trader": trader,
		"In": 1, "Out": 1, "GasPrice": gas, "Index": index,
	}
}

func cmpBlockLine(chain, hash string, number int64, swaps ...map[string]any) string {
	block := map[string]any{
		"chainId": chain, "blockHash": hash, "blockNumber": number, "swaps": swaps,
	}
	raw, err := json.Marshal(block)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// compareFixtureInput covers every diff shape in one archived block:
//
//	p1 0xa0f/0xa0v/0xa0b  sandwich sev4 under archA -> displacement sev4
//	                      under candC (kind change, severity identical);
//	p2 0xb0f/0xb0v/0xb0z  displacement sev1 (mult 3) -> sev4 (mult 2),
//	                      a severity-only change;
//	p3 0xc0f/0xc0v       no conclusion under either version, no diff;
//	p4 0xd0f/0xd0v       absent under archA (25 <= 30), displacement
//	                      sev4 under candC (25 > 20): added;
//	p5 0xe0f/0xe0v/0xe0b sandwich sev4 under archA (15/11 bracket 10),
//	                      nothing under candC (sandwich off, 15 <= 20):
//	                      removed.
func compareFixtureInput() string {
	lines := []string{
		cmpBlockLine("1", "0xblk", 100,
			cmpSwap("0xa0f", "p1", "bot", 90, 0),
			cmpSwap("0xa0v", "p1", "user", 10, 1),
			cmpSwap("0xa0b", "p1", "bot", 80, 2),
			cmpSwap("0xb0f", "p2", "w", 40, 3),
			cmpSwap("0xb0v", "p2", "u", 10, 4),
			cmpSwap("0xb0z", "p2", "z", 10, 5),
			cmpSwap("0xc0f", "p3", "w", 15, 6),
			cmpSwap("0xc0v", "p3", "u", 10, 7),
			cmpSwap("0xd0f", "p4", "w", 25, 8),
			cmpSwap("0xd0v", "p4", "u", 10, 9),
			cmpSwap("0xe0f", "p5", "bot", 15, 10),
			cmpSwap("0xe0v", "p5", "user", 10, 11),
			cmpSwap("0xe0b", "p5", "bot", 11, 12),
		),
		// Decoy: same height, different block hash on the same chain.
		cmpBlockLine("1", "0xother", 100,
			cmpSwap("0xzz1", "pz", "tz", 999, 0),
			cmpSwap("0xzz2", "pz", "tz2", 998, 1),
		),
		// Decoy: same height and hash on another chain.
		cmpBlockLine("2", "0xblk", 100,
			cmpSwap("0xqq1", "pq", "tq", 777, 0),
			cmpSwap("0xqq2", "pq", "tq2", 776, 1),
		),
	}
	return strings.Join(lines, "\n") + "\n"
}

// setupCompareArchive writes the fixture to a real (then deleted) input
// file, archives it under archA, registers candC and enables liveB. The
// returned input path has already been removed, proving compare needs no
// source file.
func setupCompareArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(compareFixtureInput()), 0o644); err != nil {
		t.Fatal(err)
	}
	register(t, dir, archivedVersionSpec)
	register(t, dir, enabledVersionSpec)
	register(t, dir, candidateVersionSpec)
	register(t, dir, twinVersionSpec)
	if reports, err := ReplayFileWithVersion(inputPath, dir, "archA"); err != nil {
		t.Fatalf("ReplayFileWithVersion: %v", err)
	} else if len(reports) != 3 {
		t.Fatalf("got %d reports, want 3", len(reports))
	}
	if _, err := EnableVersion(dir, "liveB"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mustRuleVersion(t *testing.T, spec string) RuleVersion {
	t.Helper()
	v, err := ParseRuleVersion([]byte(spec))
	if err != nil {
		t.Fatalf("ParseRuleVersion: %v", err)
	}
	return v
}

func TestCompareRegressionFullDiff(t *testing.T) {
	dir := setupCompareArchive(t)

	result, err := Compare(dir, "1", "0xblk", "candC")
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	// Block identity is exactly the selected chain/block; the same-height
	// same-chain decoy and the same-hash other-chain decoy never mix in.
	if result.ChainID != "1" || result.BlockHash != "0xblk" || result.BlockNumber != 100 {
		t.Fatalf("block identity wrong: %s/%s @%d", result.ChainID, result.BlockHash, result.BlockNumber)
	}

	// Each side carries its own full parameters: the archived conclusion
	// uses archA even though liveB is now enabled, and the candidate side
	// uses candC rather than the enabled liveB.
	if !reflect.DeepEqual(result.OriginalVersion, mustRuleVersion(t, archivedVersionSpec)) {
		t.Fatalf("original version = %+v, want archA", result.OriginalVersion)
	}
	if !reflect.DeepEqual(result.ComparedVersion, mustRuleVersion(t, candidateVersionSpec)) {
		t.Fatalf("compared version = %+v, want candC", result.ComparedVersion)
	}
	if result.ComparedVersion.ID == "liveB" ||
		result.ComparedVersion.Rules.Sandwich.Enabled ||
		result.ComparedVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("candidate side leaked the enabled version: %+v", result.ComparedVersion)
	}

	// Original findings: severity desc, hash asc within a severity.
	// p1 and p5 are both sandwiches sev4 (hash asc: 0xa0v before 0xe0v),
	// the p2 displacement sev1 comes last.
	wantOrig := []struct {
		tx       string
		kind     string
		severity int
		evidence int
	}{
		{"0xa0v", "sandwich", 4, 3},
		{"0xe0v", "sandwich", 4, 3},
		{"0xb0v", "displacement", 1, 2},
	}
	if len(result.OriginalFindings) != len(wantOrig) {
		t.Fatalf("original findings = %+v", result.OriginalFindings)
	}
	for i, w := range wantOrig {
		got := result.OriginalFindings[i]
		if got.TxHash != w.tx || got.Kind != w.kind || got.Severity != w.severity || len(got.Evidence) != w.evidence {
			t.Fatalf("original[%d] = %+v, want %+v", i, got, w)
		}
	}

	// Candidate findings: all displacement sev4 under candC (sandwich is
	// off), hash asc. In particular 0xa0v is a displacement here, so the
	// enabled liveB (which would still flag it as a sandwich sev5) was
	// never consulted.
	wantComp := []struct {
		tx       string
		evidence int
	}{
		{"0xa0v", 2},
		{"0xb0v", 2},
		{"0xd0v", 2},
	}
	if len(result.ComparedFindings) != len(wantComp) {
		t.Fatalf("compared findings = %+v", result.ComparedFindings)
	}
	for i, w := range wantComp {
		got := result.ComparedFindings[i]
		if got.TxHash != w.tx || got.Kind != "displacement" || got.Severity != 4 || len(got.Evidence) != w.evidence {
			t.Fatalf("compared[%d] = %+v, want tx %s displacement sev4 with %d evidence", i, got, w.tx, w.evidence)
		}
	}

	// Diffs are per victim transaction with the expected shapes.
	if len(result.Added) != 1 || result.Added[0].TxHash != "0xd0v" {
		t.Fatalf("added = %+v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].TxHash != "0xe0v" {
		t.Fatalf("removed = %+v", result.Removed)
	}
	if len(result.Changed) != 2 {
		t.Fatalf("changed = %+v", result.Changed)
	}
	if result.Changed[0].TxHash != "0xa0v" || result.Changed[1].TxHash != "0xb0v" {
		t.Fatalf("changed not hash-sorted: %+v", result.Changed)
	}

	// Sandwich -> displacement for one transaction stays a single change
	// carrying both conclusions; it must never be split into add+remove.
	kindChange := result.Changed[0]
	if kindChange.Original.Kind != "sandwich" || kindChange.Original.Severity != 4 ||
		len(kindChange.Original.Evidence) != 3 {
		t.Fatalf("kind change original side wrong: %+v", kindChange.Original)
	}
	if kindChange.Compared.Kind != "displacement" || kindChange.Compared.Severity != 4 ||
		len(kindChange.Compared.Evidence) != 2 {
		t.Fatalf("kind change compared side wrong: %+v", kindChange.Compared)
	}
	// Severity-only change likewise keeps both sides.
	sevChange := result.Changed[1]
	if sevChange.Original.Kind != "displacement" || sevChange.Original.Severity != 1 ||
		sevChange.Compared.Kind != "displacement" || sevChange.Compared.Severity != 4 {
		t.Fatalf("severity change wrong: %+v", sevChange)
	}

	// The victim flagged identically under both versions (none in this
	// block) would be absent from every diff list; p3's swaps stay only
	// in the full evidence record.

	// Full archived swap records survive: all 13, in Index order, with
	// every original field, including swaps that took no part in any
	// conclusion (the sandwich backs, 0xb0z and the whole p3 pair).
	if len(result.Swaps) != 13 {
		t.Fatalf("swaps = %+v", result.Swaps)
	}
	wantSwap := Swap{TxHash: "0xb0z", Pool: "p2", Trader: "z", In: 1, Out: 1, GasPrice: 10, Index: 5}
	if !reflect.DeepEqual(result.Swaps[5], wantSwap) {
		t.Fatalf("swap record not preserved: got %+v", result.Swaps[5])
	}
	for i, s := range result.Swaps {
		if s.Index != i {
			t.Fatalf("swaps not in index order at %d: %+v", i, s)
		}
	}

	// Evidence inside conclusions keeps raw tx/pool/trader/amount/gas/index.
	ev := result.OriginalFindings[0].Evidence[0]
	if ev != (Swap{TxHash: "0xa0f", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0}) {
		t.Fatalf("sandwich evidence damaged: %+v", ev)
	}
}

func TestCompareRegressionDiffListsAreHashSorted(t *testing.T) {
	dir := t.TempDir()
	// Archived under builtin: three displacement victims (front gas > 20),
	// hash order deliberately different from pool/input order.
	input := strings.Join([]string{
		cmpBlockLine("1", "0xsort", 9,
			cmpSwap("0xm", "p3", "w", 23, 5),
			cmpSwap("0xm-v", "p3", "u", 10, 6),
			cmpSwap("0xa", "p1", "w", 23, 0),
			cmpSwap("0xa-v", "p1", "u", 10, 1),
			cmpSwap("0xg", "p2", "w", 23, 3),
			cmpSwap("0xg-v", "p2", "u", 10, 4),
		),
	}, "\n")
	replay(t, dir, input)
	strict3 := `{"id":"m3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	register(t, dir, strict3)
	result, err := Compare(dir, "1", "0xsort", "m3")
	if err != nil {
		t.Fatal(err)
	}
	// 23 <= 30: every displacement disappears; removed must be hash asc.
	wantRemoved := []string{"0xa-v", "0xg-v", "0xm-v"}
	if len(result.Removed) != len(wantRemoved) {
		t.Fatalf("removed = %+v", result.Removed)
	}
	for i, tx := range wantRemoved {
		if result.Removed[i].TxHash != tx {
			t.Fatalf("removed order = %v, want %v", txHashes(result.Removed), wantRemoved)
		}
	}
	if len(result.Added) != 0 || len(result.Changed) != 0 {
		t.Fatalf("unexpected added/changed: %+v / %+v", result.Added, result.Changed)
	}

	// Reverse direction: archive under multiplier 3, compare under
	// builtin; all three are added and again hash asc.
	dir2 := t.TempDir()
	register(t, dir2, strict3)
	if _, err := ReplayWithVersion(strings.NewReader(input), dir2, "m3"); err != nil {
		t.Fatal(err)
	}
	rev, err := Compare(dir2, "1", "0xsort", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.Added) != len(wantRemoved) {
		t.Fatalf("added = %+v", rev.Added)
	}
	for i, tx := range wantRemoved {
		if rev.Added[i].TxHash != tx {
			t.Fatalf("added order = %v, want %v", txHashes(rev.Added), wantRemoved)
		}
	}
}

func txHashes(fs []ReportFinding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.TxHash
	}
	return out
}

func TestCompareRegressionIdenticalConclusionsHaveEmptyDiff(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput) // archived under builtin
	register(t, dir, twinVersionSpec)
	result, err := Compare(dir, "1", "0xa", "twin")
	if err != nil {
		t.Fatal(err)
	}
	// Same kind and same severity for every transaction: no diffs, but
	// both full conclusion sets remain present and ordered.
	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Fatalf("identical conclusions produced diffs: %+v", result)
	}
	if len(result.OriginalFindings) != 1 || len(result.ComparedFindings) != 1 {
		t.Fatalf("full findings missing: %+v / %+v", result.OriginalFindings, result.ComparedFindings)
	}
	o, c := result.OriginalFindings[0], result.ComparedFindings[0]
	if o.Kind != c.Kind || o.Severity != c.Severity || o.TxHash != c.TxHash {
		t.Fatalf("twin conclusion mismatch: %+v vs %+v", o, c)
	}
}

func TestCompareRegressionBothSidesEmptyMarshalsArrays(t *testing.T) {
	// A block with no conclusion on either side: 15 vs 10 beats neither
	// archA's multiplier 3 nor candC's multiplier 2.
	emptyDir := t.TempDir()
	register(t, emptyDir, archivedVersionSpec)
	register(t, emptyDir, candidateVersionSpec)
	emptyInput := cmpBlockLine("1", "0empty", 1,
		cmpSwap("0g0", "p", "w", 15, 0),
		cmpSwap("0g1", "p", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(emptyInput), emptyDir, "archA"); err != nil {
		t.Fatal(err)
	}
	empty, err := Compare(emptyDir, "1", "0empty", "candC")
	if err != nil {
		t.Fatal(err)
	}
	for name, fs := range map[string][]ReportFinding{
		"originalFindings": empty.OriginalFindings,
		"comparedFindings": empty.ComparedFindings,
		"added":            empty.Added,
		"removed":          empty.Removed,
	} {
		if fs == nil || len(fs) != 0 {
			t.Fatalf("%s must be a non-nil empty slice, got %v", name, fs)
		}
	}
	if empty.Changed == nil || len(empty.Changed) != 0 {
		t.Fatalf("changed must be a non-nil empty slice, got %v", empty.Changed)
	}
	if len(empty.Swaps) != 2 {
		t.Fatalf("empty-findings block must still carry its swap records: %+v", empty.Swaps)
	}
	// JSON must show [], never null, for all five lists.
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"originalFindings":[]`, `"comparedFindings":[]`, `"added":[]`, `"removed":[]`, `"changed":[]`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("JSON missing %s in %s", key, raw)
		}
	}
}

func TestCompareRegressionLegacyArchiveUsesBuiltin(t *testing.T) {
	dir := t.TempDir()
	// Pre-version archive: records have no version field at all.
	legacy := `{"records":[` +
		`{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	register(t, dir, candidateVersionSpec)
	result, err := Compare(dir, "1", "0old", "candC")
	if err != nil {
		t.Fatal(err)
	}
	// Archived side is explained as the built-in version with all params.
	if !reflect.DeepEqual(result.OriginalVersion, BuiltinVersion()) {
		t.Fatalf("original version = %+v, want builtin", result.OriginalVersion)
	}
	if result.OriginalVersion.Rules.Displacement.Multiplier != 2 ||
		result.OriginalVersion.Rules.Sandwich.Severity != 3 {
		t.Fatalf("builtin parameters incomplete: %+v", result.OriginalVersion)
	}
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "sandwich" {
		t.Fatalf("legacy findings damaged: %+v", result.OriginalFindings)
	}
	// Candidate side is judged under candC: sandwich off, displacement
	// sev4 with multiplier 2 (90 > 20).
	if len(result.ComparedFindings) != 1 ||
		result.ComparedFindings[0].Kind != "displacement" || result.ComparedFindings[0].Severity != 4 {
		t.Fatalf("candidate re-judgment wrong: %+v", result.ComparedFindings)
	}
	if len(result.Swaps) != 3 || result.Swaps[0].In != 7 || result.Swaps[2].Out != 5 {
		t.Fatalf("legacy swap records damaged: %+v", result.Swaps)
	}
}

func TestCompareRegressionReadOnly(t *testing.T) {
	dir := setupCompareArchive(t)
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}

	run := func(chain, hash, version string) {
		t.Helper()
		_, _ = Compare(dir, chain, hash, version)
	}
	// Successful comparisons, including the decoy identities...
	run("1", "0xblk", "candC")
	run("1", "0xblk", BuiltinVersionID)
	run("1", "0xother", "candC")
	run("2", "0xblk", "candC")
	// ...and every failure shape leave the archive file byte-identical.
	run("1", "0xmissing", "candC")
	run("1", "0xblk", "ghost")
	run("9", "0xblk", "candC")

	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("compare changed the archive:\nbefore=%s\nafter =%s", before, after)
	}

	// The archived report keeps archA conclusions; the enabled version is
	// still liveB; failed comparisons changed neither.
	report, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "archA" || len(report.Findings) != 3 {
		t.Fatalf("archived report changed: %+v", report)
	}
	_, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "liveB" {
		t.Fatalf("enabled version = %q, want liveB", enabled)
	}
}

func TestCompareRegressionDecoysDoNotMixIn(t *testing.T) {
	dir := setupCompareArchive(t)
	main, err := Compare(dir, "1", "0xblk", "candC")
	if err != nil {
		t.Fatal(err)
	}
	other, err := Compare(dir, "1", "0xother", "candC")
	if err != nil {
		t.Fatal(err)
	}
	chain2, err := Compare(dir, "2", "0xblk", "candC")
	if err != nil {
		t.Fatal(err)
	}
	if other.ChainID != "1" || other.BlockHash != "0xother" || len(other.Swaps) != 2 {
		t.Fatalf("same-height other block scoping wrong: %+v", other)
	}
	if chain2.ChainID != "2" || chain2.BlockHash != "0xblk" || len(chain2.Swaps) != 2 {
		t.Fatalf("other-chain block scoping wrong: %+v", chain2)
	}
	if chain2.Swaps[0].TxHash != "0xqq1" || main.Swaps[0].TxHash != "0xa0f" {
		t.Fatalf("swap records leaked across chains: main=%+v chain2=%+v", main.Swaps, chain2.Swaps)
	}
	// Findings from one identity never appear under another.
	all := append(append([]ReportFinding{}, main.OriginalFindings...), other.OriginalFindings...)
	all = append(all, chain2.OriginalFindings...)
	for _, f := range all {
		if strings.HasPrefix(f.TxHash, "0xzz") || strings.HasPrefix(f.TxHash, "0xqq") {
			t.Fatalf("decoy conclusion leaked into another block's set: %+v", all)
		}
	}
	// Determinism: repeated queries produce identical JSON.
	again, err := Compare(dir, "1", "0xblk", "candC")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(main)
	b2, _ := json.Marshal(again)
	if string(b1) != string(b2) {
		t.Fatalf("compare is not deterministic:\n%s\n%s", b1, b2)
	}
	// Sanity: findings inside each result stay severity desc / hash asc.
	for _, r := range []CompareResult{main, other, chain2} {
		if !sort.SliceIsSorted(r.OriginalFindings, func(i, j int) bool {
			a, b := r.OriginalFindings[i], r.OriginalFindings[j]
			if a.Severity != b.Severity {
				return a.Severity > b.Severity
			}
			return a.TxHash < b.TxHash
		}) {
			t.Fatalf("original findings not severity/hash ordered: %+v", r.OriginalFindings)
		}
	}
}

// rewriteStoredVersion rewrites the stored archive document of the
// registered version id through mutate, simulating an archive whose
// registered version no longer satisfies the registration rules even
// though the file is still valid JSON.
func rewriteStoredVersion(t *testing.T, dir, id string, mutate func(ver map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	versions, ok := doc["versions"].([]any)
	if !ok {
		t.Fatalf("no versions array in archive: %s", raw)
	}
	found := false
	for _, entry := range versions {
		ver, ok := entry.(map[string]any)
		if !ok || ver["id"] != id {
			continue
		}
		mutate(ver)
		found = true
	}
	if !found {
		t.Fatalf("version %s not stored in archive", id)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// storedRule navigates to one rule object inside a stored version
// document.
func storedRule(t *testing.T, ver map[string]any, name string) map[string]any {
	t.Helper()
	rules, ok := ver["rules"].(map[string]any)
	if !ok {
		t.Fatalf("stored version has no rules object: %v", ver)
	}
	rule, ok := rules[name].(map[string]any)
	if !ok {
		t.Fatalf("stored version has no rules.%s object: %v", name, ver)
	}
	return rule
}

// setupCorruptCompareArchive registers candC (sandwich off, displacement
// severity 4 multiplier 2) and twin, and archives one block under candC
// whose adjacent same-pool swaps hit displacement with no sandwich — the
// exact shape that crashed detection when the stored multiplier decayed
// to zero.
func setupCorruptCompareArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	register(t, dir, twinVersionSpec)
	input := cmpBlockLine("1", "0xblk", 7,
		cmpSwap("0xf", "p1", "w", 40, 0),
		cmpSwap("0xv", "p1", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// corruptVersionCases is the full matrix of ways a stored candidate
// version document can stop satisfying the registration rules: missing,
// null, wrong-typed or out-of-range fields on either rule (including a
// rule explicitly disabled), and missing rule/rules objects. Both the
// single-block comparison and the review-range evaluation must refuse the
// whole operation with ErrCorruptVersion for every one of them.
var corruptVersionCases = []struct {
	name    string
	mutate  func(t *testing.T, ver map[string]any)
	wantErr string
}{
	{"multiplier missing", func(t *testing.T, v map[string]any) {
		delete(storedRule(t, v, "displacement"), "multiplier")
	}, "multiplier"},
	{"multiplier zero", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["multiplier"] = 0
	}, "multiplier"},
	{"multiplier below range", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["multiplier"] = 1
	}, "multiplier"},
	{"multiplier above range", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["multiplier"] = 101
	}, "multiplier"},
	{"multiplier null", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["multiplier"] = nil
	}, "multiplier"},
	{"multiplier wrong type", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["multiplier"] = "2"
	}, "multiplier"},
	{"displacement severity missing", func(t *testing.T, v map[string]any) {
		delete(storedRule(t, v, "displacement"), "severity")
	}, "severity"},
	{"displacement severity zero", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["severity"] = 0
	}, "severity"},
	{"displacement severity above range", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["severity"] = 6
	}, "severity"},
	{"displacement severity null", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["severity"] = nil
	}, "severity"},
	{"displacement enabled missing", func(t *testing.T, v map[string]any) {
		delete(storedRule(t, v, "displacement"), "enabled")
	}, "enabled"},
	{"displacement enabled null", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["enabled"] = nil
	}, "enabled"},
	{"displacement enabled wrong type", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "displacement")["enabled"] = "true"
	}, "enabled"},
	// The sandwich rule is disabled in candC, but a disabled rule must
	// still declare complete, in-range parameters; an explicit false is a
	// legal off state and stays valid.
	{"disabled sandwich severity zero", func(t *testing.T, v map[string]any) {
		storedRule(t, v, "sandwich")["severity"] = 0
	}, "severity"},
	{"disabled sandwich enabled missing", func(t *testing.T, v map[string]any) {
		delete(storedRule(t, v, "sandwich"), "enabled")
	}, "enabled"},
	{"sandwich object missing", func(t *testing.T, v map[string]any) {
		delete(v["rules"].(map[string]any), "sandwich")
	}, "sandwich"},
	{"displacement object missing", func(t *testing.T, v map[string]any) {
		delete(v["rules"].(map[string]any), "displacement")
	}, "displacement"},
	{"sandwich object null", func(t *testing.T, v map[string]any) {
		v["rules"].(map[string]any)["sandwich"] = nil
	}, "sandwich"},
	{"rules object missing", func(t *testing.T, v map[string]any) {
		delete(v, "rules")
	}, "rules"},
	{"rules null", func(t *testing.T, v map[string]any) {
		v["rules"] = nil
	}, "rules"},
	// Unknown fields are rejected at registration, so a stored document
	// that grew one is corrupt too.
	{"unknown field", func(t *testing.T, v map[string]any) {
		v["extra"] = 1
	}, "extra"},
	{"unknown rule", func(t *testing.T, v map[string]any) {
		v["rules"].(map[string]any)["frontrun"] = map[string]any{"enabled": true, "severity": 1}
	}, "frontrun"},
}

func TestCompareCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			_, err := Compare(dir, "1", "0xblk", "candC")
			if err == nil {
				t.Fatalf("corrupt version compared successfully")
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrUnknownBlock) {
				t.Fatalf("corruption misreported as unknown version/block: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the requested version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCompareCorruptVersionEmptySwapsStillRefused(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	// A block with no swaps produces no conclusions under any version; the
	// corrupt candidate must still be refused, not reported as an empty
	// success.
	input := `{"chainId":"1","blockHash":"0xempty","blockNumber":3,"swaps":[]}`
	if _, err := ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	_, err := Compare(dir, "1", "0xempty", "candC")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
}

func TestCompareCorruptVersionDistinctFromUnknown(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	// A version that was never registered stays an unknown-version
	// failure, never a corruption one.
	if _, err := Compare(dir, "1", "0xblk", "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	// An unknown block stays an unknown-block failure.
	if _, err := Compare(dir, "1", "0xghost", "candC"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block error = %v", err)
	}
	// The corrupt sibling does not contaminate intact versions: comparing
	// under twin or builtin still succeeds against the same archive.
	for _, id := range []string{"twin", BuiltinVersionID} {
		result, err := Compare(dir, "1", "0xblk", id)
		if err != nil {
			t.Fatalf("compare under intact %s failed: %v", id, err)
		}
		if len(result.ComparedFindings) != 1 || result.ComparedFindings[0].Kind != "displacement" {
			t.Fatalf("compare under intact %s misjudged: %+v", id, result.ComparedFindings)
		}
	}
}

func TestCompareCorruptVersionReadOnly(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Compare(dir, "1", "0xblk", "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed compare against a corrupt version changed the archive")
	}
	// The archived report keeps its candC conclusions and parameters.
	report, err := Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" || report.Findings[0].Severity != 4 {
		t.Fatalf("archived report changed: %+v", report)
	}
}
