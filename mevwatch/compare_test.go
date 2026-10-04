package mevwatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// kindflip disables the sandwich rule but keeps the exact built-in
// displacement parameters, so a bracketed victim that was a sandwich stays
// detectable as a displacement: the same transaction changes kind instead
// of disappearing and reappearing.
const kindflipSpec = `{"id":"kindflip","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`

// sevBump keeps both rules and their thresholds, changing only severities.
const sevBumpSpec = `{"id":"sevbump","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`

// quiet turns both rules off, so any block archived or compared under it
// has empty conclusions.
const quietSpec = `{"id":"quiet","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`

func findingMap(fs []ReportFinding) map[string]ReportFinding {
	m := make(map[string]ReportFinding, len(fs))
	for _, f := range fs {
		m[f.TxHash] = f
	}
	return m
}

func txHashes(fs []ReportFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.TxHash)
	}
	return out
}

func swapHashes(swaps []Swap) []string {
	out := make([]string, 0, len(swaps))
	for _, s := range swaps {
		out = append(out, s.TxHash)
	}
	return out
}

func assertNonNilEmptySlice[T any](t *testing.T, name string, got []T) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is nil, want a non-nil empty slice", name)
	}
	if len(got) != 0 {
		t.Fatalf("%s has %d entries, want 0", name, len(got))
	}
}

// TestCompareKindChangeIsOneEntryWithBothConclusions pins the core diff
// rule: one victim that is a sandwich in the archive and a displacement
// under the candidate is a single changed entry carrying both conclusions,
// never a removed plus an added pair. A conclusion identical on both sides
// stays out of every diff list.
func TestCompareKindChangeIsOneEntryWithBothConclusions(t *testing.T) {
	dir := t.TempDir()
	// p1: bot brackets user with gas 100/90 against 10 -> builtin sandwich.
	// p2: whale 30 ahead of user 10, zoe behind -> displacement only,
	// identical (kind displacement, severity 2) under builtin and kindflip.
	input := `{"chainId":"1","blockHash":"0xkind","blockNumber":20,"swaps":[` +
		`{"TxHash":"0xfs","Pool":"p1","Trader":"bot","In":11,"Out":12,"GasPrice":100,"Index":0},` +
		`{"TxHash":"0xt1","Pool":"p1","Trader":"user","In":21,"Out":22,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xbs","Pool":"p1","Trader":"bot","In":31,"Out":32,"GasPrice":90,"Index":2},` +
		`{"TxHash":"0xfd","Pool":"p2","Trader":"whale","In":41,"Out":42,"GasPrice":30,"Index":3},` +
		`{"TxHash":"0xt2","Pool":"p2","Trader":"user","In":51,"Out":52,"GasPrice":10,"Index":4},` +
		`{"TxHash":"0xzd","Pool":"p2","Trader":"zoe","In":61,"Out":62,"GasPrice":5,"Index":5}]}`
	reports := replay(t, dir, input)
	if len(reports[0].Findings) != 2 {
		t.Fatalf("setup findings = %+v, want sandwich t1 and displacement t2", reports[0].Findings)
	}
	register(t, dir, kindflipSpec)

	result, err := Compare(dir, "1", "0xkind", "kindflip")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("kind change must not be split into added/removed: added=%+v removed=%+v",
			result.Added, result.Removed)
	}
	if len(result.Changed) != 1 {
		t.Fatalf("changed = %+v, want exactly t1", result.Changed)
	}
	change := result.Changed[0]
	if change.TxHash != "0xt1" {
		t.Fatalf("changed tx = %q, want 0xt1", change.TxHash)
	}
	if change.Original.Kind != "sandwich" || change.Original.Severity != 3 {
		t.Fatalf("original side of the kind change lost: %+v", change.Original)
	}
	if change.Compared.Kind != "displacement" || change.Compared.Severity != 2 {
		t.Fatalf("compared side of the kind change lost: %+v", change.Compared)
	}
	// Each side keeps its own evidence: three bracketing swaps for the
	// sandwich, front and victim for the displacement.
	if len(change.Original.Evidence) != 3 || len(change.Compared.Evidence) != 2 {
		t.Fatalf("evidence not kept per side: %+v / %+v",
			change.Original.Evidence, change.Compared.Evidence)
	}
	// The unchanged displacement is present in both full lists and in no diff.
	orig := findingMap(result.OriginalFindings)
	comp := findingMap(result.ComparedFindings)
	o2, c2 := orig["0xt2"], comp["0xt2"]
	if o2.Kind != "displacement" || c2.Kind != "displacement" ||
		o2.Severity != 2 || c2.Severity != 2 {
		t.Fatalf("identical conclusion damaged: %+v / %+v", o2, c2)
	}
	for _, list := range [][]ReportFinding{result.Added, result.Removed} {
		for _, f := range list {
			if f.TxHash == "0xt2" {
				t.Fatalf("identical conclusion entered a diff list: %+v", list)
			}
		}
	}
	for _, ch := range result.Changed {
		if ch.TxHash == "0xt2" {
			t.Fatal("identical conclusion entered changed list")
		}
	}
	// t1 itself is present on both full conclusion lists under each version.
	if orig["0xt1"].Kind != "sandwich" || comp["0xt1"].Kind != "displacement" {
		t.Fatalf("full lists do not carry t1 under both versions: %+v / %+v",
			orig["0xt1"], comp["0xt1"])
	}
}

// TestCompareSeverityOnlyIsChanged verifies that a changed severity with
// the same kind is a change (both conclusions retained), not a match.
func TestCompareSeverityOnlyIsChanged(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0xsev","blockNumber":21,"swaps":[` +
		`{"TxHash":"0xfa","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xva","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xba","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},` +
		`{"TxHash":"0xfd","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":30,"Index":3},` +
		`{"TxHash":"0xvd","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4},` +
		`{"TxHash":"0xnx","Pool":"p2","Trader":"zoe","In":1,"Out":1,"GasPrice":5,"Index":5}]}`
	replay(t, dir, input)
	register(t, dir, sevBumpSpec)

	result, err := Compare(dir, "1", "0xsev", "sevbump")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("severity-only change split into add/remove: %+v / %+v",
			result.Added, result.Removed)
	}
	want := map[string][2]int{
		"0xva": {3, 4}, // sandwich 3 -> 4
		"0xvd": {2, 4}, // displacement 2 -> 4
	}
	if len(result.Changed) != len(want) {
		t.Fatalf("changed = %+v, want two severity-only entries", result.Changed)
	}
	for _, ch := range result.Changed {
		sev, ok := want[ch.TxHash]
		if !ok {
			t.Fatalf("unexpected changed tx %q: %+v", ch.TxHash, ch)
		}
		if ch.Original.Severity != sev[0] || ch.Compared.Severity != sev[1] {
			t.Fatalf("%s severities = %d/%d, want %d/%d", ch.TxHash,
				ch.Original.Severity, ch.Compared.Severity, sev[0], sev[1])
		}
		if ch.Original.Kind != ch.Compared.Kind {
			t.Fatalf("%s kind changed too: %q vs %q",
				ch.TxHash, ch.Original.Kind, ch.Compared.Kind)
		}
	}
	// Diff lists sort by tx hash ascending; full lists keep severity desc
	// then tx hash ascending on both sides.
	changedHashes := []string{}
	for _, ch := range result.Changed {
		changedHashes = append(changedHashes, ch.TxHash)
	}
	if !reflect.DeepEqual(changedHashes, []string{"0xva", "0xvd"}) {
		t.Fatalf("changed not hash-sorted: %v", changedHashes)
	}
	if tx := txHashes(result.OriginalFindings); !reflect.DeepEqual(tx, []string{"0xva", "0xvd"}) {
		t.Fatalf("original full list order = %v, want severity desc then hash", tx)
	}
	if tx := txHashes(result.ComparedFindings); !reflect.DeepEqual(tx, []string{"0xva", "0xvd"}) {
		t.Fatalf("compared full list order = %v, want hash order within equal severity", tx)
	}
}

// TestCompareDiffListsSortByTxHash exercises added and removed together and
// pins their ascending tx-hash order, including a changed victim sitting in
// the middle that must not consume either list entry.
func TestCompareDiffListsSortByTxHash(t *testing.T) {
	// v2 raises the sandwich severity to 5 and tightens displacement to
	// multiplier 3, so one block produces one of every diff kind at once.
	v2Spec := `{"id":"v2","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	block := `{"chainId":"1","blockHash":"0xmix","blockNumber":9,"swaps":[` +
		// pa: front gas 25 vs victim 10 -> displacement under builtin (25>20), gone under mult3 (25<=30).
		`{"TxHash":"0xm0f","Pool":"pa","Trader":"w","In":1,"Out":1,"GasPrice":25,"Index":0},` +
		`{"TxHash":"0xm0","Pool":"pa","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		// pb: front gas 21 vs victim 10 -> same, a second removal.
		`{"TxHash":"0xm1f","Pool":"pb","Trader":"w","In":1,"Out":1,"GasPrice":21,"Index":2},` +
		`{"TxHash":"0xm1","Pool":"pb","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":3},` +
		// pc: bracketed victim -> sandwich on both sides, severity 3 -> 5 (changed).
		`{"TxHash":"0xm2f","Pool":"pc","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":4},` +
		`{"TxHash":"0xm2","Pool":"pc","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":5},` +
		`{"TxHash":"0xm2b","Pool":"pc","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":6},` +
		// pd: front gas 40 vs victim 10 -> displacement under both (40>30), identical.
		`{"TxHash":"0xm3f","Pool":"pd","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":7},` +
		`{"TxHash":"0xm3","Pool":"pd","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":8}]}`

	dir := t.TempDir()
	replay(t, dir, block) // builtin archive
	register(t, dir, v2Spec)
	out, err := Compare(dir, "1", "0xmix", "v2")
	if err != nil {
		t.Fatal(err)
	}
	if got := txHashes(out.Removed); !reflect.DeepEqual(got, []string{"0xm0", "0xm1"}) {
		t.Fatalf("removed not hash-sorted: %v", got)
	}
	if len(out.Added) != 0 {
		t.Fatalf("added = %+v, want empty", out.Added)
	}
	if len(out.Changed) != 1 || out.Changed[0].TxHash != "0xm2" {
		t.Fatalf("changed = %+v, want only 0xm2", out.Changed)
	}
	if got := txHashes(out.OriginalFindings); !reflect.DeepEqual(got, []string{"0xm2", "0xm0", "0xm1", "0xm3"}) {
		t.Fatalf("original full list not severity-desc/hash-asc: %v", got)
	}
	if got := txHashes(out.ComparedFindings); !reflect.DeepEqual(got, []string{"0xm2", "0xm3"}) {
		t.Fatalf("compared full list order wrong: %v", got)
	}

	// Reverse direction: same block archived under v2, compared against
	// builtin -> the two displacement victims are added, hash-sorted, while
	// the sandwich stays a single change.
	dir2 := t.TempDir()
	register(t, dir2, v2Spec)
	reverse := strings.ReplaceAll(block, "0xmix", "0xmix2")
	if _, err := ReplayWithVersion(strings.NewReader(reverse), dir2, "v2"); err != nil {
		t.Fatal(err)
	}
	back, err := Compare(dir2, "1", "0xmix2", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if back.OriginalVersion.ID != "v2" {
		t.Fatalf("archive version = %q, want v2", back.OriginalVersion.ID)
	}
	if got := txHashes(back.Added); !reflect.DeepEqual(got, []string{"0xm0", "0xm1"}) {
		t.Fatalf("added not hash-sorted: %v", got)
	}
	if len(back.Removed) != 0 || len(back.Changed) != 1 || back.Changed[0].TxHash != "0xm2" {
		t.Fatalf("reverse diffs wrong: removed=%+v changed=%+v", back.Removed, back.Changed)
	}
}

// TestCompareEmptyConclusionsRenderAsArrays covers a block that produces no
// conclusion on either side: both full lists and all three diff lists must
// be empty arrays, never null, in JSON.
func TestCompareEmptyConclusionsRenderAsArrays(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, quietSpec)
	// Real patterns that would hit under builtin, but the archive used the
	// all-rules-off version, so both sides are empty by rule, not by lack
	// of data.
	input := `{"chainId":"1","blockHash":"0q","blockNumber":1,"swaps":[` +
		`{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xb","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2}]}`
	reports, err := ReplayWithVersion(strings.NewReader(input), dir, "quiet")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Findings) != 0 {
		t.Fatalf("setup: quiet version must archive no findings: %+v", reports[0].Findings)
	}
	result, err := Compare(dir, "1", "0q", "quiet")
	if err != nil {
		t.Fatal(err)
	}
	assertNonNilEmptySlice(t, "originalFindings", result.OriginalFindings)
	assertNonNilEmptySlice(t, "comparedFindings", result.ComparedFindings)
	assertNonNilEmptySlice(t, "added", result.Added)
	assertNonNilEmptySlice(t, "removed", result.Removed)
	assertNonNilEmptySlice(t, "changed", result.Changed)
	if len(result.Swaps) != 3 {
		t.Fatalf("empty conclusions must still carry the archived swaps: %+v", result.Swaps)
	}

	// JSON must render [], not null, for every list.
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	// The conclusion and diff lists must render [] (never null); the archived
	// swap records stay populated alongside them.
	for _, key := range []string{"originalFindings", "comparedFindings", "added", "removed", "changed"} {
		if string(decoded[key]) != "[]" {
			t.Fatalf("JSON field %s = %s, want []", key, decoded[key])
		}
	}

	// A block that carries no swaps at all is empty on both sides even when
	// both versions would otherwise flag patterns; the five lists must again
	// be non-nil empty arrays.
	emptyBlock := `{"chainId":"1","blockHash":"0empty","blockNumber":2,"swaps":[]}`
	if _, err := Replay(strings.NewReader(emptyBlock), dir); err != nil {
		t.Fatal(err)
	}
	emptyResult, err := Compare(dir, "1", "0empty", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	assertNonNilEmptySlice(t, "empty originalFindings", emptyResult.OriginalFindings)
	assertNonNilEmptySlice(t, "empty comparedFindings", emptyResult.ComparedFindings)
	assertNonNilEmptySlice(t, "empty added", emptyResult.Added)
	assertNonNilEmptySlice(t, "empty removed", emptyResult.Removed)
	assertNonNilEmptySlice(t, "empty changed", emptyResult.Changed)
	assertNonNilEmptySlice(t, "empty swaps", emptyResult.Swaps)
}

// TestCompareVersionsAreIndependent pins the three-version rule: the
// archived side uses the version stored at replay time, the candidate side
// uses the version named on the compare call, and the currently enabled
// version influences neither side — even though all three differ. Both
// sides carry their own full rule parameters.
func TestCompareVersionsAreIndependent(t *testing.T) {
	dir := t.TempDir()
	archSpec := `{"id":"archv","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":3,"multiplier":3}}}`
	curSpec := `{"id":"curv","rules":{"sandwich":{"enabled":true,"severity":1},"displacement":{"enabled":true,"severity":5,"multiplier":10}}}`
	candSpec := `{"id":"candv","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":1,"multiplier":4}}}`
	archV, _ := register(t, dir, archSpec)
	curV, _ := register(t, dir, curSpec)
	candV, _ := register(t, dir, candSpec)
	if _, err := EnableVersion(dir, "curv"); err != nil {
		t.Fatal(err)
	}

	// p1: bracketed victim -> sandwich under every version (severity differs).
	// p2-p4: displacement-only victims (front trader differs from the back
	// trader), ratios chosen against multipliers 3 (archive) and 4 (candidate):
	//   45/10 hits both, 35/10 hits only mult3, 55/10 hits both.
	// The enabled mult10 would flag none of them, so any enabled-version
	// leakage would visibly delete conclusions.
	input := `{"chainId":"1","blockHash":"0xthree","blockNumber":30,"swaps":[` +
		`{"TxHash":"0xsf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xs1","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xsb","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},` +
		`{"TxHash":"0xdf","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":45,"Index":3},` +
		`{"TxHash":"0xd2","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4},` +
		`{"TxHash":"0xdb","Pool":"p2","Trader":"zoe","In":1,"Out":1,"GasPrice":5,"Index":5},` +
		`{"TxHash":"0xef","Pool":"p3","Trader":"whale","In":1,"Out":1,"GasPrice":35,"Index":6},` +
		`{"TxHash":"0xe3","Pool":"p3","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":7},` +
		`{"TxHash":"0xeb","Pool":"p3","Trader":"zoe","In":1,"Out":1,"GasPrice":5,"Index":8},` +
		`{"TxHash":"0xff","Pool":"p4","Trader":"whale","In":1,"Out":1,"GasPrice":55,"Index":9},` +
		`{"TxHash":"0xf4","Pool":"p4","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":10},` +
		`{"TxHash":"0xfb","Pool":"p4","Trader":"zoe","In":1,"Out":1,"GasPrice":5,"Index":11}]}`
	reports, err := ReplayWithVersion(strings.NewReader(input), dir, "archv")
	if err != nil {
		t.Fatal(err)
	}
	if reports[0].Version.ID != "archv" {
		t.Fatalf("replay ignored the explicit version while another version is enabled: %+v", reports[0].Version)
	}

	result, err := Compare(dir, "1", "0xthree", "candv")
	if err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion != archV {
		t.Fatalf("original version = %+v, want the archived archv with full params", result.OriginalVersion)
	}
	if result.ComparedVersion != candV {
		t.Fatalf("compared version = %+v, want the requested candv with full params", result.ComparedVersion)
	}
	if result.OriginalVersion == curV || result.ComparedVersion == curV {
		t.Fatal("compare leaked the enabled version into a result side")
	}

	// Independent recomputation under each side's own parameters.
	wantOrig := DetectBlockWithRules(result.Swaps, archV.Rules)
	wantCand := DetectBlockWithRules(result.Swaps, candV.Rules)
	if !reflect.DeepEqual(result.OriginalFindings, wantOrig) {
		t.Fatalf("original findings %+v != recomputation under archv %+v",
			result.OriginalFindings, wantOrig)
	}
	if !reflect.DeepEqual(result.ComparedFindings, wantCand) {
		t.Fatalf("compared findings %+v != recomputation under candv %+v",
			result.ComparedFindings, wantCand)
	}
	// Full-list ordering: severity desc, hash asc within one severity.
	if got := txHashes(result.OriginalFindings); !reflect.DeepEqual(got, []string{"0xs1", "0xd2", "0xe3", "0xf4"}) {
		t.Fatalf("original full list order = %v", got)
	}
	if got := txHashes(result.ComparedFindings); !reflect.DeepEqual(got, []string{"0xs1", "0xd2", "0xf4"}) {
		t.Fatalf("compared full list order = %v", got)
	}
	// Diff classification: s1 severity change, d2 severity change, f4
	// severity change, e3 removed; nothing added; changed sorted by hash.
	if got := txHashes(result.Removed); !reflect.DeepEqual(got, []string{"0xe3"}) {
		t.Fatalf("removed = %v, want [0xe3]", got)
	}
	if len(result.Added) != 0 {
		t.Fatalf("added = %+v, want empty", result.Added)
	}
	changed := map[string]FindingChange{}
	for _, ch := range result.Changed {
		changed[ch.TxHash] = ch
	}
	if len(changed) != 3 {
		t.Fatalf("changed = %+v, want s1,d2,f4", result.Changed)
	}
	if got := []string{result.Changed[0].TxHash, result.Changed[1].TxHash, result.Changed[2].TxHash}; !reflect.DeepEqual(got, []string{"0xd2", "0xf4", "0xs1"}) {
		t.Fatalf("changed not hash-sorted: %v", got)
	}
	if c := changed["0xs1"]; c.Original.Kind != "sandwich" || c.Original.Severity != 4 ||
		c.Compared.Kind != "sandwich" || c.Compared.Severity != 5 {
		t.Fatalf("s1 change wrong: %+v", c)
	}
	if c := changed["0xd2"]; c.Original.Kind != "displacement" || c.Original.Severity != 3 ||
		c.Compared.Kind != "displacement" || c.Compared.Severity != 1 {
		t.Fatalf("d2 change wrong: %+v", c)
	}
	if c := changed["0xf4"]; c.Original.Severity != 3 || c.Compared.Severity != 1 {
		t.Fatalf("f4 change wrong: %+v", c)
	}
	// The enabled version stays curv after the read-only query.
	if _, enabled, err := ListVersions(dir); err != nil || enabled != "curv" {
		t.Fatalf("enabled version after compare = %q, %v", enabled, err)
	}
}

// TestCompareScopedToSelectedBlock pins chain/block-hash/height scoping:
// another block at the same height, same hash on another chain and other
// chains never mix into a result.
func TestCompareScopedToSelectedBlock(t *testing.T) {
	dir := t.TempDir()
	blocks := []string{
		// chain 1, height 100, hash 0hA: one displacement victim.
		`{"chainId":"1","blockHash":"0hA","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xAf","Pool":"p","Trader":"w","In":1,"Out":2,"GasPrice":40,"Index":0},` +
			`{"TxHash":"0xAv","Pool":"p","Trader":"u","In":3,"Out":4,"GasPrice":10,"Index":1}]}`,
		// chain 1, height 100, hash 0hB: one sandwich victim, distinct hashes.
		`{"chainId":"1","blockHash":"0hB","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xBf","Pool":"p","Trader":"bot","In":5,"Out":6,"GasPrice":90,"Index":0},` +
			`{"TxHash":"0xBv","Pool":"p","Trader":"u","In":7,"Out":8,"GasPrice":10,"Index":1},` +
			`{"TxHash":"0xBb","Pool":"p","Trader":"bot","In":9,"Out":10,"GasPrice":80,"Index":2}]}`,
		// chain 2, height 100, same hash 0hA: no findings.
		`{"chainId":"2","blockHash":"0hA","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xCf","Pool":"p","Trader":"w","In":1,"Out":2,"GasPrice":15,"Index":0},` +
			`{"TxHash":"0xCv","Pool":"p","Trader":"u","In":3,"Out":4,"GasPrice":10,"Index":1}]}`,
	}
	for _, b := range blocks {
		replay(t, dir, b)
	}

	a, err := Compare(dir, "1", "0hA", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if a.ChainID != "1" || a.BlockHash != "0hA" || a.BlockNumber != 100 {
		t.Fatalf("identity wrong: %+v", a)
	}
	if got := swapHashes(a.Swaps); !reflect.DeepEqual(got, []string{"0xAf", "0xAv"}) {
		t.Fatalf("swaps from another record leaked in: %v", got)
	}
	if len(a.OriginalFindings) != 1 || a.OriginalFindings[0].TxHash != "0xAv" {
		t.Fatalf("findings leaked from another block: %+v", a.OriginalFindings)
	}

	b, err := Compare(dir, "1", "0hB", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if b.BlockHash != "0hB" || len(b.Swaps) != 3 || b.OriginalFindings[0].TxHash != "0xBv" {
		t.Fatalf("same-height block A leaked into B: %+v / %+v", b.Swaps, b.OriginalFindings)
	}

	c, err := Compare(dir, "2", "0hA", BuiltinVersionID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainID != "2" || len(c.Swaps) != 2 || len(c.OriginalFindings) != 0 {
		t.Fatalf("chain-1 record leaked across chains: %+v", c)
	}

	// Same hash on the wrong chain and same-height other hashes are unknown.
	for _, q := range [][2]string{{"2", "0hB"}, {"1", "0hC"}, {"3", "0hA"}} {
		if _, err := Compare(dir, q[0], q[1], BuiltinVersionID); !errors.Is(err, ErrUnknownBlock) {
			t.Fatalf("Compare(%s,%s) err = %v, want ErrUnknownBlock", q[0], q[1], err)
		}
	}
}

// TestCompareKeepsRawSwapEvidenceAndArchiveRecord checks that conclusions
// on both sides keep the original TxHash/Pool/Trader/In/Out/GasPrice/Index
// of every participating swap, that the result also carries the full
// archived swap record set (not just diffs or prose), and that sandwich
// evidence includes the back-run swap while displacement evidence does not.
func TestCompareKeepsRawSwapEvidenceAndArchiveRecord(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0xev","blockNumber":40,"swaps":[` +
		`{"TxHash":"0xfs","Pool":"pool-1","Trader":"bot","In":500,"Out":480,"GasPrice":100,"Index":0},` +
		`{"TxHash":"0xt1","Pool":"pool-1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xbs","Pool":"pool-1","Trader":"bot","In":480,"Out":505,"GasPrice":90,"Index":2}]}`
	replay(t, dir, input)
	register(t, dir, kindflipSpec)

	result, err := Compare(dir, "1", "0xev", "kindflip")
	if err != nil {
		t.Fatal(err)
	}
	wantSwaps := []Swap{
		{TxHash: "0xfs", Pool: "pool-1", Trader: "bot", In: 500, Out: 480, GasPrice: 100, Index: 0},
		{TxHash: "0xt1", Pool: "pool-1", Trader: "user", In: 200, Out: 188, GasPrice: 10, Index: 1},
		{TxHash: "0xbs", Pool: "pool-1", Trader: "bot", In: 480, Out: 505, GasPrice: 90, Index: 2},
	}
	if !reflect.DeepEqual(result.Swaps, wantSwaps) {
		t.Fatalf("archived swap records not returned in full: %+v", result.Swaps)
	}
	ch := result.Changed[0]
	wantFront := wantSwaps[0]
	wantVictim := wantSwaps[1]
	wantBack := wantSwaps[2]
	if !reflect.DeepEqual(ch.Original.Evidence, []Swap{wantFront, wantVictim, wantBack}) {
		t.Fatalf("sandwich evidence lost raw fields or misses the back-run: %+v", ch.Original.Evidence)
	}
	if !reflect.DeepEqual(ch.Compared.Evidence, []Swap{wantFront, wantVictim}) {
		t.Fatalf("displacement evidence lost raw fields: %+v", ch.Compared.Evidence)
	}
	// Full lists carry the same raw evidence, not just the diff pair.
	orig := findingMap(result.OriginalFindings)["0xt1"]
	comp := findingMap(result.ComparedFindings)["0xt1"]
	if !reflect.DeepEqual(orig.Evidence, ch.Original.Evidence) ||
		!reflect.DeepEqual(comp.Evidence, ch.Compared.Evidence) {
		t.Fatalf("full-list evidence diverges from diff evidence: %+v / %+v", orig, comp)
	}
}

// TestCompareIsReadOnlyOnSuccessAndFailure hashes the archive file before a
// successful compare and failing compares (unknown block, unregistered
// candidate) and asserts the bytes never change; neither does the enabled
// version. It also confirms compare works after the original replay input
// is gone — only archived swap records are read.
func TestCompareIsReadOnlyOnSuccessAndFailure(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(sandwichInput+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayFile(inputPath, dir); err != nil {
		t.Fatal(err)
	}
	register(t, dir, strictSpec)
	if _, err := EnableVersion(dir, "strict"); err != nil {
		t.Fatal(err)
	}
	// The original input file is no longer available: comparison must still
	// complete from the archived swap records.
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(dir, archiveFileName)
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	check := func() {
		t.Helper()
		after, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("compare changed the archive file")
		}
		_, enabled, err := ListVersions(dir)
		if err != nil {
			t.Fatal(err)
		}
		if enabled != "strict" {
			t.Fatalf("enabled version changed to %q", enabled)
		}
	}

	if _, err := Compare(dir, "1", "0xa", BuiltinVersionID); err != nil {
		t.Fatalf("compare after input deletion failed: %v", err)
	}
	check()
	if _, err := Compare(dir, "1", "0xa", "ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("unknown candidate: %v", err)
	}
	check()
	if _, err := Compare(dir, "1", "0xmissing", BuiltinVersionID); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block: %v", err)
	}
	check()
	// An unknown candidate must fail even when the block exists and the
	// failure must produce no success payload; archive stays byte-identical.
	r, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version.ID != BuiltinVersionID {
		t.Fatalf("archived report version changed: %+v", r.Version)
	}
}

// TestCompareUnknownVersionFailsOnEmptyArchiveAndWithoutBlock ensures an
// unregistered candidate is rejected on its own merits (not silently mapped
// to the enabled or built-in version) before any block lookup short-circuit.
func TestCompareUnknownVersionFailures(t *testing.T) {
	// No archive directory at all: unknown block wins at the entry, but an
	// existing archive with no matching block must still reject a ghost
	// version as unknown version.
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	if _, err := Compare(dir, "1", "0xa", "ghost"); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("err = %v, want ErrUnknownVersion", err)
	}
	// Empty version id is not a registered version either.
	if _, err := Compare(dir, "1", "0xa", ""); !errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("empty version id: err = %v, want ErrUnknownVersion", err)
	}
}

// TestCompareLegacyArchiveInterpretedAsBuiltin extends the legacy-archive
// guarantee specifically for compare: a versionless record supplies builtin
// full parameters on the original side while the candidate keeps its own,
// and re-judging still only uses the archived swap records.
func TestCompareLegacyArchiveInterpretedAsBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":77,` +
		`"swaps":[{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p","Trader":"user","In":2,"Out":3,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xb","Pool":"p","Trader":"bot","In":4,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p","Trader":"user","In":2,"Out":3,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xb","Pool":"p","Trader":"bot","In":4,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	strict, _ := register(t, dir, strictSpec)

	result, err := Compare(dir, "1", "0old", "strict")
	if err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion != BuiltinVersion() {
		t.Fatalf("versionless record must be interpreted as builtin, got %+v", result.OriginalVersion)
	}
	if result.ComparedVersion != strict {
		t.Fatalf("candidate must carry registered strict params, got %+v", result.ComparedVersion)
	}
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "sandwich" {
		t.Fatalf("archived conclusions lost: %+v", result.OriginalFindings)
	}
	// Under strict (mult5): victim 10, front 90 -> still sandwich, severity 5.
	if len(result.ComparedFindings) != 1 ||
		result.ComparedFindings[0].Kind != "sandwich" ||
		result.ComparedFindings[0].Severity != 5 {
		t.Fatalf("candidate re-judgment wrong: %+v", result.ComparedFindings)
	}
	if len(result.Swaps) != 3 {
		t.Fatalf("archived swap records missing: %+v", result.Swaps)
	}
	if len(result.Changed) != 1 || result.Changed[0].TxHash != "0v" {
		t.Fatalf("strict severity bump must be one change: %+v", result.Changed)
	}

	// The versionless record must not be rewritten by the read.
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if data.Records[0].Version != nil {
		t.Fatalf("legacy record gained a version: %+v", data.Records[0].Version)
	}
}
