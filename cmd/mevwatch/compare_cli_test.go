package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// mevwatchBin is built once per test process from the current source, so
// every test drives the real command entry point and its exit codes. The
// build is forced offline with the local toolchain and GOPROXY=off.
var mevwatchBin = func() string {
	dir, err := os.MkdirTemp("", "mevwatch-cli-")
	if err != nil {
		panic(err)
	}
	bin := filepath.Join(dir, "mevwatch")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(os.Environ(),
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
		"GOFLAGS=-mod=readonly",
		"CGO_ENABLED=0",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("go build: " + err.Error() + ": " + string(out))
	}
	return bin
}()

// runCLI invokes the binary and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(mevwatchBin, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), errOut.String(), ee.ExitCode()
	}
	t.Fatalf("failed to start %s: %v", mevwatchBin, err)
	return "", "", -1
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	// Archived version: sandwich sev 4, displacement sev 3, multiplier 3.
	cliArchSpec = `{"id":"archv","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":3,"multiplier":3}}}`
	// Candidate version: sandwich sev 5, displacement sev 1, multiplier 4.
	cliCandSpec = `{"id":"candv","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":1,"multiplier":4}}}`
	// Currently enabled version: never used by either compare side.
	cliCurSpec = `{"id":"curv","rules":{"sandwich":{"enabled":true,"severity":1},"displacement":{"enabled":true,"severity":5,"multiplier":10}}}`
)

// cliRichBlock: one sandwich victim and three displacement victims, with
// front gas chosen so the archived (mult3) and candidate (mult4) versions
// disagree exactly as documented below. Every swap carries distinct raw
// fields so evidence preservation is checkable.
const cliRichBlock = `{"chainId":"1","blockHash":"0xthree","blockNumber":30,"swaps":[` +
	`{"TxHash":"0xsf","Pool":"p1","Trader":"bot","In":101,"Out":102,"GasPrice":90,"Index":0},` +
	`{"TxHash":"0xs1","Pool":"p1","Trader":"user","In":103,"Out":104,"GasPrice":10,"Index":1},` +
	`{"TxHash":"0xsb","Pool":"p1","Trader":"bot","In":105,"Out":106,"GasPrice":80,"Index":2},` +
	`{"TxHash":"0xdf","Pool":"p2","Trader":"whale","In":201,"Out":202,"GasPrice":45,"Index":3},` +
	`{"TxHash":"0xd2","Pool":"p2","Trader":"user","In":203,"Out":204,"GasPrice":10,"Index":4},` +
	`{"TxHash":"0xdb","Pool":"p2","Trader":"zoe","In":205,"Out":206,"GasPrice":5,"Index":5},` +
	`{"TxHash":"0xef","Pool":"p3","Trader":"whale","In":301,"Out":302,"GasPrice":35,"Index":6},` +
	`{"TxHash":"0xe3","Pool":"p3","Trader":"user","In":303,"Out":304,"GasPrice":10,"Index":7},` +
	`{"TxHash":"0xeb","Pool":"p3","Trader":"zoe","In":305,"Out":306,"GasPrice":5,"Index":8},` +
	`{"TxHash":"0xff","Pool":"p4","Trader":"whale","In":401,"Out":402,"GasPrice":55,"Index":9},` +
	`{"TxHash":"0xf4","Pool":"p4","Trader":"user","In":403,"Out":404,"GasPrice":10,"Index":10},` +
	`{"TxHash":"0xfb","Pool":"p4","Trader":"zoe","In":405,"Out":406,"GasPrice":5,"Index":11}]}`

func setupRichArchive(t *testing.T) (dir, inputPath string) {
	t.Helper()
	dir = t.TempDir()
	writeSpec := func(name, spec string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		mustWrite(t, path, spec)
		if out, _, code := runCLI(t, "", "rules", "register", dir, path); code != 0 {
			t.Fatalf("register %s: exit %d out=%s", name, code, out)
		}
	}
	writeSpec("arch.json", cliArchSpec)
	writeSpec("cand.json", cliCandSpec)
	writeSpec("cur.json", cliCurSpec)
	if _, _, code := runCLI(t, "", "rules", "enable", dir, "curv"); code != 0 {
		t.Fatal("enable curv failed")
	}
	inputPath = filepath.Join(t.TempDir(), "blocks.jsonl")
	mustWrite(t, inputPath, cliRichBlock)
	if _, errOut, code := runCLI(t, "", "replay", "--version", "archv", inputPath, dir); code != 0 {
		t.Fatalf("replay --version archv: exit %d: %s", code, errOut)
	}
	return dir, inputPath
}

// TestCLICompareJSON drives the compare command entry point end to end and
// pins the full JSON contract on stdout: block identity, both versions'
// parameters, full conclusion order, per-victim diffs, raw swap evidence and
// the complete archived swap records. The original replay input is deleted
// first, and the archive plus enabled version must remain untouched.
func TestCLICompareJSON(t *testing.T) {
	dir, inputPath := setupRichArchive(t)
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	archiveBytes, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runCLI(t, "", "compare", dir, "1", "0xthree", "candv")
	if code != 0 {
		t.Fatalf("compare exit %d: %s", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("successful compare wrote stderr: %q", stderr)
	}

	var result mevwatch.CompareResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
	}
	// Identity is exactly the block the user selected.
	if result.ChainID != "1" || result.BlockHash != "0xthree" || result.BlockNumber != 30 {
		t.Fatalf("identity wrong: %+v", result)
	}
	// Three distinct versions: archive side archv, candidate side candv, the
	// enabled curv must appear on neither side.
	if result.OriginalVersion.ID != "archv" ||
		result.OriginalVersion.Rules.Sandwich.Severity != 4 ||
		result.OriginalVersion.Rules.Displacement.Severity != 3 ||
		result.OriginalVersion.Rules.Displacement.Multiplier != 3 {
		t.Fatalf("original version must carry the archived full params: %+v", result.OriginalVersion)
	}
	if result.ComparedVersion.ID != "candv" ||
		result.ComparedVersion.Rules.Sandwich.Severity != 5 ||
		result.ComparedVersion.Rules.Displacement.Severity != 1 ||
		result.ComparedVersion.Rules.Displacement.Multiplier != 4 {
		t.Fatalf("compared version must carry the requested full params: %+v", result.ComparedVersion)
	}
	if result.OriginalVersion.ID == "curv" || result.ComparedVersion.ID == "curv" {
		t.Fatal("enabled version leaked into a compare side")
	}

	// Full conclusion lists: severity desc, hash asc within one severity.
	wantOrigOrder := []string{"0xs1", "0xd2", "0xe3", "0xf4"}
	wantCandOrder := []string{"0xs1", "0xd2", "0xf4"}
	gotOrig := make([]string, len(result.OriginalFindings))
	for i, f := range result.OriginalFindings {
		gotOrig[i] = f.TxHash
	}
	gotCand := make([]string, len(result.ComparedFindings))
	for i, f := range result.ComparedFindings {
		gotCand[i] = f.TxHash
	}
	if !reflect.DeepEqual(gotOrig, wantOrigOrder) {
		t.Fatalf("originalFindings order = %v, want %v", gotOrig, wantOrigOrder)
	}
	if !reflect.DeepEqual(gotCand, wantCandOrder) {
		t.Fatalf("comparedFindings order = %v, want %v", gotCand, wantCandOrder)
	}

	// Per-victim diffs: e3 removed, nothing added, three changes hash-sorted.
	removed := []string{}
	for _, f := range result.Removed {
		removed = append(removed, f.TxHash)
	}
	if !reflect.DeepEqual(removed, []string{"0xe3"}) {
		t.Fatalf("removed = %v, want [0xe3]", removed)
	}
	if len(result.Added) != 0 {
		t.Fatalf("added = %+v, want empty", result.Added)
	}
	changed := map[string]mevwatch.FindingChange{}
	for _, c := range result.Changed {
		changed[c.TxHash] = c
	}
	actualOrder := make([]string, 0, len(result.Changed))
	for _, c := range result.Changed {
		actualOrder = append(actualOrder, c.TxHash)
	}
	sortedOrder := append([]string(nil), actualOrder...)
	sort.Strings(sortedOrder)
	if !reflect.DeepEqual(actualOrder, sortedOrder) {
		t.Fatalf("changed not hash-sorted: %v", actualOrder)
	}
	wantChanges := map[string]struct {
		kind          string
		origSev, cSev int
	}{
		"0xs1": {"sandwich", 4, 5},
		"0xd2": {"displacement", 3, 1},
		"0xf4": {"displacement", 3, 1},
	}
	if len(changed) != len(wantChanges) {
		t.Fatalf("changed = %v, want %v", actualOrder, sortedOrder)
	}
	for tx, want := range wantChanges {
		c, ok := changed[tx]
		if !ok {
			t.Fatalf("missing change for %s: %+v", tx, result.Changed)
		}
		if c.Original.Kind != want.kind || c.Compared.Kind != want.kind ||
			c.Original.Severity != want.origSev || c.Compared.Severity != want.cSev {
			t.Fatalf("change %s = orig %+v comp %+v, want %s %d/%d",
				tx, c.Original, c.Compared, want.kind, want.origSev, want.cSev)
		}
	}

	// The sandwich severity change keeps the sandwich conclusion on both
	// sides, so both carry the three bracketing swaps as raw evidence.
	s1 := changed["0xs1"]
	if len(s1.Original.Evidence) != 3 || len(s1.Compared.Evidence) != 3 {
		t.Fatalf("s1 evidence wrong: %+v / %+v", s1.Original.Evidence, s1.Compared.Evidence)
	}
	// Raw evidence fields survive: original tx, pool, trader, amounts, gas, index.
	front := s1.Original.Evidence[0]
	if front != (mevwatch.Swap{TxHash: "0xsf", Pool: "p1", Trader: "bot", In: 101, Out: 102, GasPrice: 90, Index: 0}) {
		t.Fatalf("raw sandwich front evidence lost fields: %+v", front)
	}
	victim := s1.Original.Evidence[1]
	if victim.In != 103 || victim.Out != 104 || victim.GasPrice != 10 || victim.Index != 1 ||
		victim.Trader != "user" || victim.Pool != "p1" {
		t.Fatalf("raw victim evidence lost fields: %+v", victim)
	}
	candFront := s1.Compared.Evidence[0]
	if candFront.GasPrice != 90 || candFront.Index != 0 || candFront.Pool != "p1" {
		t.Fatalf("candidate evidence lost raw fields: %+v", candFront)
	}

	// The complete archived swap records are present, in Index order.
	if len(result.Swaps) != 12 {
		t.Fatalf("swaps = %d records, want all 12 archived records", len(result.Swaps))
	}
	for i, s := range result.Swaps {
		if s.Index != i {
			t.Fatalf("archived swap set damaged at position %d: %+v", i, s)
		}
	}
	if result.Swaps[3] != (mevwatch.Swap{TxHash: "0xdf", Pool: "p2", Trader: "whale", In: 201, Out: 202, GasPrice: 45, Index: 3}) {
		t.Fatalf("archived swap record lost raw fields: %+v", result.Swaps[3])
	}
	// An empty diff list renders as a JSON array, never null.
	if !strings.Contains(stdout, `"added":[]`) {
		t.Fatalf("empty added list not rendered as []: %s", stdout)
	}

	// Read-only: archive bytes and enabled version survive both the deleted
	// input scenario and a repeated compare.
	for i := 0; i < 2; i++ {
		if _, stderr, code := runCLI(t, "", "compare", dir, "1", "0xthree", "candv"); code != 0 {
			t.Fatalf("compare #%d failed: %s", i, stderr)
		}
	}
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(archiveBytes, after) {
		t.Fatal("compare modified the archive file")
	}
	listOut, _, code := runCLI(t, "", "rules", "list", dir)
	if code != 0 {
		t.Fatal("rules list failed")
	}
	var listed struct {
		Enabled string `json:"enabled"`
	}
	if err := json.Unmarshal([]byte(listOut), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Enabled != "curv" {
		t.Fatalf("enabled version changed to %q after compare", listed.Enabled)
	}
}

// TestCLICompareBlockScoping archives a same-height sibling block and the
// same block hash on another chain, then proves the compare JSON can only
// ever describe the block the user selected.
func TestCLICompareBlockScoping(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(t.TempDir(), "blocks.jsonl")
	mustWrite(t, input, strings.Join([]string{
		`{"chainId":"1","blockHash":"0hA","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xAf","Pool":"p","Trader":"w","In":1,"Out":2,"GasPrice":40,"Index":0},` +
			`{"TxHash":"0xAv","Pool":"p","Trader":"u","In":3,"Out":4,"GasPrice":10,"Index":1}]}`,
		`{"chainId":"1","blockHash":"0hB","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xBf","Pool":"p","Trader":"bot","In":5,"Out":6,"GasPrice":90,"Index":0},` +
			`{"TxHash":"0xBv","Pool":"p","Trader":"u","In":7,"Out":8,"GasPrice":10,"Index":1},` +
			`{"TxHash":"0xBb","Pool":"p","Trader":"bot","In":9,"Out":10,"GasPrice":80,"Index":2}]}`,
		`{"chainId":"2","blockHash":"0hA","blockNumber":100,"swaps":[` +
			`{"TxHash":"0xCf","Pool":"p","Trader":"w","In":1,"Out":2,"GasPrice":15,"Index":0},` +
			`{"TxHash":"0xCv","Pool":"p","Trader":"u","In":3,"Out":4,"GasPrice":10,"Index":1}]}`,
	}, "\n"))
	if _, errOut, code := runCLI(t, "", "replay", input, dir); code != 0 {
		t.Fatalf("replay: %d %s", code, errOut)
	}

	parse := func(chain, hash string) mevwatch.CompareResult {
		stdout, stderr, code := runCLI(t, "", "compare", dir, chain, hash, "builtin")
		if code != 0 {
			t.Fatalf("compare %s/%s: %d %s", chain, hash, code, stderr)
		}
		var r mevwatch.CompareResult
		if err := json.Unmarshal([]byte(stdout), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	a := parse("1", "0hA")
	if a.ChainID != "1" || a.BlockHash != "0hA" || a.BlockNumber != 100 {
		t.Fatalf("identity wrong: %+v", a)
	}
	if len(a.Swaps) != 2 || a.Swaps[0].TxHash != "0xAf" || len(a.OriginalFindings) != 1 ||
		a.OriginalFindings[0].TxHash != "0xAv" {
		t.Fatalf("sibling block data leaked into 0hA: %+v", a)
	}
	b := parse("1", "0hB")
	if len(b.Swaps) != 3 || b.OriginalFindings[0].TxHash != "0xBv" || b.ComparedFindings[0].Kind != "sandwich" {
		t.Fatalf("same-height block A leaked into 0hB: %+v", b)
	}
	c := parse("2", "0hA")
	if c.ChainID != "2" || len(c.Swaps) != 2 || len(c.OriginalFindings) != 0 {
		t.Fatalf("chain-1 data leaked across chains: %+v", c)
	}
}

// TestCLICompareFailures pins the non-zero exit behavior: a missing block
// or an unregistered candidate fails with a specific reason on stderr and no
// success JSON on stdout; an argument error is a usage failure (exit 2).
func TestCLICompareFailures(t *testing.T) {
	dir, _ := setupRichArchive(t)

	fail := func(args ...string) (string, string, int) {
		return runCLI(t, "", args...)
	}
	stdout, stderr, code := fail("compare", dir, "1", "0xmissing", "builtin")
	if code != 1 {
		t.Fatalf("unknown block exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("failure must not print a success result: %q", stdout)
	}
	if !strings.Contains(stderr, "unknown block") {
		t.Fatalf("stderr must explain the unknown block, got %q", stderr)
	}

	stdout, stderr, code = fail("compare", dir, "1", "0xthree", "ghost")
	if code != 1 {
		t.Fatalf("unknown version exit = %d, want 1", code)
	}
	if stdout != "" {
		t.Fatalf("unknown version printed a result: %q", stdout)
	}
	if !strings.Contains(stderr, "unknown version") || !strings.Contains(stderr, "ghost") {
		t.Fatalf("stderr must name the unregistered version, got %q", stderr)
	}

	// Unknown block on the other chain and same-height sibling likewise fail.
	if _, stderr, code := fail("compare", dir, "2", "0xthree", "builtin"); code != 1 ||
		!strings.Contains(stderr, "unknown block") {
		t.Fatalf("cross-chain lookup: code %d stderr %q", code, stderr)
	}
	if _, stderr, code := fail("compare", filepath.Join(dir, "does-not-exist"), "1", "0xthree", "builtin"); code != 1 ||
		!strings.Contains(stderr, "unknown block") {
		t.Fatalf("missing archive: code %d stderr %q", code, stderr)
	}

	if _, stderr, code := fail("compare", dir, "1", "0xthree"); code != 2 {
		t.Fatalf("missing argument exit = %d, want 2", code)
	} else if !strings.Contains(stderr, "usage") {
		t.Fatalf("argument error must print usage, got %q", stderr)
	}

	// Success and failure leave no half-written archive or enabled change.
	info, err := os.Stat(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		t.Fatal("archive replaced by a directory")
	}
}

// TestCLICompareBothEmpty covers the empty-arrays contract through the CLI:
// when neither side has conclusions, both full lists and the three diff
// lists are JSON arrays, and the query stays read-only.
func TestCLICompareBothEmpty(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(t.TempDir(), "empty.jsonl")
	mustWrite(t, input, `{"chainId":"1","blockHash":"0empty","blockNumber":2,"swaps":[]}`)
	if _, errOut, code := runCLI(t, "", "replay", input, dir); code != 0 {
		t.Fatalf("replay: %d %s", code, errOut)
	}
	stdout, stderr, code := runCLI(t, "", "compare", dir, "1", "0empty", "builtin")
	if code != 0 {
		t.Fatalf("compare: %d %s", code, stderr)
	}
	for _, key := range []string{
		`"originalFindings":[]`, `"comparedFindings":[]`,
		`"added":[]`, `"removed":[]`, `"changed":[]`, `"swaps":[]`,
	} {
		if !strings.Contains(stdout, key) {
			t.Fatalf("empty result missing %s: %s", key, stdout)
		}
	}
	var result mevwatch.CompareResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion.ID != "builtin" || result.ComparedVersion.ID != "builtin" {
		t.Fatalf("versions wrong: %+v / %+v", result.OriginalVersion, result.ComparedVersion)
	}
}

// TestCLICompareLegacyArchive verifies the pre-version archive format: a
// versionless record compares successfully with the original side reported
// as builtin and full parameters, while the candidate carries its own.
func TestCLICompareLegacyArchive(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":77,` +
		`"swaps":[{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p","Trader":"user","In":2,"Out":3,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xb","Pool":"p","Trader":"bot","In":4,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p","Trader":"user","In":2,"Out":3,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xb","Pool":"p","Trader":"bot","In":4,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	mustWrite(t, filepath.Join(dir, "archive.json"), legacy)
	specPath := filepath.Join(t.TempDir(), "strict.json")
	mustWrite(t, specPath, `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`)
	if _, stderr, code := runCLI(t, "", "rules", "register", dir, specPath); code != 0 {
		t.Fatalf("register: %d %s", code, stderr)
	}

	stdout, stderr, code := runCLI(t, "", "compare", dir, "1", "0old", "strict")
	if code != 0 {
		t.Fatalf("legacy compare: %d %s", code, stderr)
	}
	var result mevwatch.CompareResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatal(err)
	}
	if result.OriginalVersion.ID != "builtin" ||
		result.OriginalVersion.Rules.Sandwich.Severity != 3 ||
		result.OriginalVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("versionless archive must be interpreted as builtin with full params: %+v", result.OriginalVersion)
	}
	if result.ComparedVersion.ID != "strict" || result.ComparedVersion.Rules.Sandwich.Severity != 5 {
		t.Fatalf("candidate params wrong: %+v", result.ComparedVersion)
	}
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "sandwich" ||
		len(result.Changed) != 1 || result.Changed[0].TxHash != "0v" {
		t.Fatalf("legacy diff wrong: %+v", result)
	}
	if len(result.Swaps) != 3 {
		t.Fatalf("archived swaps missing in legacy compare: %+v", result.Swaps)
	}

	// The versionless record is never rewritten by the read.
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"version"`) {
		t.Fatalf("legacy record gained a version field after compare:\n%s", raw)
	}
}
