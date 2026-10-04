package main

// End-to-end regression coverage for the `compare` command entry point.
// The test binary re-executes itself (see TestMain) and runs the real
// main(), so these tests exercise argument parsing, exit status, stderr
// failure wording and the exact stdout JSON exactly as a user does.
// Everything runs offline against archive directories under t.TempDir;
// the original block input file is deleted before the CLI is invoked,
// proving comparison reads archived swap records only.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

const cliHelperEnv = "MEVWATCH_TEST_HELPER"

// cliResult is the captured outcome of one forked CLI invocation.
type cliResult struct {
	stdout   string
	stderr   string
	exitCode int
}

func TestMain(m *testing.M) {
	if os.Getenv(cliHelperEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// runCLI executes the real command entry with the given arguments in a
// forked copy of the test binary.
func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	cmd := execCommand(args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		code = exitCode(t, err)
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

type cliSwap = map[string]any

func cliSwapRecord(tx, pool, trader string, gas int64, index int) cliSwap {
	return map[string]any{
		"TxHash": tx, "Pool": pool, "Trader": trader,
		"In": 1, "Out": 1, "GasPrice": gas, "Index": index,
	}
}

func cliBlockLine(chain, hash string, number int64, swaps ...cliSwap) string {
	raw, err := json.Marshal(map[string]any{
		"chainId": chain, "blockHash": hash, "blockNumber": number, "swaps": swaps,
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// setupCLIArchive builds an archive exercising every diff shape and
// deletes the source input file before returning:
//
//	p1 0xa1 sandwich sev4 (archived under archA) -> displacement sev4
//	   under candC (sandwich disabled): kind change;
//	p2 0xb1 displacement sev1 multiplier 3 -> sev4 multiplier 2:
//	   severity change;
//	p3 0xd1 nothing under archA (21 <= 30) -> displacement sev4 under
//	   candC (21 > 20): added;
//	p4 0xe1 sandwich sev4 under archA, nothing under candC (16 <= 20):
//	   removed.
func setupCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	lines := []string{
		cliBlockLine("1", "0xblk", 42,
			cliSwapRecord("0xaf", "p1", "bot", 90, 0),
			cliSwapRecord("0xa1", "p1", "user", 10, 1),
			cliSwapRecord("0xab", "p1", "bot", 80, 2),
			cliSwapRecord("0xbf", "p2", "w", 40, 3),
			cliSwapRecord("0xb1", "p2", "u", 10, 4),
			cliSwapRecord("0xbz", "p2", "z", 10, 5),
			cliSwapRecord("0xdf", "p3", "w", 21, 6),
			cliSwapRecord("0xd1", "p3", "u", 10, 7),
			cliSwapRecord("0xef", "p4", "bot", 16, 8),
			cliSwapRecord("0xe1", "p4", "user", 10, 9),
			cliSwapRecord("0xeb", "p4", "bot", 12, 10),
		),
		// Same height, different hash: must never mix into 0xblk.
		cliBlockLine("1", "0xother", 42,
			cliSwapRecord("0zz0", "pz", "tz", 900, 0),
			cliSwapRecord("0zz1", "pz", "tz2", 901, 1),
		),
		// Same height and hash on a different chain: also must not mix.
		cliBlockLine("2", "0xblk", 42,
			cliSwapRecord("0qq0", "pq", "tq", 700, 0),
			cliSwapRecord("0qq1", "pq", "tq2", 701, 1),
		),
	}
	if err := os.WriteFile(inputPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const (
		archA = `{"id":"archA","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":1,"multiplier":3}}}`
		liveB = `{"id":"liveB","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":5,"multiplier":4}}}`
		candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	)
	for _, spec := range []string{archA, liveB, candC} {
		if _, _, err := mevwatch.RegisterVersion(dir, []byte(spec)); err != nil {
			t.Fatalf("RegisterVersion: %v", err)
		}
	}
	reports, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "archA")
	if err != nil {
		t.Fatalf("ReplayFileWithVersion: %v", err)
	}
	if len(reports) != 3 {
		t.Fatalf("got %d reports, want 3", len(reports))
	}
	if _, err := mevwatch.EnableVersion(dir, "liveB"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func parseCompareJSON(t *testing.T, raw string) mevwatch.CompareResult {
	t.Helper()
	var result mevwatch.CompareResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, raw)
	}
	return result
}

func TestCLICompareSuccessJSON(t *testing.T) {
	dir := setupCLIArchive(t) // input file already deleted

	res := runCLI(t, "compare", dir, "1", "0xblk", "candC")
	if res.exitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if strings.TrimSpace(res.stderr) != "" {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
	// Exactly one JSON object on stdout, no extra text.
	if !strings.HasSuffix(res.stdout, "}\n") || strings.Count(strings.TrimSpace(res.stdout), "{") < 1 {
		t.Fatalf("stdout shape wrong: %q", res.stdout)
	}
	result := parseCompareJSON(t, res.stdout)

	// Identity corresponds to the selected block only.
	if result.ChainID != "1" || result.BlockHash != "0xblk" || result.BlockNumber != 42 {
		t.Fatalf("block identity wrong: %s/%s @%d", result.ChainID, result.BlockHash, result.BlockNumber)
	}

	// Historical side keeps the archive-time version archA; the candidate
	// side uses candC, not the currently enabled liveB. Each side carries
	// its complete parameters.
	if result.OriginalVersion.ID != "archA" ||
		result.OriginalVersion.Rules.Sandwich.Severity != 4 ||
		result.OriginalVersion.Rules.Displacement.Multiplier != 3 ||
		result.OriginalVersion.Rules.Displacement.Severity != 1 {
		t.Fatalf("original side must keep archived version params: %+v", result.OriginalVersion)
	}
	if result.ComparedVersion.ID != "candC" ||
		result.ComparedVersion.Rules.Sandwich.Enabled ||
		result.ComparedVersion.Rules.Displacement.Severity != 4 ||
		result.ComparedVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("candidate side must use the named version params: %+v", result.ComparedVersion)
	}

	// Full conclusions: severity desc, hash asc. 0xa1/0xe1 are sandwich
	// sev4, 0xb1 displacement sev1.
	if len(result.OriginalFindings) != 3 {
		t.Fatalf("original findings = %+v", result.OriginalFindings)
	}
	wantOrig := []struct {
		tx   string
		kind string
		sev  int
	}{
		{"0xa1", "sandwich", 4},
		{"0xe1", "sandwich", 4},
		{"0xb1", "displacement", 1},
	}
	for i, w := range wantOrig {
		got := result.OriginalFindings[i]
		if got.TxHash != w.tx || got.Kind != w.kind || got.Severity != w.sev {
			t.Fatalf("original[%d] = %+v, want %+v", i, got, w)
		}
	}
	// Candidate side: three displacement sev4, hash asc.
	if len(result.ComparedFindings) != 3 {
		t.Fatalf("compared findings = %+v", result.ComparedFindings)
	}
	wantComp := []string{"0xa1", "0xb1", "0xd1"}
	for i, tx := range wantComp {
		got := result.ComparedFindings[i]
		if got.TxHash != tx || got.Kind != "displacement" || got.Severity != 4 {
			t.Fatalf("compared[%d] = %+v, want %s displacement 4", i, got, tx)
		}
	}

	// Per-victim diff: added, removed, and two changes hash asc.
	if len(result.Added) != 1 || result.Added[0].TxHash != "0xd1" {
		t.Fatalf("added = %+v", result.Added)
	}
	if len(result.Removed) != 1 || result.Removed[0].TxHash != "0xe1" {
		t.Fatalf("removed = %+v", result.Removed)
	}
	if len(result.Changed) != 2 ||
		result.Changed[0].TxHash != "0xa1" || result.Changed[1].TxHash != "0xb1" {
		t.Fatalf("changed = %+v", result.Changed)
	}
	// Sandwich -> displacement keeps BOTH conclusions in one change entry.
	kindChange := result.Changed[0]
	if kindChange.Original.Kind != "sandwich" || kindChange.Original.Severity != 4 ||
		len(kindChange.Original.Evidence) != 3 {
		t.Fatalf("kind change original side wrong: %+v", kindChange.Original)
	}
	if kindChange.Compared.Kind != "displacement" || kindChange.Compared.Severity != 4 ||
		len(kindChange.Compared.Evidence) != 2 {
		t.Fatalf("kind change compared side wrong: %+v", kindChange.Compared)
	}
	// Severity-only change keeps both sides with the same kind.
	sevChange := result.Changed[1]
	if sevChange.Original.Kind != "displacement" || sevChange.Original.Severity != 1 ||
		sevChange.Compared.Kind != "displacement" || sevChange.Compared.Severity != 4 {
		t.Fatalf("severity change wrong: %+v", sevChange)
	}

	// Full archived swap records survive (11 records for this block), and
	// conclusion evidence keeps raw tx/pool/trader/amount/gas/index.
	if len(result.Swaps) != 11 {
		t.Fatalf("full swap records missing: %+v", result.Swaps)
	}
	if result.Swaps[0] != (mevwatch.Swap{TxHash: "0xaf", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0}) {
		t.Fatalf("raw swap fields damaged: %+v", result.Swaps[0])
	}
	front := result.Changed[0].Original.Evidence[0]
	if front.TxHash != "0xaf" || front.Pool != "p1" || front.Trader != "bot" ||
		front.In != 1 || front.Out != 1 || front.GasPrice != 90 || front.Index != 0 {
		t.Fatalf("conclusion evidence damaged: %+v", front)
	}

	// Output is deterministic across repeated offline invocations.
	again := runCLI(t, "compare", dir, "1", "0xblk", "candC")
	if again.exitCode != 0 {
		t.Fatalf("second run failed: %d %q", again.exitCode, again.stderr)
	}
	if again.stdout != res.stdout {
		t.Fatalf("compare output is not deterministic:\n%s\n%s", res.stdout, again.stdout)
	}
}

func TestCLICompareScoping(t *testing.T) {
	dir := setupCLIArchive(t)

	sameHeightOther := runCLI(t, "compare", dir, "1", "0xother", "candC")
	if sameHeightOther.exitCode != 0 {
		t.Fatalf("other block compare failed: %q", sameHeightOther.stderr)
	}
	r := parseCompareJSON(t, sameHeightOther.stdout)
	if r.BlockHash != "0xother" || r.BlockNumber != 42 || len(r.Swaps) != 2 ||
		r.Swaps[0].TxHash != "0zz0" {
		t.Fatalf("same-height other block mixed records in: %+v", r)
	}

	otherChain := runCLI(t, "compare", dir, "2", "0xblk", "candC")
	if otherChain.exitCode != 0 {
		t.Fatalf("other chain compare failed: %q", otherChain.stderr)
	}
	r = parseCompareJSON(t, otherChain.stdout)
	if r.ChainID != "2" || r.BlockHash != "0xblk" || len(r.Swaps) != 2 ||
		r.Swaps[0].TxHash != "0qq0" {
		t.Fatalf("other chain records mixed in: %+v", r)
	}
	for _, f := range append(append([]mevwatch.ReportFinding{}, r.OriginalFindings...), r.ComparedFindings...) {
		if strings.HasPrefix(f.TxHash, "0xa") || f.TxHash == "0xb1" {
			t.Fatalf("chain-1 conclusion leaked into chain-2 result: %+v", f)
		}
	}
}

func TestCLICompareFailures(t *testing.T) {
	dir := setupCLIArchive(t)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"unknown block", []string{"compare", dir, "1", "0xghost", "candC"}, 1, "unknown block"},
		{"unknown chain", []string{"compare", dir, "9", "0xblk", "candC"}, 1, "unknown block"},
		{"unregistered version", []string{"compare", dir, "1", "0xblk", "nope"}, 1, "unknown version: nope"},
		{"missing archive dir", []string{"compare", filepath.Join(dir, "missing"), "1", "0xblk", "candC"}, 1, "unknown block"},
		{"too few args", []string{"compare", dir, "1", "0xblk"}, 2, "usage: mevwatch compare"},
		{"too many args", []string{"compare", dir, "1", "0xblk", "candC", "extra"}, 2, "usage: mevwatch compare"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, tc.args...)
			if res.exitCode != tc.wantCode {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q",
					res.exitCode, tc.wantCode, res.stdout, res.stderr)
			}
			if res.stdout != "" {
				t.Fatalf("failure must print no success JSON, got %q", res.stdout)
			}
			if !strings.Contains(res.stderr, tc.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", res.stderr, tc.wantErr)
			}
		})
	}
}

func TestCLICompareEmptyBothSides(t *testing.T) {
	dir := t.TempDir()
	const (
		archA = `{"id":"archA","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":1,"multiplier":3}}}`
		candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	)
	for _, spec := range []string{archA, candC} {
		if _, _, err := mevwatch.RegisterVersion(dir, []byte(spec)); err != nil {
			t.Fatal(err)
		}
	}
	inputPath := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0none", 1,
		cliSwapRecord("0g0", "p", "w", 15, 0),
		cliSwapRecord("0g1", "p", "u", 10, 1),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "archA"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "compare", dir, "1", "0none", "candC")
	if res.exitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	result := parseCompareJSON(t, res.stdout)
	if len(result.OriginalFindings) != 0 || len(result.ComparedFindings) != 0 ||
		len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Fatalf("both sides empty must yield empty lists: %+v", result)
	}
	if len(result.Swaps) != 2 {
		t.Fatalf("full swap records must remain: %+v", result.Swaps)
	}
	// The wire format must be [], never null.
	for _, key := range []string{`"originalFindings":[]`, `"comparedFindings":[]`, `"added":[]`, `"removed":[]`, `"changed":[]`} {
		if !strings.Contains(res.stdout, key) {
			t.Fatalf("stdout missing %s:\n%s", key, res.stdout)
		}
	}
}

func TestCLICompareLegacyArchiveBuiltin(t *testing.T) {
	dir := t.TempDir()
	// Pre-version archive (no version field on the record).
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	const candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(candC)); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "compare", dir, "1", "0old", "candC")
	if res.exitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	result := parseCompareJSON(t, res.stdout)
	if result.OriginalVersion.ID != "builtin" ||
		result.OriginalVersion.Rules.Sandwich.Severity != 3 ||
		result.OriginalVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("legacy record must be explained as builtin: %+v", result.OriginalVersion)
	}
	if len(result.OriginalFindings) != 1 || result.OriginalFindings[0].Kind != "sandwich" {
		t.Fatalf("legacy conclusions damaged: %+v", result.OriginalFindings)
	}
	if len(result.ComparedFindings) != 1 || result.ComparedFindings[0].Kind != "displacement" ||
		result.ComparedFindings[0].Severity != 4 {
		t.Fatalf("candidate re-judgment wrong: %+v", result.ComparedFindings)
	}
}

func TestCLICompareIsReadOnly(t *testing.T) {
	dir := setupCLIArchive(t)
	archivePath := filepath.Join(dir, "archive.json")
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	// Successful comparisons against every block...
	for _, args := range [][]string{
		{"compare", dir, "1", "0xblk", "candC"},
		{"compare", dir, "1", "0xblk", "builtin"},
		{"compare", dir, "1", "0xother", "candC"},
		{"compare", dir, "2", "0xblk", "candC"},
		// ...and every failure shape leave the archive byte-identical.
		{"compare", dir, "1", "0xghost", "candC"},
		{"compare", dir, "1", "0xblk", "ghost"},
	} {
		runCLI(t, args...)
	}

	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("compare modified the archive file")
	}

	// The archived report and the enabled version are both unchanged.
	report, err := mevwatch.Query(dir, "1", "0xblk")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "archA" || len(report.Findings) != 3 {
		t.Fatalf("archived report changed: %+v", report)
	}
	_, enabled, err := mevwatch.ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "liveB" {
		t.Fatalf("enabled version changed to %q", enabled)
	}
}

// corruptStoredVersion rewrites the stored archive document of one
// registered version, simulating an archive that is still valid JSON but
// whose registered version no longer satisfies the registration rules.
func corruptStoredVersion(t *testing.T, dir, id string, mutate func(ver map[string]any)) {
	t.Helper()
	archivePath := filepath.Join(dir, "archive.json")
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc["versions"].([]any) {
		ver := entry.(map[string]any)
		if ver["id"] == id {
			mutate(ver)
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCLICompareCorruptVersion(t *testing.T) {
	dir := setupCLIArchive(t)
	// The stored candC document loses its displacement multiplier: valid
	// JSON, but no longer a complete rule declaration.
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	res := runCLI(t, "compare", dir, "1", "0xblk", "candC")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version must print no success JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}

	// An unregistered version stays a plain unknown-version failure.
	res = runCLI(t, "compare", dir, "1", "0xblk", "nope")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: nope") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// The corrupt sibling does not contaminate intact versions.
	res = runCLI(t, "compare", dir, "1", "0xblk", "builtin")
	if res.exitCode != 0 {
		t.Fatalf("compare under builtin failed: %d %q", res.exitCode, res.stderr)
	}
}

// setupReviewCLIArchive builds an archive with one block carrying a
// sandwich and a displacement, registers a mult3 candidate (multiplier 3
// still flags the displacement at 50 > 30), and stores one false-positive
// review on the displacement. The original block input file is never
// needed by reviews evaluate and is not even created here.
func setupReviewCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0xa", 10,
		cliSwapRecord("0xf", "p1", "bot", 90, 0),
		cliSwapRecord("0xv", "p1", "user", 10, 1),
		cliSwapRecord("0+k", "p1", "bot", 80, 2),
		cliSwapRecord("0+w", "p2", "whale", 50, 3),
		cliSwapRecord("0xd", "p2", "user", 10, 4),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFile(inputPath, dir); err != nil {
		t.Fatalf("ReplayFile: %v", err)
	}
	mult3 := `{"id":"mult3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(mult3)); err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
	sub := mevwatch.ReviewSubmission{
		ChainID: "1", BlockHash: "0xa", TxHash: "0xd", Kind: "displacement",
		SubmissionID: "f-1", Operator: "alice", Reason: "fp",
		Status: mevwatch.ReviewStatusFalsePositive, ExpectedVersion: 0,
	}
	if _, err := mevwatch.SubmitReview(dir, sub); err != nil {
		t.Fatalf("SubmitReview: %v", err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCLIReviewEvaluateCorruptVersion(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	// Damage the stored candidate document: the displacement multiplier
	// vanishes, which previously decoded as zero and sent detection into a
	// zeroed rule.
	corruptStoredVersion(t, dir, "mult3", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "mult3")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version must print no success statistics JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "mult3", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	// The failure must be a clean message, never a panic with a Go stack.
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("evaluation crashed instead of failing cleanly: %q", res.stderr)
	}

	// An unregistered id stays a plain unknown-version failure.
	res = runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "nope")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: nope") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// The corrupt sibling does not contaminate intact versions: builtin
	// still prints its statistics JSON and exits zero.
	res = runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "builtin")
	if res.exitCode != 0 {
		t.Fatalf("evaluate under builtin failed: %d %q", res.exitCode, res.stderr)
	}
	var eval struct {
		StillHit int `json:"stillHit"`
		Pending  int `json:"pending"`
		Version  struct {
			ID string `json:"id"`
		} `json:"version"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &eval); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if eval.Version.ID != "builtin" || eval.StillHit != 1 || eval.Pending != 1 {
		t.Fatalf("builtin evaluation stats wrong: %s", res.stdout)
	}
}

// TestCLIReviewEvaluateCorruptVersionEmptyRange proves the corrupt
// candidate is refused even when the range matches no blocks: the failure
// is about the archived rule version, not about the range contents.
func TestCLIReviewEvaluateCorruptVersionEmptyRange(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	corruptStoredVersion(t, dir, "mult3", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})
	res := runCLI(t, "reviews", "evaluate", dir, "1", "1000", "2000", "mult3")
	if res.exitCode != 1 || res.stdout != "" || !strings.Contains(res.stderr, "corrupt") ||
		!strings.Contains(res.stderr, "mult3") {
		t.Fatalf("empty-range failure shape wrong: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}
}
