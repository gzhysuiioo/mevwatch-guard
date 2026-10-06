package main

// End-to-end regression coverage for the historical side of `compare`
// through the real command entry point (see TestMain): the version
// declaration embedded in the compared archived report must pass the
// same integrity proof a `report` query enforces before any comparison
// JSON is printed. A written null used to be explained as the built-in
// rules and an incomplete declaration used to compare under zeroed
// parameters. On a damaged historical declaration the command exits 1,
// prints nothing on stdout, and names the target chain, block, the
// readable saved version id and the offending rule or field on stderr —
// even for a block with no swaps. Success or failure leaves the
// archive untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// corruptStoredReportVersion rewrites the version declaration embedded
// in one archived record (not the versions-registry entry).
func corruptStoredReportVersion(t *testing.T, dir, chain, hash string, mutate func(rec map[string]any)) {
	t.Helper()
	path := filepath.Join(dir, "archive.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc["records"].([]any) {
		rec := r.(map[string]any)
		if rec["chainId"] == chain && rec["blockHash"] == hash {
			mutate(rec)
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("record %s/%s not found in archive", chain, hash)
}

// TestCLICompareCorruptHistoricalDeclaration pins the CLI failure
// shape for a damaged historical declaration while the candidate
// (candC) stays perfectly legal.
func TestCLICompareCorruptHistoricalDeclaration(t *testing.T) {
	dir := setupCLIArchive(t)

	// The report was archived under archA; drop the displacement
	// multiplier only from its embedded declaration while the
	// registered archA entry and the candC candidate stay intact.
	corruptStoredReportVersion(t, dir, "1", "0xblk", func(rec map[string]any) {
		ver := rec["version"].(map[string]any)
		rules := ver["rules"].(map[string]any)
		disp := rules["displacement"].(map[string]any)
		delete(disp, "multiplier")
	})

	res := runCLI(t, "compare", dir, "1", "0xblk", "candC")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt historical declaration must print no comparison JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"corrupt",      // ErrCorruptVersion
		"chain 1",      // target chain
		"block 0xblk",  // target block
		"archA",        // readable historical version id
		"multiplier",   // offending field
		"displacement", // offending rule
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("compare crashed instead of failing cleanly: %q", res.stderr)
	}

	// A legal candidate can never rescue the historical declaration:
	// the intact builtin and liveB candidates fail the same way.
	for _, candidate := range []string{"builtin", "liveB"} {
		again := runCLI(t, "compare", dir, "1", "0xblk", candidate)
		if again.exitCode != 1 || again.stdout != "" ||
			!strings.Contains(again.stderr, "corrupt") ||
			!strings.Contains(again.stderr, "archA") {
			t.Fatalf("candidate %s must not rescue the corrupt report: exit=%d stdout=%q stderr=%q",
				candidate, again.exitCode, again.stdout, again.stderr)
		}
	}

	// Unknown block and unknown candidate keep their existing error
	// behavior instead of becoming corruption errors.
	missingBlock := runCLI(t, "compare", dir, "1", "0xghost", "candC")
	if missingBlock.exitCode != 1 || !strings.Contains(missingBlock.stderr, "unknown block") ||
		strings.Contains(missingBlock.stderr, "corrupt") {
		t.Fatalf("unknown block failure changed shape: %q", missingBlock.stderr)
	}
	unknownVersion := runCLI(t, "compare", dir, "1", "0xblk", "ghost")
	if unknownVersion.exitCode != 1 || !strings.Contains(unknownVersion.stderr, "corrupt") {
		t.Fatalf("a corrupt historical declaration still fails as corruption against an unknown candidate: %q",
			unknownVersion.stderr)
	}

	// The failed comparison is read-only: report still fails the same
	// way (declaration untouched), and other blocks still compare.
	if report := runCLI(t, "report", dir, "1", "0xblk"); report.exitCode != 1 ||
		!strings.Contains(report.stderr, "corrupt") || report.stdout != "" {
		t.Fatalf("report on the same record must keep failing: exit=%d stdout=%q stderr=%q",
			report.exitCode, report.stdout, report.stderr)
	}
	other := runCLI(t, "compare", dir, "1", "0xother", "candC")
	if other.exitCode != 0 {
		t.Fatalf("an intact other block must still compare: %q", other.stderr)
	}
	_, enabled, err := mevwatch.ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "liveB" {
		t.Fatalf("enabled version changed to %q", enabled)
	}
}

// TestCLICompareNullHistoricalVersionCorrupt pins the exact misread
// being fixed: a written "version":null on the report must fail rather
// than be explained as the built-in rules, even for a no-swap block.
func TestCLICompareNullHistoricalVersionCorrupt(t *testing.T) {
	dir := t.TempDir()
	const candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(candC)); err != nil {
		t.Fatal(err)
	}
	// A block with no swaps: an empty comparison must not skip the proof.
	input := cliBlockLine("1", "0empty", 3, []cliSwap{}...)
	if _, err := mevwatch.ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	corruptStoredReportVersion(t, dir, "1", "0empty", func(rec map[string]any) {
		rec["version"] = nil
	})
	res := runCLI(t, "compare", dir, "1", "0empty", "candC")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("null historical version must print no comparison JSON, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupt") ||
		!strings.Contains(res.stderr, "chain 1") ||
		!strings.Contains(res.stderr, "block 0empty") ||
		!strings.Contains(res.stderr, "null") {
		t.Fatalf("stderr must report a corrupt null declaration naming chain and block: %q", res.stderr)
	}
}

// TestCLICompareLegacyHistoricalVersionStillBuiltin proves the single
// carve-out still works through the CLI: a record with no version key
// compares with the built-in historical side.
func TestCLICompareLegacyHistoricalVersionStillBuiltin(t *testing.T) {
	dir := t.TempDir()
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
		t.Fatalf("legacy record must compare under builtin: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	result := parseCompareJSON(t, res.stdout)
	if result.OriginalVersion.ID != "builtin" ||
		result.OriginalVersion.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("historical side must be builtin: %+v", result.OriginalVersion)
	}
}
