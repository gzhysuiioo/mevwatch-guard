package main

// End-to-end regression coverage for the `report` command. The forked CLI
// runs the real main(), so these tests pin argument parsing, exit status,
// stderr wording and the exact stdout JSON exactly as a user sees them:
//
//   - a healthy report prints the archived identity, height, swap count,
//     the original conclusions with all swap evidence and the parameters
//     the report archived (never the currently enabled version), with no
//     re-detection;
//   - before any report is printed, the saved version declaration is
//     re-validated: version:null, an empty/incomplete object or a damaged
//     "builtin" declaration fails with exit code 1, no report JSON on
//     stdout, and a stderr that names the target chain and block, the
//     readable saved version id and the offending rule or field — it is
//     never reported as an unknown block/version or shown zero-filled;
//   - an old-format record with no version key still prints under the
//     built-in rules;
//   - a never-archived block keeps the unknown-block failure;
//   - the whole query is read-only.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupReportCLIArchive registers two complete versions, archives one
// block under v1 (a displacement the enabled v2 would judge differently),
// then enables v2 and deletes the source input file.
func setupReportCLIArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	const (
		v1 = `{"id":"v1","rules":{"sandwich":{"enabled":true,"severity":4},"displacement":{"enabled":true,"severity":3,"multiplier":3}}}`
		v2 = `{"id":"v2","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":5,"multiplier":4}}}`
	)
	for _, spec := range []string{v1, v2} {
		if _, _, err := mevwatch.RegisterVersion(dir, []byte(spec)); err != nil {
			t.Fatalf("RegisterVersion: %v", err)
		}
	}
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	// 40 > 3*10 flags displacement sev3 under v1.
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0xrep", 77,
		cliSwapRecord("0xf", "p1", "w", 40, 0),
		cliSwapRecord("0xv", "p1", "u", 10, 1),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "v1"); err != nil {
		t.Fatalf("ReplayFileWithVersion: %v", err)
	}
	if _, err := mevwatch.EnableVersion(dir, "v2"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func parseReportJSON(t *testing.T, raw string) mevwatch.Report {
	t.Helper()
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("stdout is not valid report JSON: %v\n%s", err, raw)
	}
	return report
}

func TestCLIReportSuccessUsesSavedParameters(t *testing.T) {
	dir := setupReportCLIArchive(t)

	res := runCLI(t, "report", dir, "1", "0xrep")
	if res.exitCode != 0 {
		t.Fatalf("exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if strings.TrimSpace(res.stderr) != "" {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
	if !strings.HasSuffix(res.stdout, "}\n") {
		t.Fatalf("stdout shape wrong: %q", res.stdout)
	}
	report := parseReportJSON(t, res.stdout)

	// Identity, height and the deduplicated swap count.
	if report.ChainID != "1" || report.BlockHash != "0xrep" || report.BlockNumber != 77 ||
		report.SwapCount != 2 {
		t.Fatalf("block identity/height/swap count wrong: %+v", report)
	}
	// The report keeps the v1 parameters it archived even though v2 is now
	// enabled; nothing is re-detected or borrowed from the enabled version.
	if report.Version.ID != "v1" ||
		report.Version.Rules.Sandwich.Severity != 4 ||
		report.Version.Rules.Displacement.Severity != 3 ||
		report.Version.Rules.Displacement.Multiplier != 3 {
		t.Fatalf("report must use its saved v1 parameters, got %+v", report.Version)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "displacement" ||
		report.Findings[0].Severity != 3 || report.Findings[0].TxHash != "0xv" {
		t.Fatalf("archived conclusion damaged: %+v", report.Findings)
	}
	if len(report.Findings[0].Evidence) != 2 ||
		report.Findings[0].Evidence[0] != (mevwatch.Swap{TxHash: "0xf", Pool: "p1", Trader: "w", In: 1, Out: 1, GasPrice: 40, Index: 0}) {
		t.Fatalf("raw swap evidence damaged: %+v", report.Findings[0].Evidence)
	}

	// Repeated offline queries are identical.
	again := runCLI(t, "report", dir, "1", "0xrep")
	if again.exitCode != 0 || again.stdout != res.stdout {
		t.Fatalf("report output not deterministic: %q vs %q", again.stdout, res.stdout)
	}
}

// corruptStoredReport mutates the version declaration embedded in the
// archived record (not the versions registry) of one block.
func corruptStoredReport(t *testing.T, dir, chain, hash string, mutate func(ver map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
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
			mutate(rec["version"].(map[string]any))
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "archive.json"), out, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("record %s/%s not found", chain, hash)
}

// replaceStoredReport replaces the embedded version declaration of one
// record wholesale (nil -> JSON null).
func replaceStoredReport(t *testing.T, dir, chain, hash string, value any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
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
			rec["version"] = value
			out, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "archive.json"), out, 0o644); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("record %s/%s not found", chain, hash)
}

func TestCLIReportCorruptSavedVersion(t *testing.T) {
	dir := setupReportCLIArchive(t)
	// The saved v1 declaration loses its displacement multiplier: valid
	// JSON, but no longer a complete declaration.
	corruptStoredReport(t, dir, "1", "0xrep", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	archivePath := filepath.Join(dir, "archive.json")
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "report", dir, "1", "0xrep")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("a corrupt report must print no report JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "1", "0xrep", "v1", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	// A clean message, never a Go panic stack.
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("report crashed instead of failing cleanly: %q", res.stderr)
	}
	// Read-only even on failure.
	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed report changed the archive")
	}
}

func TestCLIReportNullAndEmptyAndBuiltinDeclarations(t *testing.T) {
	cases := []struct {
		name    string
		replace bool
		value   any
		wantID  string
	}{
		{"null declaration", true, nil, ""},
		{"empty object", true, map[string]any{}, ""},
		{"builtin id with missing multiplier", true, map[string]any{
			"id": "builtin",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2},
			},
		}, "builtin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupReportCLIArchive(t)
			replaceStoredReport(t, dir, "1", "0xrep", tc.value)
			res := runCLI(t, "report", dir, "1", "0xrep")
			if res.exitCode != 1 || res.stdout != "" {
				t.Fatalf("exit=%d stdout=%q, want exit 1 with no JSON; stderr=%q",
					res.exitCode, res.stdout, res.stderr)
			}
			for _, want := range append([]string{"corrupt", "1", "0xrep"}, tc.wantID) {
				if want == "" {
					continue
				}
				if !strings.Contains(res.stderr, want) {
					t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
				}
			}
		})
	}
}

func TestCLIReportLegacyAbsentVersionUsesBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "report", dir, "1", "0old")
	if res.exitCode != 0 {
		t.Fatalf("legacy report failed: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	report := parseReportJSON(t, res.stdout)
	if report.Version.ID != "builtin" || report.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("legacy record must be explained as builtin: %+v", report.Version)
	}
	if report.SwapCount != 3 || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "sandwich" || len(report.Findings[0].Evidence) != 3 {
		t.Fatalf("legacy identity/findings/evidence damaged: %+v", report)
	}
}

func TestCLIReportFailures(t *testing.T) {
	dir := setupReportCLIArchive(t)

	cases := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"unknown block", []string{"report", dir, "1", "0xghost"}, 1, "unknown block"},
		{"unknown chain", []string{"report", dir, "9", "0xrep"}, 1, "unknown block"},
		{"missing archive dir", []string{"report", filepath.Join(dir, "missing"), "1", "0xrep"}, 1, "unknown block"},
		{"too few args", []string{"report", dir, "1"}, 2, "usage: mevwatch report"},
		{"too many args", []string{"report", dir, "1", "0xrep", "extra"}, 2, "usage: mevwatch report"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, tc.args...)
			if res.exitCode != tc.wantCode {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q",
					res.exitCode, tc.wantCode, res.stdout, res.stderr)
			}
			if res.stdout != "" {
				t.Fatalf("failure must print no JSON, got %q", res.stdout)
			}
			if !strings.Contains(res.stderr, tc.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", res.stderr, tc.wantErr)
			}
		})
	}
}

func TestCLIReportCorruptRecordDoesNotAffectOthers(t *testing.T) {
	// A second, healthy block in the same archive must still report while
	// the corrupt block refuses, and neither query writes anything.
	dir := setupReportCLIArchive(t)
	inputPath := filepath.Join(t.TempDir(), "more.jsonl")
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0xok", 88,
		cliSwapRecord("0g0", "p", "w", 1, 0),
		cliSwapRecord("0g1", "p", "u", 1, 1),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "v1"); err != nil {
		t.Fatalf("ReplayFileWithVersion: %v", err)
	}
	corruptStoredReport(t, dir, "1", "0xrep", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	bad := runCLI(t, "report", dir, "1", "0xrep")
	if bad.exitCode != 1 || bad.stdout != "" || !strings.Contains(bad.stderr, "corrupt") ||
		!strings.Contains(bad.stderr, "v1") || !strings.Contains(bad.stderr, "multiplier") {
		t.Fatalf("corrupt block failure shape wrong: exit=%d stdout=%q stderr=%q",
			bad.exitCode, bad.stdout, bad.stderr)
	}
	good := runCLI(t, "report", dir, "1", "0xok")
	if good.exitCode != 0 {
		t.Fatalf("the healthy sibling block must still report: %q", good.stderr)
	}
	report := parseReportJSON(t, good.stdout)
	if report.BlockHash != "0xok" || report.Version.ID != "v1" {
		t.Fatalf("healthy sibling report wrong: %+v", report)
	}
	// An absent block in the same archive stays an unknown-block error.
	missing := runCLI(t, "report", dir, "1", "0xabsent")
	if missing.exitCode != 1 || !strings.Contains(missing.stderr, "unknown block") {
		t.Fatalf("unknown block shape wrong: exit=%d stderr=%q", missing.exitCode, missing.stderr)
	}

	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("report queries rewrote the archive")
	}
}
