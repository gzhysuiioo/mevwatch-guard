package main

// End-to-end regression coverage for the `report` command against an
// archived record whose stored version declaration no longer satisfies the
// registration rules: the query must fail with exit code 1, print no
// report JSON on stdout, and name the chain, the block, the offending rule
// or field and — whenever the stored document still carries a readable one
// — the version id, never misreporting corruption as an unknown version.
// A record with no version field at all keeps the legacy built-in
// interpretation, and the archive is byte for byte untouched whether the
// query succeeds or fails.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupReportCLIArchive registers candC (sandwich off, displacement
// severity 4 multiplier 2) and archives one block under it.
func setupReportCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	const candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(candC)); err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0xblk", 7,
		cliSwapRecord("0xf", "p1", "w", 40, 0),
		cliSwapRecord("0xv", "p1", "u", 10, 1),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "candC"); err != nil {
		t.Fatalf("ReplayFileWithVersion: %v", err)
	}
	return dir
}

// corruptStoredRecordVersion rewrites the stored version document of one
// archived record through mutate, simulating an archive whose record
// declaration decayed while the file stays valid JSON.
func corruptStoredRecordVersion(t *testing.T, dir, chainID, blockHash string, mutate func(rec map[string]any)) {
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
	records, ok := doc["records"].([]any)
	if !ok {
		t.Fatalf("no records array in archive: %s", raw)
	}
	found := false
	for _, entry := range records {
		rec, ok := entry.(map[string]any)
		if !ok || rec["chainId"] != chainID || rec["blockHash"] != blockHash {
			continue
		}
		mutate(rec)
		found = true
	}
	if !found {
		t.Fatalf("record %s/%s not archived", chainID, blockHash)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCLIReportCorruptRecordVersion(t *testing.T) {
	dir := setupReportCLIArchive(t)
	// The record's stored version loses its displacement multiplier: valid
	// JSON, but no longer a complete rule declaration.
	corruptStoredRecordVersion(t, dir, "1", "0xblk", func(rec map[string]any) {
		delete(rec["version"].(map[string]any)["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	archivePath := filepath.Join(dir, "archive.json")
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "report", dir, "1", "0xblk")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt record version must print no report JSON, got %q", res.stdout)
	}
	// The message names the chain, the block, the stored version id and the
	// offending field — and never calls the corruption an unknown version.
	for _, want := range []string{"corrupt", "1", "0xblk", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("corruption misreported as unknown version: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("report crashed instead of failing cleanly: %q", res.stderr)
	}

	// An unknown block keeps its own error shape.
	res = runCLI(t, "report", dir, "1", "0xghost")
	if res.exitCode != 1 || res.stdout != "" || !strings.Contains(res.stderr, "unknown block") {
		t.Fatalf("unknown block failure changed shape: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}

	// The failures never touched the archive.
	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed report queries changed the archive")
	}
}

// TestCLIReportRecordVersionNull pins the boundary between legacy and
// corrupt: an explicit "version":null on the record is damage, not the
// pre-version built-in interpretation, and the message cannot name a
// version id the document does not carry.
func TestCLIReportRecordVersionNull(t *testing.T) {
	dir := setupReportCLIArchive(t)
	corruptStoredRecordVersion(t, dir, "1", "0xblk", func(rec map[string]any) {
		rec["version"] = nil
	})

	res := runCLI(t, "report", dir, "1", "0xblk")
	if res.exitCode != 1 || res.stdout != "" {
		t.Fatalf("exit=%d stdout=%q, want a clean refusal", res.exitCode, res.stdout)
	}
	for _, want := range []string{"corrupt", "1", "0xblk", "null"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "unknown version") || strings.Contains(res.stderr, "candC") {
		t.Fatalf("null version misreported: %q", res.stderr)
	}
}

// TestCLIReportIntactAndLegacy covers the successful shapes: a record with
// an intact saved declaration prints its report with its own parameters,
// and a pre-version record with no version field at all is still explained
// as the built-in rules.
func TestCLIReportIntactAndLegacy(t *testing.T) {
	dir := setupReportCLIArchive(t)
	res := runCLI(t, "report", dir, "1", "0xblk")
	if res.exitCode != 0 {
		t.Fatalf("report failed: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("report stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if report.ChainID != "1" || report.BlockHash != "0xblk" || report.BlockNumber != 7 ||
		report.SwapCount != 2 {
		t.Fatalf("block identity wrong: %+v", report)
	}
	if report.Version.ID != "candC" || report.Version.Rules.Sandwich.Enabled ||
		report.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("report does not carry its own saved parameters: %+v", report.Version)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "displacement" ||
		report.Findings[0].Severity != 4 || report.Findings[0].TxHash != "0xv" {
		t.Fatalf("archived conclusions damaged: %+v", report.Findings)
	}

	// A pre-version archive: the record carries no version field at all.
	legacyDir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1}],` +
		`"findings":[{"kind":"displacement","severity":2,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1}]}]}]}`
	if err := os.WriteFile(filepath.Join(legacyDir, "archive.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	res = runCLI(t, "report", legacyDir, "1", "0old")
	if res.exitCode != 0 {
		t.Fatalf("legacy report failed: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	var legacyReport mevwatch.Report
	if err := json.Unmarshal([]byte(res.stdout), &legacyReport); err != nil {
		t.Fatalf("legacy report stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if legacyReport.Version.ID != "builtin" ||
		legacyReport.Version.Rules.Displacement.Multiplier != 2 ||
		legacyReport.Version.Rules.Sandwich.Severity != 3 {
		t.Fatalf("legacy record must be explained as builtin: %+v", legacyReport.Version)
	}
}
