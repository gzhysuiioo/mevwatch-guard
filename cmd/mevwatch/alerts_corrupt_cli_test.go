package main

// End-to-end regression coverage for `alerts generate` over an archive
// whose stored report carries a decayed rule-version declaration: the
// whole generation must fail with exit code 1, no processing-record JSON
// on stdout, an error naming the chain, block, readable version id and
// offending rule or field, and no change to the archive — even when the
// decayed report has no conclusions in range and another block's
// conclusions would have produced records.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupCorruptVersionCLIArchive archives two blocks on chain "1" — 0xok at
// height 10 with a sandwich conclusion, 0xdecayed at height 20 with no
// swaps — then rewrites 0xdecayed's embedded version declaration to null and
// deletes the source input file.
func setupCorruptVersionCLIArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	lines := cliBlockLine("1", "0xok", 10,
		cliSwapRecord("0xf", "p1", "bot", 90, 0),
		cliSwapRecord("0xv", "p1", "user", 10, 1),
		cliSwapRecord("0+k", "p1", "bot", 80, 2),
	) + "\n" + `{"chainId":"1","blockHash":"0xdecayed","blockNumber":20,"swaps":[]}` + "\n"
	if err := os.WriteFile(inputPath, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "replay", inputPath, dir); res.exitCode != 0 {
		t.Fatalf("replay exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}

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
		if rec["blockHash"] == "0xdecayed" {
			rec["version"] = nil
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCLIAlertsGenerateCorruptSavedVersion pins the command-level
// contract: exit code 1, no JSON on stdout, the error naming chain, block
// and the problem, and the archive — reports and processing records —
// unchanged.
func TestCLIAlertsGenerateCorruptSavedVersion(t *testing.T) {
	dir := setupCorruptVersionCLIArchive(t)
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry processing-record JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupted", "1", "0xdecayed"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr %q must name %q", res.stderr, want)
		}
	}

	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed generation changed the archive")
	}

	// The intact block's conclusion was not processed either: a later
	// history query over the whole range is empty.
	hist := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if hist.exitCode != 0 {
		t.Fatalf("alerts history exit=%d stderr=%q", hist.exitCode, hist.stderr)
	}
	if strings.TrimSpace(hist.stdout) != "[]" {
		t.Fatalf("history = %q, want [] (nothing committed by the failed run)", hist.stdout)
	}
}
