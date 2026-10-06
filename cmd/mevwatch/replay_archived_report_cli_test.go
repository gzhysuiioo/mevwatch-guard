package main

// End-to-end regression coverage for re-importing an already archived
// block whose content is identical but whose saved version declaration has
// decayed. A legal version for the run must not pardon the old report: the
// import exits 1, prints nothing on stdout, and names the input line, the
// target chain and block, the readable saved version id and the offending
// rule or field — never "unknown block" or "unknown version". Any corrupt
// old report fails the whole batch, whether it precedes or follows a new
// block: no report is printed, no new block is archived and the archive is
// untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// corruptStoredReportVersionCLI rewrites the version declaration embedded
// in one archived record (not the same-id registry entry).
func corruptStoredReportVersionCLI(t *testing.T, dir, chain, hash string, mutate func(ver map[string]any)) {
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
			ver := rec["version"].(map[string]any)
			mutate(ver)
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
	t.Fatalf("record %s/%s not found", chain, hash)
}

// identicalArchivedBlockInput is the exact block setupReplayCLIArchive
// archived under candC.
func identicalArchivedBlockInput(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reimport.jsonl")
	line := cliBlockLine("1", "0xblk", 7,
		cliSwapRecord("0xf", "p1", "w", 40, 0),
		cliSwapRecord("0xv", "p1", "u", 10, 1),
	)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCLIReplayCorruptArchivedReport pins the regression end to end: with
// the enabled candC intact for new blocks, the identical reimport of a
// block whose own saved declaration lost its multiplier must still fail.
func TestCLIReplayCorruptArchivedReport(t *testing.T) {
	dir := setupReplayCLIArchive(t)
	inputPath := identicalArchivedBlockInput(t)
	corruptStoredReportVersionCLI(t, dir, "1", "0xblk", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Plain replay: candC is selected (enabled) and its registry document
	// is intact — the legality of the run's own version must not pardon the
	// old report.
	res := runCLI(t, "replay", inputPath, dir)
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("a corrupt old report must print no report JSON, got %q", res.stdout)
	}
	for _, want := range []string{"line 1", "corrupt", "1", "0xblk", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "unknown block") || strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("corrupt old report misreported as unknown: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("replay crashed instead of failing cleanly: %q", res.stderr)
	}

	// Explicit --version candC behaves identically.
	res = runCLI(t, "replay", "--version", "candC", inputPath, dir)
	if res.exitCode != 1 || res.stdout != "" {
		t.Fatalf("explicit-version failure shape wrong: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{"line 1", "corrupt", "0xblk", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}

	// Nothing was written.
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("refused replay changed the archive")
	}
}

// TestCLIReplayCorruptArchivedReportFailsBatch proves the all-or-nothing
// ordering guarantee at the CLI: a corrupt old block fails the batch and
// prints nothing whether it is the first or the second input line, and the
// new block on the other line is never archived.
func TestCLIReplayCorruptArchivedReportFailsBatch(t *testing.T) {
	oldLine := cliBlockLine("1", "0xblk", 7,
		cliSwapRecord("0xf", "p1", "w", 40, 0),
		cliSwapRecord("0xv", "p1", "u", 10, 1),
	)
	newLine := cliBlockLine("1", "0xnew", 8,
		cliSwapRecord("0xn1", "p1", "w", 40, 0),
		cliSwapRecord("0xn2", "p1", "u", 10, 1),
	)
	cases := []struct {
		name string
		file string
		line string
	}{
		{"old then new", oldLine + "\n" + newLine + "\n", "line 1"},
		{"new then old", newLine + "\n" + oldLine + "\n", "line 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupReplayCLIArchive(t)
			corruptStoredReportVersionCLI(t, dir, "1", "0xblk", func(ver map[string]any) {
				delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
			})
			before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
			if err != nil {
				t.Fatal(err)
			}
			inputPath := filepath.Join(t.TempDir(), "batch.jsonl")
			if err := os.WriteFile(inputPath, []byte(tc.file), 0o644); err != nil {
				t.Fatal(err)
			}

			res := runCLI(t, "replay", "--version", "candC", inputPath, dir)
			if res.exitCode != 1 || res.stdout != "" {
				t.Fatalf("exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
			}
			if !strings.Contains(res.stderr, tc.line) {
				t.Fatalf("stderr %q must name %s", res.stderr, tc.line)
			}
			for _, want := range []string{"0xblk", "candC", "multiplier"} {
				if !strings.Contains(res.stderr, want) {
					t.Fatalf("stderr %q must contain %q", res.stderr, want)
				}
			}
			after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("failed batch changed the archive")
			}
			if _, err := os.Stat(filepath.Join(dir, "archive.json")); err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Records []struct {
					BlockHash string `json:"blockHash"`
				} `json:"records"`
			}
			if err := json.Unmarshal(after, &doc); err != nil {
				t.Fatal(err)
			}
			for _, r := range doc.Records {
				if r.BlockHash == "0xnew" {
					t.Fatalf("new block archived by a refused batch")
				}
			}
		})
	}
}

// TestCLIReplayNullVersionArchivedReport proves the precise misread the fix
// targets: "version":null in the old record used to print a report
// explained by the built-in rules. It must now exit 1 with empty stdout,
// naming the chain and block but never the built-in substitution.
func TestCLIReplayNullVersionArchivedReport(t *testing.T) {
	dir := setupReplayCLIArchive(t)
	inputPath := identicalArchivedBlockInput(t)

	// Replace the embedded declaration wholesale with null.
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
		if rec["chainId"] == "1" && rec["blockHash"] == "0xblk" {
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

	res := runCLI(t, "replay", inputPath, dir)
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("null-version old report must print nothing, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupt") || !strings.Contains(res.stderr, "0xblk") ||
		!strings.Contains(res.stderr, "line 1") {
		t.Fatalf("stderr = %q must name the corrupt old report", res.stderr)
	}
	if strings.Contains(res.stderr, "unknown block") || strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("null version misreported as unknown: %q", res.stderr)
	}
}
