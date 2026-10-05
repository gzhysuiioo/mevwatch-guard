package main

// End-to-end regression coverage for the `replay` command against a
// corrupt archived rule version: the run must refuse the whole import with
// a clean corruption error — naming the version and the offending rule or
// field — before any report is printed or any block is archived, whether
// the version was selected with --version or through the archive's enabled
// marker. A corrupt version is never misreported as unknown, and a corrupt
// sibling never blocks an intact one.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupReplayCLIArchive registers candC (sandwich off, displacement
// severity 4 multiplier 2), archives one block under it and enables it.
func setupReplayCLIArchive(t *testing.T) (dir string) {
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
	if _, err := mevwatch.EnableVersion(dir, "candC"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	return dir
}

// writeReplayInput writes one new block whose two adjacent same-pool swaps
// hit displacement under any intact multiplier — the input shape that
// crashed detection when a stored multiplier decayed to zero.
func writeReplayInput(t *testing.T) string {
	t.Helper()
	inputPath := filepath.Join(t.TempDir(), "new.jsonl")
	if err := os.WriteFile(inputPath, []byte(cliBlockLine("1", "0xnew", 8,
		cliSwapRecord("0xn1", "p1", "w", 40, 0),
		cliSwapRecord("0xn2", "p1", "u", 10, 1),
	)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return inputPath
}

func TestCLIReplayCorruptVersion(t *testing.T) {
	dir := setupReplayCLIArchive(t)
	inputPath := writeReplayInput(t)
	// The stored candC document loses its displacement multiplier: valid
	// JSON, but no longer a complete rule declaration.
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	// Explicit selection refuses the whole import before any report.
	res := runCLI(t, "replay", "--version", "candC", inputPath, dir)
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version must print no report JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	// A clean message, never a panic with a Go stack.
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("replay crashed instead of failing cleanly: %q", res.stderr)
	}

	// The enabled marker selects the same corrupt version for a plain
	// replay: same refusal.
	res = runCLI(t, "replay", inputPath, dir)
	if res.exitCode != 1 || res.stdout != "" ||
		!strings.Contains(res.stderr, "corrupt") || !strings.Contains(res.stderr, "candC") {
		t.Fatalf("enabled-version failure shape wrong: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}

	// An unregistered version stays a plain unknown-version failure.
	res = runCLI(t, "replay", "--version", "nope", inputPath, dir)
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: nope") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// The corrupt sibling does not contaminate the built-in version.
	res = runCLI(t, "replay", "--version", "builtin", inputPath, dir)
	if res.exitCode != 0 {
		t.Fatalf("replay under builtin failed: %d %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"blockHash":"0xnew"`) {
		t.Fatalf("builtin replay must print the new block's report, got %q", res.stdout)
	}

	// The refusals never touched the archive; only the final successful
	// builtin replay appended its block. Verify the corrupt version
	// document survived verbatim instead: no missing field was completed,
	// no bad value fixed, and the enabled marker still names candC.
	var doc struct {
		Versions []struct {
			ID    string `json:"id"`
			Rules struct {
				Displacement map[string]any `json:"displacement"`
			} `json:"rules"`
		} `json:"versions"`
		EnabledVersion string `json:"enabledVersion"`
	}
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.EnabledVersion != "candC" {
		t.Fatalf("enabled marker changed to %q", doc.EnabledVersion)
	}
	for _, v := range doc.Versions {
		if v.ID == "candC" {
			if _, ok := v.Rules.Displacement["multiplier"]; ok {
				t.Fatalf("refused replay repaired the corrupt version: %v", v.Rules.Displacement)
			}
		}
	}
}

// TestCLIReplayCorruptVersionLeavesArchiveUntouched proves the refusal
// itself is not a write: with only refused replays attempted, the archive
// file stays byte-identical, including reports, rules, the enabled marker
// and review history.
func TestCLIReplayCorruptVersionLeavesArchiveUntouched(t *testing.T) {
	dir := setupReplayCLIArchive(t)
	inputPath := writeReplayInput(t)
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})
	archivePath := filepath.Join(dir, "archive.json")
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	// Multiplier zero with displacement enabled and two adjacent same-pool
	// swaps: the exact shape that used to crash detection.
	for _, args := range [][]string{
		{"replay", "--version", "candC", inputPath, dir},
		{"replay", inputPath, dir},
	} {
		res := runCLI(t, args...)
		if res.exitCode != 1 || res.stdout != "" || !strings.Contains(res.stderr, "corrupt") {
			t.Fatalf("args %v: exit=%d stdout=%q stderr=%q", args, res.exitCode, res.stdout, res.stderr)
		}
		if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
			t.Fatalf("args %v crashed: %q", args, res.stderr)
		}
	}

	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("refused replays changed the archive")
	}
	if _, err := mevwatch.Query(dir, "1", "0xnew"); err == nil {
		t.Fatalf("new block archived by a refused replay")
	}
}
