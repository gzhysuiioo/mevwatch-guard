package main

// End-to-end regression coverage for corrupt rule-version refusal on the
// `replay` command. The test binary re-executes itself (see TestMain) and
// runs the real main(), exercising argument parsing, exit status, stderr
// wording and stdout exactly as a user does: a corrupt selected version —
// named with --version or taken from the enabled marker — must fail the
// whole replay with exit 1, print no report JSON, name the version and the
// offending field, leave the archive bytes untouched, and never be confused
// with an unknown version or silently replaced by builtin.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

const cliCandCSpec = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`

// cliReplayTrigger is a fresh two-swap block whose front gas (40) dominates
// the victim (10) at multiplier 2; with a decayed zero multiplier the old
// code panicked, so a clean failure here proves the gate runs first.
const cliReplayTrigger = `{"chainId":"1","blockHash":"0xtrig","blockNumber":9,"swaps":[` +
	`{"TxHash":"0xf","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":0},` +
	`{"TxHash":"0xv","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`

// setupReplayCLIArchive registers candC (optionally enabled) and writes an
// input file of the given block lines, returning the archive and input
// paths.
func setupReplayCLIArchive(t *testing.T, enable bool, lines ...string) (dir, inputPath string) {
	t.Helper()
	dir = t.TempDir()
	inputPath = filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(cliCandCSpec)); err != nil {
		t.Fatalf("RegisterVersion: %v", err)
	}
	if enable {
		if _, err := mevwatch.EnableVersion(dir, "candC"); err != nil {
			t.Fatalf("EnableVersion: %v", err)
		}
	}
	return dir, inputPath
}

func assertReplayCorruptFailure(t *testing.T, res cliResult) {
	t.Helper()
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt replay must print no report JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("replay crashed instead of failing cleanly: %q", res.stderr)
	}
}

// TestCLIReplayCorruptExplicitVersion damages the named --version and
// expects the whole run refused with no partial output and no file change.
func TestCLIReplayCorruptExplicitVersion(t *testing.T) {
	dir, inputPath := setupReplayCLIArchive(t, false, cliReplayTrigger)
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "replay", "--version", "candC", inputPath, dir)
	assertReplayCorruptFailure(t, res)

	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("corrupt replay modified the archive file")
	}
}

// TestCLIReplayCorruptEnabledVersion proves a replay with no --version
// re-validates the enabled marker and does not fall back to builtin.
func TestCLIReplayCorruptEnabledVersion(t *testing.T) {
	dir, inputPath := setupReplayCLIArchive(t, true, cliReplayTrigger)
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})

	res := runCLI(t, "replay", inputPath, dir)
	assertReplayCorruptFailure(t, res)

	// Enabled marker unchanged.
	_, enabled, err := mevwatch.ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "candC" {
		t.Fatalf("enabled marker changed to %q on refusal", enabled)
	}
}

// TestCLIReplayCorruptVersionMixedBatch archives an intact block first, then
// offers it again followed by a new block in one file. The corrupt version
// must fail before the new block is reported or written.
func TestCLIReplayCorruptVersionMixedBatch(t *testing.T) {
	dir, inputPath := setupReplayCLIArchive(t, false, cliReplayTrigger)
	// Seed the trigger block while the version is still intact.
	if _, err := mevwatch.ReplayFileWithVersion(inputPath, dir, "candC"); err != nil {
		t.Fatalf("seed replay: %v", err)
	}
	emptyBlock := `{"chainId":"1","blockHash":"0empty","blockNumber":1,"swaps":[]}`
	mixed := filepath.Join(t.TempDir(), "mixed.jsonl")
	if err := os.WriteFile(mixed, []byte(cliReplayTrigger+"\n"+emptyBlock+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = nil
	})

	res := runCLI(t, "replay", "--version", "candC", mixed, dir)
	assertReplayCorruptFailure(t, res)
	if _, err := mevwatch.Query(dir, "1", "0empty"); !errors.Is(err, mevwatch.ErrUnknownBlock) {
		t.Fatalf("new block from refused batch leaked into archive: %v", err)
	}
}

// TestCLIReplayCorruptVersionDistinctFromUnknown keeps unknown-version
// wording separate and shows intact versions still replay.
func TestCLIReplayCorruptVersionDistinctFromUnknown(t *testing.T) {
	dir, inputPath := setupReplayCLIArchive(t, false, cliReplayTrigger)
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	// An unregistered id stays a plain unknown-version failure.
	res := runCLI(t, "replay", "--version", "ghost", inputPath, dir)
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: ghost") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// The corrupt sibling does not contaminate builtin: a real report is
	// printed and the block is archived under builtin.
	res = runCLI(t, "replay", "--version", "builtin", inputPath, dir)
	if res.exitCode != 0 {
		t.Fatalf("replay under builtin failed: %d %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"id":"builtin"`) || !strings.Contains(res.stdout, "displacement") {
		t.Fatalf("builtin replay output wrong: %q", res.stdout)
	}
	r, err := mevwatch.Query(dir, "1", "0xtrig")
	if err != nil || r.Version.ID != "builtin" {
		t.Fatalf("block not archived under builtin: %+v err=%v", r, err)
	}
}
