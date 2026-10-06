package main

// End-to-end regression coverage for `alerts generate` when an archived
// report in range carries a decayed rule-version declaration. Generation
// must fail as a command error: exit code 1, no processing-record JSON on
// stdout, and an stderr message naming the chain, the block, the readable
// saved version id and the offending rule or field. The failure is
// all-or-nothing — no record is created for any other in-range block,
// earlier processing records and suppression conditions survive, and the
// archive file is left byte-identical. A damaged report outside the
// requested range is never judged and does not block healthy reports.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// patchCLIReportVersion rewrites the embedded version declaration of one
// archived record through mutate (the archive is decoded into generic maps
// because this external-package test has no access to the package's
// internal corrupt-archive helpers).
func patchCLIReportVersion(t *testing.T, dir, chain, hash string, mutate func(ver map[string]any)) {
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
		if rec["chainId"] != chain || rec["blockHash"] != hash {
			continue
		}
		ver, ok := rec["version"].(map[string]any)
		if !ok {
			t.Fatalf("record %s/%s has no object version to rewrite: %v", chain, hash, rec["version"])
		}
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
	t.Fatalf("record %s/%s not found in archive", chain, hash)
}

// replaceCLIReportVersion replaces the embedded version declaration of one
// archived record wholesale (used for null and rebuilt documents).
func replaceCLIReportVersion(t *testing.T, dir, chain, hash string, value any) {
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
			rec["version"] = value
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

// builtinFullVersion is a complete self-contained built-in-id declaration.
var builtinFullVersion = map[string]any{
	"id": "builtin",
	"rules": map[string]any{
		"sandwich":     map[string]any{"enabled": true, "severity": 3},
		"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
	},
}

// TestCLIAlertsGenerateCorruptVersion is the main failure scenario: after
// one successful generation, the in-range report loses its displacement
// multiplier. The next run must exit 1 with no stdout JSON and a message
// naming the chain, block, saved id and offending field; it must not store
// the still-pending displacement nor touch the existing sandwich record or
// the archive bytes. Restoring the declaration then backfills normally.
func TestCLIAlertsGenerateCorruptVersion(t *testing.T) {
	dir := setupAlertsCLIArchive(t)

	// One successful run first, so the failure below has an existing
	// processing record to protect and the displacement stays pending.
	res := generateAlertsCLI(t, dir, "3")
	if got := parseAlertRecords(t, res.stdout); len(got) != 1 || got[0].Finding.Kind != "sandwich" {
		t.Fatalf("precondition: first run = %s", res.stdout)
	}

	// The saved built-in-id declaration loses its displacement multiplier.
	patchCLIReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res = runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("a failed generation must print no processing-record JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"alerts generate",
		"archived rule version is corrupted",
		"chain 1", "block 0xa", "builtin", "multiplier",
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}

	// No write happened: the archive is byte-identical, and history still
	// holds exactly the earlier sandwich record.
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed generation changed the archive")
	}
	res = runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if res.exitCode != 0 {
		t.Fatalf("history: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseAlertRecords(t, res.stdout)
	if len(hist) != 1 || hist[0].Finding.Kind != "sandwich" || hist[0].MinSeverity != 3 {
		t.Fatalf("existing processing record damaged: %+v", hist)
	}

	// Restoring the complete declaration makes the pending displacement
	// backfill exactly once — the refusal left no partial state behind.
	replaceCLIReportVersion(t, dir, "1", "0xa", builtinFullVersion)
	res = generateAlertsCLI(t, dir, "1")
	backfill := parseAlertRecords(t, res.stdout)
	if len(backfill) != 1 || backfill[0].Finding.Kind != "displacement" {
		t.Fatalf("post-repair backfill wrong: %s", res.stdout)
	}
}

// TestCLIAlertsGenerateNullVersionCorrupt covers the headline misread: a
// declaration saved as null once decoded into the built-in rules. It must
// now fail with exit 1 and no stdout, naming the chain and block.
func TestCLIAlertsGenerateNullVersionCorrupt(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	replaceCLIReportVersion(t, dir, "1", "0xa", nil)

	res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("failed generation printed records: %q", res.stdout)
	}
	for _, want := range []string{"alerts generate", "archived rule version is corrupted", "chain 1", "block 0xa"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	// No record was stored despite the run failing.
	res = runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if strings.TrimSpace(res.stdout) != "[]" {
		t.Fatalf("failed generation stored records: %q", res.stdout)
	}
}

// TestCLIAlertsGenerateCorruptReportAllOrNothing puts a healthy second
// block next to the damaged one: the run must not partially succeed by
// processing just the healthy block. A narrow range covering only the
// healthy block still succeeds, since out-of-range damage is never judged.
func TestCLIAlertsGenerateCorruptReportAllOrNothing(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	second := cliBlockLine("1", "0xb", 11,
		alertSwap("0xf2", "p1", "w", 1, 1, 40, 0),
		alertSwap("0xd2", "p1", "u", 1, 1, 10, 1),
	)
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(inputPath, []byte(second+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "replay", inputPath, dir)
	if res.exitCode != 0 {
		t.Fatalf("replay second block: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// Damage only the height-10 report.
	patchCLIReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})

	// Whole range: all-or-nothing failure, no record for the healthy 0xb.
	res = runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q", res.exitCode, res.stdout)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("failed run printed records: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "block 0xa") {
		t.Fatalf("stderr must name the damaged block, got %q", res.stderr)
	}
	res = runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if strings.TrimSpace(res.stdout) != "[]" {
		t.Fatalf("healthy block was partially processed: %q", res.stdout)
	}

	// Narrow range over only the healthy block at height 11 succeeds.
	res = runCLI(t, "alerts", "generate", dir, "1", "11", "11", "1", "ops")
	if res.exitCode != 0 {
		t.Fatalf("healthy narrow range: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	healthy := parseAlertRecords(t, res.stdout)
	if len(healthy) != 1 || healthy[0].BlockHash != "0xb" {
		t.Fatalf("healthy narrow range produced %+v", healthy)
	}
}
