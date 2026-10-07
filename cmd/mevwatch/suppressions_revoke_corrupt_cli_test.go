package main

// End-to-end regression coverage for `suppressions revoke` over an archive
// whose stored report carries a decayed rule-version declaration: the
// whole revocation must fail with exit code 1, no result JSON on stdout,
// an error naming the chain, block and the problem, and no change to the
// archive — the target condition keeps its revoked:false state and the
// damaged declaration is left exactly as it was.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupCorruptRevokeCLIArchive archives two blocks on chain "1" — 0xok at
// height 10 with a sandwich conclusion, 0xdecayed at height 20 with no
// swaps — registers suppression condition s1, then rewrites 0xdecayed's
// embedded version declaration to null and deletes the source input file.
func setupCorruptRevokeCLIArchive(t *testing.T) string {
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
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"known bot war"}`
	if res := runCLIStdin(t, spec, "suppressions", "register", dir, "-"); res.exitCode != 0 {
		t.Fatalf("suppressions register exit=%d stderr=%q", res.exitCode, res.stderr)
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

// TestCLISuppressionsRevokeCorruptSavedVersion pins the command-level
// contract: exit code 1, no JSON on stdout, the error naming chain, block
// and the problem, and the archive — reports, the damaged declaration and
// the condition's revoked state — unchanged.
func TestCLISuppressionsRevokeCorruptSavedVersion(t *testing.T) {
	dir := setupCorruptRevokeCLIArchive(t)
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "suppressions", "revoke", dir, "s1")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry revocation JSON, got %q", res.stdout)
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
		t.Fatal("failed revocation changed the archive")
	}
	// The written null survived as a null, not as a dropped version key.
	if !strings.Contains(string(after), `"version": null`) {
		t.Fatal("failed revocation rewrote the null declaration")
	}
	// The condition was not revoked: a later list still shows revoked:false.
	list := runCLI(t, "suppressions", "list", dir)
	if list.exitCode != 0 {
		t.Fatalf("suppressions list exit=%d stderr=%q", list.exitCode, list.stderr)
	}
	var conds []struct {
		ID      string `json:"id"`
		Revoked bool   `json:"revoked"`
	}
	if err := json.Unmarshal([]byte(list.stdout), &conds); err != nil {
		t.Fatalf("list output: %v", err)
	}
	if len(conds) != 1 || conds[0].ID != "s1" || conds[0].Revoked {
		t.Fatalf("failed revocation changed the condition state: %q", list.stdout)
	}
}

// TestCLISuppressionsRevokeIntactArchive pins the unchanged success path
// over an archive with reports: the first revoke prints changed:true with
// the full condition carrying revoked:true, the second changed:false.
func TestCLISuppressionsRevokeIntactArchive(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	lines := cliBlockLine("1", "0xok", 10,
		cliSwapRecord("0xf", "p1", "bot", 90, 0),
		cliSwapRecord("0xv", "p1", "user", 10, 1),
		cliSwapRecord("0+k", "p1", "bot", 80, 2),
	) + "\n"
	if err := os.WriteFile(inputPath, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "replay", inputPath, dir); res.exitCode != 0 {
		t.Fatalf("replay exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"known bot war"}`
	if res := runCLIStdin(t, spec, "suppressions", "register", dir, "-"); res.exitCode != 0 {
		t.Fatalf("suppressions register exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	first := runCLI(t, "suppressions", "revoke", dir, "s1")
	if first.exitCode != 0 {
		t.Fatalf("first revoke exit=%d stderr=%q", first.exitCode, first.stderr)
	}
	var out struct {
		Changed     bool `json:"changed"`
		Suppression struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
			Reason  string `json:"reason"`
		} `json:"suppression"`
	}
	if err := json.Unmarshal([]byte(first.stdout), &out); err != nil {
		t.Fatalf("first revoke output: %v", err)
	}
	if !out.Changed || out.Suppression.ID != "s1" || !out.Suppression.Revoked ||
		out.Suppression.Reason != "known bot war" {
		t.Fatalf("first revoke = %q, want changed:true with the full revoked condition", first.stdout)
	}

	again := runCLI(t, "suppressions", "revoke", dir, "s1")
	if again.exitCode != 0 {
		t.Fatalf("second revoke exit=%d stderr=%q", again.exitCode, again.stderr)
	}
	out = struct {
		Changed     bool `json:"changed"`
		Suppression struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
			Reason  string `json:"reason"`
		} `json:"suppression"`
	}{}
	if err := json.Unmarshal([]byte(again.stdout), &out); err != nil {
		t.Fatalf("second revoke output: %v", err)
	}
	if out.Changed || !out.Suppression.Revoked {
		t.Fatalf("second revoke = %q, want changed:false with revoked:true", again.stdout)
	}
}
