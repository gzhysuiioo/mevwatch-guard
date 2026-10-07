package main

// End-to-end regression coverage for `suppressions register` over an archive
// whose stored report carries a decayed rule-version declaration: the whole
// registration must fail with exit code 1, no result JSON on stdout, an
// error naming the chain, block and the problem, and no change to the
// archive — no condition is added and the damaged declaration is left
// exactly as it was. Both intake paths (a spec file and standard input)
// fail identically, and over an intact archive both paths still register.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliRegisterSpec is a legal condition that would cover 0xok but never the
// empty 0xdecayed report — which still has to be opened by the proof.
const cliRegisterSpec = `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"known bot war"}`

// setupCorruptRegisterCLIArchive archives two blocks on chain "1" — 0xok at
// height 10 with a sandwich conclusion, 0xdecayed at height 20 with no
// swaps — then rewrites 0xdecayed's embedded version declaration to null
// and deletes the source input file. No condition is registered beforehand:
// the registration under test would be the archive's first.
func setupCorruptRegisterCLIArchive(t *testing.T) string {
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

// assertRegisterFailure pins the command-level contract shared by both
// intake paths: exit 1, empty stdout, the error naming the corruption and
// the damaged report, and an archive that neither gained the condition nor
// lost the written null.
func assertRegisterFailure(t *testing.T, res cliResult, before []byte, dir string) {
	t.Helper()
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry registration JSON, got %q", res.stdout)
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
		t.Fatal("failed registration changed the archive")
	}
	// The written null survived as a null, not as a dropped version key.
	if !strings.Contains(string(after), `"version": null`) {
		t.Fatal("failed registration rewrote the null declaration")
	}
	// The condition was not added: the list is empty.
	list := runCLI(t, "suppressions", "list", dir)
	if list.exitCode != 0 {
		t.Fatalf("suppressions list exit=%d stderr=%q", list.exitCode, list.stderr)
	}
	if strings.TrimSpace(list.stdout) != "[]" {
		t.Fatalf("failed registration added a condition: %q", list.stdout)
	}
}

// TestCLISuppressionsRegisterCorruptSavedVersionFile exercises the spec-file
// intake: a corrupt archived report makes the whole registration fail with
// exit 1, no JSON on stdout and no archive change.
func TestCLISuppressionsRegisterCorruptSavedVersionFile(t *testing.T) {
	dir := setupCorruptRegisterCLIArchive(t)
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	specPath := filepath.Join(t.TempDir(), "suppression.json")
	if err := os.WriteFile(specPath, []byte(cliRegisterSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "suppressions", "register", dir, specPath)
	assertRegisterFailure(t, res, before, dir)
}

// TestCLISuppressionsRegisterCorruptSavedVersionStdin exercises the standard
// input intake ('-'): the same corruption fails the registration the same
// way.
func TestCLISuppressionsRegisterCorruptSavedVersionStdin(t *testing.T) {
	dir := setupCorruptRegisterCLIArchive(t)
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res := runCLIStdin(t, cliRegisterSpec, "suppressions", "register", dir, "-")
	assertRegisterFailure(t, res, before, dir)
}

// TestCLISuppressionsRegisterIntactArchive pins the unchanged success path
// for both intake paths: a spec file and then standard input each append
// their condition, print created:true with the full condition carrying
// revoked:false, and the second registration of identical content is a
// created:false no-op that leaves the revoked state untouched after a
// revocation.
func TestCLISuppressionsRegisterIntactArchive(t *testing.T) {
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

	// First condition through a spec file.
	specPath := filepath.Join(t.TempDir(), "suppression.json")
	if err := os.WriteFile(specPath, []byte(cliRegisterSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	first := runCLI(t, "suppressions", "register", dir, specPath)
	if first.exitCode != 0 {
		t.Fatalf("file register exit=%d stderr=%q", first.exitCode, first.stderr)
	}
	var out struct {
		Created     bool `json:"created"`
		Suppression struct {
			ID      string `json:"id"`
			Revoked bool   `json:"revoked"`
			Reason  string `json:"reason"`
		} `json:"suppression"`
	}
	if err := json.Unmarshal([]byte(first.stdout), &out); err != nil {
		t.Fatalf("file register output: %v", err)
	}
	if !out.Created || out.Suppression.ID != "s1" || out.Suppression.Revoked ||
		out.Suppression.Reason != "known bot war" {
		t.Fatalf("file register = %q, want created:true with the full condition", first.stdout)
	}

	// An identical retry through standard input is a created:false no-op and
	// never flips revoked.
	again := runCLIStdin(t, cliRegisterSpec, "suppressions", "register", dir, "-")
	if again.exitCode != 0 {
		t.Fatalf("stdin retry exit=%d stderr=%q", again.exitCode, again.stderr)
	}
	if err := json.Unmarshal([]byte(again.stdout), &out); err != nil {
		t.Fatalf("stdin retry output: %v", err)
	}
	if out.Created || out.Suppression.Revoked {
		t.Fatalf("stdin retry = %q, want created:false with revoked:false", again.stdout)
	}

	// Revoke s1, then prove the same-content retry through stdin still does
	// not re-enable it.
	if res := runCLI(t, "suppressions", "revoke", dir, "s1"); res.exitCode != 0 {
		t.Fatalf("revoke exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	afterRevoke := runCLIStdin(t, cliRegisterSpec, "suppressions", "register", dir, "-")
	if afterRevoke.exitCode != 0 {
		t.Fatalf("post-revoke retry exit=%d stderr=%q", afterRevoke.exitCode, afterRevoke.stderr)
	}
	if err := json.Unmarshal([]byte(afterRevoke.stdout), &out); err != nil {
		t.Fatalf("post-revoke retry output: %v", err)
	}
	if out.Created || !out.Suppression.Revoked {
		t.Fatalf("post-revoke retry = %q, want created:false with revoked:true", afterRevoke.stdout)
	}

	// A new condition through standard input is appended.
	secondSpec := `{"id":"s2","chainId":"2","pool":"p2","kind":"displacement","channel":"ops","startHeight":0,"endHeight":9,"reason":"r2"}`
	second := runCLIStdin(t, secondSpec, "suppressions", "register", dir, "-")
	if second.exitCode != 0 {
		t.Fatalf("stdin register exit=%d stderr=%q", second.exitCode, second.stderr)
	}
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
	if len(conds) != 2 || conds[0].ID != "s1" || !conds[0].Revoked ||
		conds[1].ID != "s2" || conds[1].Revoked {
		t.Fatalf("conditions = %q, want revoked s1 and active s2", list.stdout)
	}
}
