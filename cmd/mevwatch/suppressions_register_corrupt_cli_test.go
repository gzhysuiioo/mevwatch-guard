package main

// End-to-end regression coverage for `suppressions register` over an
// archive whose stored report carries a decayed rule-version declaration:
// the whole registration must fail with exit code 1, no result JSON on
// stdout, an error naming the chain, block and the problem, and no change
// to the archive — no new condition and the damaged declaration left
// exactly as it was. Both the spec-file and standard-input entry points
// share the proof; an intact archive keeps the normal created result.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliRegisterCorruptSpec is a legal, not-yet-registered condition. It names
// chain 1 and covers both archived blocks, so the refusal cannot come from
// the condition ignoring them — it comes from the decayed declaration.
const cliRegisterCorruptSpec = `{"id":"s2","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"new window"}`

// assertCLIRegisterRefused runs one register invocation and pins the
// command-level contract: exit 1, empty stdout, stderr naming the damaged
// report's chain and block, the archive byte-identical afterwards and the
// submitted id absent from the condition list.
func assertCLIRegisterRefused(t *testing.T, res cliResult, dir, id string) {
	t.Helper()
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry a registration result, got %q", res.stdout)
	}
	for _, want := range []string{"corrupted", "1", "0xdecayed"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr %q must name %q", res.stderr, want)
		}
	}
	list := runCLI(t, "suppressions", "list", dir)
	if list.exitCode != 0 {
		t.Fatalf("suppressions list exit=%d stderr=%q", list.exitCode, list.stderr)
	}
	var conds []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(list.stdout), &conds); err != nil {
		t.Fatalf("list output: %v", err)
	}
	for _, c := range conds {
		if c.ID == id {
			t.Fatalf("failed registration left condition %q in the archive", id)
		}
	}
}

// TestCLISuppressionsRegisterCorruptSavedVersion drives both spec entry
// points over an archive carrying a version:null report and proves the
// refusal contract and that the written null survives the failed command.
func TestCLISuppressionsRegisterCorruptSavedVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, dir, spec string) cliResult
	}{
		{"from spec file", func(t *testing.T, dir, spec string) cliResult {
			specPath := filepath.Join(t.TempDir(), "suppression.json")
			if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
				t.Fatal(err)
			}
			return runCLI(t, "suppressions", "register", dir, specPath)
		}},
		{"from stdin", func(t *testing.T, dir, spec string) cliResult {
			return runCLIStdin(t, spec, "suppressions", "register", dir, "-")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptRevokeCLIArchive(t)
			before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
			if err != nil {
				t.Fatal(err)
			}

			res := tc.run(t, dir, cliRegisterCorruptSpec)
			assertCLIRegisterRefused(t, res, dir, "s2")

			after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("failed registration changed the archive")
			}
			// The written null survived as a null, not as a dropped version
			// key a later report query would explain as built-in.
			if !strings.Contains(string(after), `"version": null`) {
				t.Fatal("failed registration rewrote the null declaration")
			}
			// The existing condition was not altered either.
			if !strings.Contains(string(after), `"s1"`) {
				t.Fatal("failed registration altered the existing condition")
			}
		})
	}
}

// TestCLISuppressionsRegisterIntactArchive pins the unchanged success path:
// a first registration prints created:true with the full condition carrying
// revoked:false, an identical retry prints created:false, and a revoked
// condition's same-spec retry still reports created:false without
// re-enabling it.
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
	specPath := filepath.Join(t.TempDir(), "suppression.json")
	if err := os.WriteFile(specPath, []byte(cliRegisterCorruptSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	first := runCLI(t, "suppressions", "register", dir, specPath)
	if first.exitCode != 0 {
		t.Fatalf("first register exit=%d stderr=%q", first.exitCode, first.stderr)
	}
	var out struct {
		Created     bool `json:"created"`
		Suppression struct {
			ID      string `json:"id"`
			Reason  string `json:"reason"`
			Revoked bool   `json:"revoked"`
		} `json:"suppression"`
	}
	if err := json.Unmarshal([]byte(first.stdout), &out); err != nil {
		t.Fatalf("first register output: %v", err)
	}
	if !out.Created || out.Suppression.ID != "s2" || out.Suppression.Revoked ||
		out.Suppression.Reason != "new window" {
		t.Fatalf("first register = %q, want created:true with the full condition", first.stdout)
	}

	again := runCLIStdin(t, cliRegisterCorruptSpec, "suppressions", "register", dir, "-")
	if again.exitCode != 0 {
		t.Fatalf("identical retry exit=%d stderr=%q", again.exitCode, again.stderr)
	}
	if err := json.Unmarshal([]byte(again.stdout), &out); err != nil {
		t.Fatalf("retry output: %v", err)
	}
	if out.Created {
		t.Fatalf("identical retry = %q, want created:false", again.stdout)
	}

	// Revoke it, then retry the same document: still created:false and the
	// condition stays revoked.
	if rev := runCLI(t, "suppressions", "revoke", dir, "s2"); rev.exitCode != 0 {
		t.Fatalf("revoke exit=%d stderr=%q", rev.exitCode, rev.stderr)
	}
	retry := runCLI(t, "suppressions", "register", dir, specPath)
	if retry.exitCode != 0 {
		t.Fatalf("post-revoke retry exit=%d stderr=%q", retry.exitCode, retry.stderr)
	}
	if err := json.Unmarshal([]byte(retry.stdout), &out); err != nil {
		t.Fatalf("post-revoke retry output: %v", err)
	}
	if out.Created || !out.Suppression.Revoked {
		t.Fatalf("post-revoke retry = %q, want created:false with revoked:true", retry.stdout)
	}
}
