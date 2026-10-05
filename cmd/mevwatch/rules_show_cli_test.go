package main

// End-to-end regression coverage for the `rules show` command entry point
// against a registered version whose stored archive document has decayed.
// A corrupt declaration must fail the command with a non-zero exit and no
// parameter object on stdout — never a silently zeroed or defaulted
// parameter set — while an intact version keeps its exact JSON shape.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const showStrictSpec = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`

// registerViaCLI registers spec in dir through the real CLI and requires
// success.
func registerViaCLI(t *testing.T, dir, spec string) {
	t.Helper()
	specFile := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(specFile, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "rules", "register", dir, specFile)
	if res.exitCode != 0 {
		t.Fatalf("rules register failed: exit=%d stderr=%s", res.exitCode, res.stderr)
	}
}

// damageStoredShowVersion nulls the displacement multiplier in the stored
// declaration of the only registered version, leaving the archive valid
// JSON but the version incomplete.
func damageStoredShowVersion(t *testing.T, dir string) {
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
	ver := doc["versions"].([]any)[0].(map[string]any)
	ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = nil
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRulesShowCLI(t *testing.T) {
	dir := t.TempDir()
	registerViaCLI(t, dir, showStrictSpec)

	// An intact version prints its full parameters and nothing else.
	res := runCLI(t, "rules", "show", dir, "strict")
	if res.exitCode != 0 {
		t.Fatalf("show intact version: exit=%d stderr=%s", res.exitCode, res.stderr)
	}
	var shown struct {
		ID    string `json:"id"`
		Rules struct {
			Sandwich struct {
				Enabled  bool `json:"enabled"`
				Severity int  `json:"severity"`
			} `json:"sandwich"`
			Displacement struct {
				Enabled    bool `json:"enabled"`
				Severity   int  `json:"severity"`
				Multiplier int  `json:"multiplier"`
			} `json:"displacement"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &shown); err != nil {
		t.Fatalf("show output is not a version object: %q: %v", res.stdout, err)
	}
	if shown.ID != "strict" || !shown.Rules.Sandwich.Enabled || shown.Rules.Sandwich.Severity != 5 ||
		!shown.Rules.Displacement.Enabled || shown.Rules.Displacement.Severity != 4 ||
		shown.Rules.Displacement.Multiplier != 5 {
		t.Fatalf("show output wrong: %s", res.stdout)
	}

	// Builtin is always queryable, registered or not.
	res = runCLI(t, "rules", "show", dir, "builtin")
	if res.exitCode != 0 || !strings.Contains(res.stdout, `"id":"builtin"`) {
		t.Fatalf("show builtin: exit=%d stdout=%s stderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	// An unregistered id fails without printing a parameter object.
	res = runCLI(t, "rules", "show", dir, "ghost")
	if res.exitCode == 0 || res.stdout != "" || !strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("show unknown: exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	// A decayed stored declaration fails as version corruption: non-zero
	// exit, the failure names the version, and stdout carries no parameter
	// object (in particular not one with a zeroed multiplier).
	damageStoredShowVersion(t, dir)
	res = runCLI(t, "rules", "show", dir, "strict")
	if res.exitCode == 0 {
		t.Fatalf("show corrupt version succeeded: stdout=%s", res.stdout)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version printed a parameter object: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupted") || !strings.Contains(res.stderr, "strict") ||
		!strings.Contains(res.stderr, "multiplier") {
		t.Fatalf("corrupt show stderr must name the corruption, version and field: %q", res.stderr)
	}

	// The corrupt sibling still does not block builtin.
	res = runCLI(t, "rules", "show", dir, "builtin")
	if res.exitCode != 0 || !strings.Contains(res.stdout, `"id":"builtin"`) {
		t.Fatalf("show builtin past a corrupt sibling: exit=%d stdout=%s stderr=%s", res.exitCode, res.stdout, res.stderr)
	}
}
