package main

// End-to-end regression coverage for the `rules list` command entry point
// against an archive holding a registered version whose stored document
// has decayed. A corrupt declaration anywhere in the archive must fail the
// command with a non-zero exit and no version list on stdout — never a
// list entry with silently zeroed or defaulted parameters — while an
// intact archive keeps its exact JSON shape: builtin first, registered
// versions in stored order, the enabled marker as stored.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	listStrictSpec = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	listOffSpec    = `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
)

// damageStoredListVersion nulls the displacement multiplier in the stored
// declaration of the named registered version, leaving the archive valid
// JSON but the version incomplete.
func damageStoredListVersion(t *testing.T, dir, id string) {
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
	for _, entry := range doc["versions"].([]any) {
		ver := entry.(map[string]any)
		if ver["id"] == id {
			ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = nil
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRulesListCLI(t *testing.T) {
	dir := t.TempDir()
	registerViaCLI(t, dir, listStrictSpec)
	registerViaCLI(t, dir, listOffSpec)
	if res := runCLI(t, "rules", "enable", dir, "off"); res.exitCode != 0 {
		t.Fatalf("rules enable failed: exit=%d stderr=%s", res.exitCode, res.stderr)
	}

	// An intact archive prints the enabled marker and every version with
	// its full parameters: builtin first, then the registered versions in
	// stored order, the explicitly disabled one included.
	res := runCLI(t, "rules", "list", dir)
	if res.exitCode != 0 {
		t.Fatalf("list intact archive: exit=%d stderr=%s", res.exitCode, res.stderr)
	}
	var listed struct {
		Enabled  string `json:"enabled"`
		Versions []struct {
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
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &listed); err != nil {
		t.Fatalf("list output is not a version list: %q: %v", res.stdout, err)
	}
	if listed.Enabled != "off" {
		t.Fatalf("enabled = %q, want off", listed.Enabled)
	}
	if len(listed.Versions) != 3 {
		t.Fatalf("got %d versions, want 3: %s", len(listed.Versions), res.stdout)
	}
	if listed.Versions[0].ID != "builtin" || !listed.Versions[0].Rules.Sandwich.Enabled ||
		listed.Versions[0].Rules.Sandwich.Severity != 3 || !listed.Versions[0].Rules.Displacement.Enabled ||
		listed.Versions[0].Rules.Displacement.Severity != 2 || listed.Versions[0].Rules.Displacement.Multiplier != 2 {
		t.Fatalf("builtin entry wrong: %s", res.stdout)
	}
	if listed.Versions[1].ID != "strict" || !listed.Versions[1].Rules.Sandwich.Enabled ||
		listed.Versions[1].Rules.Sandwich.Severity != 5 || listed.Versions[1].Rules.Displacement.Severity != 4 ||
		listed.Versions[1].Rules.Displacement.Multiplier != 5 {
		t.Fatalf("strict entry wrong: %s", res.stdout)
	}
	if listed.Versions[2].ID != "off" || listed.Versions[2].Rules.Sandwich.Enabled ||
		listed.Versions[2].Rules.Sandwich.Severity != 1 || listed.Versions[2].Rules.Displacement.Enabled ||
		listed.Versions[2].Rules.Displacement.Severity != 1 || listed.Versions[2].Rules.Displacement.Multiplier != 2 {
		t.Fatalf("explicitly disabled entry wrong: %s", res.stdout)
	}

	// A decayed stored declaration fails the whole list — even though the
	// damaged version is not the enabled one: non-zero exit, the failure
	// names the corruption, the version and the field, and stdout carries
	// no complete or partial list (in particular not one with a zeroed
	// multiplier).
	damageStoredListVersion(t, dir, "strict")
	res = runCLI(t, "rules", "list", dir)
	if res.exitCode == 0 {
		t.Fatalf("list with a corrupt version succeeded: stdout=%s", res.stdout)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt archive printed a version list: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupted") || !strings.Contains(res.stderr, "strict") ||
		!strings.Contains(res.stderr, "multiplier") {
		t.Fatalf("corrupt list stderr must name the corruption, version and field: %q", res.stderr)
	}

	// The corrupt entry still does not block showing an intact version.
	res = runCLI(t, "rules", "show", dir, "off")
	if res.exitCode != 0 || !strings.Contains(res.stdout, `"id":"off"`) {
		t.Fatalf("show intact version past a corrupt sibling: exit=%d stdout=%s stderr=%s",
			res.exitCode, res.stdout, res.stderr)
	}
}
