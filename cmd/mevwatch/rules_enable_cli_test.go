package main

// End-to-end regression coverage for `rules enable` against a corrupt
// archived rule version. Enable picks the version later replays use, so a
// successful enable must mean the selected version's stored document still
// satisfies the registration rules in full: a registered-but-corrupt
// version (even the one already enabled) fails with a clean corruption
// error naming the version and offending field, an unregistered
// identifier stays an unknown-version failure, and an intact version
// (including builtin) still enables beside the damage without repairing,
// completing or dropping the corrupt entry.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupRulesCLIArchive registers an intact candC and twin and returns the
// archive directory.
func setupRulesCLIArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	const candC = `{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`
	const twin = `{"id":"twin","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":2}}}`
	for _, spec := range []string{candC, twin} {
		if _, _, err := mevwatch.RegisterVersion(dir, []byte(spec)); err != nil {
			t.Fatalf("RegisterVersion: %v", err)
		}
	}
	return dir
}

func TestCLIRulesEnableCorruptVersion(t *testing.T) {
	dir := setupRulesCLIArchive(t)
	// The version is enabled while intact, then damaged on disk.
	res := runCLI(t, "rules", "enable", dir, "candC")
	if res.exitCode != 0 {
		t.Fatalf("intact enable failed: %d %q", res.exitCode, res.stderr)
	}
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	// Re-selecting the already-enabled, now-corrupt marker refuses.
	res = runCLI(t, "rules", "enable", dir, "candC")
	if res.exitCode != 1 || res.stdout != "" {
		t.Fatalf("corrupt marker enable: exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	for _, want := range []string{"corrupt", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr=%q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("registered corruption reported unknown: %q", res.stderr)
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("enable crashed instead of failing cleanly: %q", res.stderr)
	}

	// An unregistered identifier remains an unknown-version failure.
	res = runCLI(t, "rules", "enable", dir, "ghost")
	if res.exitCode != 1 || res.stdout != "" ||
		!strings.Contains(res.stderr, "unknown version: ghost") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown id failure shape wrong: exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}

	// The intact twin enables beside the damage and its full parameters are
	// printed.
	res = runCLI(t, "rules", "enable", dir, "twin")
	if res.exitCode != 0 {
		t.Fatalf("twin enable exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	var got mevwatch.RuleVersion
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil {
		t.Fatalf("twin enable stdout not JSON: %v (%q)", err, res.stdout)
	}
	if got.ID != "twin" || got.Rules.Displacement.Multiplier != 2 ||
		!got.Rules.Sandwich.Enabled || got.Rules.Sandwich.Severity != 3 {
		t.Fatalf("twin enable returned wrong parameters: %+v", got)
	}

	// builtin needs no registration and still enables.
	res = runCLI(t, "rules", "enable", dir, "builtin")
	if res.exitCode != 0 {
		t.Fatalf("builtin enable failed: %d %q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"id":"builtin"`) ||
		!strings.Contains(res.stdout, `"multiplier":2`) {
		t.Fatalf("builtin enable output wrong: %q", res.stdout)
	}

	// The corrupt entry survives all successful enables: the missing
	// multiplier was not completed, and the final marker is builtin.
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Versions []struct {
			ID    string `json:"id"`
			Rules struct {
				Displacement map[string]any `json:"displacement"`
			} `json:"rules"`
		} `json:"versions"`
		EnabledVersion string `json:"enabledVersion"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.EnabledVersion != "builtin" {
		t.Fatalf("enabled marker = %q, want builtin", doc.EnabledVersion)
	}
	if len(doc.Versions) != 2 || doc.Versions[0].ID != "candC" || doc.Versions[1].ID != "twin" {
		t.Fatalf("versions were reordered or dropped: %+v", doc.Versions)
	}
	if _, ok := doc.Versions[0].Rules.Displacement["multiplier"]; ok {
		t.Fatalf("corrupt entry repaired by a successful enable: %v", doc.Versions[0])
	}

	// And the damaged version is still refused end to end.
	res = runCLI(t, "rules", "enable", dir, "candC")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("corrupt entry later accepted: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
}
