package main

// End-to-end regression coverage for the `rules show` command against a
// corrupt archived rule version. Viewing a registered version must prove
// its stored declaration still satisfies the registration rules before
// printing a single parameter: a corrupt version fails with a clean
// corruption error — naming the version and the offending rule or field —
// and prints no JSON object, instead of coming back with enabled:false
// and zeroed severity/multiplier. Only the named version is checked: a
// corrupt sibling (even the enabled one) never blocks an intact version
// or builtin, and an unregistered id stays an unknown-version failure.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

func TestCLIRulesShowCorruptVersion(t *testing.T) {
	dir := setupCLIArchive(t)
	// candC is enabled-worthy but liveB is currently enabled; enable candC
	// first so the damaged version is also the enabled one when viewed.
	// candC declares sandwich enabled:false with full parameters.
	if _, err := mevwatch.EnableVersion(dir, "candC"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	// Before decay, the disabled-but-complete declaration views normally:
	// enabled:false comes back as written, severity and multiplier intact.
	res := runCLI(t, "rules", "show", dir, "candC")
	if res.exitCode != 0 {
		t.Fatalf("intact show failed: %d %q", res.exitCode, res.stderr)
	}
	var intact map[string]any
	if err := json.Unmarshal([]byte(res.stdout), &intact); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	rules := intact["rules"].(map[string]any)
	sandwich := rules["sandwich"].(map[string]any)
	displacement := rules["displacement"].(map[string]any)
	if intact["id"] != "candC" || sandwich["enabled"] != false || sandwich["severity"].(float64) != 3 ||
		displacement["enabled"] != true || displacement["severity"].(float64) != 4 ||
		displacement["multiplier"].(float64) != 2 {
		t.Fatalf("intact declaration returned wrong: %s", res.stdout)
	}

	// The stored candC document loses its displacement multiplier: valid
	// JSON, but no longer a complete rule declaration.
	corruptStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	res = runCLI(t, "rules", "show", dir, "candC")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version must print no parameter JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "candC", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("show crashed instead of failing cleanly: %q", res.stderr)
	}

	// An unregistered id stays a plain unknown-version failure.
	res = runCLI(t, "rules", "show", dir, "nope")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: nope") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	// Exact id matching: case variants and surrounding whitespace never
	// resolve to the corrupt (or any) version.
	for _, asked := range []string{"CandC", "candc", " candC", "candC "} {
		res = runCLI(t, "rules", "show", dir, asked)
		if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version") ||
			strings.Contains(res.stderr, "corrupt") {
			t.Fatalf("show %q must stay an unknown-version failure: exit=%d stderr=%q",
				asked, res.exitCode, res.stderr)
		}
	}

	// The corrupt, currently-enabled sibling does not contaminate intact
	// versions: liveB views in full...
	res = runCLI(t, "rules", "show", dir, "liveB")
	if res.exitCode != 0 {
		t.Fatalf("show intact liveB failed: %d %q", res.exitCode, res.stderr)
	}
	var liveB struct {
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
	if err := json.Unmarshal([]byte(res.stdout), &liveB); err != nil {
		t.Fatalf("liveB stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if liveB.ID != "liveB" || !liveB.Rules.Sandwich.Enabled || liveB.Rules.Sandwich.Severity != 5 ||
		!liveB.Rules.Displacement.Enabled || liveB.Rules.Displacement.Severity != 5 ||
		liveB.Rules.Displacement.Multiplier != 4 {
		t.Fatalf("liveB parameters wrong or completed from elsewhere: %s", res.stdout)
	}
	// ...and builtin needs no registration and views normally.
	res = runCLI(t, "rules", "show", dir, "builtin")
	if res.exitCode != 0 {
		t.Fatalf("show builtin failed: %d %q", res.exitCode, res.stderr)
	}
	var builtin mevwatch.RuleVersion
	if err := json.Unmarshal([]byte(res.stdout), &builtin); err != nil {
		t.Fatalf("builtin stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if builtin != mevwatch.BuiltinVersion() {
		t.Fatalf("builtin parameters wrong: %+v", builtin)
	}

	// Success and failure leave the archive — the damaged declaration and
	// the enabled marker included — byte for byte untouched.
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rules show changed the archive")
	}
	_, enabled, err := mevwatch.ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "candC" {
		t.Fatalf("enabled marker changed to %q on a read-only view", enabled)
	}
}

func TestCLIRulesShowNoArchive(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-archive-yet")

	// Builtin is always queryable, even with no archive directory.
	res := runCLI(t, "rules", "show", missing, "builtin")
	if res.exitCode != 0 {
		t.Fatalf("builtin show without a directory failed: %d %q", res.exitCode, res.stderr)
	}
	var builtin mevwatch.RuleVersion
	if err := json.Unmarshal([]byte(res.stdout), &builtin); err != nil || builtin != mevwatch.BuiltinVersion() {
		t.Fatalf("builtin output wrong: %v %s", err, res.stdout)
	}

	// Any other id is unknown, not corrupt.
	res = runCLI(t, "rules", "show", missing, "v")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: v") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("missing-dir failure shape wrong: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
}

func TestCLIRulesShowUsage(t *testing.T) {
	res := runCLI(t, "rules", "show", t.TempDir())
	if res.exitCode != 2 || !strings.Contains(res.stderr, "usage: mevwatch rules show") {
		t.Fatalf("missing args: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
}
