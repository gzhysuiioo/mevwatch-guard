package main

// End-to-end regression coverage for the `rules list` command entry point
// when a registered version's stored archive document has decayed. Listing
// used to decode every stored entry straight into structs and display a
// missing enabled as false and a missing multiplier as 0 — normal-looking
// values for a damaged declaration. The list must instead fail the whole
// command: non-zero exit, stderr naming the corruption, the identifiable
// version and the offending field, and no full or partial list on stdout —
// while intact archives keep their exact JSON shape (builtin first,
// registered versions in stored order) and explicitly disabled rules list
// normally.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const listSecondSpec = `{"id":"second","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`

// listCLIVersion is one version entry as the list JSON presents it.
type listCLIVersion struct {
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

func decodeList(t *testing.T, stdout string) (string, []listCLIVersion) {
	t.Helper()
	var doc struct {
		Enabled  string           `json:"enabled"`
		Versions []listCLIVersion `json:"versions"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &doc); err != nil {
		t.Fatalf("list output is not the list document: %q: %v", stdout, err)
	}
	return doc.Enabled, doc.Versions
}

func TestRulesListCLIIntact(t *testing.T) {
	dir := t.TempDir()

	// A missing archive directory lists just builtin with its parameters.
	res := runCLI(t, "rules", "list", dir)
	if res.exitCode != 0 || res.stderr != "" {
		t.Fatalf("list on empty dir: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	enabled, versions := decodeList(t, res.stdout)
	if enabled != "builtin" || len(versions) != 1 {
		t.Fatalf("empty-dir list = %s", res.stdout)
	}
	b := versions[0]
	if b.ID != "builtin" || !b.Rules.Sandwich.Enabled || b.Rules.Sandwich.Severity != 3 ||
		!b.Rules.Displacement.Enabled || b.Rules.Displacement.Severity != 2 ||
		b.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("builtin parameters wrong: %s", res.stdout)
	}

	registerViaCLI(t, dir, showStrictSpec)
	registerViaCLI(t, dir, listSecondSpec)
	res = runCLI(t, "rules", "list", dir)
	if res.exitCode != 0 {
		t.Fatalf("list intact archive: exit=%d stderr=%s", res.exitCode, res.stderr)
	}
	enabled, versions = decodeList(t, res.stdout)
	if enabled != "builtin" {
		t.Fatalf("enabled = %q, want builtin", enabled)
	}
	if len(versions) != 3 {
		t.Fatalf("want builtin + 2 registered, got %s", res.stdout)
	}
	// builtin leads, registered versions follow in registration order.
	if versions[0].ID != "builtin" || versions[1].ID != "strict" || versions[2].ID != "second" {
		t.Fatalf("version order wrong: %s", res.stdout)
	}
	// Full parameters of both registered versions are present; the second
	// version explicitly turns both rules off and must show real false
	// flags alongside its severity and multiplier, not zero-fill.
	strict, second := versions[1], versions[2]
	if !strict.Rules.Sandwich.Enabled || strict.Rules.Sandwich.Severity != 5 ||
		!strict.Rules.Displacement.Enabled || strict.Rules.Displacement.Severity != 4 ||
		strict.Rules.Displacement.Multiplier != 5 {
		t.Fatalf("strict parameters wrong: %+v", strict)
	}
	if second.Rules.Sandwich.Enabled || second.Rules.Sandwich.Severity != 1 ||
		second.Rules.Displacement.Enabled || second.Rules.Displacement.Severity != 1 ||
		second.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("explicitly-off second version distorted: %+v", second.Rules)
	}
}

func TestRulesListCLILegacyArchive(t *testing.T) {
	dir := t.TempDir()
	// Pre-version archive: records only, no versions or enabled marker.
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,"swaps":[],"findings":[]}]}`
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "rules", "list", dir)
	if res.exitCode != 0 {
		t.Fatalf("list legacy archive: exit=%d stderr=%s", res.exitCode, res.stderr)
	}
	enabled, versions := decodeList(t, res.stdout)
	if enabled != "builtin" || len(versions) != 1 || versions[0].ID != "builtin" {
		t.Fatalf("legacy list = %s", res.stdout)
	}
}

func TestRulesListCLICorruptVersionFails(t *testing.T) {
	dir := t.TempDir()
	registerViaCLI(t, dir, showStrictSpec)
	registerViaCLI(t, dir, listSecondSpec)
	damageStoredShowVersion(t, dir)

	res := runCLI(t, "rules", "list", dir)
	if res.exitCode == 0 {
		t.Fatalf("list corrupt archive succeeded: %s", res.stdout)
	}
	// No full or partial list on stdout.
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("corrupt archive printed a list: %q", res.stdout)
	}
	// stderr explains the corruption and names the identifiable version
	// and the offending field.
	if !strings.Contains(res.stderr, "corrupted") ||
		!strings.Contains(res.stderr, "strict") ||
		!strings.Contains(res.stderr, "multiplier") {
		t.Fatalf("stderr must name corruption, version strict and field multiplier: %q", res.stderr)
	}

	// The failed list rewrote nothing: the archive is still intact enough
	// to fail the same way again, and the intact sibling still shows.
	again := runCLI(t, "rules", "list", dir)
	if again.exitCode == 0 || again.stdout != "" {
		t.Fatalf("corruption was repaired by the failed list: exit=%d stdout=%q", again.exitCode, again.stdout)
	}
	show := runCLI(t, "rules", "show", dir, "second")
	if show.exitCode != 0 || !strings.Contains(show.stdout, `"id":"second"`) {
		t.Fatalf("intact sibling no longer showable: exit=%d stdout=%s stderr=%s",
			show.exitCode, show.stdout, show.stderr)
	}
}

func TestRulesListCLIInvalidArchive(t *testing.T) {
	dir := t.TempDir()
	registerViaCLI(t, dir, showStrictSpec)
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "rules", "list", dir)
	if res.exitCode == 0 || res.stdout != "" {
		t.Fatalf("invalid-JSON archive: exit=%d stdout=%q", res.exitCode, res.stdout)
	}
	if !strings.Contains(res.stderr, "archive is corrupted") {
		t.Fatalf("stderr must report whole-archive corruption: %q", res.stderr)
	}
}
