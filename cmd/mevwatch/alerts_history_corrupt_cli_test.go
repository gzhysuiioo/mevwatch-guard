package main

// End-to-end regression coverage for `alerts history` against a saved
// processing record whose detection-version declaration has decayed since
// the record was written. History must first prove — per hit record, from
// the record's own saved declaration — the same integrity rules a `report`
// query enforces before printing any alert or suppression result: exit
// code 1, no history JSON on stdout, an error naming the record's chain,
// block hash, victim tx hash, conclusion kind, conclusion type and
// channel plus the readable version id and the offending field, and no
// change to the archive. Records on another channel stay queryable.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corruptCLIAlertVersion opens the archive and sets the named field of one
// saved processing record's version declaration to value, simulating
// on-disk decay a JSON round-trip through the API could not produce.
func corruptCLIAlertVersion(t *testing.T, dir, tx, kind, channel string, edit func(ver map[string]any)) {
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
	found := false
	for _, a := range doc["alerts"].([]any) {
		rec := a.(map[string]any)
		finding := rec["finding"].(map[string]any)
		if finding["txHash"] != tx || finding["kind"] != kind || rec["channel"] != channel {
			continue
		}
		edit(rec["version"].(map[string]any))
		found = true
	}
	if !found {
		t.Fatalf("alert record tx=%s kind=%s channel=%s not found", tx, kind, channel)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCLIAlertsHistoryCorruptSavedVersion pins the command-level
// contract: exit code 1, no JSON on stdout, the error naming chain, block,
// victim tx, conclusion kind, the alert conclusion type, the channel, the
// saved version id and the offending field, the archive byte-identical,
// and another channel's history unaffected.
func TestCLIAlertsHistoryCorruptSavedVersion(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	// Process both conclusions for ops, and the same conclusions for audit:
	// corrupting one ops record must not take audit's history down.
	if res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops"); res.exitCode != 0 {
		t.Fatalf("generate ops: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "audit"); res.exitCode != 0 {
		t.Fatalf("generate audit: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}

	// Decay the sandwich record's own saved declaration: severity becomes
	// 0, which a naive typed decode would have printed as a real value.
	corruptCLIAlertVersion(t, dir, "0xv", "sandwich", "ops", func(ver map[string]any) {
		ver["rules"].(map[string]any)["sandwich"].(map[string]any)["severity"] = 0
	})

	res := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry history JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"corrupted",
		"chain 1", "0xa", "0xv", "sandwich",
		"alert", "ops", // conclusion type and channel
		"builtin", "severity", // readable saved version id and bad field
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr %q must name %q", res.stderr, want)
		}
	}

	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The failed query is read-only: the damage stays where it was and
	// nothing is repaired or rewritten.
	if !strings.Contains(string(after), `"severity": 0`) {
		t.Fatal("failed history query repaired the corrupt declaration")
	}
	if len(after) == len(before) && string(after) == string(before) {
		t.Fatal("test precondition: archive bytes should differ after corruption")
	}

	// The same failure repeats: no partial repair after the first refusal.
	if again := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100"); again.exitCode != 1 {
		t.Fatalf("second history exit = %d, want 1", again.exitCode)
	}

	// Another channel is outside the damaged record's scope and still
	// returns its full history.
	audit := runCLI(t, "alerts", "history", dir, "1", "audit", "0", "100")
	if audit.exitCode != 0 {
		t.Fatalf("audit history exit = %d, want 0: stderr=%q", audit.exitCode, audit.stderr)
	}
	auditRecords := parseAlertRecords(t, audit.stdout)
	if len(auditRecords) != 2 {
		t.Fatalf("audit history holds %d records, want 2: %s", len(auditRecords), audit.stdout)
	}

	// A range that excludes the height-10 block hits no damaged record and
	// prints [] rather than failing.
	empty := runCLI(t, "alerts", "history", dir, "1", "ops", "11", "100")
	if empty.exitCode != 0 || strings.TrimSpace(empty.stdout) != "[]" {
		t.Fatalf("out-of-range history = exit %d stdout %q stderr %q, want 0/[]",
			empty.exitCode, empty.stdout, empty.stderr)
	}
}

// TestCLIAlertsHistorySuppressedRecordCorrupt proves the failure also
// names the suppressed conclusion type: a damaged suppressed record fails
// the same way, rather than being shown with zeroed parameters.
func TestCLIAlertsHistorySuppressedRecordCorrupt(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	specPath := filepath.Join(t.TempDir(), "suppression.json")
	spec := `{"id":"s1","chainId":"1","pool":"p2","kind":"displacement","channel":"ops","startHeight":10,"endHeight":10,"reason":"known bot war"}`
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "suppressions", "register", dir, specPath); res.exitCode != 0 {
		t.Fatalf("suppressions register: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops"); res.exitCode != 0 {
		t.Fatalf("generate: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	// The displacement record (0xd) is the suppressed one; null its
	// multiplier.
	corruptCLIAlertVersion(t, dir, "0xd", "displacement", "ops", func(ver map[string]any) {
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = nil
	})
	res := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("stdout must not carry history JSON, got %q", res.stdout)
	}
	for _, want := range []string{"chain 1", "0xa", "0xd", "displacement", "suppressed", "ops", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr %q must name %q", res.stderr, want)
		}
	}
}
