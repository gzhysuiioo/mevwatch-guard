package main

// End-to-end regression coverage for `alerts history` through the real
// command entry point (see TestMain): every stored processing record a
// history query hits must first pass — from the version declaration it
// saved for itself, not from the block report — the same integrity proof a
// `report` query enforces: a non-empty id, sandwich and displacement each
// with a boolean enabled and an integer severity 1-5, and a displacement
// multiplier 2-100. A written null used to be explained as the built-in
// rules and an incomplete declaration used to come back with missing values
// shown as 0. A processing record is always written with a resolved
// version, so even a wholly missing version key is its own corruption. One
// corrupt hit fails the whole command with exit code 1, no history JSON on
// stdout, and an error naming the record's chain, block hash, victim tx
// hash, conclusion kind and channel, the readable saved version id and the
// offending rule or field. Damage confined to another chain/channel, an
// out-of-range record, a block report or a registered version never blocks
// the query. Success or failure leaves the archive untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mutateAlertsArchive decodes the archive, hands the top-level document to
// mutate and writes it back.
func mutateAlertsArchive(t *testing.T, dir string, mutate func(doc map[string]any)) {
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
	mutate(doc)
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// alertRecords returns the archive's non-empty processing-record array.
func alertRecords(t *testing.T, doc map[string]any) []any {
	t.Helper()
	alerts, ok := doc["alerts"].([]any)
	if !ok || len(alerts) == 0 {
		t.Fatalf("archive has no non-empty alerts array: %v", doc["alerts"])
	}
	return alerts
}

// corruptStoredAlertVersion mutates the embedded version object of the
// processing record whose finding carries tx/kind on channel.
func corruptStoredAlertVersion(t *testing.T, dir, tx, kind, channel string, mutate func(ver map[string]any)) {
	t.Helper()
	mutateAlertsArchive(t, dir, func(doc map[string]any) {
		found := false
		for _, a := range alertRecords(t, doc) {
			rec := a.(map[string]any)
			finding := rec["finding"].(map[string]any)
			if finding["txHash"] != tx || finding["kind"] != kind || rec["channel"] != channel {
				continue
			}
			ver, ok := rec["version"].(map[string]any)
			if !ok {
				t.Fatalf("alert record for tx %s has no object version: %v", tx, rec["version"])
			}
			mutate(ver)
			found = true
		}
		if !found {
			t.Fatalf("alert record tx %s %s channel %s not found", tx, kind, channel)
		}
	})
}

// setStoredAlertVersion replaces (or, when drop is true, removes) the
// embedded version declaration of one processing record.
func setStoredAlertVersion(t *testing.T, dir, tx, kind, channel string, drop bool, value any) {
	t.Helper()
	mutateAlertsArchive(t, dir, func(doc map[string]any) {
		found := false
		for _, a := range alertRecords(t, doc) {
			rec := a.(map[string]any)
			finding := rec["finding"].(map[string]any)
			if finding["txHash"] != tx || finding["kind"] != kind || rec["channel"] != channel {
				continue
			}
			if drop {
				delete(rec, "version")
			} else {
				rec["version"] = value
			}
			found = true
		}
		if !found {
			t.Fatalf("alert record tx %s %s channel %s not found", tx, kind, channel)
		}
	})
}

// appendCorruptAlert deep-copies an existing processing record, gives the
// copy a distinct identity and a damaged declaration, and appends it.
func appendCorruptAlert(t *testing.T, dir string, chain, channel, hash, tx, kind string, number int64) {
	t.Helper()
	mutateAlertsArchive(t, dir, func(doc map[string]any) {
		alerts := alertRecords(t, doc)
		raw, err := json.Marshal(alerts[0])
		if err != nil {
			t.Fatal(err)
		}
		var clone map[string]any
		if err := json.Unmarshal(raw, &clone); err != nil {
			t.Fatal(err)
		}
		clone["chainId"] = chain
		clone["channel"] = channel
		clone["blockHash"] = hash
		clone["blockNumber"] = number
		clone["finding"].(map[string]any)["txHash"] = tx
		clone["finding"].(map[string]any)["kind"] = kind
		// Damaged declaration: displacement multiplier missing.
		clone["version"] = map[string]any{
			"id": "builtin",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2},
			},
		}
		doc["alerts"] = append(alerts, clone)
	})
}

// historyCmd runs `alerts history` over channel ops for the given range.
func historyCmd(t *testing.T, dir, channel, start, end string) cliResult {
	t.Helper()
	return runCLI(t, "alerts", "history", dir, "1", channel, start, end)
}

// TestCLIAlertsHistoryCorruptDeclaration pins the command-level contract:
// exit code 1, no history JSON on stdout, the error naming the record's
// chain, block hash, victim tx hash, conclusion kind and channel plus the
// readable saved version id and offending rule or field, and the archive
// untouched. One corrupt record fails the whole query even though another
// stored record is intact.
func TestCLIAlertsHistoryCorruptDeclaration(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	generateAlertsCLI(t, dir, "1") // sandwich 0xv and displacement 0xd
	archivePath := filepath.Join(dir, "archive.json")

	// Damage only the displacement record's own declaration (drop the
	// multiplier); the block report and the other record stay intact.
	corruptStoredAlertVersion(t, dir, "0xd", "displacement", "ops", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	corruptBytes := mustReadFile(t, archivePath)

	res := historyCmd(t, dir, "ops", "0", "100")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("corrupt record must print no history JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"corrupt",      // ErrCorruptVersion
		"chain 1",      // chain
		"block 0xa",    // block hash
		"tx 0xd",       // victim tx hash
		"displacement", // conclusion kind
		"channel ops",  // channel
		"builtin",      // readable saved version id
		"multiplier",   // offending field
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("history crashed instead of failing cleanly: %q", res.stderr)
	}

	// A second attempt fails the same way and nothing in the archive was
	// rewritten — the intact record is never returned as a partial result.
	again := historyCmd(t, dir, "ops", "0", "100")
	if again.exitCode != 1 || strings.TrimSpace(again.stdout) != "" ||
		!strings.Contains(again.stderr, "corrupt") {
		t.Fatalf("second attempt changed shape: exit=%d stdout=%q stderr=%q",
			again.exitCode, again.stdout, again.stderr)
	}
	if after := mustReadFile(t, archivePath); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed history query rewrote the archive")
	}
}

// TestCLIAlertsHistoryNullAndMissingVersionCorrupt pins the exact misread
// being fixed: a written null must not be explained as the built-in rules,
// and — unlike a block report — a processing record missing the version key
// entirely is still corruption, never a legacy built-in interpretation.
func TestCLIAlertsHistoryNullAndMissingVersionCorrupt(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop bool
		val  any
	}{
		{"null", false, nil},
		{"empty object", false, map[string]any{}},
		{"missing key", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupAlertsCLIArchive(t)
			generateAlertsCLI(t, dir, "1")
			setStoredAlertVersion(t, dir, "0xv", "sandwich", "ops", tc.drop, tc.val)
			res := historyCmd(t, dir, "ops", "0", "100")
			if res.exitCode != 1 {
				t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
			}
			if strings.TrimSpace(res.stdout) != "" {
				t.Fatalf("damaged declaration must print no history JSON, got %q", res.stdout)
			}
			for _, want := range []string{"corrupt", "chain 1", "block 0xa", "tx 0xv", "sandwich", "channel ops"} {
				if !strings.Contains(res.stderr, want) {
					t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
				}
			}
		})
	}
}

// TestCLIAlertsHistoryDuplicateField covers decay written straight into the
// alerts section: a repeated field under a case-folded spelling that names
// the same field must fail the same way a fresh registration rejects it.
func TestCLIAlertsHistoryDuplicateField(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	generateAlertsCLI(t, dir, "1")
	path := filepath.Join(dir, "archive.json")
	text := string(mustReadFile(t, path))
	alertsAt := strings.Index(text, `"alerts":`)
	if alertsAt < 0 {
		t.Fatal("alerts section not found")
	}
	atRel := strings.Index(text[alertsAt:], `"id": "builtin"`)
	if atRel < 0 {
		t.Fatal("processing record's embedded builtin declaration not found")
	}
	at := alertsAt + atRel
	anchor := `"severity": 2,`
	fieldRel := strings.Index(text[at:], anchor)
	if fieldRel < 0 {
		t.Fatal("displacement severity field not found in an alert declaration")
	}
	pos := at + fieldRel
	patched := text[:pos] + `"Severity": 2, ` + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	res := historyCmd(t, dir, "ops", "0", "100")
	if res.exitCode != 1 || strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("duplicate-field declaration exit=%d stdout=%q stderr=%q",
			res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "corrupt") || !strings.Contains(res.stderr, "duplicate") ||
		!strings.Contains(res.stderr, "severity") {
		t.Fatalf("stderr must name the duplicate severity field: %q", res.stderr)
	}
}

// TestCLIAlertsHistoryCorruptSiblingOutOfScope proves the proof is scoped:
// damaged records on another chain or channel, or outside the height range,
// never block the in-scope intact history, while a query that actually hits
// a damaged record fails naming that record's own identity. Damage to the
// block report declaration or to a registered version never blocks history.
func TestCLIAlertsHistoryCorruptSiblingOutOfScope(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	generateAlertsCLI(t, dir, "1")
	appendCorruptAlert(t, dir, "2", "ops", "0xa", "0xq", "displacement", 10)
	appendCorruptAlert(t, dir, "1", "oncall", "0xa", "0xc", "displacement", 10)
	appendCorruptAlert(t, dir, "1", "ops", "0xhigh", "0xh", "displacement", 99)

	// Chain 1 / ops / 0..50 hits only the two intact records; the other
	// chain, other channel and height-99 decoys are all skipped.
	res := historyCmd(t, dir, "ops", "0", "50")
	if res.exitCode != 0 {
		t.Fatalf("out-of-scope corrupt records blocked the target: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseAlertRecords(t, res.stdout)
	if len(hist) != 2 {
		t.Fatalf("target history holds %d records, want the two intact ones: %s", len(hist), res.stdout)
	}

	// Each damaged sibling fails the query whose identity/range hits it,
	// with its own identity named.
	check := func(channel, start, end, tx string) {
		t.Helper()
		r := historyCmd(t, dir, channel, start, end)
		if r.exitCode != 1 || strings.TrimSpace(r.stdout) != "" {
			t.Fatalf("damaged sibling exit=%d stdout=%q stderr=%q", r.exitCode, r.stdout, r.stderr)
		}
		for _, want := range []string{"corrupt", tx, "displacement", "channel " + channel, "builtin", "multiplier"} {
			if !strings.Contains(r.stderr, want) {
				t.Fatalf("stderr = %q, want substring %q", r.stderr, want)
			}
		}
	}
	check("oncall", "0", "100", "0xc")
	check("ops", "90", "100", "0xh")

	// The other-chain decoy requires querying chain 2: run it directly.
	chain2 := runCLI(t, "alerts", "history", dir, "2", "ops", "0", "100")
	if chain2.exitCode != 1 || strings.TrimSpace(chain2.stdout) != "" {
		t.Fatalf("other-chain damaged record exit=%d stdout=%q stderr=%q",
			chain2.exitCode, chain2.stdout, chain2.stderr)
	}
	for _, want := range []string{"corrupt", "chain 2", "0xq", "channel ops"} {
		if !strings.Contains(chain2.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", chain2.stderr, want)
		}
	}

	// A damaged block-report declaration does not block alert history.
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		ver := rec["version"].(map[string]any)
		ver["rules"].(map[string]any)["displacement"].(map[string]any)["multiplier"] = 0
	})
	if r := historyCmd(t, dir, "ops", "0", "50"); r.exitCode != 0 {
		t.Fatalf("a corrupt block report blocked history: exit=%d stderr=%q", r.exitCode, r.stderr)
	}

	// A damaged registered version does not block it either.
	specPath := filepath.Join(t.TempDir(), "strict.json")
	const strict = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	if err := os.WriteFile(specPath, []byte(strict), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := runCLI(t, "rules", "register", dir, specPath); r.exitCode != 0 {
		t.Fatalf("rules register: exit=%d stderr=%q", r.exitCode, r.stderr)
	}
	corruptStoredVersion(t, dir, "strict", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	if r := historyCmd(t, dir, "ops", "0", "50"); r.exitCode != 0 {
		t.Fatalf("a corrupt registered version blocked history: exit=%d stderr=%q", r.exitCode, r.stderr)
	}
}

// TestCLIAlertsHistoryEmptyAndLegacyOutputsArray proves an old archive with
// no alert data and a range with no match still print [] with exit 0.
func TestCLIAlertsHistoryEmptyAndLegacyOutputsArray(t *testing.T) {
	// Archive with a block report but no processing records (pre-alerting).
	dir := setupAlertsCLIArchive(t)
	if r := historyCmd(t, dir, "ops", "0", "100"); r.exitCode != 0 || strings.TrimSpace(r.stdout) != "[]" {
		t.Fatalf("archive with no alerts must print [], exit=%d stdout=%q stderr=%q",
			r.exitCode, r.stdout, r.stderr)
	}
	// After generation, a range and channel with no matches still print [].
	generateAlertsCLI(t, dir, "1")
	for _, tc := range []struct{ channel, start, end string }{
		{"ops", "0", "9"},
		{"oncall", "0", "100"},
	} {
		r := historyCmd(t, dir, tc.channel, tc.start, tc.end)
		if r.exitCode != 0 || strings.TrimSpace(r.stdout) != "[]" {
			t.Fatalf("no-match history must print [], exit=%d stdout=%q stderr=%q",
				r.exitCode, r.stdout, r.stderr)
		}
	}
	// A wholly missing archive directory is an empty history too.
	absent := filepath.Join(t.TempDir(), "absent")
	if r := historyCmd(t, absent, "ops", "0", "100"); r.exitCode != 0 || strings.TrimSpace(r.stdout) != "[]" {
		t.Fatalf("missing directory must print [], exit=%d stdout=%q", r.exitCode, r.stdout)
	}
}

// TestCLIAlertsHistoryCorruptedArchiveFails proves a wholly unreadable
// archive still reports an error and prints no history JSON.
func TestCLIAlertsHistoryCorruptedArchiveFails(t *testing.T) {
	dir := setupAlertsCLIArchive(t)
	generateAlertsCLI(t, dir, "1")
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := historyCmd(t, dir, "ops", "0", "100")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1", res.exitCode)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("corrupt archive must print no history JSON, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupted") {
		t.Fatalf("stderr = %q, want a corrupted-archive error", res.stderr)
	}
}
