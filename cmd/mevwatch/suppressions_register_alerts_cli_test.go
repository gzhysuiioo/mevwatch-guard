package main

// End-to-end regression coverage for `suppressions register` over an
// archive whose stored alert processing records carry a decayed
// detection-version declaration. Unlike a block report's declaration,
// which registration proves before saving (a corrupt one fails the whole
// command), a processing record's declaration is evidence belonging to the
// earlier `alerts generate`: registration must neither judge it nor rewrite
// it. A record carrying version:null therefore registers the new condition
// normally through either intake path (a spec file and standard input) —
// exit 0, created:true with the full condition — while the record's null
// declaration, conclusion, evidence, threshold, status and suppression
// hits survive byte for byte in content, and a later `alerts history`
// still fails on the damaged record exactly as before.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cliRegisterOverCorruptAlertSpec is a legal condition covering the
// already-processed sandwich event itself; registering it after the fact
// must not turn the saved alert into a suppression.
const cliRegisterOverCorruptAlertSpec = `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"known bot war"}`

// setupCorruptAlertRegisterCLIArchive replays the two-finding block,
// processes both conclusions for channel ops, and replaces the sandwich
// record's version declaration with null. The block report itself stays
// intact, so the registration proof over reports passes; only the
// processing record is damaged.
func setupCorruptAlertRegisterCLIArchive(t *testing.T) string {
	t.Helper()
	dir := setupAlertsCLIArchive(t)
	if res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops"); res.exitCode != 0 {
		t.Fatalf("alerts generate exit=%d stderr=%q", res.exitCode, res.stderr)
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
	found := false
	for _, a := range doc["alerts"].([]any) {
		rec := a.(map[string]any)
		finding := rec["finding"].(map[string]any)
		if finding["txHash"] == "0xv" && finding["kind"] == "sandwich" && rec["channel"] == "ops" {
			rec["version"] = nil
			found = true
		}
	}
	if !found {
		t.Fatal("sandwich ops alert record not found")
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

// compactedAlertRecords returns each processing record's semantic bytes
// (whitespace normalized) so a before/after comparison ignores the
// re-indentation a save performs but catches any null that became an
// object, any completed field or merged duplicate.
func compactedAlertRecords(t *testing.T, dir string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Alerts []json.RawMessage `json:"alerts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(doc.Alerts))
	for i, rec := range doc.Alerts {
		var buf bytes.Buffer
		if err := json.Compact(&buf, rec); err != nil {
			t.Fatal(err)
		}
		out[i] = bytes.Clone(buf.Bytes())
	}
	return out
}

// assertRegisterSuccessOverCorruptAlert runs one registration (file or
// stdin) over the damaged archive and pins the full command contract.
func assertRegisterSuccessOverCorruptAlert(t *testing.T, dir string, res cliResult) {
	t.Helper()
	if res.exitCode != 0 {
		t.Fatalf("exit = %d, want 0 (stdout=%q stderr=%q)", res.exitCode, res.stdout, res.stderr)
	}
	var out struct {
		Created     bool `json:"created"`
		Suppression struct {
			ID          string `json:"id"`
			ChainID     string `json:"chainId"`
			Pool        string `json:"pool"`
			Kind        string `json:"kind"`
			Channel     string `json:"channel"`
			StartHeight uint64 `json:"startHeight"`
			EndHeight   uint64 `json:"endHeight"`
			Reason      string `json:"reason"`
			Revoked     bool   `json:"revoked"`
		} `json:"suppression"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &out); err != nil {
		t.Fatalf("registration output %q: %v", res.stdout, err)
	}
	if !out.Created {
		t.Fatalf("want created:true, got %q", res.stdout)
	}
	if out.Suppression.ID != "s1" || out.Suppression.ChainID != "1" || out.Suppression.Pool != "p1" ||
		out.Suppression.Kind != "sandwich" || out.Suppression.Channel != "ops" ||
		out.Suppression.StartHeight != 0 || out.Suppression.EndHeight != 100 ||
		out.Suppression.Reason != "known bot war" || out.Suppression.Revoked {
		t.Fatalf("registered condition incomplete: %+v", out.Suppression)
	}
}

// TestCLISuppressionsRegisterKeepsCorruptAlertRecordFile exercises the
// spec-file intake over a processing record carrying version:null.
func TestCLISuppressionsRegisterKeepsCorruptAlertRecordFile(t *testing.T) {
	dir := setupCorruptAlertRegisterCLIArchive(t)
	before := compactedAlertRecords(t, dir)
	specPath := filepath.Join(t.TempDir(), "suppression.json")
	if err := os.WriteFile(specPath, []byte(cliRegisterOverCorruptAlertSpec), 0o644); err != nil {
		t.Fatal(err)
	}

	res := runCLI(t, "suppressions", "register", dir, specPath)
	assertRegisterSuccessOverCorruptAlert(t, dir, res)

	after := string(mustReadFile(t, filepath.Join(dir, "archive.json")))
	if !strings.Contains(after, `"version": null`) {
		t.Fatalf("registration rewrote the null processing-record declaration:\n%s", after)
	}
	afterRecs := compactedAlertRecords(t, dir)
	if len(afterRecs) != len(before) {
		t.Fatalf("alerts section length changed: %d before, %d after", len(before), len(afterRecs))
	}
	for i := range before {
		if !bytes.Equal(before[i], afterRecs[i]) {
			t.Fatalf("alert record %d changed:\nbefore=%s\nafter =%s", i, before[i], afterRecs[i])
		}
	}

	// The new condition covers this event, yet the saved alert is not
	// rewritten: regeneration produces nothing for its identity.
	if gen := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "1", "ops"); gen.exitCode != 0 {
		t.Fatalf("regeneration exit=%d stderr=%q", gen.exitCode, gen.stderr)
	} else if strings.TrimSpace(gen.stdout) != "[]" {
		t.Fatalf("new condition re-processed history: %q", gen.stdout)
	}

	// The damaged record still fails a history query explicitly: no history
	// JSON, exit 1, error naming the record and the corruption.
	hist := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if hist.exitCode != 1 {
		t.Fatalf("history exit=%d, want 1 (stdout=%q)", hist.exitCode, hist.stdout)
	}
	if strings.TrimSpace(hist.stdout) != "" {
		t.Fatalf("corrupt history must not print records: %q", hist.stdout)
	}
	for _, want := range []string{"corrupted", "1", "0xa", "0xv", "sandwich", "ops"} {
		if !strings.Contains(hist.stderr, want) {
			t.Fatalf("stderr %q must name %q", hist.stderr, want)
		}
	}
	if !strings.Contains(string(mustReadFile(t, filepath.Join(dir, "archive.json"))), `"version": null`) {
		t.Fatal("failed history query repaired the null declaration")
	}
}

// TestCLISuppressionsRegisterKeepsCorruptAlertRecordStdin exercises the
// standard input intake ('-'): it must behave identically to the file.
func TestCLISuppressionsRegisterKeepsCorruptAlertRecordStdin(t *testing.T) {
	dir := setupCorruptAlertRegisterCLIArchive(t)
	before := compactedAlertRecords(t, dir)

	res := runCLIStdin(t, cliRegisterOverCorruptAlertSpec, "suppressions", "register", dir, "-")
	assertRegisterSuccessOverCorruptAlert(t, dir, res)

	if !strings.Contains(string(mustReadFile(t, filepath.Join(dir, "archive.json"))), `"version": null`) {
		t.Fatal("stdin registration rewrote the null declaration")
	}
	afterRecs := compactedAlertRecords(t, dir)
	for i := range before {
		if !bytes.Equal(before[i], afterRecs[i]) {
			t.Fatalf("alert record %d changed through stdin registration:\nbefore=%s\nafter =%s",
				i, before[i], afterRecs[i])
		}
	}
	// An identical retry through stdin stays created:false and still changes
	// no record.
	again := runCLIStdin(t, cliRegisterOverCorruptAlertSpec, "suppressions", "register", dir, "-")
	if again.exitCode != 0 {
		t.Fatalf("stdin retry exit=%d stderr=%q", again.exitCode, again.stderr)
	}
	var out struct {
		Created bool `json:"created"`
	}
	if err := json.Unmarshal([]byte(again.stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Created {
		t.Fatalf("identical retry must report created:false, got %q", again.stdout)
	}
	for i := range before {
		if !bytes.Equal(before[i], compactedAlertRecords(t, dir)[i]) {
			t.Fatal("identical retry changed the processing records")
		}
	}
}
