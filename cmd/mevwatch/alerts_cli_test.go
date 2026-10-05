package main

// End-to-end regression coverage for threshold backfilling through the
// real `alerts generate` / `alerts history` / `report` command entries.
// The test binary re-executes itself (see TestMain in compare_cli_test.go)
// and runs the real main(), so argument parsing (including invalid
// minSeverity values), exit status, stderr wording and the exact stdout
// JSON are exercised exactly as a user invokes them. Everything runs
// offline against archive directories under t.TempDir; the original block
// input file is deleted before any alert command runs, proving generation
// consumes archived conclusions only.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// cliFullSwap builds one swap line whose every numeric field carries a
// distinct value, so a test can prove the original amounts and gas prices
// survive into processing records without being defaulted or copied from a
// neighbouring transaction.
func cliFullSwap(tx, pool, trader string, in, out, gas int64, index int) cliSwap {
	return map[string]any{
		"TxHash": tx, "Pool": pool, "Trader": trader,
		"In": in, "Out": out, "GasPrice": gas, "Index": index,
	}
}

// setupAlertsCLIArchive archives exactly one block (chain 1, hash
// 0xablock, height 10) carrying one sandwich and one displacement, then
// deletes the source input file:
//
//	p1: 0xf gas90 (bot) / 0xv gas10 (user) / 0xb gas80 (bot)
//	    -> sandwich on 0xv, severity 3 (same trader squeezes on both sides)
//	p2: 0xw gas50 (whale) / 0xd gas10 (user)
//	    -> displacement on 0xd, severity 2 (50 strictly exceeds 2*10)
//
// The block is archived under the built-in version through the real
// `replay` entry point.
func setupAlertsCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	line := cliBlockLine("1", "0xablock", 10,
		cliFullSwap("0xf", "p1", "bot", 101, 99, 90, 0),
		cliFullSwap("0xv", "p1", "user", 202, 188, 10, 1),
		cliFullSwap("0xb", "p1", "bot", 303, 311, 80, 2),
		cliFullSwap("0xw", "p2", "whale", 505, 490, 50, 3),
		cliFullSwap("0xd", "p2", "user", 606, 580, 10, 4),
	)
	if err := os.WriteFile(inputPath, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "replay", inputPath, dir); res.exitCode != 0 {
		t.Fatalf("replay: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func parseAlertRecords(t *testing.T, raw string) []mevwatch.ProcessingRecord {
	t.Helper()
	var records []mevwatch.ProcessingRecord
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		t.Fatalf("stdout is not a parseable JSON array: %v\n%s", err, raw)
	}
	return records
}

func parseCLIReport(t *testing.T, raw string) mevwatch.Report {
	t.Helper()
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("report stdout is not valid JSON: %v\n%s", err, raw)
	}
	return report
}

// findingInReport returns the archived conclusion for tx/kind, failing the
// test when it is absent.
func findingInReport(t *testing.T, report mevwatch.Report, tx, kind string) mevwatch.ReportFinding {
	t.Helper()
	for _, f := range report.Findings {
		if f.TxHash == tx && f.Kind == kind {
			return f
		}
	}
	t.Fatalf("report for %s has no %s conclusion: %+v", report.BlockHash, kind, report.Findings)
	return mevwatch.ReportFinding{}
}

// TestCLIAlertsThresholdBackfill guards the same-channel behaviour when the
// severity threshold is lowered: a finding below the first threshold leaves
// no processed record, so lowering the threshold produces it for the first
// time, while an identity already processed at the higher threshold is never
// sent a second time. A rule version with different parameters registered
// and enabled between the two generations must not re-judge the archived
// conclusions or rewrite the earlier record.
func TestCLIAlertsThresholdBackfill(t *testing.T) {
	dir := setupAlertsCLIArchive(t)

	// Snapshot the archived report before any alert command exists; the
	// generations below must leave it byte-for-byte intact.
	beforeReportRes := runCLI(t, "report", dir, "1", "0xablock")
	if beforeReportRes.exitCode != 0 {
		t.Fatalf("report before generation: %q", beforeReportRes.stderr)
	}

	// First generation at threshold 3: only the severity-3 sandwich
	// qualifies. Severity equal to the threshold counts as a hit.
	first := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "3", "ops")
	if first.exitCode != 0 {
		t.Fatalf("first generate: exit=%d stderr=%q", first.exitCode, first.stderr)
	}
	if strings.TrimSpace(first.stderr) != "" {
		t.Fatalf("unexpected stderr: %q", first.stderr)
	}
	firstRecords := parseAlertRecords(t, first.stdout)
	if len(firstRecords) != 1 {
		t.Fatalf("threshold 3 must yield only the sandwich, got %d records: %s", len(firstRecords), first.stdout)
	}
	sandwich := firstRecords[0]
	if sandwich.Status != mevwatch.AlertStatusAlert {
		t.Fatalf("status = %q, want alert", sandwich.Status)
	}
	if !strings.Contains(first.stdout, `"status":"alert"`) ||
		!strings.Contains(first.stdout, `"suppressions":[]`) {
		t.Fatalf("alert record must serialize status alert and an empty suppression list: %s", first.stdout)
	}
	if sandwich.ChainID != "1" || sandwich.BlockHash != "0xablock" || sandwich.BlockNumber != 10 {
		t.Fatalf("block identity wrong: %+v", sandwich)
	}
	if sandwich.Channel != "ops" {
		t.Fatalf("record must belong to the requested channel, got %q", sandwich.Channel)
	}
	if sandwich.Pool != "p1" ||
		sandwich.Finding.Kind != "sandwich" || sandwich.Finding.TxHash != "0xv" ||
		sandwich.Finding.Severity != 3 {
		t.Fatalf("first record finding wrong: %+v", sandwich.Finding)
	}
	// The record keeps the threshold of its first processing.
	if sandwich.MinSeverity != 3 {
		t.Fatalf("minSeverity = %d, want 3", sandwich.MinSeverity)
	}
	// The complete detection version and parameters travel with the record.
	if sandwich.Version.ID != "builtin" ||
		!sandwich.Version.Rules.Sandwich.Enabled || sandwich.Version.Rules.Sandwich.Severity != 3 ||
		!sandwich.Version.Rules.Displacement.Enabled ||
		sandwich.Version.Rules.Displacement.Severity != 2 ||
		sandwich.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("record must keep builtin detection parameters: %+v", sandwich.Version)
	}
	// The exchange evidence keeps every field and the original values of
	// all three participating swaps.
	wantSandwichEvidence := []mevwatch.Swap{
		{TxHash: "0xf", Pool: "p1", Trader: "bot", In: 101, Out: 99, GasPrice: 90, Index: 0},
		{TxHash: "0xv", Pool: "p1", Trader: "user", In: 202, Out: 188, GasPrice: 10, Index: 1},
		{TxHash: "0xb", Pool: "p1", Trader: "bot", In: 303, Out: 311, GasPrice: 80, Index: 2},
	}
	if !reflect.DeepEqual(sandwich.Finding.Evidence, wantSandwichEvidence) {
		t.Fatalf("sandwich evidence damaged:\n got %+v\nwant %+v", sandwich.Finding.Evidence, wantSandwichEvidence)
	}

	// Between the two generations the user registers and enables a version
	// with different parameters: displacement severity 4 and multiplier 5.
	// Under multiplier 5 the archived displacement would no longer hit
	// (50 > 5*10 is false), so a regression that re-judges with the current
	// version drops the backfill or stamps severity 4 on it.
	specPath := filepath.Join(t.TempDir(), "strict.json")
	const strictSpec = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	if err := os.WriteFile(specPath, []byte(strictSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "rules", "register", dir, specPath); res.exitCode != 0 {
		t.Fatalf("rules register: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if res := runCLI(t, "rules", "enable", dir, "strict"); res.exitCode != 0 {
		t.Fatalf("rules enable: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// Second generation at threshold 2: only the previously unprocessed
	// displacement comes back. The sandwich handled at threshold 3 must not
	// appear again, and the displacement skipped earlier must not be
	// permanently excluded.
	second := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "2", "ops")
	if second.exitCode != 0 {
		t.Fatalf("second generate: exit=%d stderr=%q", second.exitCode, second.stderr)
	}
	secondRecords := parseAlertRecords(t, second.stdout)
	if len(secondRecords) != 1 {
		t.Fatalf("threshold 2 must backfill only the displacement, got %d records: %s",
			len(secondRecords), second.stdout)
	}
	// Checked on the parsed records rather than raw substrings: the
	// surviving record's embedded version parameters legitimately contain a
	// "sandwich" rule declaration even though the first run's sandwich
	// record itself is absent.
	if secondRecords[0].Finding.TxHash == "0xv" ||
		secondRecords[0].Finding.Kind == "sandwich" {
		t.Fatalf("backfill output must not mix in the first run's record: %s", second.stdout)
	}
	displacement := secondRecords[0]
	if displacement.Status != mevwatch.AlertStatusAlert ||
		len(displacement.Suppressions) != 0 {
		t.Fatalf("backfill must be an alert with an empty suppression list: %+v", displacement)
	}
	if !strings.Contains(second.stdout, `"suppressions":[]`) {
		t.Fatalf("backfill stdout must serialize [] suppressions: %s", second.stdout)
	}
	if displacement.ChainID != "1" || displacement.BlockHash != "0xablock" ||
		displacement.BlockNumber != 10 || displacement.Channel != "ops" || displacement.Pool != "p2" {
		t.Fatalf("backfill identity wrong: %+v", displacement)
	}
	if displacement.Finding.Kind != "displacement" || displacement.Finding.TxHash != "0xd" {
		t.Fatalf("backfill finding wrong: %+v", displacement.Finding)
	}
	// Archived conclusion consumed as-is: severity 2 from builtin, not the
	// current strict version's severity 4.
	if displacement.Finding.Severity != 2 {
		t.Fatalf("backfill must keep archived severity 2, got %d (re-judged?)", displacement.Finding.Severity)
	}
	if displacement.MinSeverity != 2 {
		t.Fatalf("backfill minSeverity = %d, want 2 (its first processing threshold)", displacement.MinSeverity)
	}
	if displacement.Version.ID != "builtin" ||
		displacement.Version.Rules.Displacement.Severity != 2 ||
		displacement.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("backfill must keep the archived builtin parameters, got %+v", displacement.Version)
	}
	wantDisplacementEvidence := []mevwatch.Swap{
		{TxHash: "0xw", Pool: "p2", Trader: "whale", In: 505, Out: 490, GasPrice: 50, Index: 3},
		{TxHash: "0xd", Pool: "p2", Trader: "user", In: 606, Out: 580, GasPrice: 10, Index: 4},
	}
	if !reflect.DeepEqual(displacement.Finding.Evidence, wantDisplacementEvidence) {
		t.Fatalf("displacement evidence damaged:\n got %+v\nwant %+v",
			displacement.Finding.Evidence, wantDisplacementEvidence)
	}

	// After the backfill, generating again at threshold 2 creates nothing.
	again := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "2", "ops")
	if again.exitCode != 0 {
		t.Fatalf("third generate: exit=%d stderr=%q", again.exitCode, again.stderr)
	}
	if strings.TrimSpace(again.stdout) != "[]" {
		t.Fatalf("post-backfill generation must print [], got %q", again.stdout)
	}

	// History exposes both records for the channel and range, ordered by
	// height, block hash, tx hash and kind: same block, so 0xd precedes 0xv.
	history := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if history.exitCode != 0 {
		t.Fatalf("history: exit=%d stderr=%q", history.exitCode, history.stderr)
	}
	stored := parseAlertRecords(t, history.stdout)
	if len(stored) != 2 {
		t.Fatalf("history must list both records, got %d: %s", len(stored), history.stdout)
	}
	if stored[0].Finding.TxHash != "0xd" || stored[0].Finding.Kind != "displacement" ||
		stored[1].Finding.TxHash != "0xv" || stored[1].Finding.Kind != "sandwich" {
		t.Fatalf("history order wrong: %+v %+v", stored[0].Finding, stored[1].Finding)
	}
	// Each record keeps the threshold used at its own first processing:
	// the sandwich stays 3 even under the current threshold 2.
	if stored[1].MinSeverity != 3 || stored[0].MinSeverity != 2 {
		t.Fatalf("first-time thresholds not preserved: displacement=%d sandwich=%d",
			stored[0].MinSeverity, stored[1].MinSeverity)
	}
	for _, r := range stored {
		if r.Channel != "ops" || r.ChainID != "1" || r.BlockHash != "0xablock" ||
			r.BlockNumber != 10 || r.Status != mevwatch.AlertStatusAlert {
			t.Fatalf("history record identity/status wrong: %+v", r)
		}
		if r.Version.ID != "builtin" {
			t.Fatalf("history record must keep the archived builtin version, got %q", r.Version.ID)
		}
	}
	// History content matches the per-call outputs.
	if !reflect.DeepEqual(stored[0], displacement) || !reflect.DeepEqual(stored[1], sandwich) {
		t.Fatalf("history records differ from generation results:\n%+v\n%+v", stored[0], stored[1])
	}

	// The archived report still carries the original findings and evidence,
	// byte-for-byte the report snapshot taken before any generation, and the
	// conclusions embedded in the records match it exactly.
	afterReportRes := runCLI(t, "report", dir, "1", "0xablock")
	if afterReportRes.exitCode != 0 {
		t.Fatalf("report after generation: %q", afterReportRes.stderr)
	}
	if afterReportRes.stdout != beforeReportRes.stdout {
		t.Fatalf("generating alerts changed the archived report")
	}
	afterReport := parseCLIReport(t, afterReportRes.stdout)
	archivedSandwich := findingInReport(t, afterReport, "0xv", "sandwich")
	archivedDisplacement := findingInReport(t, afterReport, "0xd", "displacement")
	if !reflect.DeepEqual(archivedSandwich, sandwich.Finding) {
		t.Fatalf("record finding diverged from the report:\nrecord %+v\nreport %+v",
			sandwich.Finding, archivedSandwich)
	}
	if !reflect.DeepEqual(archivedDisplacement, displacement.Finding) {
		t.Fatalf("record finding diverged from the report:\nrecord %+v\nreport %+v",
			displacement.Finding, archivedDisplacement)
	}
	if !reflect.DeepEqual(afterReport.Version, sandwich.Version) {
		t.Fatalf("record version diverged from the archived report version")
	}

	// The other channel handled nothing: both its generation and history
	// stay empty, proving channel independence of the processed identities.
	otherChan := runCLI(t, "alerts", "history", dir, "1", "other", "0", "100")
	if otherChan.exitCode != 0 || strings.TrimSpace(otherChan.stdout) != "[]" {
		t.Fatalf("other channel history must be []: exit=%d stdout=%q", otherChan.exitCode, otherChan.stdout)
	}

	// Repeated offline invocations are deterministic.
	historyAgain := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if historyAgain.stdout != history.stdout {
		t.Fatalf("history output is not deterministic:\n%s\n%s", history.stdout, historyAgain.stdout)
	}
}

// TestCLIAlertsInvalidThreshold guards the user-facing threshold input
// validation: non-integer arguments are parameter errors, integers outside
// 1..5 are range errors; both fail with a non-zero exit, a reason on stderr
// and no success record on stdout. A rejected invocation neither consumes
// the pending conclusions nor disturbs alerts already generated.
func TestCLIAlertsInvalidThreshold(t *testing.T) {
	dir := setupAlertsCLIArchive(t)

	// An existing alert precedes the invalid attempts.
	first := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "3", "ops")
	if first.exitCode != 0 || len(parseAlertRecords(t, first.stdout)) != 1 {
		t.Fatalf("baseline generation failed: exit=%d stdout=%q stderr=%q",
			first.exitCode, first.stdout, first.stderr)
	}

	cases := []struct {
		name      string
		threshold string
		wantCode  int
		wantErr   string
	}{
		{"non-numeric", "abc", 2, "invalid minSeverity"},
		{"fraction", "2.5", 2, "invalid minSeverity"},
		{"trailing unit", "3x", 2, "invalid minSeverity"},
		{"empty string", "", 2, "invalid minSeverity"},
		{"zero", "0", 1, "minSeverity must be between 1 and 5"},
		{"negative", "-1", 1, "minSeverity must be between 1 and 5"},
		{"above range", "6", 1, "minSeverity must be between 1 and 5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", tc.threshold, "ops")
			if res.exitCode != tc.wantCode {
				t.Fatalf("threshold %q: exit = %d, want %d; stdout=%q stderr=%q",
					tc.threshold, res.exitCode, tc.wantCode, res.stdout, res.stderr)
			}
			if res.exitCode == 0 {
				t.Fatalf("threshold %q must not succeed", tc.threshold)
			}
			if res.stdout != "" {
				t.Fatalf("failure must print no success record, got stdout=%q", res.stdout)
			}
			if !strings.Contains(res.stderr, tc.wantErr) {
				t.Fatalf("threshold %q: stderr = %q, want substring %q",
					tc.threshold, res.stderr, tc.wantErr)
			}
			if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
				t.Fatalf("invalid threshold crashed instead of failing cleanly: %q", res.stderr)
			}
		})
	}

	// The failed attempts left both the existing alert and the pending
	// displacement untouched: a valid threshold 2 still backfills exactly
	// the displacement once.
	backfill := runCLI(t, "alerts", "generate", dir, "1", "0", "100", "2", "ops")
	if backfill.exitCode != 0 {
		t.Fatalf("backfill after invalid attempts: exit=%d stderr=%q", backfill.exitCode, backfill.stderr)
	}
	records := parseAlertRecords(t, backfill.stdout)
	if len(records) != 1 || records[0].Finding.TxHash != "0xd" ||
		records[0].Finding.Kind != "displacement" || records[0].MinSeverity != 2 {
		t.Fatalf("valid threshold must still backfill the pending displacement, got %s", backfill.stdout)
	}

	// History shows exactly the two alerts, first-time thresholds preserved.
	history := runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	stored := parseAlertRecords(t, history.stdout)
	if len(stored) != 2 {
		t.Fatalf("invalid attempts must not add records, history = %s", history.stdout)
	}
	byTx := map[string]mevwatch.ProcessingRecord{}
	for _, r := range stored {
		byTx[r.Finding.TxHash] = r
	}
	s, okS := byTx["0xv"]
	d, okD := byTx["0xd"]
	if !okS || s.MinSeverity != 3 || !okD || d.MinSeverity != 2 {
		t.Fatalf("thresholds/records after invalid attempts wrong: %+v %+v", s, d)
	}
}
