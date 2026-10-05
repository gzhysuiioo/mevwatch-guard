package main

// End-to-end regression coverage for the `alerts generate` and
// `alerts history` command entry points, focused on threshold-reduction
// backfill: a finding archived below the generation threshold leaves no
// processing record, so lowering the threshold later must still produce it
// exactly once, while identities already processed under the higher
// threshold are never re-emitted. The tests drive the real CLI (forked
// test binary, see TestMain), parse the stdout JSON the way a user script
// would, and confirm through `alerts history` and `report` that records
// keep their first-processing threshold, channel, block identity,
// conclusion, detection version and raw swap evidence — even when a
// different rule version is enabled between the two generations.
// Everything runs offline against archive directories under t.TempDir.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// alertSwap builds one swap record with distinctive raw values so the
// tests can prove evidence keeps every original field and number.
func alertSwap(tx, pool, trader string, in, out, gas int64, index int) cliSwap {
	return map[string]any{
		"TxHash": tx, "Pool": pool, "Trader": trader,
		"In": in, "Out": out, "GasPrice": gas, "Index": index,
	}
}

// setupAlertsCLIArchive archives one block on chain "1" (hash 0xa, height
// 10) under the built-in rules, carrying two conclusions and no matching
// suppression condition:
//
//	p1: 0xf (bot, gas 90) / 0xv (user, gas 10) / 0+k (bot, gas 80)
//	    -> sandwich on 0xv, severity 3
//	p2: 0+w (whale, gas 50) / 0xd (user, gas 10)
//	    -> displacement on 0xd, severity 2
//
// The source input file is deleted before returning: everything the tests
// assert afterwards must come from the archive alone.
func setupAlertsCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	line := cliBlockLine("1", "0xa", 10,
		alertSwap("0xf", "p1", "bot", 500, 480, 90, 0),
		alertSwap("0xv", "p1", "user", 200, 188, 10, 1),
		alertSwap("0+k", "p1", "bot", 480, 505, 80, 2),
		alertSwap("0+w", "p2", "whale", 700, 690, 50, 3),
		alertSwap("0xd", "p2", "user", 300, 295, 10, 4),
	)
	if err := os.WriteFile(inputPath, []byte(line+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mevwatch.ReplayFile(inputPath, dir); err != nil {
		t.Fatalf("ReplayFile: %v", err)
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

// generateAlertsCLI runs `alerts generate` for channel ops over the
// inclusive range 0..100 and requires a clean success.
func generateAlertsCLI(t *testing.T, dir, minSeverity string) cliResult {
	t.Helper()
	res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", minSeverity, "ops")
	if res.exitCode != 0 {
		t.Fatalf("alerts generate (minSeverity %s) exit=%d stderr=%q", minSeverity, res.exitCode, res.stderr)
	}
	if strings.TrimSpace(res.stderr) != "" {
		t.Fatalf("unexpected stderr: %q", res.stderr)
	}
	return res
}

// parseAlertRecords requires stdout to be exactly one JSON array of
// processing records and returns it.
func parseAlertRecords(t *testing.T, raw string) []mevwatch.ProcessingRecord {
	t.Helper()
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("stdout is not a JSON array: %q", raw)
	}
	var records []mevwatch.ProcessingRecord
	if err := json.Unmarshal([]byte(trimmed), &records); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, raw)
	}
	return records
}

// wantSwap is the full raw field set of one evidence swap.
type wantSwap struct {
	tx, pool, trader string
	in, out, gas     int64
	index            int
}

func checkEvidence(t *testing.T, label string, got []mevwatch.Swap, want []wantSwap) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d evidence swaps, want %d: %+v", label, len(got), len(want), got)
	}
	for i, w := range want {
		s := got[i]
		if s.TxHash != w.tx || s.Pool != w.pool || s.Trader != w.trader ||
			s.In != w.in || s.Out != w.out || s.GasPrice != w.gas || s.Index != w.index {
			t.Fatalf("%s: evidence[%d] = %+v, want tx=%s pool=%s trader=%s in=%d out=%d gas=%d index=%d",
				label, i, s, w.tx, w.pool, w.trader, w.in, w.out, w.gas, w.index)
		}
	}
}

// checkBuiltinVersion requires the record to carry the built-in detection
// version with its complete parameters — proof that generation consumed
// the archived conclusion instead of re-judging under the currently
// enabled version.
func checkBuiltinVersion(t *testing.T, label string, v mevwatch.RuleVersion) {
	t.Helper()
	if v.ID != mevwatch.BuiltinVersionID ||
		!v.Rules.Sandwich.Enabled || v.Rules.Sandwich.Severity != 3 ||
		!v.Rules.Displacement.Enabled || v.Rules.Displacement.Severity != 2 ||
		v.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("%s: record must keep the archived builtin version with full params, got %+v", label, v)
	}
}

var (
	sandwichEvidence = []wantSwap{
		{"0xf", "p1", "bot", 500, 480, 90, 0},
		{"0xv", "p1", "user", 200, 188, 10, 1},
		{"0+k", "p1", "bot", 480, 505, 80, 2},
	}
	displacementEvidence = []wantSwap{
		{"0+w", "p2", "whale", 700, 690, 50, 3},
		{"0xd", "p2", "user", 300, 295, 10, 4},
	}
)

// TestCLIAlertsGenerateThresholdBackfill is the core scenario: threshold 3
// processes only the sandwich (severity equal to the threshold counts);
// lowering the threshold to 2 — after enabling a different rule version —
// backfills exactly the displacement, consuming the archived conclusion;
// a further run at threshold 2 finds nothing left.
func TestCLIAlertsGenerateThresholdBackfill(t *testing.T) {
	dir := setupAlertsCLIArchive(t)

	// First generation at threshold 3: only the severity-3 sandwich.
	res := generateAlertsCLI(t, dir, "3")
	first := parseAlertRecords(t, res.stdout)
	if len(first) != 1 {
		t.Fatalf("threshold 3 produced %d records, want exactly the sandwich: %s", len(first), res.stdout)
	}
	sand := first[0]
	if sand.ChainID != "1" || sand.BlockHash != "0xa" || sand.BlockNumber != 10 ||
		sand.Channel != "ops" || sand.Pool != "p1" {
		t.Fatalf("sandwich record identity wrong: %+v", sand)
	}
	if sand.Finding.Kind != "sandwich" || sand.Finding.TxHash != "0xv" || sand.Finding.Severity != 3 {
		t.Fatalf("sandwich conclusion wrong: %+v", sand.Finding)
	}
	if sand.MinSeverity != 3 {
		t.Fatalf("sandwich record threshold = %d, want 3", sand.MinSeverity)
	}
	if sand.Status != mevwatch.AlertStatusAlert {
		t.Fatalf("sandwich status = %q, want alert", sand.Status)
	}
	if len(sand.Suppressions) != 0 || !strings.Contains(res.stdout, `"suppressions":[]`) {
		t.Fatalf("no suppression matched: list must serialize as [], got %s", res.stdout)
	}
	checkBuiltinVersion(t, "first generation", sand.Version)
	checkEvidence(t, "first generation", sand.Finding.Evidence, sandwichEvidence)

	// Between the two generations the user registers and enables a rule
	// version with different parameters through the regular CLI.
	specPath := filepath.Join(t.TempDir(), "strict.json")
	const strict = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	if err := os.WriteFile(specPath, []byte(strict), 0o644); err != nil {
		t.Fatal(err)
	}
	if res := runCLI(t, "rules", "register", dir, specPath); res.exitCode != 0 {
		t.Fatalf("rules register: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if res := runCLI(t, "rules", "enable", dir, "strict"); res.exitCode != 0 {
		t.Fatalf("rules enable: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// Lowering the threshold to 2 backfills only the displacement: the
	// first run's sandwich record must not be mixed in, and the skipped
	// displacement was not permanently excluded.
	res = generateAlertsCLI(t, dir, "2")
	second := parseAlertRecords(t, res.stdout)
	if len(second) != 1 {
		t.Fatalf("threshold 2 backfill produced %d records, want exactly the displacement: %s", len(second), res.stdout)
	}
	disp := second[0]
	if disp.Finding.Kind != "displacement" || disp.Finding.TxHash != "0xd" {
		t.Fatalf("backfill must return only the displacement, got %+v", disp.Finding)
	}
	if disp.Finding.Severity != 2 {
		t.Fatalf("backfill re-judged the archived conclusion: severity = %d, want 2", disp.Finding.Severity)
	}
	if disp.MinSeverity != 2 {
		t.Fatalf("displacement record threshold = %d, want 2", disp.MinSeverity)
	}
	if disp.ChainID != "1" || disp.BlockHash != "0xa" || disp.BlockNumber != 10 ||
		disp.Channel != "ops" || disp.Pool != "p2" {
		t.Fatalf("displacement record identity wrong: %+v", disp)
	}
	if disp.Status != mevwatch.AlertStatusAlert {
		t.Fatalf("displacement status = %q, want alert", disp.Status)
	}
	if len(disp.Suppressions) != 0 || !strings.Contains(res.stdout, `"suppressions":[]`) {
		t.Fatalf("no suppression matched: list must serialize as [], got %s", res.stdout)
	}
	// The enabled strict version must not leak into the backfill: the
	// record consumes the archived builtin conclusion and parameters.
	checkBuiltinVersion(t, "backfill", disp.Version)
	checkEvidence(t, "backfill", disp.Finding.Evidence, displacementEvidence)

	// After the backfill, generating again at threshold 2 yields [].
	res = generateAlertsCLI(t, dir, "2")
	if strings.TrimSpace(res.stdout) != "[]" {
		t.Fatalf("post-backfill generation must print [], got %q", res.stdout)
	}

	// History shows both records, each keeping the threshold of its own
	// first processing, attributed to the user's channel.
	res = runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if res.exitCode != 0 {
		t.Fatalf("alerts history: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseAlertRecords(t, res.stdout)
	if len(hist) != 2 {
		t.Fatalf("history holds %d records, want 2: %s", len(hist), res.stdout)
	}
	byKind := map[string]mevwatch.ProcessingRecord{}
	for _, r := range hist {
		if r.Channel != "ops" || r.ChainID != "1" || r.BlockHash != "0xa" || r.BlockNumber != 10 {
			t.Fatalf("history record identity wrong: %+v", r)
		}
		if r.Status != mevwatch.AlertStatusAlert || len(r.Suppressions) != 0 {
			t.Fatalf("history record status/suppressions wrong: %+v", r)
		}
		checkBuiltinVersion(t, "history "+r.Finding.Kind, r.Version)
		byKind[r.Finding.Kind] = r
	}
	hs, okS := byKind["sandwich"]
	hd, okD := byKind["displacement"]
	if !okS || !okD {
		t.Fatalf("history must hold both conclusions, got %+v", byKind)
	}
	if hs.MinSeverity != 3 || hd.MinSeverity != 2 {
		t.Fatalf("records must keep first-processing thresholds 3 and 2, got %d and %d",
			hs.MinSeverity, hd.MinSeverity)
	}
	if hs.Finding.Severity != 3 || hd.Finding.Severity != 2 {
		t.Fatalf("history conclusions changed: %+v / %+v", hs.Finding, hd.Finding)
	}
	checkEvidence(t, "history sandwich", hs.Finding.Evidence, sandwichEvidence)
	checkEvidence(t, "history displacement", hd.Finding.Evidence, displacementEvidence)

	// Records belong to the user's channel only.
	res = runCLI(t, "alerts", "history", dir, "1", "other", "0", "100")
	if res.exitCode != 0 || strings.TrimSpace(res.stdout) != "[]" {
		t.Fatalf("other channel history must be [], exit=%d stdout=%q", res.exitCode, res.stdout)
	}

	// The archived report itself is untouched: same conclusions, same
	// evidence, still explained by the built-in version.
	res = runCLI(t, "report", dir, "1", "0xa")
	if res.exitCode != 0 {
		t.Fatalf("report: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil {
		t.Fatalf("report stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	checkBuiltinVersion(t, "report", report.Version)
	if len(report.Findings) != 2 {
		t.Fatalf("report findings changed: %+v", report.Findings)
	}
	reportByKind := map[string]mevwatch.ReportFinding{}
	for _, f := range report.Findings {
		reportByKind[f.Kind] = f
	}
	if reportByKind["sandwich"].Severity != 3 || reportByKind["sandwich"].TxHash != "0xv" ||
		reportByKind["displacement"].Severity != 2 || reportByKind["displacement"].TxHash != "0xd" {
		t.Fatalf("report conclusions changed by alerting: %+v", report.Findings)
	}
	checkEvidence(t, "report sandwich", reportByKind["sandwich"].Evidence, sandwichEvidence)
	checkEvidence(t, "report displacement", reportByKind["displacement"].Evidence, displacementEvidence)
}

// TestCLIAlertsGenerateInvalidThreshold covers the failure shapes: a
// non-integer threshold is an argument error, an integer outside 1..5 is a
// threshold-range error; both exit non-zero, explain themselves on stderr
// and print no success records. The failures leave existing alerts and
// still-pending conclusions untouched, so a later valid threshold produces
// exactly the expected backfill.
func TestCLIAlertsGenerateInvalidThreshold(t *testing.T) {
	dir := setupAlertsCLIArchive(t)

	// One successful generation first, so the failures below have existing
	// alerts to protect and the displacement stays pending.
	res := generateAlertsCLI(t, dir, "3")
	if got := parseAlertRecords(t, res.stdout); len(got) != 1 {
		t.Fatalf("precondition: threshold 3 produced %d records, want 1", len(got))
	}

	cases := []struct {
		name     string
		arg      string
		wantCode int
		wantErr  string
	}{
		{"non-integer", "abc", 2, "invalid minSeverity"},
		{"fractional", "2.5", 2, "invalid minSeverity"},
		{"zero", "0", 1, "minSeverity must be between 1 and 5"},
		{"negative", "-1", 1, "minSeverity must be between 1 and 5"},
		{"above range", "6", 1, "minSeverity must be between 1 and 5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, "alerts", "generate", dir, "1", "0", "100", tc.arg, "ops")
			if res.exitCode != tc.wantCode {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q",
					res.exitCode, tc.wantCode, res.stdout, res.stderr)
			}
			if res.stdout != "" {
				t.Fatalf("failed generation must print no success records, got %q", res.stdout)
			}
			if !strings.Contains(res.stderr, tc.wantErr) {
				t.Fatalf("stderr = %q, want substring %q", res.stderr, tc.wantErr)
			}
		})
	}

	// The failures changed nothing: history still holds exactly the
	// sandwich alert from the first generation...
	res = runCLI(t, "alerts", "history", dir, "1", "ops", "0", "100")
	if res.exitCode != 0 {
		t.Fatalf("alerts history: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseAlertRecords(t, res.stdout)
	if len(hist) != 1 || hist[0].Finding.Kind != "sandwich" || hist[0].MinSeverity != 3 {
		t.Fatalf("failed generations damaged stored alerts: %+v", hist)
	}

	// ...and the still-pending displacement backfills normally with a
	// valid threshold.
	res = generateAlertsCLI(t, dir, "2")
	backfill := parseAlertRecords(t, res.stdout)
	if len(backfill) != 1 || backfill[0].Finding.Kind != "displacement" ||
		backfill[0].Finding.TxHash != "0xd" || backfill[0].MinSeverity != 2 {
		t.Fatalf("post-failure backfill wrong: %+v", backfill)
	}
}
