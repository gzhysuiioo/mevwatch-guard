package main

// End-to-end regression coverage for the historical side of `reviews
// evaluate` through the real command entry point (see TestMain): every
// archived report inside the selected chain and inclusive height range
// must pass the same integrity proof a `report` query enforces before
// any statistics or details JSON is printed. A written null used to be
// explained as the built-in rules and an incomplete declaration used to
// evaluate under zeroed parameters. On a damaged historical declaration
// the command exits 1, prints nothing on stdout, and names the chain,
// the block, the readable saved version id and the offending rule or
// field on stderr — even for a block with no swaps, no conclusions or
// no review. A damaged report on another chain or outside the range
// never blocks. Success or failure leaves the archive untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// TestCLIReviewEvaluateCorruptHistoricalDeclaration pins the CLI
// failure shape for a damaged historical declaration while the
// candidate (mult3) stays perfectly legal.
func TestCLIReviewEvaluateCorruptHistoricalDeclaration(t *testing.T) {
	dir := setupReviewCLIArchive(t)

	// The report was archived under builtin; drop the displacement
	// multiplier only from its embedded declaration while the mult3
	// candidate registry entry stays intact. corruptStoredReportVersion
	// (from the compare CLI tests) rewrites the record's own embedded
	// declaration, not the versions-registry entry.
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		ver := rec["version"].(map[string]any)
		disp := ver["rules"].(map[string]any)["displacement"].(map[string]any)
		delete(disp, "multiplier")
	})

	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "mult3")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("corrupt historical declaration must print no statistics JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"corrupt",      // ErrCorruptVersion
		"chain 1",      // report chain
		"block 0xa",    // report block
		"builtin",      // readable historical version id written in the report
		"multiplier",   // offending field
		"displacement", // offending rule
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("evaluation crashed instead of failing cleanly: %q", res.stderr)
	}

	// A legal candidate can never rescue the historical declaration:
	// the intact builtin candidate fails the same way.
	for _, candidate := range []string{"builtin", "mult3"} {
		again := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", candidate)
		if again.exitCode != 1 || strings.TrimSpace(again.stdout) != "" ||
			!strings.Contains(again.stderr, "corrupt") ||
			!strings.Contains(again.stderr, "block 0xa") ||
			!strings.Contains(again.stderr, "multiplier") {
			t.Fatalf("candidate %s must not rescue the corrupt report: exit=%d stdout=%q stderr=%q",
				candidate, again.exitCode, again.stdout, again.stderr)
		}
	}

	// Other read entries name the same damage.
	if report := runCLI(t, "report", dir, "1", "0xa"); report.exitCode != 1 ||
		!strings.Contains(report.stderr, "corrupt") || report.stdout != "" {
		t.Fatalf("report on the same record must keep failing: exit=%d stdout=%q stderr=%q",
			report.exitCode, report.stdout, report.stderr)
	}

	// The stored review revision is untouched and still readable.
	hist := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	if hist.exitCode != 0 || !strings.Contains(hist.stdout, `"status":"false_positive"`) {
		t.Fatalf("review history changed after refused evaluation: exit=%d stdout=%q stderr=%q",
			hist.exitCode, hist.stdout, hist.stderr)
	}

	// A range that excludes the damaged block prints an empty success
	// result: out-of-range reports are never read.
	excluded := runCLI(t, "reviews", "evaluate", dir, "1", "11", "100", "mult3")
	if excluded.exitCode != 0 {
		t.Fatalf("out-of-range corrupt report must not block: %q", excluded.stderr)
	}
	var empty struct {
		Retained   int `json:"retained"`
		Missed     int `json:"missed"`
		StillHit   int `json:"stillHit"`
		Eliminated int `json:"eliminated"`
		Pending    int `json:"pending"`
		Details    []any
	}
	if err := json.Unmarshal([]byte(excluded.stdout), &empty); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, excluded.stdout)
	}
	if empty.Retained+empty.Missed+empty.StillHit+empty.Eliminated+empty.Pending != 0 || len(empty.Details) != 0 {
		t.Fatalf("excluding range must be empty: %s", excluded.stdout)
	}
}

// TestCLIReviewEvaluateNullHistoricalVersionCorrupt pins the exact
// misread being fixed: a written "version":null on the report must fail
// rather than be explained as the built-in rules, even for a no-swap
// block, and the message still says which report is broken.
func TestCLIReviewEvaluateNullHistoricalVersionCorrupt(t *testing.T) {
	dir := t.TempDir()
	const mult3 = `{"id":"mult3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(mult3)); err != nil {
		t.Fatal(err)
	}
	input := cliBlockLine("1", "0empty", 3, []cliSwap{}...)
	if _, err := mevwatch.ReplayFileWithVersion(writeCLILines(t, input), dir, "mult3"); err != nil {
		t.Fatal(err)
	}
	corruptStoredReportVersion(t, dir, "1", "0empty", func(rec map[string]any) {
		rec["version"] = nil
	})
	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "mult3")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if strings.TrimSpace(res.stdout) != "" {
		t.Fatalf("null historical version must print no statistics JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "chain 1", "block 0empty", "null"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
}

// TestCLIReviewEvaluateOtherChainCorruptDoesNotBlock proves a damaged
// declaration on another chain never blocks the selected chain's
// evaluation, while evaluating that chain itself still fails.
func TestCLIReviewEvaluateOtherChainCorruptDoesNotBlock(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	// A second block at the same height on chain 2.
	input := cliBlockLine("2", "0xa2", 10,
		cliSwapRecord("0q0", "pq", "tq", 70, 0),
		cliSwapRecord("0q1", "pq", "u2", 10, 1),
	)
	if _, err := mevwatch.ReplayFile(writeCLILines(t, input), dir); err != nil {
		t.Fatalf("ReplayFile: %v", err)
	}
	corruptStoredReportVersion(t, dir, "2", "0xa2", func(rec map[string]any) {
		delete(rec["version"].(map[string]any)["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	// Chain 1 evaluates normally: the false-positive displacement still
	// hits under mult3, the unreviewed sandwich is pending.
	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "mult3")
	if res.exitCode != 0 {
		t.Fatalf("a corrupt other-chain report must not block: %q", res.stderr)
	}
	var eval struct {
		StillHit int `json:"stillHit"`
		Pending  int `json:"pending"`
		Details  []struct {
			ChainID string `json:"chainId"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &eval); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if eval.StillHit != 1 || eval.Pending != 1 {
		t.Fatalf("chain-1 stats wrong: %s", res.stdout)
	}
	for _, d := range eval.Details {
		if d.ChainID != "1" {
			t.Fatalf("other-chain detail leaked into chain-1 evaluation")
		}
	}

	// Evaluating chain 2 itself fails outright.
	bad := runCLI(t, "reviews", "evaluate", dir, "2", "0", "100", "mult3")
	if bad.exitCode != 1 || strings.TrimSpace(bad.stdout) != "" ||
		!strings.Contains(bad.stderr, "corrupt") ||
		!strings.Contains(bad.stderr, "chain 2") ||
		!strings.Contains(bad.stderr, "block 0xa2") {
		t.Fatalf("damaged chain must fail its own evaluation: exit=%d stdout=%q stderr=%q",
			bad.exitCode, bad.stdout, bad.stderr)
	}
}

// TestCLIReviewEvaluateLegacyHistoricalVersionStillBuiltin proves the
// single carve-out still works through the CLI: a record with no
// version key evaluates with the built-in historical side and its
// review classification intact.
func TestCLIReviewEvaluateLegacyHistoricalVersionStillBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "archive.json"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	const mult3 = `{"id":"mult3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	if _, _, err := mevwatch.RegisterVersion(dir, []byte(mult3)); err != nil {
		t.Fatal(err)
	}
	sub := mevwatch.ReviewSubmission{
		ChainID: "1", BlockHash: "0old", TxHash: "0v", Kind: "sandwich",
		SubmissionID: "s-1", Operator: "alice", Reason: "r",
		Status: mevwatch.ReviewStatusReal, ExpectedVersion: 0,
	}
	if _, err := mevwatch.SubmitReview(dir, sub); err != nil {
		t.Fatalf("SubmitReview: %v", err)
	}

	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "mult3")
	if res.exitCode != 0 {
		t.Fatalf("legacy record must evaluate under builtin: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	var eval struct {
		Retained int `json:"retained"`
		Details  []struct {
			Bucket   string `json:"bucket"`
			Original struct {
				Version struct {
					ID string `json:"id"`
				} `json:"version"`
				Finding struct {
					Severity int   `json:"severity"`
					Evidence []any `json:"evidence"`
				} `json:"finding"`
			} `json:"original"`
			Candidate struct {
				Version struct {
					ID string `json:"id"`
				} `json:"version"`
			} `json:"candidate"`
			AppliedRevision struct {
				SubmissionID string `json:"submissionId"`
			} `json:"appliedRevision"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &eval); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, res.stdout)
	}
	if eval.Retained != 1 || len(eval.Details) != 1 {
		t.Fatalf("legacy evaluation stats wrong: %s", res.stdout)
	}
	d := eval.Details[0]
	if d.Bucket != "retained" || d.Original.Version.ID != "builtin" ||
		d.Candidate.Version.ID != "mult3" || d.AppliedRevision.SubmissionID != "s-1" {
		t.Fatalf("legacy detail wrong: %+v", d)
	}
	if d.Original.Finding.Severity != 3 || len(d.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy findings/evidence damaged: %+v", d.Original.Finding)
	}
}

// writeCLILines writes one JSON block line to a temp file and returns
// its path for the file-based replay entries.
func writeCLILines(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blocks.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
