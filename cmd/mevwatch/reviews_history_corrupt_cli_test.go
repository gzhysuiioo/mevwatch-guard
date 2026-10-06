package main

// End-to-end regression coverage for `reviews history` through the real
// command entry point (see TestMain): once the query hits the original
// archived conclusion, the version declaration that conclusion's report
// saved must pass the same integrity proof a `report` query enforces
// before any history JSON is printed. A written null used to be explained
// as the built-in rules and an incomplete declaration used to return the
// original under silently zeroed parameters. On a damaged historical
// declaration the command exits 1, prints no history JSON on stdout, and
// names the target chain, block, the readable saved version id and the
// offending rule or field on stderr. Success or failure leaves the
// archive untouched.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupCLIReviewArchive archives one block with a sandwich conclusion on
// 0xv under the built-in rules and records one real review on it, so the
// history query has both an original conclusion and a stored revision.
func setupCLIReviewArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	input := cliBlockLine("1", "0xa", 10,
		cliSwapRecord("0xf", "p1", "bot", 90, 0),
		cliSwapRecord("0xv", "p1", "user", 10, 1),
		cliSwapRecord("0+k", "p1", "bot", 80, 2),
	)
	if _, err := mevwatch.Replay(strings.NewReader(input), dir); err != nil {
		t.Fatal(err)
	}
	_, err := mevwatch.SubmitReview(dir, mevwatch.ReviewSubmission{
		ChainID: "1", BlockHash: "0xa", TxHash: "0xv", Kind: "sandwich",
		SubmissionID: "s1", Operator: "op", Reason: "looks real", Status: "real",
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestCLIReviewsHistoryCorruptHistoricalDeclaration pins the CLI failure
// shape for a damaged declaration embedded in the targeted report.
func TestCLIReviewsHistoryCorruptHistoricalDeclaration(t *testing.T) {
	dir := setupCLIReviewArchive(t)

	// Drop the displacement multiplier only from the report's own embedded
	// declaration; the archive has no registry entry to borrow from.
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		ver := rec["version"].(map[string]any)
		rules := ver["rules"].(map[string]any)
		disp := rules["displacement"].(map[string]any)
		delete(disp, "multiplier")
	})

	before, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt historical declaration must print no history JSON, got %q", res.stdout)
	}
	for _, want := range []string{
		"corrupt",      // ErrCorruptVersion
		"chain 1",      // target chain
		"block 0xa",    // target block
		"builtin",      // readable historical version id
		"multiplier",   // offending field
		"displacement", // offending rule
	} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
		t.Fatalf("reviews history crashed instead of failing cleanly: %q", res.stderr)
	}

	// The failed query is read-only and never returns a partial history.
	after, err := os.ReadFile(filepath.Join(dir, "archive.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("failed history query changed the archive")
	}
	again := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if again.exitCode != 1 || again.stdout != "" || !strings.Contains(again.stderr, "corrupt") {
		t.Fatalf("second query must fail the same way: exit=%d stdout=%q stderr=%q",
			again.exitCode, again.stdout, again.stderr)
	}

	// An identity no archived conclusion matches never opens the damaged
	// declaration: it keeps the unreviewed, original:null shape at exit 0.
	missing := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xghost", "sandwich")
	if missing.exitCode != 0 || !strings.Contains(missing.stdout, `"original":null`) ||
		!strings.Contains(missing.stdout, `"status":"unreviewed"`) {
		t.Fatalf("unmatched identity changed shape: exit=%d stdout=%q stderr=%q",
			missing.exitCode, missing.stdout, missing.stderr)
	}
}

// TestCLIReviewsHistoryNullHistoricalVersionCorrupt pins the exact misread
// being fixed: a written "version":null on the targeted report must fail
// rather than explain the original conclusion as the built-in rules.
func TestCLIReviewsHistoryNullHistoricalVersionCorrupt(t *testing.T) {
	dir := setupCLIReviewArchive(t)
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		rec["version"] = nil
	})
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("null historical version must print no history JSON, got %q", res.stdout)
	}
	if !strings.Contains(res.stderr, "corrupt") ||
		!strings.Contains(res.stderr, "chain 1") ||
		!strings.Contains(res.stderr, "block 0xa") {
		t.Fatalf("stderr must report a corrupt declaration naming chain and block: %q", res.stderr)
	}
}

// TestCLIReviewsHistoryIntactDeclarationUnchanged proves the fix does not
// alter the success path: an intact archive returns the current status, the
// version, every revision and the original conclusion with its saved
// parameters and swap evidence, at exit 0.
func TestCLIReviewsHistoryIntactDeclarationUnchanged(t *testing.T) {
	dir := setupCLIReviewArchive(t)
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 0 {
		t.Fatalf("intact history must succeed: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	for _, want := range []string{
		`"status":"real"`, `"version":1`, `"submissionId":"s1"`,
		`"id":"builtin"`, `"multiplier":2`, `"txHash":"0xv"`, `"evidence"`,
	} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("stdout = %q, want substring %q", res.stdout, want)
		}
	}
}
