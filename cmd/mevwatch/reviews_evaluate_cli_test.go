package main

// End-to-end regression coverage for `reviews evaluate` against a corrupt
// registered rule version: the command must fail with a non-zero exit, name
// the archived corrupt version and the offending rule or field on stderr,
// print no success statistics JSON, and never crash with a stack trace on
// an invalid multiplier — while intact versions on the same archive keep
// evaluating normally.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// setupEvaluateCLIArchive archives one block with a sandwich and a
// displacement under the built-in rules, registers strict (mult 5) and
// mult3, submits one real and one false-positive review, and deletes the
// source input file before returning.
func setupEvaluateCLIArchive(t *testing.T) (dir string) {
	t.Helper()
	dir = t.TempDir()
	inputPath := filepath.Join(t.TempDir(), "blocks.jsonl")
	input := cliBlockLine("1", "0xa", 10,
		cliSwapRecord("0xf", "p1", "bot", 90, 0),
		cliSwapRecord("0xv", "p1", "user", 10, 1),
		cliSwapRecord("0xb", "p1", "bot", 80, 2),
		cliSwapRecord("0xw", "p2", "whale", 50, 3),
		cliSwapRecord("0xd", "p2", "user", 10, 4),
	) + "\n"
	if err := os.WriteFile(inputPath, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	const (
		strict = `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
		mult3  = `{"id":"mult3","rules":{"sandwich":{"enabled":true,"severity":3},"displacement":{"enabled":true,"severity":2,"multiplier":3}}}`
	)
	for _, spec := range []string{strict, mult3} {
		if _, _, err := mevwatch.RegisterVersion(dir, []byte(spec)); err != nil {
			t.Fatalf("RegisterVersion: %v", err)
		}
	}
	if _, err := mevwatch.ReplayFile(inputPath, dir); err != nil {
		t.Fatalf("ReplayFile: %v", err)
	}
	reviews := []mevwatch.ReviewSubmission{
		{ChainID: "1", BlockHash: "0xa", TxHash: "0xv", Kind: "sandwich",
			SubmissionID: "r", Operator: "op", Reason: "real", Status: mevwatch.ReviewStatusReal},
		{ChainID: "1", BlockHash: "0xa", TxHash: "0xd", Kind: "displacement",
			SubmissionID: "f", Operator: "op", Reason: "fp", Status: mevwatch.ReviewStatusFalsePositive},
	}
	for _, sub := range reviews {
		if _, err := mevwatch.SubmitReview(dir, sub); err != nil {
			t.Fatalf("SubmitReview: %v", err)
		}
	}
	if err := os.Remove(inputPath); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCLIReviewsEvaluateCorruptVersion(t *testing.T) {
	dir := setupEvaluateCLIArchive(t)
	// The stored strict document loses its displacement multiplier: valid
	// JSON, but no longer a complete rule declaration.
	corruptStoredVersion(t, dir, "strict", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})

	res := runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "strict")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("corrupt version must print no success JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "strict", "multiplier"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
	if strings.Contains(res.stderr, "unknown version") {
		t.Fatalf("corruption misreported as unknown version: %q", res.stderr)
	}
	// No panic or goroutine stack trace from the invalid multiplier.
	for _, crash := range []string{"panic", "goroutine "} {
		if strings.Contains(res.stderr, crash) {
			t.Fatalf("stderr shows a crash (%q): %q", crash, res.stderr)
		}
	}

	// A range with no blocks in it fails the same way.
	res = runCLI(t, "reviews", "evaluate", dir, "1", "500", "600", "strict")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "corrupt") || res.stdout != "" {
		t.Fatalf("empty range: exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}

	// An unregistered version stays a plain unknown-version failure.
	res = runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", "nope")
	if res.exitCode != 1 || !strings.Contains(res.stderr, "unknown version: nope") ||
		strings.Contains(res.stderr, "corrupt") {
		t.Fatalf("unknown version failure changed shape: exit=%d stderr=%q", res.exitCode, res.stderr)
	}

	// The corrupt sibling does not contaminate intact versions: mult3 and
	// builtin still evaluate and print the statistics JSON.
	for _, id := range []string{"mult3", "builtin"} {
		res = runCLI(t, "reviews", "evaluate", dir, "1", "0", "100", id)
		if res.exitCode != 0 {
			t.Fatalf("evaluate under intact %s failed: %d %q", id, res.exitCode, res.stderr)
		}
		if !strings.Contains(res.stdout, `"retained":1`) || !strings.Contains(res.stdout, `"stillHit":1`) {
			t.Fatalf("evaluate under intact %s misjudged: %q", id, res.stdout)
		}
	}
}
