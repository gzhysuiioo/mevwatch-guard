package main

// End-to-end regression coverage for `reviews submit` spec intake. The
// review submission, whether read from a file or standard input, must be
// exactly one complete JSON object: a stray '}' or ']', a second object or
// any other non-whitespace content after the closing brace must fail the
// whole command through stderr (exit 1, no success JSON on stdout), leave
// the review object untouched and leave the submission id free.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runCLIStdin executes the real command entry with the given arguments and
// pipes input into the command's standard input.
func runCLIStdin(t *testing.T, input string, args ...string) cliResult {
	t.Helper()
	cmd := execCommand(args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		code = exitCode(t, err)
	}
	return cliResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

// setupReviewCLIArchive (defined in compare_cli_test.go) already builds an
// archive whose block 0xa carries an unreviewed sandwich on 0xv, which is
// the object these submit tests target.

const cliReviewSpec = `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"r-1","operator":"alice","reason":"confirmed bot war","status":"real","expectedVersion":0}`

func reviewHistoryState(t *testing.T, dir string) (status string, version int, revisions int) {
	t.Helper()
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 0 {
		t.Fatalf("history failed: %s", res.stderr)
	}
	var hist struct {
		Status    string           `json:"status"`
		Version   int              `json:"version"`
		Revisions []map[string]any `json:"revisions"`
	}
	if err := json.Unmarshal([]byte(res.stdout), &hist); err != nil {
		t.Fatalf("decode history %q: %v", res.stdout, err)
	}
	return hist.Status, hist.Version, len(hist.Revisions)
}

// TestReviewsSubmitTrailingBracketsRejectedFromFileAndStdin drives the real
// command both ways a user supplies a spec and proves trailing } and ]
// never create a revision.
func TestReviewsSubmitTrailingBracketsRejectedFromFileAndStdin(t *testing.T) {
	dir := setupReviewCLIArchive(t)

	for _, suffix := range []string{"}", "]", " " + cliReviewSpec, " extra"} {
		corrupt := cliReviewSpec + suffix

		// From a spec file.
		specPath := filepath.Join(t.TempDir(), "review.json")
		if err := os.WriteFile(specPath, []byte(corrupt), 0o644); err != nil {
			t.Fatal(err)
		}
		res := runCLI(t, "reviews", "submit", dir, specPath)
		if res.exitCode != 1 {
			t.Fatalf("file submit of corrupt spec (suffix %q) exited %d", suffix, res.exitCode)
		}
		if strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("file submit of corrupt spec (suffix %q) wrote success output: %q", suffix, res.stdout)
		}
		if !strings.Contains(res.stderr, "trailing") {
			t.Fatalf("file submit of corrupt spec (suffix %q) stderr = %q, want trailing-data error", suffix, res.stderr)
		}

		// From standard input.
		res = runCLIStdin(t, corrupt, "reviews", "submit", dir, "-")
		if res.exitCode != 1 {
			t.Fatalf("stdin submit of corrupt spec (suffix %q) exited %d", suffix, res.exitCode)
		}
		if strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("stdin submit of corrupt spec (suffix %q) wrote success output: %q", suffix, res.stdout)
		}
		if !strings.Contains(res.stderr, "trailing") {
			t.Fatalf("stdin submit of corrupt spec (suffix %q) stderr = %q, want trailing-data error", suffix, res.stderr)
		}
	}

	// Nothing was committed: state stays unreviewed at version 0.
	status, version, revisions := reviewHistoryState(t, dir)
	if status != "unreviewed" || version != 0 || revisions != 0 {
		t.Fatalf("corrupt submissions changed state: %s/%d with %d revisions", status, version, revisions)
	}

	// The submission id was never consumed: the complete legal document
	// creates version 1.
	specPath := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(specPath, []byte(cliReviewSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLI(t, "reviews", "submit", dir, specPath)
	if res.exitCode != 0 {
		t.Fatalf("legal submit failed: %s", res.stderr)
	}
	if !strings.Contains(res.stdout, `"created":true`) || !strings.Contains(res.stdout, `"version":1`) {
		t.Fatalf("legal submit output = %q, want created at version 1", res.stdout)
	}
	status, version, revisions = reviewHistoryState(t, dir)
	if status != "real" || version != 1 || revisions != 1 {
		t.Fatalf("state after legal submit: %s/%d with %d revisions", status, version, revisions)
	}

	// Even with the id already stored and every earlier field matching, a
	// structurally corrupt resubmission is the parsing failure, never the
	// idempotent created:false duplicate response.
	for _, suffix := range []string{"}", "]"} {
		res := runCLIStdin(t, cliReviewSpec+suffix, "reviews", "submit", dir, "-")
		if res.exitCode != 1 {
			t.Fatalf("corrupt reuse of stored id (suffix %q) exited %d", suffix, res.exitCode)
		}
		if strings.Contains(res.stdout, `"created":false`) {
			t.Fatalf("corrupt reuse of stored id (suffix %q) reported duplicate success: %q", suffix, res.stdout)
		}
		if !strings.Contains(res.stderr, "trailing") {
			t.Fatalf("corrupt reuse of stored id (suffix %q) stderr = %q", suffix, res.stderr)
		}
	}
	status, version, revisions = reviewHistoryState(t, dir)
	if status != "real" || version != 1 || revisions != 1 {
		t.Fatalf("corrupt reuse changed state: %s/%d with %d revisions", status, version, revisions)
	}
}

// TestReviewsSubmitNonObjectAndUnclosedSpecs pins that the other
// non-single-object shapes fail through the command as spec errors rather
// than as version conflicts or unknown conclusions.
func TestReviewsSubmitNonObjectAndUnclosedSpecs(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	for _, spec := range []string{"", "   \n\t ", "[]", "null", "7", `{"chainId":"1"`} {
		res := runCLIStdin(t, spec, "reviews", "submit", dir, "-")
		if res.exitCode != 1 {
			t.Fatalf("spec %q exited %d", spec, res.exitCode)
		}
		if strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("spec %q wrote success output: %q", spec, res.stdout)
		}
		if !strings.Contains(res.stderr, "review spec") {
			t.Fatalf("spec %q stderr = %q, want review spec error", spec, res.stderr)
		}
	}
	status, version, revisions := reviewHistoryState(t, dir)
	if status != "unreviewed" || version != 0 || revisions != 0 {
		t.Fatalf("rejected specs changed state: %s/%d with %d revisions", status, version, revisions)
	}
}
