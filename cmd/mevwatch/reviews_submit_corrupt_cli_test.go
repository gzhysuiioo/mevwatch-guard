package main

// End-to-end regression coverage for `reviews submit` through the real
// command entry point (see TestMain): once a submission finds its target
// original conclusion, the version declaration embedded in that report
// must pass the same integrity proof a `report` query and a `reviews
// history` query enforce before any revision is accepted. A written null
// used to be explained as the built-in rules and the accepting submission
// re-encoded the record and stripped the damage out of the archive. On a
// damaged target declaration the command exits 1, prints nothing on
// stdout (no success result and no review JSON), and names the target
// chain, block, the readable saved version id and the offending rule or
// field on stderr — for a first submission, a rejudgment and an
// identical retry of an already stored submission alike, whether the
// spec comes from a file or standard input. The archive is left exactly
// as it was and the refused submission id stays free. A record with no
// version key at all keeps the built-in explanation, and an identity the
// archive does not carry stays an unknown-conclusion error.

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cliSubmitTarget is a legal first-time review of the sandwich 0xv in the
// setupReviewCLIArchive block (chain 1, block 0xa).
const cliSubmitTarget = `{"chainId":"1","blockHash":"0xa","txHash":"0xv","kind":"sandwich","submissionId":"r-1","operator":"alice","reason":"confirmed bot war","status":"real","expectedVersion":0}`

// assertCLISubmitRefusedCorrupt drives one failing submit both from a spec
// file and from standard input and pins the failure shape: exit 1, empty
// stdout, a clean corrupt-version error naming the target chain, block and
// every required substring.
func assertCLISubmitRefusedCorrupt(t *testing.T, dir, spec string, want ...string) {
	t.Helper()
	specPath := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, res := range []cliResult{
		runCLI(t, "reviews", "submit", dir, specPath),
		runCLIStdin(t, spec, "reviews", "submit", dir, "-"),
	} {
		if res.exitCode != 1 {
			t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
		if strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("corrupt declaration must print no success JSON, got %q", res.stdout)
		}
		for _, sub := range append([]string{"corrupt", "chain 1", "block 0xa"}, want...) {
			if !strings.Contains(res.stderr, sub) {
				t.Fatalf("stderr = %q, want substring %q", res.stderr, sub)
			}
		}
		if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
			t.Fatalf("submit crashed instead of failing cleanly: %q", res.stderr)
		}
	}
}

// TestCLIReviewsSubmitCorruptDeclaration pins the CLI failure shape for a
// damaged target declaration while the registered versions stay intact.
// The block in setupReviewCLIArchive was archived under the built-in
// rules, so its embedded declaration carries id "builtin": that id must
// not bypass the proof.
func TestCLIReviewsSubmitCorruptDeclaration(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	archivePath := filepath.Join(dir, "archive.json")

	// Drop the displacement multiplier only from the record's embedded
	// declaration; the registry section is untouched.
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		ver := rec["version"].(map[string]any)
		disp := ver["rules"].(map[string]any)["displacement"].(map[string]any)
		delete(disp, "multiplier")
	})
	corruptBytes := mustReadFile(t, archivePath)

	// A first submission against the sandwich conclusion and a rejudgment
	// against the displacement that already carries revision f-1 both fail
	// before any revision handling.
	assertCLISubmitRefusedCorrupt(t, dir, cliSubmitTarget, "builtin", "multiplier", "displacement")
	rejudgment := `{"chainId":"1","blockHash":"0xa","txHash":"0xd","kind":"displacement","submissionId":"r-2","operator":"bob","reason":"second look","status":"real","expectedVersion":1}`
	assertCLISubmitRefusedCorrupt(t, dir, rejudgment, "builtin", "multiplier", "displacement")

	// The heart of the fix: retrying the exact, already-stored submission
	// f-1 must fail as corruption, never come back as the idempotent
	// created:false success.
	storedRetry := `{"chainId":"1","blockHash":"0xa","txHash":"0xd","kind":"displacement","submissionId":"f-1","operator":"alice","reason":"fp","status":"false_positive","expectedVersion":0}`
	for _, res := range []cliResult{
		runCLIStdin(t, storedRetry, "reviews", "submit", dir, "-"),
	} {
		if res.exitCode != 1 || strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("stored-id retry exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
		}
		if !strings.Contains(res.stderr, "corrupt") || strings.Contains(res.stderr, "already used") {
			t.Fatalf("stored-id retry must report corruption, got %q", res.stderr)
		}
	}

	// Repeated attempts leave the archive byte-identical; the existing
	// false-positive revision survives and the new ids are not consumed.
	again := runCLIStdin(t, cliSubmitTarget, "reviews", "submit", dir, "-")
	if again.exitCode != 1 || again.stdout != "" || !strings.Contains(again.stderr, "corrupt") {
		t.Fatalf("second attempt changed shape: exit=%d stdout=%q stderr=%q", again.exitCode, again.stdout, again.stderr)
	}
	if after := mustReadFile(t, archivePath); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed submit rewrote the archive")
	}

	// An identity the corrupt report does not carry is an unknown
	// conclusion, not corruption: the damaged declaration is only opened
	// for a matching conclusion.
	ghost := strings.Replace(cliSubmitTarget, `"txHash":"0xv"`, `"txHash":"0ghost"`, 1)
	ghost = strings.Replace(ghost, `"submissionId":"r-1"`, `"submissionId":"r-9"`, 1)
	res := runCLIStdin(t, ghost, "reviews", "submit", dir, "-")
	if res.exitCode != 1 || strings.Contains(res.stderr, "corrupt") ||
		!strings.Contains(res.stderr, "unknown conclusion") {
		t.Fatalf("non-matching identity stderr = %q exit=%d", res.stderr, res.exitCode)
	}

	// Restore a complete built-in declaration: the refused id is free and
	// creates version 1, while f-1 is again the ordinary idempotent
	// created:false retry — normal conventions are fully intact.
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		rec["version"] = map[string]any{
			"id": "builtin",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
			},
		}
	})
	ok := runCLIStdin(t, cliSubmitTarget, "reviews", "submit", dir, "-")
	if ok.exitCode != 0 || !strings.Contains(ok.stdout, `"created":true`) ||
		!strings.Contains(ok.stdout, `"version":1`) {
		t.Fatalf("refused id must be free after restore: exit=%d stdout=%q stderr=%q", ok.exitCode, ok.stdout, ok.stderr)
	}
	retry := runCLIStdin(t, storedRetry, "reviews", "submit", dir, "-")
	if retry.exitCode != 0 || !strings.Contains(retry.stdout, `"created":false`) {
		t.Fatalf("stored retry must be idempotent again: exit=%d stdout=%q stderr=%q",
			retry.exitCode, retry.stdout, retry.stderr)
	}
}

// TestCLIReviewsSubmitNullDeclarationCorrupt pins the exact misread being
// fixed: a written "version":null must fail rather than be explained as
// the built-in rules and stripped from the report.
func TestCLIReviewsSubmitNullDeclarationCorrupt(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	archivePath := filepath.Join(dir, "archive.json")
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		rec["version"] = nil
	})
	corruptBytes := mustReadFile(t, archivePath)

	assertCLISubmitRefusedCorrupt(t, dir, cliSubmitTarget, "null")
	if after := mustReadFile(t, archivePath); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed submit rewrote the null declaration")
	}
}

// TestCLIReviewsSubmitDuplicateFieldInDeclaration covers decay written
// straight into the archive: a repeated field under a case-folded
// spelling must fail the same way a fresh registration rejects it.
func TestCLIReviewsSubmitDuplicateFieldInDeclaration(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	path := filepath.Join(dir, "archive.json")
	text := string(mustReadFile(t, path))
	versionsAt := strings.Index(text, `"versions":`)
	if versionsAt < 0 {
		t.Fatal("versions section not found")
	}
	at := strings.Index(text[:versionsAt], `"id": "builtin"`)
	if at < 0 {
		t.Fatal("record's embedded builtin declaration not found")
	}
	anchor := `"severity": 2,`
	field := strings.Index(text[at:versionsAt], anchor)
	if field < 0 {
		t.Fatal("displacement severity field not found in embedded declaration")
	}
	pos := at + field
	patched := text[:pos] + `"Severity": 2, ` + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runCLIStdin(t, cliSubmitTarget, "reviews", "submit", dir, "-")
	if res.exitCode != 1 || res.stdout != "" {
		t.Fatalf("duplicate-field declaration exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "corrupt") || !strings.Contains(res.stderr, "duplicate") ||
		!strings.Contains(res.stderr, "severity") {
		t.Fatalf("stderr must name the duplicate severity field: %q", res.stderr)
	}
}

// TestCLIReviewsSubmitLegacyBuiltin proves the single carve-out through
// the CLI: a record with no version key at all accepts a review under the
// built-in rules, both via stdin and via a spec file.
func TestCLIReviewsSubmitLegacyBuiltin(t *testing.T) {
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
	spec := `{"chainId":"1","blockHash":"0old","txHash":"0v","kind":"sandwich","submissionId":"s-1","operator":"alice","reason":"r","status":"real","expectedVersion":0}`
	res := runCLIStdin(t, spec, "reviews", "submit", dir, "-")
	if res.exitCode != 0 {
		t.Fatalf("legacy record must accept a review under builtin: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"created":true`) || !strings.Contains(res.stdout, `"version":1`) {
		t.Fatalf("legacy submit output = %q", res.stdout)
	}
	// The legacy record still queries under builtin: the review write
	// neither added a version key nor altered the report.
	report := runCLI(t, "report", dir, "1", "0old")
	if report.exitCode != 0 || !strings.Contains(report.stdout, `"id":"builtin"`) {
		t.Fatalf("legacy report changed across the review: exit=%d stdout=%q stderr=%q",
			report.exitCode, report.stdout, report.stderr)
	}
}
