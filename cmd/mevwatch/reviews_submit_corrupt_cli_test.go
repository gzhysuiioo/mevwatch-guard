package main

// End-to-end regression coverage for `reviews submit` through the real
// command entry point (see TestMain) when the archived report carrying
// the target conclusion has a decayed saved rule-version declaration.
// Once the target original conclusion is found, the declaration embedded
// in that report must pass the same integrity proof a `report` query
// enforces before a review can be accepted — a non-empty id, both rules
// with a boolean enabled and an integer severity 1-5, and a
// displacement multiplier 2-100. A written null used to be explained as
// the built-in rules and stripped from the report on the rewrite, and an
// incomplete declaration used to submit under zeroed parameters. On a
// damaged target declaration the command exits 1, prints nothing on
// stdout (no success result and no review JSON), and names the target
// chain, block, the readable saved version id and the offending rule or
// field on stderr — for a fresh submission, an idempotent retry and a
// rejudgment alike, whether the spec comes from a file or standard
// input. Damage confined to another record never blocks an intact
// target, an identity without a conclusion stays an unknown-conclusion
// error, and a record with no version key at all keeps the built-in
// explanation. The archive is left untouched and the submission id
// unconsumed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cliDispRetrySpec is the exact false-positive submission already stored
// on 0xd by setupReviewCLIArchive, so resubmitting it is the idempotent
// retry branch; it must still fail on a corrupt declaration rather than
// come back as created:false.
const cliDispRetrySpec = `{"chainId":"1","blockHash":"0xa","txHash":"0xd","kind":"displacement","submissionId":"f-1","operator":"alice","reason":"fp","status":"false_positive","expectedVersion":0}`

// cliDispRejudgeSpec is a fresh rejudgment against the object already at
// version 1; with a corrupt declaration it must fail the integrity proof
// rather than be accepted (created:true) or rejected only as a version
// conflict.
const cliDispRejudgeSpec = `{"chainId":"1","blockHash":"0xa","txHash":"0xd","kind":"displacement","submissionId":"f-2","operator":"bob","reason":"second look","status":"real","expectedVersion":1}`

// assertCLISubmitCorrupt drives one failing submit through the real
// command and pins exit 1, empty stdout and the required stderr
// substrings.
func assertCLISubmitCorrupt(t *testing.T, dir, spec string, want ...string) {
	t.Helper()
	specPath := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(specPath, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		run  func() cliResult
	}{
		{"spec file", func() cliResult { return runCLI(t, "reviews", "submit", dir, specPath) }},
		{"stdin", func() cliResult { return runCLIStdin(t, spec, "reviews", "submit", dir, "-") }},
	} {
		res := tc.run()
		if res.exitCode != 1 {
			t.Fatalf("%s submit exit = %d, want 1; stdout=%q stderr=%q", tc.name, res.exitCode, res.stdout, res.stderr)
		}
		if strings.TrimSpace(res.stdout) != "" {
			t.Fatalf("%s submit of corrupt target wrote success output: %q", tc.name, res.stdout)
		}
		for _, w := range want {
			if !strings.Contains(res.stderr, w) {
				t.Fatalf("%s submit stderr = %q, want substring %q", tc.name, res.stderr, w)
			}
		}
		if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
			t.Fatalf("%s submit crashed instead of failing cleanly: %q", tc.name, res.stderr)
		}
	}
}

// TestCLIReviewsSubmitCorruptDeclaration pins the CLI failure shape for
// a damaged target declaration while the registered versions stay
// intact. The block in setupReviewCLIArchive was archived under the
// built-in rules, so its embedded declaration carries id "builtin": that
// id must not bypass the proof.
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

	// A first submission for the unreviewed sandwich, the idempotent
	// retry of the stored displacement review and a fresh rejudgment of
	// that object all fail the integrity proof — via file and via stdin.
	for _, spec := range []string{cliReviewSpec, cliDispRetrySpec, cliDispRejudgeSpec} {
		assertCLISubmitCorrupt(t, dir, spec,
			"corrupt",      // ErrCorruptVersion
			"chain 1",      // target chain
			"block 0xa",    // target block
			"builtin",      // readable saved version id
			"multiplier",   // offending field
			"displacement", // offending rule
		)
	}

	// The failure must not masquerade as one of the ordinary submit
	// outcomes on stderr.
	specPath := filepath.Join(t.TempDir(), "review.json")
	if err := os.WriteFile(specPath, []byte(cliReviewSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	stderr := runCLI(t, "reviews", "submit", dir, specPath).stderr
	for _, ordinary := range []string{"unknown conclusion", "version conflict", "already used"} {
		if strings.Contains(stderr, ordinary) {
			t.Fatalf("corruption misreported as %q: %q", ordinary, stderr)
		}
	}

	// A second attempt fails the same way and the archive is untouched:
	// no revision appended, the stored false-positive revision survives,
	// the damaged field was not stripped.
	again := runCLIStdin(t, cliReviewSpec, "reviews", "submit", dir, "-")
	if again.exitCode != 1 || again.stdout != "" || !strings.Contains(again.stderr, "corrupt") {
		t.Fatalf("second attempt changed shape: exit=%d stdout=%q stderr=%q", again.exitCode, again.stdout, again.stderr)
	}
	if after := mustReadFile(t, archivePath); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed submit rewrote the archive")
	}

	// The unreviewed sandwich object stayed at version 0 and the
	// submitted id was never consumed. `reviews history` itself fails on
	// the same corrupt declaration by design, so inspect the reviews
	// section of the raw archive instead.
	var stored struct {
		Reviews []struct {
			TxHash    string `json:"txHash"`
			Kind      string `json:"kind"`
			Revisions []struct {
				SubmissionID string `json:"submissionId"`
			} `json:"revisions"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal(mustReadFile(t, archivePath), &stored); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, obj := range stored.Reviews {
		for _, rev := range obj.Revisions {
			counts[rev.SubmissionID]++
		}
	}
	if counts["r-1"] != 0 || counts["f-2"] != 0 {
		t.Fatalf("refused submission ids were stored: %+v", counts)
	}
	if counts["f-1"] != 1 {
		t.Fatalf("the stored false-positive revision must survive, counts=%+v", counts)
	}
	var dispRevisions int
	for _, obj := range stored.Reviews {
		if obj.TxHash == "0xd" && obj.Kind == "displacement" {
			dispRevisions = len(obj.Revisions)
		}
	}
	if dispRevisions != 1 {
		t.Fatalf("displacement object holds %d revisions, want 1", dispRevisions)
	}

	// An identity the corrupt report does not carry stays an
	// unknown-conclusion error: the damaged declaration is only opened
	// for a matching conclusion.
	ghost := runCLIStdin(t,
		`{"chainId":"1","blockHash":"0xa","txHash":"0ghost","kind":"sandwich","submissionId":"g-1","operator":"a","reason":"r","status":"real","expectedVersion":0}`,
		"reviews", "submit", dir, "-")
	if ghost.exitCode != 1 || ghost.stdout != "" {
		t.Fatalf("ghost identity exit=%d stdout=%q stderr=%q", ghost.exitCode, ghost.stdout, ghost.stderr)
	}
	if !strings.Contains(ghost.stderr, "unknown conclusion") ||
		strings.Contains(ghost.stderr, "corrupt") {
		t.Fatalf("ghost identity stderr = %q, want unknown conclusion without corruption", ghost.stderr)
	}
}

// TestCLIReviewsSubmitNullDeclarationCorrupt pins the exact misread the
// fix removes: a written "version":null must fail rather than be
// explained as the built-in rules and removed from the report by the
// atomic rewrite.
func TestCLIReviewsSubmitNullDeclarationCorrupt(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		rec["version"] = nil
	})
	assertCLISubmitCorrupt(t, dir, cliReviewSpec, "corrupt", "chain 1", "block 0xa")
	// The null must still be right there in the file: no rewrite
	// stripped it into a legacy record.
	if !strings.Contains(string(mustReadFile(t, filepath.Join(dir, "archive.json"))), `"version": null`) {
		t.Fatal("failed submit stripped the null version declaration")
	}
}

// TestCLIReviewsSubmitDuplicateField covers decay written straight into
// the archive: a repeated field under a case-folded spelling must fail
// a submit the same way it fails a history query.
func TestCLIReviewsSubmitDuplicateField(t *testing.T) {
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
	assertCLISubmitCorrupt(t, dir, cliReviewSpec, "corrupt", "duplicate", "severity")
}

// TestCLIReviewsSubmitLegacyBuiltin proves the single carve-out through
// the CLI: a record with no version key at all keeps the built-in
// explanation and accepts a review.
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
		t.Fatalf("legacy submit output = %q, want created at version 1", res.stdout)
	}
}

// TestCLIReviewsSubmitCorruptRegistryDoesNotBlock proves damage confined
// to the registered versions section never blocks a review of a target
// whose own embedded declaration is intact.
func TestCLIReviewsSubmitCorruptRegistryDoesNotBlock(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	corruptStoredVersion(t, dir, "mult3", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	res := runCLIStdin(t, cliReviewSpec, "reviews", "submit", dir, "-")
	if res.exitCode != 0 {
		t.Fatalf("a corrupt registry sibling blocked an intact report review: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stdout, `"created":true`) {
		t.Fatalf("intact target submit output = %q", res.stdout)
	}
}
