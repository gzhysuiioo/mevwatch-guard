package main

// End-to-end regression coverage for `reviews history` through the real
// command entry point (see TestMain): once a history query hits the
// archived original conclusion, the version declaration embedded in that
// report must pass the same integrity proof a `report` query enforces
// before any history JSON is printed. A written null used to be explained
// as the built-in rules and an incomplete declaration used to come back
// with zeroed parameters. On a damaged target declaration the command
// exits 1, prints nothing on stdout, and names the target chain, block,
// the readable saved version id and the offending rule or field on
// stderr. Damage confined to another record or to the registered
// versions section never blocks the target, and a record with no version
// key at all keeps the built-in explanation. Success or failure leaves
// the archive untouched.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// historyJSON is the decoded shape of one `reviews history` line.
type historyJSON struct {
	ChainID   string `json:"chainId"`
	BlockHash string `json:"blockHash"`
	TxHash    string `json:"txHash"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Version   int    `json:"version"`
	Original  *struct {
		BlockNumber int64 `json:"blockNumber"`
		Finding     struct {
			Kind     string           `json:"kind"`
			Severity int              `json:"severity"`
			TxHash   string           `json:"txHash"`
			Evidence []map[string]any `json:"evidence"`
		} `json:"finding"`
		Version struct {
			ID    string `json:"id"`
			Rules struct {
				Displacement struct {
					Multiplier int `json:"multiplier"`
				} `json:"displacement"`
			} `json:"rules"`
		} `json:"version"`
	} `json:"original"`
	Revisions []map[string]any `json:"revisions"`
}

func parseHistoryJSON(t *testing.T, raw string) historyJSON {
	t.Helper()
	var hist historyJSON
	if err := json.Unmarshal([]byte(raw), &hist); err != nil {
		t.Fatalf("stdout is not valid history JSON: %v\n%s", err, raw)
	}
	return hist
}

// TestCLIReviewsHistoryCorruptDeclaration pins the CLI failure shape for
// a damaged target declaration while the registered versions stay
// intact. The block in setupReviewCLIArchive was archived under the
// built-in rules, so its embedded declaration carries id "builtin": that
// id must not bypass the proof.
func TestCLIReviewsHistoryCorruptDeclaration(t *testing.T) {
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

	for _, target := range [][2]string{{"0xd", "displacement"}, {"0xv", "sandwich"}} {
		res := runCLI(t, "reviews", "history", dir, "1", "0xa", target[0], target[1])
		if res.exitCode != 1 {
			t.Fatalf("target %s/%s exit = %d, want 1; stderr=%q", target[1], target[0], res.exitCode, res.stderr)
		}
		if res.stdout != "" {
			t.Fatalf("corrupt declaration must print no history JSON, got %q", res.stdout)
		}
		for _, want := range []string{
			"corrupt",      // ErrCorruptVersion
			"chain 1",      // target chain
			"block 0xa",    // target block
			"builtin",      // readable saved version id
			"multiplier",   // offending field
			"displacement", // offending rule
		} {
			if !strings.Contains(res.stderr, want) {
				t.Fatalf("target %s/%s stderr = %q, want substring %q", target[1], target[0], res.stderr, want)
			}
		}
		if strings.Contains(res.stderr, "goroutine") || strings.Contains(res.stderr, "runtime error") {
			t.Fatalf("history crashed instead of failing cleanly: %q", res.stderr)
		}
	}

	// A second attempt fails the same way and the archive is untouched:
	// the failed queries repaired neither the declaration nor anything
	// else, and the stored false-positive revision survives.
	again := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	if again.exitCode != 1 || again.stdout != "" || !strings.Contains(again.stderr, "corrupt") {
		t.Fatalf("second attempt changed shape: exit=%d stdout=%q stderr=%q", again.exitCode, again.stdout, again.stderr)
	}
	if after := mustReadFile(t, archivePath); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatal("failed history query rewrote the archive")
	}

	// An identity the corrupt report does not carry keeps original:null:
	// the damaged declaration is only opened for a matching conclusion.
	ghost := runCLI(t, "reviews", "history", dir, "1", "0xa", "0ghost", "sandwich")
	if ghost.exitCode != 0 || !strings.Contains(ghost.stdout, `"original":null`) {
		t.Fatalf("non-matching identity changed shape: exit=%d stdout=%q stderr=%q",
			ghost.exitCode, ghost.stdout, ghost.stderr)
	}
}

// TestCLIReviewsHistoryCorruptRegistryDoesNotBlock proves damage confined
// to the registered versions section never blocks a target whose own
// embedded declaration is intact: the history uses the report's saved
// parameters and never consults the registry.
func TestCLIReviewsHistoryCorruptRegistryDoesNotBlock(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	corruptStoredVersion(t, dir, "mult3", func(ver map[string]any) {
		delete(ver["rules"].(map[string]any)["displacement"].(map[string]any), "multiplier")
	})
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	if res.exitCode != 0 {
		t.Fatalf("a corrupt registry sibling blocked an intact report: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseHistoryJSON(t, res.stdout)
	if hist.Original == nil || hist.Original.Version.ID != "builtin" ||
		hist.Original.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("history must explain the report under its own saved declaration: %+v", hist.Original)
	}
}

// TestCLIReviewsHistoryNullDeclarationCorrupt pins the exact misread
// being fixed: a written "version":null must fail rather than be
// explained as the built-in rules.
func TestCLIReviewsHistoryNullDeclarationCorrupt(t *testing.T) {
	dir := setupReviewCLIArchive(t)
	corruptStoredReportVersion(t, dir, "1", "0xa", func(rec map[string]any) {
		rec["version"] = nil
	})
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 1 {
		t.Fatalf("exit = %d, want 1; stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if res.stdout != "" {
		t.Fatalf("null declaration must print no history JSON, got %q", res.stdout)
	}
	for _, want := range []string{"corrupt", "chain 1", "block 0xa", "null"} {
		if !strings.Contains(res.stderr, want) {
			t.Fatalf("stderr = %q, want substring %q", res.stderr, want)
		}
	}
}

// TestCLIReviewsHistoryDuplicateField covers decay written straight into
// the archive: a repeated field under a case-folded spelling must fail
// the same way a fresh registration rejects it.
func TestCLIReviewsHistoryDuplicateField(t *testing.T) {
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
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	if res.exitCode != 1 || res.stdout != "" {
		t.Fatalf("duplicate-field declaration exit=%d stdout=%q stderr=%q", res.exitCode, res.stdout, res.stderr)
	}
	if !strings.Contains(res.stderr, "corrupt") || !strings.Contains(res.stderr, "duplicate") ||
		!strings.Contains(res.stderr, "severity") {
		t.Fatalf("stderr must name the duplicate severity field: %q", res.stderr)
	}
}

// TestCLIReviewsHistoryLegacyBuiltin proves the single carve-out through
// the CLI: a record with no version key at all is explained by the
// built-in rules.
func TestCLIReviewsHistoryLegacyBuiltin(t *testing.T) {
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
	res := runCLI(t, "reviews", "history", dir, "1", "0old", "0v", "sandwich")
	if res.exitCode != 0 {
		t.Fatalf("legacy record must query under builtin: exit=%d stderr=%q", res.exitCode, res.stderr)
	}
	hist := parseHistoryJSON(t, res.stdout)
	if hist.Original == nil || hist.Original.Version.ID != "builtin" ||
		hist.Original.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("original must be explained under builtin: %+v", hist.Original)
	}
	if hist.Original.Finding.Kind != "sandwich" || hist.Original.Finding.Severity != 3 ||
		len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy conclusion/evidence damaged: %+v", hist.Original.Finding)
	}
	if hist.Status != "unreviewed" || hist.Version != 0 {
		t.Fatalf("legacy default state wrong: %s/%d", hist.Status, hist.Version)
	}
	if !strings.Contains(res.stdout, `"revisions":[]`) || !strings.Contains(res.stdout, `"original":{`) {
		t.Fatalf("legacy history shape wrong: %s", res.stdout)
	}
}

// TestCLIReviewsHistorySuccessContent proves a successful history keeps
// the current review status and version, every ascending revision, the
// original conclusion with its saved detection parameters and the full
// swap evidence — for a reviewed object, an unreviewed object and an
// identity without a conclusion alike.
func TestCLIReviewsHistorySuccessContent(t *testing.T) {
	dir := setupReviewCLIArchive(t)

	// Reviewed displacement 0xd: one false-positive revision.
	res := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	reviewed := res.stdout
	if res.exitCode != 0 {
		t.Fatalf("history failed: %s", res.stderr)
	}
	hist := parseHistoryJSON(t, res.stdout)
	if hist.Status != "false_positive" || hist.Version != 1 || len(hist.Revisions) != 1 {
		t.Fatalf("review state wrong: %s/%d with %d revisions", hist.Status, hist.Version, len(hist.Revisions))
	}
	if hist.Revisions[0]["submissionId"] != "f-1" || hist.Revisions[0]["status"] != "false_positive" {
		t.Fatalf("revision content wrong: %+v", hist.Revisions[0])
	}
	if hist.Original == nil || hist.Original.BlockNumber != 10 ||
		hist.Original.Finding.TxHash != "0xd" || hist.Original.Finding.Kind != "displacement" ||
		hist.Original.Finding.Severity != 2 || len(hist.Original.Finding.Evidence) != 2 ||
		hist.Original.Version.ID != "builtin" {
		t.Fatalf("original conclusion/evidence/version wrong: %+v", hist.Original)
	}

	// Unreviewed sandwich 0xv: defaults plus the full original with its
	// three-swap evidence; revisions serialize as [].
	res = runCLI(t, "reviews", "history", dir, "1", "0xa", "0xv", "sandwich")
	if res.exitCode != 0 {
		t.Fatalf("unreviewed history failed: %s", res.stderr)
	}
	hist = parseHistoryJSON(t, res.stdout)
	if hist.Status != "unreviewed" || hist.Version != 0 || len(hist.Revisions) != 0 {
		t.Fatalf("unreviewed state wrong: %s/%d with %d revisions", hist.Status, hist.Version, len(hist.Revisions))
	}
	if hist.Original == nil || hist.Original.Finding.Severity != 3 ||
		len(hist.Original.Finding.Evidence) != 3 {
		t.Fatalf("unreviewed original wrong: %+v", hist.Original)
	}
	if !strings.Contains(res.stdout, `"revisions":[]`) {
		t.Fatalf("revisions must serialize as []: %s", res.stdout)
	}

	// An identity without a conclusion keeps original:null.
	res = runCLI(t, "reviews", "history", dir, "1", "0xa", "0ghost", "sandwich")
	if res.exitCode != 0 {
		t.Fatalf("missing-identity history failed: %s", res.stderr)
	}
	hist = parseHistoryJSON(t, res.stdout)
	if hist.Original != nil || hist.Status != "unreviewed" || hist.Version != 0 {
		t.Fatalf("missing identity state wrong: %+v", hist)
	}
	if !strings.Contains(res.stdout, `"original":null`) {
		t.Fatalf("missing identity must carry original:null: %s", res.stdout)
	}

	// Deterministic output for the reviewed object.
	again := runCLI(t, "reviews", "history", dir, "1", "0xa", "0xd", "displacement")
	if again.exitCode != 0 || again.stdout != reviewed {
		t.Fatalf("history output is not deterministic:\n%s\n%s", reviewed, again.stdout)
	}
}

// mustReadFile reads a file or fails the test.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
