package mevwatch

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const sandwichInput = `{"chainId":"1","blockHash":"0xa","blockNumber":10,"swaps":[{"TxHash":"0xfront","Pool":"p1","Trader":"bot","In":500,"Out":480,"GasPrice":90,"Index":0},{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},{"TxHash":"0xback","Pool":"p1","Trader":"bot","In":480,"Out":505,"GasPrice":80,"Index":2}]}`

func replay(t *testing.T, dir, input string) []Report {
	t.Helper()
	reports, err := Replay(strings.NewReader(input), dir)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	return reports
}

func TestReplaySandwichReport(t *testing.T) {
	dir := t.TempDir()
	reports := replay(t, dir, sandwichInput)
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.ChainID != "1" || r.BlockHash != "0xa" || r.BlockNumber != 10 {
		t.Fatalf("bad identity: %+v", r)
	}
	if r.SwapCount != 3 {
		t.Fatalf("SwapCount = %d, want 3", r.SwapCount)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(r.Findings))
	}
	f := r.Findings[0]
	if f.Kind != "sandwich" || f.Severity != 3 || f.TxHash != "0xvictim" {
		t.Fatalf("bad finding: %+v", f)
	}
	if len(f.Evidence) != 3 {
		t.Fatalf("evidence has %d swaps, want 3", len(f.Evidence))
	}
	wantOrder := []string{"0xfront", "0xvictim", "0xback"}
	for i, want := range wantOrder {
		if f.Evidence[i].TxHash != want {
			t.Fatalf("evidence[%d].TxHash = %s, want %s", i, f.Evidence[i].TxHash, want)
		}
	}
	if f.Evidence[0].GasPrice != 90 || f.Evidence[1].Trader != "user" || f.Evidence[2].In != 480 {
		t.Fatalf("evidence lost raw fields: %+v", f.Evidence)
	}
}

func TestReplayDisplacementIncludesLastSwap(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0xb","blockNumber":11,"swaps":[{"TxHash":"0xbig","Pool":"p1","Trader":"whale","In":1,"Out":1,"GasPrice":30,"Index":0},{"TxHash":"0xsmall","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1}]}`
	reports := replay(t, dir, input)
	if len(reports[0].Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(reports[0].Findings))
	}
	f := reports[0].Findings[0]
	if f.Kind != "displacement" || f.Severity != 2 || f.TxHash != "0xsmall" {
		t.Fatalf("bad finding: %+v", f)
	}
	if len(f.Evidence) != 2 || f.Evidence[0].TxHash != "0xbig" || f.Evidence[1].TxHash != "0xsmall" {
		t.Fatalf("bad displacement evidence: %+v", f.Evidence)
	}
}

func TestReplayGasPriceEdges(t *testing.T) {
	dir := t.TempDir()
	input := fmt.Sprintf(`{"chainId":"1","blockHash":"0xc","blockNumber":12,"swaps":[{"TxHash":"0xg1","Pool":"zero","Trader":"a","In":0,"Out":0,"GasPrice":1,"Index":0},{"TxHash":"0xg2","Pool":"zero","Trader":"b","In":0,"Out":0,"GasPrice":0,"Index":1},{"TxHash":"0xg3","Pool":"max","Trader":"a","In":0,"Out":0,"GasPrice":%[1]d,"Index":2},{"TxHash":"0xg4","Pool":"max","Trader":"b","In":0,"Out":0,"GasPrice":%[1]d,"Index":3},{"TxHash":"0xg5","Pool":"huge","Trader":"a","In":0,"Out":0,"GasPrice":%[1]d,"Index":4},{"TxHash":"0xg6","Pool":"huge","Trader":"b","In":0,"Out":0,"GasPrice":100,"Index":5}]}`, math.MaxInt64)
	reports := replay(t, dir, input)
	got := map[string]string{}
	for _, f := range reports[0].Findings {
		got[f.TxHash] = f.Kind
	}
	// victim gas 0: any positive front gas dominates.
	if got["0xg2"] != "displacement" {
		t.Fatalf("0xg2 = %q, want displacement", got["0xg2"])
	}
	// victim gas MaxInt64: 2x would overflow, must not flag.
	if _, flagged := got["0xg4"]; flagged {
		t.Fatalf("0xg4 must not be flagged (overflow)")
	}
	// front gas MaxInt64 vs victim 100: dominates without overflow.
	if got["0xg6"] != "displacement" {
		t.Fatalf("0xg6 = %q, want displacement", got["0xg6"])
	}
	if len(got) != 2 {
		t.Fatalf("unexpected findings: %v", got)
	}
}

func TestReplayFindingsSorted(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0xd","blockNumber":13,"swaps":[{"TxHash":"0xza","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":99,"Index":0},{"TxHash":"0xzb","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},{"TxHash":"0xf1","Pool":"p2","Trader":"bot","In":1,"Out":1,"GasPrice":50,"Index":2},{"TxHash":"0xv1","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":3},{"TxHash":"0xb1","Pool":"p2","Trader":"bot","In":1,"Out":1,"GasPrice":40,"Index":4},{"TxHash":"0xaa","Pool":"p3","Trader":"w","In":1,"Out":1,"GasPrice":99,"Index":5},{"TxHash":"0xab","Pool":"p3","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":6}]}`
	findings := replay(t, dir, input)[0].Findings
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	// severity 3 first, then severity 2 ordered by tx hash ascending.
	if findings[0].Kind != "sandwich" || findings[0].TxHash != "0xv1" {
		t.Fatalf("findings[0] = %+v", findings[0])
	}
	if findings[1].TxHash != "0xab" || findings[2].TxHash != "0xzb" {
		t.Fatalf("severity-2 findings not sorted by hash: %+v", findings[1:])
	}
	for _, f := range findings[1:] {
		if f.Severity != 2 {
			t.Fatalf("severity order broken: %+v", findings)
		}
	}
}

func TestReplayDedupAndPermutation(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0xe","blockNumber":20,"swaps":[{"TxHash":"0xs1","Pool":"p","Trader":"a","In":1,"Out":2,"GasPrice":5,"Index":0},{"TxHash":"0xs2","Pool":"p","Trader":"b","In":3,"Out":4,"GasPrice":6,"Index":1},{"TxHash":"0xs1","Pool":"p","Trader":"a","In":1,"Out":2,"GasPrice":5,"Index":0}]}` + "\n" +
		`{"chainId":"1","blockHash":"0xe","blockNumber":20,"swaps":[{"TxHash":"0xs2","Pool":"p","Trader":"b","In":3,"Out":4,"GasPrice":6,"Index":1},{"TxHash":"0xs1","Pool":"p","Trader":"a","In":1,"Out":2,"GasPrice":5,"Index":0}]}` + "\n"
	reports := replay(t, dir, input)
	if len(reports) != 1 {
		t.Fatalf("permuted duplicate block produced %d reports, want 1", len(reports))
	}
	if reports[0].SwapCount != 2 {
		t.Fatalf("SwapCount = %d, want 2 after dedup", reports[0].SwapCount)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Records) != 1 {
		t.Fatalf("archive holds %d records, want 1", len(data.Records))
	}
}

func TestReplayEmptySwapsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	input := "\n  \n{\"chainId\":\"1\",\"blockHash\":\"0xf\",\"blockNumber\":1,\"swaps\":[]}\n\n"
	reports := replay(t, dir, input)
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	if reports[0].SwapCount != 0 || len(reports[0].Findings) != 0 {
		t.Fatalf("empty block report wrong: %+v", reports[0])
	}
	// Empty findings must serialize as [], not null.
	raw, err := Query(dir, "1", "0xf")
	if err != nil {
		t.Fatal(err)
	}
	if raw.Findings == nil {
		t.Fatal("findings must be an empty array, not null")
	}
}

func TestReplayValidationErrors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		line  int
	}{
		{"bad json", `{"chainId":`, 1},
		{"trailing garbage", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[]} extra`, 1},
		{"empty chainId", `{"chainId":"","blockHash":"0x","blockNumber":1,"swaps":[]}`, 1},
		{"missing blockHash", `{"chainId":"1","blockNumber":1,"swaps":[]}`, 1},
		{"negative blockNumber", `{"chainId":"1","blockHash":"0x","blockNumber":-1,"swaps":[]}`, 1},
		{"missing swaps", `{"chainId":"1","blockHash":"0x","blockNumber":1}`, 1},
		{"empty txhash", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":0,"Index":0}]}`, 1},
		{"empty pool", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"","Trader":"t","In":0,"Out":0,"GasPrice":0,"Index":0}]}`, 1},
		{"empty trader", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"","In":0,"Out":0,"GasPrice":0,"Index":0}]}`, 1},
		{"negative gas", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":-5,"Index":0}]}`, 1},
		{"negative index", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":0,"Index":-1}]}`, 1},
		{"fractional gas", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":1.5,"Index":0}]}`, 1},
		{"missing in", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","Out":0,"GasPrice":0,"Index":0}]}`, 1},
		{"missing out", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"GasPrice":0,"Index":0}]}`, 1},
		{"missing gas", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"Index":0}]}`, 1},
		{"missing index", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":0}]}`, 1},
		{"null in", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":null,"Out":0,"GasPrice":0,"Index":0}]}`, 1},
		{"null out", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":null,"GasPrice":0,"Index":0}]}`, 1},
		{"null gas", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":null,"Index":0}]}`, 1},
		{"null index", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":0,"Index":null}]}`, 1},
		{"missing gas on later swap", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":30,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"u","In":0,"Out":0,"Index":1}]}`, 1},
		{"conflicting duplicate tx", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":1,"Index":0},{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":2,"Index":0}]}`, 1},
		{"shared index", `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":0,"Out":0,"GasPrice":1,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"u","In":0,"Out":0,"GasPrice":1,"Index":0}]}`, 1},
		{"error on later line", "{\"chainId\":\"1\",\"blockHash\":\"0x\",\"blockNumber\":1,\"swaps\":[]}\n\nnot json", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := Replay(strings.NewReader(tc.input), dir)
			if err == nil {
				t.Fatal("expected error")
			}
			var le *LineError
			if !errors.As(err, &le) {
				t.Fatalf("error %v is not a LineError", err)
			}
			if le.Line != tc.line {
				t.Fatalf("error line = %d, want %d (%v)", le.Line, tc.line, err)
			}
			// Archive must stay untouched.
			if _, serr := os.Stat(filepath.Join(dir, archiveFileName)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("archive file exists after failed replay: %v", serr)
			}
		})
	}
}

func TestReplayInFileConflict(t *testing.T) {
	dir := t.TempDir()
	input := "{\"chainId\":\"1\",\"blockHash\":\"0x\",\"blockNumber\":1,\"swaps\":[]}\n" +
		"{\"chainId\":\"1\",\"blockHash\":\"0x\",\"blockNumber\":2,\"swaps\":[]}\n"
	_, err := Replay(strings.NewReader(input), dir)
	var le *LineError
	if !errors.As(err, &le) || le.Line != 2 {
		t.Fatalf("want LineError at line 2, got %v", err)
	}
}

// TestReplayIncompleteSwapNamesFieldAndSwap covers the core data-quality
// fix: a missing or null numeric field fails the replay with the actual
// input line, the swap position and the field name, and is never silently
// treated as zero.
func TestReplayIncompleteSwapNamesFieldAndSwap(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSub string
	}{
		{
			"missing GasPrice after higher-gas swap",
			`{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":30,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"u","In":1,"Out":1,"Index":1}]}`,
			"swaps[1]: GasPrice",
		},
		{
			"null GasPrice",
			`{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":null,"Index":0}]}`,
			"swaps[0]: GasPrice",
		},
		{
			"null In",
			`{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":null,"Out":1,"GasPrice":1,"Index":0}]}`,
			"swaps[0]: In",
		},
		{
			"missing Out",
			`{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"GasPrice":1,"Index":0}]}`,
			"swaps[0]: Out",
		},
		{
			"null Index",
			`{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":null}]}`,
			"swaps[0]: Index",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, err := Replay(strings.NewReader(tc.input), dir)
			if err == nil {
				t.Fatal("incomplete swap must fail the replay")
			}
			var le *LineError
			if !errors.As(err, &le) || le.Line != 1 {
				t.Fatalf("want LineError at line 1, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q must name %q", err.Error(), tc.wantSub)
			}
			if _, serr := os.Stat(filepath.Join(dir, archiveFileName)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("archive file exists after failed replay: %v", serr)
			}
		})
	}
}

// TestReplayIncompleteSwapLineNumbers checks 1-based line counting with
// blank lines counted, including a last line without a trailing newline.
func TestReplayIncompleteSwapLineNumbers(t *testing.T) {
	dir := t.TempDir()
	good := "{\"chainId\":\"1\",\"blockHash\":\"0g\",\"blockNumber\":1,\"swaps\":[]}\n"
	blank := "\n  \n"
	// Last line has no trailing newline; it is still line 4.
	bad := `{"chainId":"1","blockHash":"0b","blockNumber":2,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"u","In":1,"Out":1,"GasPrice":null,"Index":1}]}`
	_, err := Replay(strings.NewReader(good+blank+bad), dir)
	var le *LineError
	if !errors.As(err, &le) || le.Line != 4 {
		t.Fatalf("want LineError at line 4, got %v", err)
	}
	if !strings.Contains(err.Error(), "swaps[1]: GasPrice") {
		t.Fatalf("error must name the second swap and GasPrice: %v", err)
	}
}

// TestReplayIncompleteSwapNotSavedByDuplicate ensures an incomplete record
// is rejected even when an earlier complete record with the same tx hash
// would otherwise be deduplicated.
func TestReplayIncompleteSwapNotSavedByDuplicate(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[` +
		`{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":2,"GasPrice":5,"Index":0},` +
		`{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":2,"GasPrice":null,"Index":0}]}`
	_, err := Replay(strings.NewReader(input), dir)
	var le *LineError
	if !errors.As(err, &le) {
		t.Fatalf("want LineError, got %v", err)
	}
	if !strings.Contains(err.Error(), "swaps[1]: GasPrice") {
		t.Fatalf("incomplete duplicate slipped through: %v", err)
	}
	if _, err := Query(dir, "1", "0x"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("block was archived despite incomplete record: %v", err)
	}
}

// TestReplayExplicitZeroesRemainValid proves explicit zero values are not
// mistaken for missing fields: gas 0 still participates in displacement
// exactly as before.
func TestReplayExplicitZeroesRemainValid(t *testing.T) {
	dir := t.TempDir()
	input := `{"chainId":"1","blockHash":"0z","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"a","In":0,"Out":0,"GasPrice":30,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"b","In":0,"Out":0,"GasPrice":0,"Index":1}]}`
	reports := replay(t, dir, input)
	found := false
	for _, f := range reports[0].Findings {
		if f.TxHash == "0x2" {
			found = true
			if f.Kind != "displacement" {
				t.Fatalf("explicit gas 0 victim judged %q, want displacement", f.Kind)
			}
			if f.Evidence[1].GasPrice != 0 {
				t.Fatalf("evidence lost explicit zero gas: %+v", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("explicit gas 0 must still produce displacement: %+v", reports[0].Findings)
	}
}

// TestReplayIncompleteSwapRejectedWithRulesOff ensures validation runs
// before and independently of rule selection, for both replay entry points.
func TestReplayIncompleteSwapRejectedWithRulesOff(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, spec)
	input := "\n" + `{"chainId":"1","blockHash":"0x","blockNumber":1,"swaps":[{"TxHash":"0x1","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":0},{"TxHash":"0x2","Pool":"p","Trader":"u","In":1,"Out":1,"Index":1}]}`
	for _, replay := range []func() error{
		func() error { _, err := Replay(strings.NewReader(input), dir); return err },
		func() error { _, err := ReplayWithVersion(strings.NewReader(input), dir, "off"); return err },
	} {
		err := replay()
		var le *LineError
		if !errors.As(err, &le) || le.Line != 2 {
			t.Fatalf("want LineError at line 2 under disabled rules, got %v", err)
		}
	}
	if _, err := Query(dir, "1", "0x"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("failed replay archived a block: %v", err)
	}
}

// TestReplayIncompleteSwapAbortsWholeBatch verifies all-or-nothing
// behaviour: valid new blocks earlier in the same file are neither
// archived nor reported when a later swap is incomplete, and previously
// archived content survives untouched.
func TestReplayIncompleteSwapAbortsWholeBatch(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	input := "{\"chainId\":\"2\",\"blockHash\":\"0xnew\",\"blockNumber\":1,\"swaps\":[]}\n" +
		"{\"chainId\":\"2\",\"blockHash\":\"0xb\",\"blockNumber\":2,\"swaps\":[{\"TxHash\":\"0x1\",\"Pool\":\"p\",\"Trader\":\"t\",\"In\":1,\"Out\":1,\"Index\":0}]}"
	reports, err := Replay(strings.NewReader(input), dir)
	if reports != nil {
		t.Fatalf("failed batch must return no reports, got %+v", reports)
	}
	var le *LineError
	if !errors.As(err, &le) || le.Line != 2 {
		t.Fatalf("want LineError at line 2, got %v", err)
	}
	if _, err := Query(dir, "2", "0xnew"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("earlier block partially committed: %v", err)
	}
	r, err := Query(dir, "1", "0xa")
	if err != nil || r.SwapCount != 3 {
		t.Fatalf("previously archived content damaged: %v %+v", err, r)
	}
}

func TestReplayIdempotentReimport(t *testing.T) {
	dir := t.TempDir()
	first := replay(t, dir, sandwichInput)
	second := replay(t, dir, sandwichInput)
	if len(second) != 1 || second[0].SwapCount != first[0].SwapCount {
		t.Fatalf("reimport changed report: %+v vs %+v", first, second)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Records) != 1 {
		t.Fatalf("reimport added records: %d", len(data.Records))
	}
	// The returned report must be the archived original.
	if len(second[0].Findings) != 1 || second[0].Findings[0].Kind != "sandwich" {
		t.Fatalf("reimport did not return original report: %+v", second[0])
	}
}

func TestReplayConflictWithArchive(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	conflict := `{"chainId":"1","blockHash":"0xa","blockNumber":99,"swaps":[]}`
	_, err := Replay(strings.NewReader(conflict), dir)
	var le *LineError
	if !errors.As(err, &le) || le.Line != 1 {
		t.Fatalf("want LineError at line 1, got %v", err)
	}
	// Original record must survive.
	r, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if r.BlockNumber != 10 || r.SwapCount != 3 {
		t.Fatalf("archived record was modified: %+v", r)
	}
}

func TestReplayAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	// New valid block followed by a conflicting one: nothing may be committed.
	input := `{"chainId":"2","blockHash":"0xnew","blockNumber":1,"swaps":[]}{"chainId":"1","blockHash":"0xa","blockNumber":99,"swaps":[]}`
	if _, err := Replay(strings.NewReader(input), dir); err == nil {
		t.Fatal("expected conflict error")
	}
	if _, err := Query(dir, "2", "0xnew"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("partial commit leaked block 2/0xnew: %v", err)
	}
	r, err := Query(dir, "1", "0xa")
	if err != nil || r.BlockNumber != 10 {
		t.Fatalf("original record damaged: %v %+v", err, r)
	}
}

func TestQueryUnknownBlock(t *testing.T) {
	dir := t.TempDir()
	replay(t, dir, sandwichInput)
	if _, err := Query(dir, "1", "0xmissing"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("got %v, want ErrUnknownBlock", err)
	}
	if _, err := Query(dir, "9", "0xa"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("got %v, want ErrUnknownBlock", err)
	}
	if _, err := Query(filepath.Join(dir, "nope"), "1", "0xa"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("got %v, want ErrUnknownBlock", err)
	}
}

func TestQueryMatchesReplayOutput(t *testing.T) {
	dir := t.TempDir()
	reports := replay(t, dir, sandwichInput)
	got, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, reports[0]) {
		t.Fatalf("query report differs from replay report:\n%+v\n%+v", got, reports[0])
	}
}

func TestReplayBusyArchive(t *testing.T) {
	dir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(strings.NewReader(sandwichInput), dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
}

func TestReplayMultiBlockOrder(t *testing.T) {
	dir := t.TempDir()
	input := "{\"chainId\":\"1\",\"blockHash\":\"0x1\",\"blockNumber\":1,\"swaps\":[]}\n" +
		"{\"chainId\":\"1\",\"blockHash\":\"0x2\",\"blockNumber\":2,\"swaps\":[]}\n" +
		"{\"chainId\":\"1\",\"blockHash\":\"0x1\",\"blockNumber\":1,\"swaps\":[]}\n"
	reports := replay(t, dir, input)
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	if reports[0].BlockHash != "0x1" || reports[1].BlockHash != "0x2" {
		t.Fatalf("reports not in first-appearance order: %+v", reports)
	}
}
