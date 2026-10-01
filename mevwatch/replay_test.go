package mevwatch

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func makeSwap(tx, pool, trader string, in, out, gas int64, index int) Swap {
	return Swap{TxHash: tx, Pool: pool, Trader: trader, In: in, Out: out, GasPrice: gas, Index: index}
}

// ---------------------------------------------------------------------------
// DetectAll
// ---------------------------------------------------------------------------

func TestDetectAllSandwich(t *testing.T) {
	swaps := []Swap{
		makeSwap("0xfront", "p1", "bot", 100, 90, 100, 0),
		makeSwap("0xvictim", "p1", "user", 50, 45, 10, 1),
		makeSwap("0xback", "p1", "bot", 90, 99, 90, 2),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Kind != "sandwich" || f.Severity != 3 || f.TxHash != "0xvictim" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if len(f.Swaps) != 3 || f.Swaps[0].TxHash != "0xfront" || f.Swaps[1].TxHash != "0xvictim" || f.Swaps[2].TxHash != "0xback" {
		t.Fatalf("unexpected swaps: %+v", f.Swaps)
	}
}

func TestDetectAllDisplacement(t *testing.T) {
	// front gas 21 > 2*10 = 20 -> displacement
	swaps := []Swap{
		makeSwap("0xf", "p", "x", 1, 1, 21, 0),
		makeSwap("0xd", "p", "y", 1, 1, 10, 1),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].Kind != "displacement" || findings[0].Severity != 2 {
		t.Fatalf("expected displacement, got %+v", findings)
	}
	if findings[0].TxHash != "0xd" || len(findings[0].Swaps) != 2 {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
}

func TestDetectAllStrictlyGreater(t *testing.T) {
	// front gas exactly 2*victim -> no displacement (strict)
	swaps := []Swap{
		makeSwap("0xf", "p", "x", 1, 1, 20, 0),
		makeSwap("0xd", "p", "y", 1, 1, 10, 1),
	}
	if findings := DetectAll(swaps); len(findings) != 0 {
		t.Fatalf("expected no finding at exactly 2x, got %+v", findings)
	}
}

func TestDetectAllLastSwapVictim(t *testing.T) {
	// The last swap in the pool has no back neighbour but can still be
	// displaced by the front.
	swaps := []Swap{
		makeSwap("0xf", "p", "x", 1, 1, 100, 0),
		makeSwap("0xd", "p", "y", 1, 1, 10, 1),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].TxHash != "0xd" {
		t.Fatalf("last swap should be flagged, got %+v", findings)
	}
}

func TestDetectAllZeroGas(t *testing.T) {
	// victim gas 0: any positive front gas dominates.
	swaps := []Swap{
		makeSwap("0xf", "p", "x", 1, 1, 1, 0),
		makeSwap("0xd", "p", "y", 1, 1, 0, 1),
	}
	if findings := DetectAll(swaps); len(findings) != 1 || findings[0].Kind != "displacement" {
		t.Fatalf("expected displacement for zero gas victim, got %+v", findings)
	}
}

func TestDetectAllMaxInt64Gas(t *testing.T) {
	maxGas := int64(math.MaxInt64)
	// front == victim == max: no displacement (2*victim overflows).
	swaps := []Swap{
		makeSwap("0xf", "p", "x", 1, 1, maxGas, 0),
		makeSwap("0xd", "p", "y", 1, 1, maxGas, 1),
	}
	if findings := DetectAll(swaps); len(findings) != 0 {
		t.Fatalf("expected no finding at max gas, got %+v", findings)
	}

	// victim = 2^62: 2*victim overflows, front cannot dominate.
	twoTo62 := int64(1) << 62
	swaps = []Swap{
		makeSwap("0xf", "p", "x", 1, 1, maxGas, 0),
		makeSwap("0xd", "p", "y", 1, 1, twoTo62, 1),
	}
	if findings := DetectAll(swaps); len(findings) != 0 {
		t.Fatalf("expected no finding at 2^62 victim, got %+v", findings)
	}

	// victim = 2^62 - 1: 2*victim = 2^63 - 2 fits, front = max dominates.
	swaps = []Swap{
		makeSwap("0xf", "p", "x", 1, 1, maxGas, 0),
		makeSwap("0xd", "p", "y", 1, 1, twoTo62-1, 1),
	}
	if findings := DetectAll(swaps); len(findings) != 1 || findings[0].Kind != "displacement" {
		t.Fatalf("expected displacement just below 2^62, got %+v", findings)
	}
}

func TestDetectAllSandwichRequiresSameTrader(t *testing.T) {
	// front and back are different traders -> no sandwich; displacement
	// still applies to the victim if front gas dominates.
	swaps := []Swap{
		makeSwap("0xf", "p", "bot-a", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1),
		makeSwap("0xb", "p", "bot-b", 1, 1, 90, 2),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].Kind != "displacement" {
		t.Fatalf("expected displacement (no sandwich), got %+v", findings)
	}
}

func TestDetectAllSandwichRequiresDifferentTrader(t *testing.T) {
	// front/back same trader as victim -> no sandwich.
	swaps := []Swap{
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "bot", 1, 1, 10, 1),
		makeSwap("0xb", "p", "bot", 1, 1, 90, 2),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].Kind != "displacement" {
		t.Fatalf("expected displacement (no sandwich), got %+v", findings)
	}
}

func TestDetectAllSandwichRequiresHigherGas(t *testing.T) {
	// back gas not higher than victim -> no sandwich.
	swaps := []Swap{
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1),
		makeSwap("0xb", "p", "bot", 1, 1, 5, 2),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].Kind != "displacement" {
		t.Fatalf("expected displacement (no sandwich), got %+v", findings)
	}
}

func TestDetectAllGroupsByPoolAndSortsByIndex(t *testing.T) {
	// Swaps arrive out of order; detection must sort by Index and keep
	// pools separate.
	swaps := []Swap{
		makeSwap("0xb", "p1", "bot", 1, 1, 90, 2),
		makeSwap("0xd", "p1", "user", 1, 1, 10, 1),
		makeSwap("0xf", "p1", "bot", 1, 1, 100, 0),
		makeSwap("0xother", "p2", "x", 1, 1, 1000, 0),
	}
	findings := DetectAll(swaps)
	if len(findings) != 1 || findings[0].Kind != "sandwich" || findings[0].TxHash != "0xd" {
		t.Fatalf("expected sandwich on p1, got %+v", findings)
	}
}

func TestDetectAllEmpty(t *testing.T) {
	if findings := DetectAll(nil); len(findings) != 0 {
		t.Fatalf("expected no findings for empty input, got %+v", findings)
	}
}

func TestRankOrdering(t *testing.T) {
	findings := []Finding{
		{TxHash: "0xb", Kind: "displacement", Severity: 2},
		{TxHash: "0xa", Kind: "sandwich", Severity: 3},
		{TxHash: "0xc", Kind: "displacement", Severity: 2},
	}
	ranked := Rank(findings)
	if ranked[0].TxHash != "0xa" || ranked[1].TxHash != "0xb" || ranked[2].TxHash != "0xc" {
		t.Fatalf("unexpected order: %+v", ranked)
	}
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

func TestParseReplayInputValid(t *testing.T) {
	input := strings.Join([]string{
		`{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[]}`,
		``,
		`   `,
		`{"chainId":"0x1","blockHash":"0xbb","blockNumber":2,"swaps":[{"TxHash":"a","Pool":"p","Trader":"t","In":1,"Out":2,"GasPrice":3,"Index":0}]}`,
	}, "\n")
	blocks, err := ParseReplayInput(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(blocks))
	}
	if blocks[0].ChainID != "0x1" || blocks[0].BlockHash != "0xaa" || blocks[0].BlockNumber != 1 || len(blocks[0].Swaps) != 0 {
		t.Fatalf("unexpected block: %+v", blocks[0])
	}
	if blocks[1].Swaps[0].TxHash != "a" || blocks[1].Swaps[0].GasPrice != 3 || blocks[1].Swaps[0].Index != 0 {
		t.Fatalf("unexpected swap: %+v", blocks[1].Swaps[0])
	}
	if blocks[0].Line != 1 || blocks[1].Line != 4 {
		t.Fatalf("unexpected line numbers: %d, %d", blocks[0].Line, blocks[1].Line)
	}
}

func TestParseReplayInputEmpty(t *testing.T) {
	blocks, err := ParseReplayInput(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(blocks) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(blocks))
	}
}

func TestParseReplayInputErrors(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"invalid json", `{not json}`, "invalid JSON"},
		{"not object", `[1,2,3]`, "expected a JSON object"},
		{"missing chainId", `{"blockHash":"0xaa","blockNumber":1,"swaps":[]}`, "missing \"chainId\""},
		{"empty chainId", `{"chainId":"","blockHash":"0xaa","blockNumber":1,"swaps":[]}`, "\"chainId\" must not be empty"},
		{"chainId not string", `{"chainId":1,"blockHash":"0xaa","blockNumber":1,"swaps":[]}`, "\"chainId\" must be a string"},
		{"missing blockHash", `{"chainId":"0x1","blockNumber":1,"swaps":[]}`, "missing \"blockHash\""},
		{"empty blockHash", `{"chainId":"0x1","blockHash":"","blockNumber":1,"swaps":[]}`, "\"blockHash\" must not be empty"},
		{"missing blockNumber", `{"chainId":"0x1","blockHash":"0xaa","swaps":[]}`, "missing \"blockNumber\""},
		{"negative blockNumber", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":-1,"swaps":[]}`, "\"blockNumber\" must not be negative"},
		{"float blockNumber", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1.5,"swaps":[]}`, "\"blockNumber\" must be a non-negative integer"},
		{"blockNumber overflow", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":99999999999999999999999,"swaps":[]}`, "\"blockNumber\" must be a non-negative integer in int64 range"},
		{"swaps not array", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":{}}`, "\"swaps\" must be an array"},
		{"swap not object", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[1]}`, "expected a JSON object"},
		{"missing TxHash", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":0}]}`, "missing \"TxHash\""},
		{"empty TxHash", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":0}]}`, "\"TxHash\" must not be empty"},
		{"empty Pool", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":0}]}`, "\"Pool\" must not be empty"},
		{"empty Trader", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"p","Trader":"","In":1,"Out":1,"GasPrice":1,"Index":0}]}`, "\"Trader\" must not be empty"},
		{"negative In", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"p","Trader":"t","In":-1,"Out":1,"GasPrice":1,"Index":0}]}`, "\"In\" must not be negative"},
		{"float Out", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"p","Trader":"t","In":1,"Out":1.5,"GasPrice":1,"Index":0}]}`, "\"Out\" must be a non-negative integer"},
		{"negative GasPrice", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":-5,"Index":0}]}`, "\"GasPrice\" must not be negative"},
		{"negative Index", `{"chainId":"0x1","blockHash":"0xaa","blockNumber":1,"swaps":[{"TxHash":"a","Pool":"p","Trader":"t","In":1,"Out":1,"GasPrice":1,"Index":-1}]}`, "\"Index\" must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseReplayInput(strings.NewReader(tt.line))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			var lineErr *LineError
			if !errors.As(err, &lineErr) {
				t.Fatalf("expected *LineError, got %T: %v", err, err)
			}
			if lineErr.Line != 1 {
				t.Fatalf("expected line 1, got %d", lineErr.Line)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %q", tt.want, err.Error())
			}
		})
	}
}

func TestParseReplayInputLineNumber(t *testing.T) {
	input := "  \n\n{not json}\n"
	_, err := ParseReplayInput(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error")
	}
	var lineErr *LineError
	if !errors.As(err, &lineErr) || lineErr.Line != 3 {
		t.Fatalf("expected line 3, got %v", err)
	}
}

func TestValidateBlockDedup(t *testing.T) {
	// Identical records repeated: keep one copy.
	block := BlockInput{Swaps: []Swap{
		makeSwap("a", "p", "t", 1, 1, 1, 0),
		makeSwap("a", "p", "t", 1, 1, 1, 0),
	}}
	deduped, err := ValidateBlock(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduped swap, got %d", len(deduped))
	}
}

func TestValidateBlockConflict(t *testing.T) {
	tests := []struct {
		name  string
		swaps []Swap
		want  string
	}{
		{
			"same tx different fields",
			[]Swap{
				makeSwap("a", "p", "t", 1, 1, 1, 0),
				makeSwap("a", "p", "t", 2, 1, 1, 0),
			},
			`conflicting records for TxHash "a"`,
		},
		{
			"different tx same index",
			[]Swap{
				makeSwap("a", "p", "t", 1, 1, 1, 0),
				makeSwap("b", "p", "t", 1, 1, 1, 0),
			},
			"Index 0 is occupied by multiple transactions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateBlock(BlockInput{Swaps: tt.swaps})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Archive
// ---------------------------------------------------------------------------

func newTestArchive(t *testing.T) *Archive {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "archive")
	return OpenArchive(dir)
}

func blockLine(chain, hash string, number int64, swaps ...Swap) string {
	// Build JSON manually to avoid import cycles in test helpers.
	var sb strings.Builder
	sb.WriteString(`{"chainId":"`)
	sb.WriteString(chain)
	sb.WriteString(`","blockHash":"`)
	sb.WriteString(hash)
	sb.WriteString(`","blockNumber":`)
	sb.WriteString(intToString(number))
	sb.WriteString(`,"swaps":[`)
	for i, s := range swaps {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"TxHash":"`)
		sb.WriteString(s.TxHash)
		sb.WriteString(`","Pool":"`)
		sb.WriteString(s.Pool)
		sb.WriteString(`","Trader":"`)
		sb.WriteString(s.Trader)
		sb.WriteString(`","In":`)
		sb.WriteString(intToString(s.In))
		sb.WriteString(`,"Out":`)
		sb.WriteString(intToString(s.Out))
		sb.WriteString(`,"GasPrice":`)
		sb.WriteString(intToString(s.GasPrice))
		sb.WriteString(`,"Index":`)
		sb.WriteString(intToString(int64(s.Index)))
		sb.WriteString(`}`)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func intToString(n int64) string {
	return strconv.FormatInt(n, 10)
}

func TestArchiveReplayAndReport(t *testing.T) {
	archive := newTestArchive(t)
	input := strings.Join([]string{
		blockLine("0x1", "0xaa", 100,
			makeSwap("0xf", "p1", "bot", 100, 90, 100, 0),
			makeSwap("0xd", "p1", "user", 50, 45, 10, 1),
			makeSwap("0xb", "p1", "bot", 90, 99, 90, 2)),
		blockLine("0x1", "0xbb", 101),
	}, "\n")

	reports, err := archive.Replay(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	if reports[0].ChainID != "0x1" || reports[0].BlockHash != "0xaa" || reports[0].BlockNumber != 100 || reports[0].SwapCount != 3 {
		t.Fatalf("unexpected report: %+v", reports[0])
	}
	if len(reports[0].Findings) != 1 || reports[0].Findings[0].Kind != "sandwich" || reports[0].Findings[0].Severity != 3 {
		t.Fatalf("unexpected findings: %+v", reports[0].Findings)
	}
	if reports[1].SwapCount != 0 || len(reports[1].Findings) != 0 {
		t.Fatalf("empty block should have empty findings, got %+v", reports[1])
	}

	// Report command reads only the archive.
	got, err := archive.Report("0x1", "0xaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, reports[0]) {
		t.Fatalf("report mismatch: %+v vs %+v", got, reports[0])
	}
}

func TestArchiveReportUnknown(t *testing.T) {
	archive := newTestArchive(t)
	_, err := archive.Report("0x1", "0xzz")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestArchiveIdempotentReimport(t *testing.T) {
	archive := newTestArchive(t)
	line := blockLine("0x1", "0xaa", 100,
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1))

	first, err := archive.Replay(strings.NewReader(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := archive.Replay(strings.NewReader(line))
	if err != nil {
		t.Fatalf("unexpected error on reimport: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("reimport should return the same report")
	}

	// Index must still have exactly one entry.
	idx, err := archive.loadIndex()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx.Blocks) != 1 {
		t.Fatalf("expected 1 index entry, got %d", len(idx.Blocks))
	}
}

func TestArchiveConflictRejected(t *testing.T) {
	archive := newTestArchive(t)
	line := blockLine("0x1", "0xaa", 100,
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1))
	if _, err := archive.Replay(strings.NewReader(line)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	conflicts := []struct {
		name string
		line string
	}{
		{"changed height", blockLine("0x1", "0xaa", 101)},
		{"changed swaps", blockLine("0x1", "0xaa", 100,
			makeSwap("0xf", "p", "bot", 1, 1, 100, 0))},
	}
	for _, c := range conflicts {
		t.Run(c.name, func(t *testing.T) {
			_, err := archive.Replay(strings.NewReader(c.line))
			if err == nil {
				t.Fatal("expected conflict error")
			}
			var lineErr *LineError
			if !errors.As(err, &lineErr) {
				t.Fatalf("expected LineError, got %T", err)
			}
			if !strings.Contains(err.Error(), "block conflict") {
				t.Fatalf("expected block conflict, got %v", err)
			}
		})
	}

	// Original report unchanged.
	got, err := archive.Report("0x1", "0xaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.BlockNumber != 100 || got.SwapCount != 2 {
		t.Fatalf("report was modified: %+v", got)
	}
}

func TestArchivePermutationInvariant(t *testing.T) {
	archive := newTestArchive(t)
	// Same swaps, different order, with an exact duplicate.
	line1 := blockLine("0x1", "0xaa", 100,
		makeSwap("0xd", "p", "user", 1, 1, 10, 1),
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0))
	line2 := blockLine("0x1", "0xaa", 100,
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1),
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0))

	if _, err := archive.Replay(strings.NewReader(line1)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reports, err := archive.Replay(strings.NewReader(line2))
	if err != nil {
		t.Fatalf("permutation with duplicate should be identical: %v", err)
	}
	if len(reports) != 1 || reports[0].SwapCount != 2 {
		t.Fatalf("expected identical report, got %+v", reports)
	}
}

func TestArchiveRepeatedIdentityInFile(t *testing.T) {
	archive := newTestArchive(t)
	// Same identity twice with identical content -> one report.
	line := blockLine("0x1", "0xaa", 100, makeSwap("a", "p", "t", 1, 1, 1, 0))
	input := line + "\n" + line
	reports, err := archive.Replay(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	// Same identity twice with different content -> reject.
	conflict := line + "\n" + blockLine("0x1", "0xaa", 101, makeSwap("a", "p", "t", 1, 1, 1, 0))
	_, err = archive.Replay(strings.NewReader(conflict))
	if err == nil || !strings.Contains(err.Error(), "block conflict") {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestArchiveErrorLeavesUnchanged(t *testing.T) {
	archive := newTestArchive(t)
	good := blockLine("0x1", "0xaa", 100, makeSwap("a", "p", "t", 1, 1, 1, 0))
	bad := `{"chainId":"0x1","blockHash":"0xbb","blockNumber":-1,"swaps":[]}`
	input := good + "\n" + bad

	if _, err := archive.Replay(strings.NewReader(input)); err == nil {
		t.Fatal("expected error")
	}

	// No index, no objects, no reports.
	entries, err := os.ReadDir(archive.dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() == "index.json" {
			t.Fatal("index.json should not exist after failed replay")
		}
	}
	objectsDir := filepath.Join(archive.dir, "objects")
	if entries, err := os.ReadDir(objectsDir); err == nil && len(entries) != 0 {
		t.Fatalf("objects dir should be empty, got %v", entries)
	}

	// Good block was not committed.
	if _, err := archive.Report("0x1", "0xaa"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("good block should not be visible, got %v", err)
	}
}

func TestArchiveNoTempFilesAfterFailure(t *testing.T) {
	archive := newTestArchive(t)
	bad := `{"chainId":"","blockHash":"0xbb","blockNumber":1,"swaps":[]}`
	if _, err := archive.Replay(strings.NewReader(bad)); err == nil {
		t.Fatal("expected error")
	}
	// A successful replay afterwards must clean up and commit normally.
	good := blockLine("0x1", "0xaa", 100, makeSwap("a", "p", "t", 1, 1, 1, 0))
	if _, err := archive.Replay(strings.NewReader(good)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entries, err := os.ReadDir(archive.dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", entry.Name())
		}
	}
}

func TestArchiveConcurrentReplays(t *testing.T) {
	archive := newTestArchive(t)
	line := blockLine("0x1", "0xaa", 100,
		makeSwap("0xf", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd", "p", "user", 1, 1, 10, 1))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := archive.Replay(strings.NewReader(line))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil && !errors.Is(err, ErrBusy) {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Archive must be consistent: exactly one block, readable report.
	idx, err := archive.loadIndex()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(idx.Blocks) != 1 {
		t.Fatalf("expected 1 block after concurrent replays, got %d", len(idx.Blocks))
	}
	report, err := archive.Report("0x1", "0xaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.SwapCount != 2 {
		t.Fatalf("expected 2 swaps, got %d", report.SwapCount)
	}

	// No temp files left.
	entries, err := os.ReadDir(archive.dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", entry.Name())
		}
	}
}

func TestArchiveSpecialCharactersInIdentity(t *testing.T) {
	archive := newTestArchive(t)
	// chainId/blockHash with path separators and dots must not escape the
	// objects dir.
	line := blockLine("../../etc", "../../passwd", 1, makeSwap("a", "p", "t", 1, 1, 1, 0))
	if _, err := archive.Replay(strings.NewReader(line)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	report, err := archive.Report("../../etc", "../../passwd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ChainID != "../../etc" || report.BlockHash != "../../passwd" {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestArchiveFindingsOrdering(t *testing.T) {
	archive := newTestArchive(t)
	// Two victims: a sandwich (severity 3) and a displacement (severity 2).
	swaps := []Swap{
		makeSwap("0xf1", "p", "bot", 1, 1, 100, 0),
		makeSwap("0xd1", "p", "user", 1, 1, 10, 1),
		makeSwap("0xb1", "p", "bot", 1, 1, 90, 2),
		makeSwap("0xf2", "p", "bot", 1, 1, 100, 3),
		makeSwap("0xd2", "p", "user", 1, 1, 10, 4),
	}
	line := blockLine("0x1", "0xaa", 100, swaps...)
	reports, err := archive.Replay(strings.NewReader(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	findings := reports[0].Findings
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// Severity 3 first, then severity 2.
	if findings[0].Severity != 3 || findings[0].TxHash != "0xd1" {
		t.Fatalf("expected sandwich first, got %+v", findings[0])
	}
	if findings[1].Severity != 2 || findings[1].TxHash != "0xd2" {
		t.Fatalf("expected displacement second, got %+v", findings[1])
	}
}

func TestArchiveReportDoesNotNeedInputFile(t *testing.T) {
	archive := newTestArchive(t)
	line := blockLine("0x1", "0xaa", 100, makeSwap("a", "p", "t", 1, 1, 1, 0))
	if _, err := archive.Replay(strings.NewReader(line)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Report works with no input file present (it never needed one).
	report, err := archive.Report("0x1", "0xaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.BlockNumber != 100 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestArchiveInputOnlyBlanks(t *testing.T) {
	archive := newTestArchive(t)
	reports, err := archive.Replay(strings.NewReader("  \n\n\t\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 0 {
		t.Fatalf("expected 0 reports, got %d", len(reports))
	}
}

func TestArchiveReportEmptyFindings(t *testing.T) {
	archive := newTestArchive(t)
	line := blockLine("0x1", "0xbb", 101)
	reports, err := archive.Replay(strings.NewReader(line))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reports[0].Findings == nil {
		t.Fatal("findings should be an empty slice, not nil")
	}
	if len(reports[0].Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(reports[0].Findings))
	}
}
