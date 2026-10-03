package mevwatch

import (
	"math"
	"reflect"
	"testing"
)

// blockFindingByTx indexes whole-block conclusions by victim transaction.
func blockFindingByTx(findings []ReportFinding) map[string]ReportFinding {
	byTx := make(map[string]ReportFinding, len(findings))
	for _, f := range findings {
		byTx[f.TxHash] = f
	}
	return byTx
}

// TestDetectMatchesDetectBlock checks that the single-transaction entry and
// the whole-block replay reach the same conclusion for every transaction of
// the same records: same hit, same kind and same severity.
func TestDetectMatchesDetectBlock(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "pool-1", Trader: "bot-a", In: 500, Out: 480, GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "pool-1", Trader: "user-1", In: 200, Out: 188, GasPrice: 12, Index: 1},
		{TxHash: "0xback", Pool: "pool-1", Trader: "bot-a", In: 480, Out: 505, GasPrice: 80, Index: 2},
		{TxHash: "0xtail", Pool: "pool-1", Trader: "user-2", In: 10, Out: 9, GasPrice: 1, Index: 3},
		{TxHash: "0xother", Pool: "pool-2", Trader: "bot-a", In: 1, Out: 1, GasPrice: 1000, Index: 0},
		{TxHash: "0xsolo", Pool: "pool-3", Trader: "user-3", In: 1, Out: 1, GasPrice: 5, Index: 0},
	}
	block := blockFindingByTx(DetectBlock(swaps))
	for _, s := range swaps {
		single := Detect(swaps, s.TxHash)
		want, hit := block[s.TxHash]
		if !hit {
			if len(single) != 0 {
				t.Fatalf("Detect(%s) = %v, want no conclusion", s.TxHash, single)
			}
			continue
		}
		if len(single) != 1 {
			t.Fatalf("Detect(%s) = %v, want exactly one conclusion", s.TxHash, single)
		}
		if single[0].Kind != want.Kind || single[0].Severity != want.Severity || single[0].TxHash != want.TxHash {
			t.Fatalf("Detect(%s) = %+v, block replay says %+v", s.TxHash, single[0], want)
		}
	}
	if got := len(Detect(swaps, "0xabsent")); got != 0 {
		t.Fatalf("Detect on absent victim returned %d findings", got)
	}
}

// TestDetectInputOrderIrrelevant permutes the input and interleaves another
// pool: the conclusion must not change, and the caller's slice and records
// must stay untouched.
func TestDetectInputOrderIrrelevant(t *testing.T) {
	base := []Swap{
		{TxHash: "0xfront", Pool: "pool-1", Trader: "bot-a", GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "pool-1", Trader: "user-1", GasPrice: 12, Index: 1},
		{TxHash: "0xback", Pool: "pool-1", Trader: "bot-a", GasPrice: 80, Index: 2},
	}
	want := Detect(base, "0xvictim")
	if len(want) != 1 || want[0].Kind != "sandwich" || want[0].Severity != 3 {
		t.Fatalf("baseline Detect = %v, want one sandwich severity 3", want)
	}
	permuted := []Swap{
		{TxHash: "0xback", Pool: "pool-1", Trader: "bot-a", GasPrice: 80, Index: 2},
		{TxHash: "0xnoise", Pool: "pool-2", Trader: "bot-a", GasPrice: 9999, Index: 0},
		{TxHash: "0xvictim", Pool: "pool-1", Trader: "user-1", GasPrice: 12, Index: 1},
		{TxHash: "0xfront", Pool: "pool-1", Trader: "bot-a", GasPrice: 90, Index: 0},
	}
	snapshot := append([]Swap(nil), permuted...)
	got := Detect(permuted, "0xvictim")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Detect on permuted input = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(permuted, snapshot) {
		t.Fatalf("Detect modified its input: %v", permuted)
	}
}

// TestDetectDisplacementEdges covers the shared judgment's edge semantics
// through the single-transaction entry: strict multiplier comparison, zero
// and near-MaxInt64 gas prices, and the pool's last swap.
func TestDetectDisplacementEdges(t *testing.T) {
	cases := []struct {
		name      string
		frontGas  int64
		victimGas int64
		wantHit   bool
	}{
		{"strictly above double hits", 25, 12, true},
		{"exactly double does not hit", 24, 12, false},
		{"zero victim dominated by positive front", 1, 0, true},
		{"zero front over zero victim does not hit", 0, 0, false},
		{"near max int64 victim not dominated", math.MaxInt64 - 1, math.MaxInt64, false},
		{"max int64 front dominates small victim", math.MaxInt64, 7, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swaps := []Swap{
				{TxHash: "0xfront", Pool: "p", Trader: "a", GasPrice: tc.frontGas, Index: 0},
				{TxHash: "0xvictim", Pool: "p", Trader: "b", GasPrice: tc.victimGas, Index: 1},
			}
			got := Detect(swaps, "0xvictim")
			if !tc.wantHit {
				if len(got) != 0 {
					t.Fatalf("Detect = %v, want no conclusion", got)
				}
				return
			}
			if len(got) != 1 || got[0].Kind != "displacement" || got[0].Severity != 2 {
				t.Fatalf("Detect = %v, want one displacement severity 2", got)
			}
			wantEvidence := []string{"front gas dominates victim by more than 2x"}
			if !reflect.DeepEqual(got[0].Evidence, wantEvidence) {
				t.Fatalf("evidence = %v, want %v", got[0].Evidence, wantEvidence)
			}
		})
	}
}

// TestDetectFirstSwapNoConclusion: a victim that is first in its pool has no
// preceding swap, so no conclusion is possible even with a matching back-run.
func TestDetectFirstSwapNoConclusion(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xvictim", Pool: "p", Trader: "user", GasPrice: 5, Index: 0},
		{TxHash: "0xback", Pool: "p", Trader: "user", GasPrice: 90, Index: 1},
	}
	if got := Detect(swaps, "0xvictim"); got != nil {
		t.Fatalf("Detect = %v, want nil", got)
	}
}

// TestDetectSandwichEvidenceOrder locks the text evidence content and order
// of a single-transaction sandwich conclusion.
func TestDetectSandwichEvidenceOrder(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p", Trader: "bot", GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "p", Trader: "user", GasPrice: 12, Index: 1},
		{TxHash: "0xback", Pool: "p", Trader: "bot", GasPrice: 80, Index: 2},
	}
	got := Detect(swaps, "0xvictim")
	if len(got) != 1 {
		t.Fatalf("Detect = %v, want one conclusion", got)
	}
	want := []string{"front-run by bot at gas 90", "back-run by bot at gas 80", "victim gas 12"}
	if !reflect.DeepEqual(got[0].Evidence, want) {
		t.Fatalf("evidence = %v, want %v", got[0].Evidence, want)
	}
}
