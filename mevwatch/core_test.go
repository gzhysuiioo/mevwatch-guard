package mevwatch

import (
	"math"
	"reflect"
	"testing"
)

func TestDetectSandwichAcrossInterleavedPools(t *testing.T) {
	// Same-pool bot/user/bot sit at Index 0/2/4; another pool occupies 1/3.
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xother1", Pool: "p2", Trader: "whale", In: 1, Out: 1, GasPrice: 999, Index: 1},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 2},
		{TxHash: "0xother2", Pool: "p2", Trader: "whale", In: 1, Out: 1, GasPrice: 999, Index: 3},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 80, Index: 4},
	}
	got := Detect(swaps, "0xvictim")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Kind != "sandwich" || f.Severity != 3 || f.TxHash != "0xvictim" {
		t.Fatalf("bad finding: %+v", f)
	}
	wantEvidence := []string{
		"front-run by bot at gas 90",
		"back-run by bot at gas 80",
		"victim gas 10",
	}
	if !reflect.DeepEqual(f.Evidence, wantEvidence) {
		t.Fatalf("evidence = %v, want %v", f.Evidence, wantEvidence)
	}
}

func TestDetectPermutationInvariant(t *testing.T) {
	base := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xother1", Pool: "p2", Trader: "whale", In: 1, Out: 1, GasPrice: 999, Index: 1},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 2},
		{TxHash: "0xother2", Pool: "p2", Trader: "whale", In: 1, Out: 1, GasPrice: 999, Index: 3},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 80, Index: 4},
	}
	orders := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{3, 1, 4, 2, 0},
		{1, 0, 3, 4, 2},
	}
	var want []Finding
	for i, order := range orders {
		shuffled := make([]Swap, len(base))
		for j, k := range order {
			shuffled[j] = base[k]
		}
		got := Detect(shuffled, "0xvictim")
		if i == 0 {
			want = got
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("order %v changed the conclusion:\n got %+v\nwant %+v", order, got, want)
		}
		// The caller's slice and its ordering must be untouched.
		for j := range shuffled {
			if shuffled[j] != base[order[j]] {
				t.Fatalf("Detect mutated caller input at order %v", order)
			}
		}
	}
}

func TestDetectOtherPoolCannotSupplyNeighbours(t *testing.T) {
	// In the victim's pool the bracket is broken (back trader differs and
	// same-pool front gas is low); the other pool's high-gas records must
	// not become sandwich or displacement evidence.
	swaps := []Swap{
		{TxHash: "0xa1", Pool: "p2", Trader: "rich", In: 1, Out: 1, GasPrice: 999, Index: 0},
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 11, Index: 1},
		{TxHash: "0xa2", Pool: "p2", Trader: "rich", In: 1, Out: 1, GasPrice: 999, Index: 2},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 3},
		{TxHash: "0xback", Pool: "p1", Trader: "someone-else", In: 1, Out: 1, GasPrice: 11, Index: 4},
	}
	if got := Detect(swaps, "0xvictim"); len(got) != 0 {
		t.Fatalf("other-pool records produced a finding: %+v", got)
	}
}

func TestDetectLastSwapInPoolStillJudgesDisplacement(t *testing.T) {
	// Victim is the final swap of its pool and sits last nowhere in array
	// terms necessarily; here another pool follows it in the input.
	swaps := []Swap{
		{TxHash: "0xbig", Pool: "p1", Trader: "whale", In: 1, Out: 1, GasPrice: 30, Index: 0},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 1},
		{TxHash: "0xlater", Pool: "p2", Trader: "x", In: 1, Out: 1, GasPrice: 0, Index: 2},
	}
	got := Detect(swaps, "0xvictim")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Kind != "displacement" || got[0].Severity != 2 || got[0].TxHash != "0xvictim" {
		t.Fatalf("bad finding: %+v", got[0])
	}
	want := []string{"front gas dominates victim by more than 2x"}
	if !reflect.DeepEqual(got[0].Evidence, want) {
		t.Fatalf("evidence = %v, want %v", got[0].Evidence, want)
	}
}

func TestDetectDisplacementEdges(t *testing.T) {
	cases := []struct {
		name   string
		front  int64
		victim int64
		hit    bool
	}{
		{"exactly twice is not a hit", 20, 10, false},
		{"just over twice hits", 21, 10, true},
		{"zero victim gas, positive front hits", 1, 0, true},
		{"zero victim gas, zero front does not", 0, 0, false},
		{"equal high gas near MaxInt64 must not overflow-hit", math.MaxInt64, math.MaxInt64, false},
		{"MaxInt64 front over 100 victim hits", math.MaxInt64, 100, true},
		{"2x MaxInt64/2 would equal MaxInt64-1, not strictly more", math.MaxInt64 - 1, math.MaxInt64 / 2, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swaps := []Swap{
				{TxHash: "0xfront", Pool: "p1", Trader: "a", In: 1, Out: 1, GasPrice: tc.front, Index: 0},
				{TxHash: "0xvictim", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: tc.victim, Index: 1},
			}
			got := Detect(swaps, "0xvictim")
			if tc.hit {
				if len(got) != 1 || got[0].Kind != "displacement" {
					t.Fatalf("got %+v, want one displacement", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("got %+v, want no conclusion", got)
			}
		})
	}
}

func TestDetectSandwichPriorityOverDisplacement(t *testing.T) {
	// Front gas is >2x victim's; the bracket still holds, so sandwich wins.
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 1},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 80, Index: 2},
	}
	got := Detect(swaps, "0xvictim")
	if len(got) != 1 || got[0].Kind != "sandwich" || got[0].Severity != 3 {
		t.Fatalf("sandwich must take priority: %+v", got)
	}
}

func TestDetectBrokenBracketFallsThroughToDisplacement(t *testing.T) {
	// Same trader on both sides but back gas not higher: no sandwich; the
	// dominating front still produces displacement.
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 1},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 5, Index: 2},
	}
	got := Detect(swaps, "0xvictim")
	if len(got) != 1 || got[0].Kind != "displacement" || got[0].Severity != 2 {
		t.Fatalf("want displacement after failed sandwich: %+v", got)
	}
}

func TestDetectNoConclusionCases(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xfirst", Pool: "p2", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 1},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 1, Out: 1, GasPrice: 80, Index: 2},
	}
	if got := Detect(swaps, "0xmissing"); got != nil {
		t.Fatalf("unknown tx: got %+v, want nil", got)
	}
	// 0xfirst is the first (and only) swap of its pool: the high-gas bot in
	// another pool must not count as a predecessor.
	if got := Detect(swaps, "0xfirst"); got != nil {
		t.Fatalf("first swap of pool: got %+v, want nil", got)
	}
	if got := Detect(nil, "0xanything"); got != nil {
		t.Fatalf("empty input: got %+v, want nil", got)
	}
}

func TestDetectMatchesBuiltinBlockConclusion(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 5, Out: 6, GasPrice: 90, Index: 0},
		{TxHash: "0z-other", Pool: "p2", Trader: "w", In: 1, Out: 1, GasPrice: 99, Index: 1},
		{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 2, Out: 3, GasPrice: 10, Index: 2},
		{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 6, Out: 7, GasPrice: 80, Index: 3},
		{TxHash: "0u-tail", Pool: "p2", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 4},
	}
	block := DetectBlock(swaps)
	byTx := map[string]ReportFinding{}
	for _, f := range block {
		byTx[f.TxHash] = f
	}
	for _, tx := range []string{"0xvictim", "0u-tail"} {
		got := Detect(swaps, tx)
		blockFinding, flagged := byTx[tx]
		if !flagged {
			if len(got) != 0 {
				t.Fatalf("tx %s: block detection found nothing, Detect found %+v", tx, got)
			}
			continue
		}
		if len(got) != 1 {
			t.Fatalf("tx %s: got %d findings, want 1", tx, len(got))
		}
		if got[0].Kind != blockFinding.Kind || got[0].Severity != blockFinding.Severity ||
			got[0].TxHash != blockFinding.TxHash {
			t.Fatalf("tx %s: Detect %+v disagrees with block %+v", tx, got[0], blockFinding)
		}
	}
}
