package mevwatch

import (
	"math"
	"reflect"
	"testing"
)

// detectSwaps covers the judgment edges: a sandwich, a displacement on the
// pool's last swap, a first-in-pool swap with no conclusion, interleaved
// records of another pool, a zero-gas victim and gas prices near MaxInt64.
var detectSwaps = []Swap{
	{TxHash: "0xfront", Pool: "p1", Trader: "bot", In: 500, Out: 480, GasPrice: 90, Index: 0},
	{TxHash: "0xother", Pool: "p2", Trader: "bot", In: 1, Out: 1, GasPrice: 999, Index: 1},
	{TxHash: "0xvictim", Pool: "p1", Trader: "user", In: 200, Out: 188, GasPrice: 10, Index: 2},
	{TxHash: "0xback", Pool: "p1", Trader: "bot", In: 480, Out: 505, GasPrice: 80, Index: 3},
	{TxHash: "0xbig", Pool: "p3", Trader: "whale", In: 1, Out: 1, GasPrice: 30, Index: 4},
	{TxHash: "0xsmall", Pool: "p3", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 5},
	{TxHash: "0xzero", Pool: "p3", Trader: "user", In: 1, Out: 1, GasPrice: 0, Index: 6},
	{TxHash: "0xmax1", Pool: "p4", Trader: "a", In: 0, Out: 0, GasPrice: math.MaxInt64, Index: 7},
	{TxHash: "0xmax2", Pool: "p4", Trader: "b", In: 0, Out: 0, GasPrice: math.MaxInt64, Index: 8},
}

func blockFindingByTx(findings []ReportFinding) map[string]ReportFinding {
	out := make(map[string]ReportFinding, len(findings))
	for _, f := range findings {
		out[f.TxHash] = f
	}
	return out
}

// The single-transaction Detect and the built-in whole-block detection must
// reach the same conclusion for every transaction of the same records:
// whether it hits, the conclusion kind and the severity.
func TestDetectConsistentWithDetectBlock(t *testing.T) {
	block := blockFindingByTx(DetectBlock(detectSwaps))
	for _, s := range detectSwaps {
		single := Detect(detectSwaps, s.TxHash)
		bf, flagged := block[s.TxHash]
		if !flagged {
			if len(single) != 0 {
				t.Fatalf("Detect(%s) = %+v, block has no conclusion", s.TxHash, single)
			}
			continue
		}
		if len(single) != 1 {
			t.Fatalf("Detect(%s) returned %d findings, want the single block conclusion", s.TxHash, len(single))
		}
		got := single[0]
		if got.TxHash != bf.TxHash || got.Kind != bf.Kind || got.Severity != bf.Severity {
			t.Fatalf("Detect(%s) = (%s, %d), block = (%s, %d)",
				s.TxHash, got.Kind, got.Severity, bf.Kind, bf.Severity)
		}
	}
	// Spot-check the expected conclusions of the fixture.
	want := map[string]string{
		"0xvictim": "sandwich",
		"0xsmall":  "displacement",
		"0xzero":   "displacement",
	}
	for tx, kind := range want {
		if got := block[tx]; got.Kind != kind {
			t.Fatalf("block conclusion for %s = %q, want %q", tx, got.Kind, kind)
		}
	}
	for _, tx := range []string{"0xfront", "0xother", "0xback", "0xbig", "0xmax1", "0xmax2"} {
		if _, flagged := block[tx]; flagged {
			t.Fatalf("%s unexpectedly flagged: %+v", tx, block[tx])
		}
	}
}

// An absent victim has no conclusion, and the input slice and its order are
// never modified.
func TestDetectUnknownVictimAndInputUntouched(t *testing.T) {
	if got := Detect(detectSwaps, "0xmissing"); got != nil {
		t.Fatalf("Detect(unknown) = %+v, want nil", got)
	}
	before := append([]Swap(nil), detectSwaps...)
	Detect(detectSwaps, "0xvictim")
	DetectBlock(detectSwaps)
	if !reflect.DeepEqual(detectSwaps, before) {
		t.Fatalf("input mutated:\nbefore %+v\nafter  %+v", before, detectSwaps)
	}
}

// Neither the input order nor interleaved records of other pools can change
// the single-transaction conclusion.
func TestDetectIndependentOfInputOrder(t *testing.T) {
	reversed := make([]Swap, len(detectSwaps))
	for i, s := range detectSwaps {
		reversed[len(detectSwaps)-1-i] = s
	}
	for _, tx := range []string{"0xvictim", "0xsmall", "0xzero", "0xfront", "0xmax2"} {
		if got, want := Detect(reversed, tx), Detect(detectSwaps, tx); !reflect.DeepEqual(got, want) {
			t.Fatalf("Detect(%s) changed under reordering:\nforward %+v\nreverse %+v", tx, want, got)
		}
	}
}

// The single-transaction text evidence keeps its established content and
// order: front-run, back-run, victim for a sandwich.
func TestDetectSandwichEvidenceText(t *testing.T) {
	findings := Detect(detectSwaps, "0xvictim")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	want := []string{
		"front-run by bot at gas 90",
		"back-run by bot at gas 80",
		"victim gas 10",
	}
	if !reflect.DeepEqual(findings[0].Evidence, want) {
		t.Fatalf("evidence = %v, want %v", findings[0].Evidence, want)
	}
}

// A sandwich-shaped pattern that only reaches the displacement threshold
// exactly (front gas == multiplier * victim gas) does not hit.
func TestDetectDisplacementStrictlyGreater(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xeq", Pool: "p", Trader: "a", In: 1, Out: 1, GasPrice: 20, Index: 0},
		{TxHash: "0xv", Pool: "p", Trader: "b", In: 1, Out: 1, GasPrice: 10, Index: 1},
	}
	if got := Detect(swaps, "0xv"); got != nil {
		t.Fatalf("exact 2x front gas flagged: %+v", got)
	}
	swaps[0].GasPrice = 21
	got := Detect(swaps, "0xv")
	if len(got) != 1 || got[0].Kind != "displacement" || got[0].Severity != 2 {
		t.Fatalf("Detect = %+v, want one displacement severity 2", got)
	}
}

// The shared judgment honours the registered version's switches: with the
// sandwich rule off the same transaction can hit displacement, and with both
// rules off the block yields an empty conclusion array.
func TestDetectBlockWithRulesSwitches(t *testing.T) {
	swaps := []Swap{
		{TxHash: "0xf", Pool: "p", Trader: "bot", In: 1, Out: 1, GasPrice: 90, Index: 0},
		{TxHash: "0xv", Pool: "p", Trader: "user", In: 1, Out: 1, GasPrice: 10, Index: 1},
		{TxHash: "0xb", Pool: "p", Trader: "bot", In: 1, Out: 1, GasPrice: 80, Index: 2},
	}
	noSandwich := RuleSet{
		Sandwich:     SandwichRule{Enabled: false, Severity: 3},
		Displacement: DisplacementRule{Enabled: true, Severity: 2, Multiplier: 2},
	}
	findings := DetectBlockWithRules(swaps, noSandwich)
	if len(findings) != 1 || findings[0].Kind != "displacement" || findings[0].TxHash != "0xv" {
		t.Fatalf("sandwich disabled: got %+v, want one displacement on 0xv", findings)
	}
	bothOff := RuleSet{
		Sandwich:     SandwichRule{Enabled: false, Severity: 3},
		Displacement: DisplacementRule{Enabled: false, Severity: 2, Multiplier: 2},
	}
	if findings := DetectBlockWithRules(swaps, bothOff); len(findings) != 0 {
		t.Fatalf("both rules off: got %+v, want empty", findings)
	}
}
