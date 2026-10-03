package mevwatch

import (
	"math"
	"sort"
)

// This file holds the single product logic behind both detection entries:
// the single-transaction Detect and the whole-block DetectBlockWithRules
// judge one victim swap against its adjacent neighbours through judgeVictim,
// so a transaction's hit, conclusion kind and severity can never diverge
// between the two. Only the evidence expression differs per entry point.

// judgment is the shared conclusion of the sandwich and displacement rules
// for one victim swap: the conclusion kind and the severity the active rule
// version assigns to it.
type judgment struct {
	kind     string
	severity int
}

// judgeVictim applies rules to one victim swap given its adjacent neighbours
// inside its own pool ordered by Index; front or back is nil at the pool
// edges. An enabled sandwich — the same trader on both sides, different from
// the victim's, with both GasPrices strictly above the victim's — takes
// priority and is then the victim's only conclusion. Otherwise an enabled
// displacement fires when the previous swap's GasPrice strictly exceeds
// Multiplier times the victim's; exact equality does not hit. A victim
// without a preceding swap in its pool has no conclusion, and with both
// rules off neither has anyone.
func judgeVictim(front *Swap, victim Swap, back *Swap, rules RuleSet) (judgment, bool) {
	if rules.Sandwich.Enabled && front != nil && back != nil &&
		front.Trader == back.Trader && front.Trader != victim.Trader &&
		front.GasPrice > victim.GasPrice && back.GasPrice > victim.GasPrice {
		return judgment{kind: "sandwich", severity: rules.Sandwich.Severity}, true
	}
	if rules.Displacement.Enabled && front != nil &&
		gasDominates(front.GasPrice, victim.GasPrice, int64(rules.Displacement.Multiplier)) {
		return judgment{kind: "displacement", severity: rules.Displacement.Severity}, true
	}
	return judgment{}, false
}

// gasDominates reports whether front strictly exceeds victim*multiplier,
// staying correct when victim is zero or near math.MaxInt64.
func gasDominates(front, victim int64, multiplier int64) bool {
	return victim <= math.MaxInt64/multiplier && front > victim*multiplier
}

// poolSwaps returns the swaps of one pool sorted by Index. The result is a
// fresh slice: the caller's records and their order are never modified, so
// input positions and interleaved records of other pools cannot influence
// the judgment.
func poolSwaps(swaps []Swap, pool string) []Swap {
	out := make([]Swap, 0, len(swaps))
	for _, s := range swaps {
		if s.Pool == pool {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}
