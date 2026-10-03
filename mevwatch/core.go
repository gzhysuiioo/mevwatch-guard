// Package mevwatch implements mempool risk detection.
package mevwatch

import (
	"math"
	"sort"
	"strconv"
)

// gasDominates reports whether front strictly exceeds victim*multiplier,
// staying correct when victim is zero or near math.MaxInt64.
func gasDominates(front, victim int64, multiplier int64) bool {
	return victim <= math.MaxInt64/multiplier && front > victim*multiplier
}

// judgeVictim is the single product logic behind both single-transaction
// detection (Detect) and whole-block replay (DetectBlockWithRules): given
// one victim swap and its adjacent neighbours inside its own pool (already
// ordered by Index), it decides whether the victim is sandwiched or
// displaced under the given rules.
//
// A sandwich requires the same trader on both sides, different from the
// victim's trader, with both GasPrices strictly above the victim's; an
// enabled sandwich hit is the victim's only conclusion. Otherwise the
// displacement rule hits when the previous swap's GasPrice strictly exceeds
// Multiplier times the victim's — exactly equal does not hit, a zero victim
// GasPrice is dominated by any positive previous value, and values near
// math.MaxInt64 still compare correctly. A victim without a previous swap
// in its pool has no conclusion; the pool's last swap can still be
// displaced. With both rules off nothing hits.
func judgeVictim(front, back *Swap, victim Swap, rules RuleSet) (kind string, severity int, hit bool) {
	if rules.Sandwich.Enabled && front != nil && back != nil &&
		front.Trader == back.Trader && front.Trader != victim.Trader &&
		front.GasPrice > victim.GasPrice && back.GasPrice > victim.GasPrice {
		return SuppressSandwich, rules.Sandwich.Severity, true
	}
	if rules.Displacement.Enabled && front != nil &&
		gasDominates(front.GasPrice, victim.GasPrice, int64(rules.Displacement.Multiplier)) {
		return SuppressDisplacement, rules.Displacement.Severity, true
	}
	return "", 0, false
}

// Swap is one observed swap in a pending or confirmed transaction.
type Swap struct {
	TxHash   string
	Pool     string
	Trader   string
	In       int64
	Out      int64
	GasPrice int64
	Index    int
}

// Finding is one risk conclusion with the evidence that produced it.
type Finding struct {
	TxHash   string
	Kind     string
	Severity int
	Evidence []string
}

// Detect flags sandwich and displacement patterns around one victim swap.
// It always applies the built-in rule version (sandwich severity 3,
// displacement severity 2 with multiplier 2) through the same judgment the
// block replay uses, so its conclusion matches DetectBlock for the same
// records: neighbours are the adjacent swaps inside the victim's own pool
// ordered by Index, never swaps from other pools and never positions in the
// input slice. Reordering the input or interleaving other pools therefore
// cannot change the result. The victim's pool's last swap is still checked
// for displacement against its predecessor; a victim that is absent or
// first in its pool has no conclusion. The passed slice is never modified.
func Detect(swaps []Swap, victim string) []Finding {
	target, ok := findSwap(swaps, victim)
	if !ok {
		return nil
	}
	// Collect the victim's pool into a private slice before sorting, so the
	// caller's records and their order stay untouched.
	pool := make([]Swap, 0, len(swaps))
	for _, s := range swaps {
		if s.Pool == target.Pool {
			pool = append(pool, s)
		}
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].Index < pool[j].Index })
	pos := -1
	for i, s := range pool {
		if s.TxHash == victim {
			pos = i
			break
		}
	}
	if pos <= 0 {
		// No preceding swap in the victim's pool: no neighbour can be
		// evidence, regardless of other pools' gas prices.
		return nil
	}
	front := pool[pos-1]
	var back *Swap
	if pos+1 < len(pool) {
		back = &pool[pos+1]
	}
	kind, severity, hit := judgeVictim(&front, back, target, BuiltinVersion().Rules)
	if !hit {
		return nil
	}
	if kind == SuppressSandwich {
		return []Finding{{
			TxHash: victim, Kind: kind, Severity: severity,
			Evidence: []string{
				"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
				"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
				"victim gas " + strconv.FormatInt(target.GasPrice, 10),
			},
		}}
	}
	return []Finding{{TxHash: victim, Kind: kind, Severity: severity,
		Evidence: []string{"front gas dominates victim by more than 2x"}}}
}

// findSwap returns the record whose TxHash equals hash. TxHash is unique
// among the valid records replay accepts.
func findSwap(swaps []Swap, hash string) (Swap, bool) {
	for _, s := range swaps {
		if s.TxHash == hash {
			return s, true
		}
	}
	return Swap{}, false
}

// Rank orders findings by severity then hash.
func Rank(findings []Finding) []Finding {
	sorted := append([]Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity == sorted[j].Severity {
			return sorted[i].TxHash < sorted[j].TxHash
		}
		return sorted[i].Severity > sorted[j].Severity
	})
	return sorted
}
