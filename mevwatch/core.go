// Package mevwatch implements mempool risk detection.
package mevwatch

import (
	"sort"
	"strconv"
)

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
// Adjacency is decided by Index order within the victim's own pool, exactly
// as the built-in block detection judges a whole block: swaps from other
// pools and the ordering of the input slice never participate, so permuting
// the records never changes the conclusion or the swaps behind it. The
// caller's slice is never modified.
//
// The built-in rules apply: a same-trader bracket with higher gas on both
// sides is a sandwich (severity 3, takes priority); otherwise the preceding
// same-pool swap strictly exceeding 2x the victim's gas is a displacement
// (severity 2), including when the victim is the last swap in its pool.
// There is no conclusion when the target tx is absent or has no preceding
// swap in its pool.
func Detect(swaps []Swap, victim string) []Finding {
	rules := BuiltinVersion().Rules
	var victimSwap Swap
	found := false
	for _, s := range swaps {
		if s.TxHash == victim {
			victimSwap = s
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	// Only records of the victim's pool participate. Sorting a local copy
	// leaves the caller's slice and its ordering untouched.
	pool := make([]Swap, 0, len(swaps))
	for _, s := range swaps {
		if s.Pool == victimSwap.Pool {
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
		// First swap in the pool (or otherwise without a predecessor): no
		// bracket and nothing to be displaced by.
		return nil
	}
	front := pool[pos-1]
	var back *Swap
	if pos+1 < len(pool) {
		back = &pool[pos+1]
	}
	if rules.Sandwich.Enabled && back != nil &&
		front.Trader == back.Trader && front.Trader != victimSwap.Trader &&
		front.GasPrice > victimSwap.GasPrice && back.GasPrice > victimSwap.GasPrice {
		return []Finding{{
			TxHash: victim, Kind: "sandwich", Severity: rules.Sandwich.Severity,
			Evidence: []string{
				"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
				"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
				"victim gas " + strconv.FormatInt(victimSwap.GasPrice, 10),
			},
		}}
	}
	if rules.Displacement.Enabled &&
		gasDominates(front.GasPrice, victimSwap.GasPrice, int64(rules.Displacement.Multiplier)) {
		return []Finding{{TxHash: victim, Kind: "displacement", Severity: rules.Displacement.Severity,
			Evidence: []string{"front gas dominates victim by more than 2x"}}}
	}
	return nil
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
