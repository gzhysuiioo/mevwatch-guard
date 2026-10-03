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
// It applies the built-in block rules to one transaction, so its conclusion
// matches DetectBlock for the same records: neighbours are the adjacent
// swaps inside the victim's own pool ordered by Index, never swaps from
// other pools and never positions in the input slice. Reordering the input
// or interleaving other pools therefore cannot change the result. The
// victim's pool's last swap is still checked for displacement against its
// predecessor; a victim that is absent or first in its pool has no
// conclusion. The passed slice is never modified.
func Detect(swaps []Swap, victim string) []Finding {
	rules := BuiltinVersion().Rules
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
	if back != nil &&
		front.Trader == back.Trader && front.Trader != target.Trader &&
		front.GasPrice > target.GasPrice && back.GasPrice > target.GasPrice {
		return []Finding{{
			TxHash: victim, Kind: "sandwich", Severity: rules.Sandwich.Severity,
			Evidence: []string{
				"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
				"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
				"victim gas " + strconv.FormatInt(target.GasPrice, 10),
			},
		}}
	}
	if gasDominates(front.GasPrice, target.GasPrice, int64(rules.Displacement.Multiplier)) {
		return []Finding{{TxHash: victim, Kind: "displacement", Severity: rules.Displacement.Severity,
			Evidence: []string{"front gas dominates victim by more than 2x"}}}
	}
	return nil
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
