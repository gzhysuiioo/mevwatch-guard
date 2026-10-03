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
	// Single-transaction detection always runs the built-in version:
	// sandwich severity 3, displacement severity 2 with multiplier 2.
	rules := BuiltinVersion().Rules
	target, ok := findSwap(swaps, victim)
	if !ok {
		return nil
	}
	pool := poolSwaps(swaps, target.Pool)
	pos := -1
	for i, s := range pool {
		if s.TxHash == victim {
			pos = i
			break
		}
	}
	var front, back *Swap
	if pos > 0 {
		front = &pool[pos-1]
	}
	if pos >= 0 && pos+1 < len(pool) {
		back = &pool[pos+1]
	}
	j, hit := judgeVictim(front, target, back, rules)
	if !hit {
		return nil
	}
	if j.kind == "sandwich" {
		return []Finding{{
			TxHash: victim, Kind: j.kind, Severity: j.severity,
			Evidence: []string{
				"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
				"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
				"victim gas " + strconv.FormatInt(target.GasPrice, 10),
			},
		}}
	}
	return []Finding{{TxHash: victim, Kind: j.kind, Severity: j.severity,
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
