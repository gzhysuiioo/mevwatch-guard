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
func Detect(swaps []Swap, victim string) []Finding {
	victimIndex := -1
	for index, swap := range swaps {
		if swap.TxHash == victim {
			victimIndex = index
			break
		}
	}
	if victimIndex <= 0 || victimIndex >= len(swaps)-1 {
		return nil
	}
	front, back := swaps[victimIndex-1], swaps[victimIndex+1]
	if front.Trader == back.Trader && front.Pool == back.Pool && front.Trader != swaps[victimIndex].Trader &&
		front.GasPrice > swaps[victimIndex].GasPrice && back.GasPrice > swaps[victimIndex].GasPrice {
		return []Finding{{
			TxHash: victim, Kind: "sandwich", Severity: 3,
			Evidence: []string{
				"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
				"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
				"victim gas " + strconv.FormatInt(swaps[victimIndex].GasPrice, 10),
			},
		}}
	}
	if front.GasPrice > swaps[victimIndex].GasPrice*2 {
		return []Finding{{TxHash: victim, Kind: "displacement", Severity: 2,
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
