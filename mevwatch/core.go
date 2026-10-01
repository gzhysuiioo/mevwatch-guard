// Package mevwatch implements mempool risk detection.
package mevwatch

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

// Swap is one observed swap in a pending or confirmed transaction.
// The JSON tags are the canonical field names used by replay input.
type Swap struct {
	TxHash   string `json:"TxHash"`
	Pool     string `json:"Pool"`
	Trader   string `json:"Trader"`
	In       int64  `json:"In"`
	Out      int64  `json:"Out"`
	GasPrice int64  `json:"GasPrice"`
	Index    int    `json:"Index"`
}

// Finding is one risk conclusion with the evidence that produced it.
type Finding struct {
	TxHash   string
	Kind     string
	Severity int
	Evidence []string
	// Swaps holds the raw swap records that participated in the judgment
	// (front/victim/back for a sandwich, front/victim for a displacement).
	Swaps []Swap
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

// DetectAll scans every swap as a potential victim. Swaps are grouped by
// pool and ordered by Index; only adjacent swaps are compared. A sandwich
// (severity 3) requires both neighbours to be the same trader, different
// from the victim, and both paying strictly more gas than the victim.
// Otherwise a displacement (severity 2) is flagged when the immediately
// preceding swap pays strictly more than twice the victim's gas. The last
// swap in a pool can be flagged as a displacement victim even though it has
// no back neighbour.
func DetectAll(swaps []Swap) []Finding {
	pools := make(map[string][]Swap)
	var poolOrder []string
	for _, swap := range swaps {
		if _, seen := pools[swap.Pool]; !seen {
			poolOrder = append(poolOrder, swap.Pool)
		}
		pools[swap.Pool] = append(pools[swap.Pool], swap)
	}

	var findings []Finding
	for _, pool := range poolOrder {
		group := pools[pool]
		sort.SliceStable(group, func(i, j int) bool { return group[i].Index < group[j].Index })
		for i := range group {
			if finding, ok := detectAt(group, i); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

// detectAt judges the swap at position i against its neighbours.
func detectAt(group []Swap, i int) (Finding, bool) {
	victim := group[i]

	if i > 0 && i < len(group)-1 {
		front, back := group[i-1], group[i+1]
		if front.Trader == back.Trader && front.Trader != victim.Trader &&
			front.GasPrice > victim.GasPrice && back.GasPrice > victim.GasPrice {
			return Finding{
				TxHash:   victim.TxHash,
				Kind:     "sandwich",
				Severity: 3,
				Evidence: []string{
					"front-run by " + front.Trader + " at gas " + strconv.FormatInt(front.GasPrice, 10),
					"back-run by " + back.Trader + " at gas " + strconv.FormatInt(back.GasPrice, 10),
					"victim gas " + strconv.FormatInt(victim.GasPrice, 10),
				},
				Swaps: []Swap{front, victim, back},
			}, true
		}
	}

	if i > 0 {
		front := group[i-1]
		if dominatesByTwo(front.GasPrice, victim.GasPrice) {
			return Finding{
				TxHash:   victim.TxHash,
				Kind:     "displacement",
				Severity: 2,
				Evidence: []string{
					"front gas " + strconv.FormatInt(front.GasPrice, 10) +
						" dominates victim gas " + strconv.FormatInt(victim.GasPrice, 10) + " by more than 2x",
				},
				Swaps: []Swap{front, victim},
			}, true
		}
	}

	return Finding{}, false
}

// dominatesByTwo reports whether front > 2*victim without overflowing int64.
// Both values are expected to be non-negative.
func dominatesByTwo(front, victim int64) bool {
	// If victim > MaxInt64/2 then 2*victim exceeds MaxInt64 while front is
	// at most MaxInt64, so front cannot dominate.
	if victim > math.MaxInt64/2 {
		return false
	}
	return front > 2*victim
}

// FormatSwap renders a swap's raw fields for evidence display.
func FormatSwap(swap Swap) string {
	return fmt.Sprintf("TxHash=%s Pool=%s Trader=%s In=%d Out=%d GasPrice=%d Index=%d",
		swap.TxHash, swap.Pool, swap.Trader, swap.In, swap.Out, swap.GasPrice, swap.Index)
}
