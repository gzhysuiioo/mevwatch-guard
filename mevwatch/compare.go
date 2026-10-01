package mevwatch

import (
	"errors"
	"os"
	"sort"
	"syscall"
)

// FindingDiff describes one conclusion that was added, removed, or changed
// between two versions. For a change, Kind/Severity hold the new values and
// OldKind/OldSeverity hold the previous ones.
type FindingDiff struct {
	TxHash      string `json:"txHash"`
	Kind        string `json:"kind"`
	Severity    int    `json:"severity"`
	OldKind     string `json:"oldKind,omitempty"`
	OldSeverity int    `json:"oldSeverity,omitempty"`
}

// VersionComparison is the result of re-detecting one block's conclusions
// under a comparison version and diffing them against the archived
// conclusions. It carries both versions' parameters, both full conclusion
// sets (with the raw swap evidence), and the per-transaction diffs.
type VersionComparison struct {
	ChainID          string          `json:"chainId"`
	BlockHash        string          `json:"blockHash"`
	BlockNumber      int64           `json:"blockNumber"`
	Original         RuleVersion     `json:"original"`
	Compared         RuleVersion     `json:"compared"`
	OriginalFindings []ReportFinding `json:"originalFindings"`
	ComparedFindings []ReportFinding `json:"comparedFindings"`
	Added            []FindingDiff   `json:"added"`
	Removed          []FindingDiff   `json:"removed"`
	Changed          []FindingDiff   `json:"changed"`
}

// ErrUnknownVersion reports a query for a version that was never registered.
var ErrUnknownVersion = errors.New("unknown version")

// diffFindings matches conclusions by transaction hash and splits them into
// added (only in compared), removed (only in original), and changed (in
// both but kind or severity differs). A type change is reported only as a
// change, not also as an add and a remove. Each list is sorted by tx hash.
func diffFindings(original, compared []ReportFinding) (added, removed, changed []FindingDiff) {
	added = []FindingDiff{}
	removed = []FindingDiff{}
	changed = []FindingDiff{}
	origByTx := make(map[string]ReportFinding, len(original))
	for _, f := range original {
		origByTx[f.TxHash] = f
	}
	compByTx := make(map[string]ReportFinding, len(compared))
	for _, f := range compared {
		compByTx[f.TxHash] = f
	}
	for tx, cf := range compByTx {
		of, ok := origByTx[tx]
		if !ok {
			added = append(added, FindingDiff{TxHash: tx, Kind: cf.Kind, Severity: cf.Severity})
			continue
		}
		if of.Kind != cf.Kind || of.Severity != cf.Severity {
			changed = append(changed, FindingDiff{
				TxHash: tx, Kind: cf.Kind, Severity: cf.Severity,
				OldKind: of.Kind, OldSeverity: of.Severity,
			})
		}
	}
	for tx, of := range origByTx {
		if _, ok := compByTx[tx]; !ok {
			removed = append(removed, FindingDiff{TxHash: tx, Kind: of.Kind, Severity: of.Severity})
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].TxHash < added[j].TxHash })
	sort.Slice(removed, func(i, j int) bool { return removed[i].TxHash < removed[j].TxHash })
	sort.Slice(changed, func(i, j int) bool { return changed[i].TxHash < changed[j].TxHash })
	return added, removed, changed
}

// Compare re-detects the conclusions of one block under versionID and
// compares them with the archived conclusions. It only reads the archive's
// swap records; it does not depend on the original input file and does not
// modify historical reports or the enabled version. An unknown block or
// version returns a clear error.
func Compare(dir, chainID, blockHash, versionID string) (VersionComparison, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return VersionComparison{}, ErrUnknownBlock
		}
		return VersionComparison{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		return VersionComparison{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return VersionComparison{}, err
	}
	var rec *record
	for i := range data.Records {
		if data.Records[i].ChainID == chainID && data.Records[i].BlockHash == blockHash {
			rec = &data.Records[i]
			break
		}
	}
	if rec == nil {
		return VersionComparison{}, ErrUnknownBlock
	}
	compared, err := resolveVersion(data, versionID)
	if err != nil {
		return VersionComparison{}, err
	}

	original := rec.versionSnapshot()
	comparedFindings := DetectBlockWithVersion(rec.Swaps, compared)
	added, removed, changed := diffFindings(rec.Findings, comparedFindings)
	return VersionComparison{
		ChainID:          rec.ChainID,
		BlockHash:        rec.BlockHash,
		BlockNumber:      rec.BlockNumber,
		Original:         original,
		Compared:         compared,
		OriginalFindings: rec.Findings,
		ComparedFindings: comparedFindings,
		Added:            added,
		Removed:          removed,
		Changed:          changed,
	}, nil
}
