package mevwatch

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Block is one validated, deduplicated input block. Swaps are kept in
// canonical order: exact duplicates removed, sorted by Index.
type Block struct {
	ChainID     string
	BlockHash   string
	BlockNumber int64
	Swaps       []Swap
}

// ReportFinding is one risk conclusion inside a block report. Evidence
// carries the raw fields of every swap that participated in the judgment.
type ReportFinding struct {
	Kind     string `json:"kind"`
	Severity int    `json:"severity"`
	TxHash   string `json:"txHash"`
	Evidence []Swap `json:"evidence"`
}

// Report is the archived per-block risk report. Version records the full
// rule parameters that produced the findings, so the report stays
// interpretable without the original rule definition.
type Report struct {
	ChainID     string          `json:"chainId"`
	BlockHash   string          `json:"blockHash"`
	BlockNumber int64           `json:"blockNumber"`
	SwapCount   int             `json:"swapCount"`
	Version     RuleVersion     `json:"version"`
	Findings    []ReportFinding `json:"findings"`
}

// LineError pins a replay failure to a 1-based input line.
type LineError struct {
	Line int
	Err  error
}

func (e *LineError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
func (e *LineError) Unwrap() error { return e.Err }

// ErrBusy reports an archive locked by another process.
var ErrBusy = errors.New("archive is busy")

// ErrUnknownBlock reports a query for a block that was never archived.
var ErrUnknownBlock = errors.New("unknown block")

type blockID struct {
	chainID   string
	blockHash string
}

// swapLine mirrors one swap record inside a block line. Pointers
// distinguish a missing field (or an explicit null) from an explicit
// zero value: a replay record must be complete on its own, so In, Out,
// GasPrice and Index are all required and may not be null.
type swapLine struct {
	TxHash   *string `json:"TxHash"`
	Pool     *string `json:"Pool"`
	Trader   *string `json:"Trader"`
	In       *int64  `json:"In"`
	Out      *int64  `json:"Out"`
	GasPrice *int64  `json:"GasPrice"`
	Index    *int    `json:"Index"`
}

// blockLine mirrors one input line. Pointers distinguish a missing field
// from an explicit zero value.
type blockLine struct {
	ChainID     *string     `json:"chainId"`
	BlockHash   *string     `json:"blockHash"`
	BlockNumber *int64      `json:"blockNumber"`
	Swaps       *[]swapLine `json:"swaps"`
}

func parseBlock(text string) (Block, error) {
	var raw blockLine
	dec := json.NewDecoder(strings.NewReader(text))
	if err := dec.Decode(&raw); err != nil {
		return Block{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if err := blockTrailingData(text, int(dec.InputOffset())); err != nil {
		return Block{}, err
	}
	if raw.ChainID == nil || *raw.ChainID == "" {
		return Block{}, errors.New("chainId must be a non-empty string")
	}
	if raw.BlockHash == nil || *raw.BlockHash == "" {
		return Block{}, errors.New("blockHash must be a non-empty string")
	}
	if raw.BlockNumber == nil {
		return Block{}, errors.New("blockNumber is required")
	}
	if *raw.BlockNumber < 0 {
		return Block{}, fmt.Errorf("blockNumber must be non-negative, got %d", *raw.BlockNumber)
	}
	if raw.Swaps == nil {
		return Block{}, errors.New("swaps must be an array")
	}

	byTx := make(map[string]Swap)
	byIndex := make(map[int]string)
	swaps := []Swap{}
	for i, s := range *raw.Swaps {
		if s.TxHash == nil || *s.TxHash == "" {
			return Block{}, fmt.Errorf("swaps[%d]: TxHash must not be empty", i)
		}
		if s.Pool == nil || *s.Pool == "" {
			return Block{}, fmt.Errorf("swaps[%d]: Pool must not be empty", i)
		}
		if s.Trader == nil || *s.Trader == "" {
			return Block{}, fmt.Errorf("swaps[%d]: Trader must not be empty", i)
		}
		// Every numeric field must be present and non-null in this very
		// record; an explicit zero is a valid value, never a missing one.
		// Values must not be borrowed from a neighbour, a same-hash record
		// or a default, so an incomplete record is rejected before dedup
		// even when a complete record with the same tx hash exists.
		for _, f := range []struct {
			name string
			v    *int64
		}{
			{"In", s.In}, {"Out", s.Out}, {"GasPrice", s.GasPrice},
		} {
			if f.v == nil {
				return Block{}, fmt.Errorf("swaps[%d]: %s is required and must not be null", i, f.name)
			}
		}
		if s.Index == nil {
			return Block{}, fmt.Errorf("swaps[%d]: Index is required and must not be null", i)
		}
		in, out, gasPrice, index := *s.In, *s.Out, *s.GasPrice, *s.Index
		if in < 0 || out < 0 || gasPrice < 0 || index < 0 {
			return Block{}, fmt.Errorf("swaps[%d]: In, Out, GasPrice and Index must be non-negative", i)
		}
		swap := Swap{
			TxHash: *s.TxHash, Pool: *s.Pool, Trader: *s.Trader,
			In: in, Out: out, GasPrice: gasPrice, Index: index,
		}
		if prev, ok := byTx[swap.TxHash]; ok {
			if prev != swap {
				return Block{}, fmt.Errorf("swaps[%d]: conflicting records for tx %s", i, swap.TxHash)
			}
			continue // exact duplicate, keep one copy
		}
		if other, ok := byIndex[swap.Index]; ok {
			return Block{}, fmt.Errorf("swaps[%d]: Index %d already used by tx %s", i, swap.Index, other)
		}
		byTx[swap.TxHash] = swap
		byIndex[swap.Index] = swap.TxHash
		swaps = append(swaps, swap)
	}
	sort.Slice(swaps, func(i, j int) bool { return swaps[i].Index < swaps[j].Index })
	return Block{
		ChainID:     *raw.ChainID,
		BlockHash:   *raw.BlockHash,
		BlockNumber: *raw.BlockNumber,
		Swaps:       swaps,
	}, nil
}

// blockTrailingData names the first non-whitespace byte after the block
// object on a replay line, so an unmatched '}' or ']' — or a second value
// of any kind — is reported directly; only whitespace may follow the
// object. dec.More cannot see this: after a complete top-level value it
// only looks for the start of another value and treats stray closing
// brackets as "nothing more".
func blockTrailingData(text string, offset int) error {
	rest := strings.TrimLeft(text[offset:], " \t\n\r")
	if len(rest) > 0 {
		return fmt.Errorf("invalid JSON: unexpected trailing data after block object: %s", trailingTokenName(rest[0]))
	}
	return nil
}

func swapsEqual(a, b []Swap) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameContent reports whether two blocks carry the same content. Both sides
// are canonical (deduplicated, sorted by Index), so ordering and exact
// duplicates in the input do not affect the comparison.
func sameContent(blockNumber int64, swaps []Swap, b Block) bool {
	return blockNumber == b.BlockNumber && swapsEqual(swaps, b.Swaps)
}

// DetectBlock checks every swap against its adjacent neighbours within its
// pool under the built-in rules. See DetectBlockWithRules.
func DetectBlock(swaps []Swap) []ReportFinding {
	return DetectBlockWithRules(swaps, BuiltinVersion().Rules)
}

// DetectBlockWithRules checks every swap against its adjacent neighbours
// within its pool under the given rule version: a sandwich when the same
// trader brackets the victim with higher gas on both sides, otherwise a
// displacement when the previous swap's gas strictly exceeds the configured
// multiple of the victim's. The last swap of a pool is checked too. An
// enabled sandwich takes priority over displacement for the same victim;
// with the sandwich rule off the victim can still be flagged for
// displacement. With both rules off the result is an empty slice. The
// judgment itself is shared with Detect; this entry only adds the block
// report's raw-swap evidence and ordering.
func DetectBlockWithRules(swaps []Swap, rules RuleSet) []ReportFinding {
	pools := make(map[string][]Swap)
	for _, s := range swaps {
		pools[s.Pool] = append(pools[s.Pool], s)
	}
	findings := []ReportFinding{}
	for _, pool := range pools {
		sort.Slice(pool, func(i, j int) bool { return pool[i].Index < pool[j].Index })
		for i, victim := range pool {
			var front, back *Swap
			if i > 0 {
				front = &pool[i-1]
			}
			if i+1 < len(pool) {
				back = &pool[i+1]
			}
			j, hit := judgeVictim(front, victim, back, rules)
			if !hit {
				continue
			}
			// The evidence keeps the full swap fields of every record that
			// participated: front, victim, and for a sandwich also back.
			evidence := []Swap{*front, victim}
			if j.kind == "sandwich" {
				evidence = append(evidence, *back)
			}
			findings = append(findings, ReportFinding{
				Kind: j.kind, Severity: j.severity, TxHash: victim.TxHash,
				Evidence: evidence,
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].TxHash < findings[j].TxHash
	})
	return findings
}

// record is the archived form of a block: the report plus the canonical
// swaps, so a later import can detect content conflicts. Version carries
// the full rule parameters used for the findings; it is nil only in
// archives written before rule versions existed, which are interpreted
// under the built-in rules.
type record struct {
	ChainID     string          `json:"chainId"`
	BlockHash   string          `json:"blockHash"`
	BlockNumber int64           `json:"blockNumber"`
	Swaps       []Swap          `json:"swaps"`
	Findings    []ReportFinding `json:"findings"`
	Version     *RuleVersion    `json:"version,omitempty"`
}

func (r record) id() blockID { return blockID{r.ChainID, r.BlockHash} }

func (r record) ruleVersion() RuleVersion {
	if r.Version != nil {
		return *r.Version
	}
	return BuiltinVersion()
}

func (r record) report() Report {
	return Report{
		ChainID:     r.ChainID,
		BlockHash:   r.BlockHash,
		BlockNumber: r.BlockNumber,
		SwapCount:   len(r.Swaps),
		Version:     r.ruleVersion(),
		Findings:    r.Findings,
	}
}

const (
	archiveFileName = "archive.json"
	lockFileName    = "lock"
)

type archiveData struct {
	Records []record `json:"records"`
	// Versions and EnabledVersion are absent in archives written before
	// rule versions existed; such archives run the built-in rules.
	Versions       []RuleVersion `json:"versions,omitempty"`
	EnabledVersion string        `json:"enabledVersion,omitempty"`
	// Suppressions and AlertRecords are absent in archives written before
	// offline alerting existed; such archives simply have no registered
	// conditions and no processing history.
	Suppressions []Suppression      `json:"suppressions,omitempty"`
	AlertRecords []ProcessingRecord `json:"alerts,omitempty"`
	// Reviews is absent in archives written before manual reviews existed;
	// every conclusion then behaves as unreviewed.
	Reviews []ReviewObject `json:"reviews,omitempty"`
}

// readArchiveBytes returns the exact bytes of the archive file, or nil
// when no archive exists yet.
func readArchiveBytes(dir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func readArchive(dir string) (archiveData, error) {
	raw, err := readArchiveBytes(dir)
	if err != nil {
		return archiveData{}, err
	}
	if raw == nil {
		return archiveData{Records: []record{}}, nil
	}
	var data archiveData
	if err := json.Unmarshal(raw, &data); err != nil {
		return archiveData{}, fmt.Errorf("archive is corrupted: %w", err)
	}
	return data, nil
}

// writeArchiveAtomic replaces the archive file in one rename, so a crash
// can only expose the previous or the next complete commit, never a half
// written file.
func writeArchiveAtomic(dir string, data archiveData) error {
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return writeArchiveBytesAtomic(dir, raw)
}

// writeArchiveBytesAtomic replaces the archive file in one rename, so a
// crash can only expose the previous or the next complete commit, never a
// half written file.
func writeArchiveBytesAtomic(dir string, raw []byte) error {
	tmp := filepath.Join(dir, archiveFileName+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, archiveFileName)); err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// lockArchive takes an flock on the archive's lock file. The lock is
// released automatically if the process dies, so no stale locks survive.
func lockArchive(dir string, how int) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return f, nil
}

type parsedBlock struct {
	line  int
	block Block
}

func parseBlocks(r io.Reader) ([]parsedBlock, error) {
	var out []parsedBlock
	reader := bufio.NewReader(r)
	lineNo := 0
	for {
		raw, err := reader.ReadBytes('\n')
		if len(raw) > 0 {
			lineNo++
		}
		if text := strings.TrimSpace(string(raw)); text != "" {
			block, perr := parseBlock(text)
			if perr != nil {
				return nil, &LineError{Line: lineNo, Err: perr}
			}
			out = append(out, parsedBlock{line: lineNo, block: block})
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// ReplayFile imports the line-delimited blocks in inputPath into the
// archive at dir and returns one report per distinct block, in order of
// first appearance. New blocks are judged under the archive's currently
// enabled rule version. The selected version's stored document must still
// satisfy the full registration declaration; a corrupt one fails the whole
// replay with ErrCorruptVersion before any report is produced.
func ReplayFile(inputPath, dir string) ([]Report, error) {
	return replayFile(inputPath, dir, "")
}

// ReplayFileWithVersion is ReplayFile under an explicitly registered rule
// version instead of the archive's enabled one. As with ReplayFile, the
// named version is re-validated from its stored document and a corrupt one
// fails the whole replay with ErrCorruptVersion, never as an unknown
// version and never replaced by defaults or the built-in rules.
func ReplayFileWithVersion(inputPath, dir, versionID string) ([]Report, error) {
	if versionID == "" {
		return nil, errors.New("version id must not be empty")
	}
	return replayFile(inputPath, dir, versionID)
}

func replayFile(inputPath, dir, versionID string) ([]Report, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return doReplay(f, dir, versionID)
}

// Replay parses, validates and archives blocks from r under the archive's
// currently enabled rule version. Every line is checked before anything is
// written; any failure leaves the archive untouched. New reports are
// committed together in a single atomic write. The selected version's
// stored document is re-validated from its raw bytes first, so a corrupt
// version fails the whole run with ErrCorruptVersion even when the input is
// blank, has no swaps or only re-imports archived blocks.
func Replay(input io.Reader, dir string) ([]Report, error) {
	return doReplay(input, dir, "")
}

// ReplayWithVersion is Replay under an explicitly registered rule version
// instead of the archive's enabled one. The named version must still
// satisfy the full registration declaration in the archive; a corrupt one
// fails with ErrCorruptVersion rather than substituting defaults, the
// enabled version or the built-in rules.
func ReplayWithVersion(input io.Reader, dir, versionID string) ([]Report, error) {
	if versionID == "" {
		return nil, errors.New("version id must not be empty")
	}
	return doReplay(input, dir, versionID)
}

func doReplay(input io.Reader, dir, versionID string) ([]Report, error) {
	parsed, err := parseBlocks(input)
	if err != nil {
		return nil, err
	}

	// Collapse repeated identities within this file, keeping first
	// appearance order; conflicting content rejects the whole file.
	type occurrence struct {
		block Block
		line  int
	}
	order := []occurrence{}
	firstSeen := make(map[blockID]int)
	for _, p := range parsed {
		id := blockID{p.block.ChainID, p.block.BlockHash}
		if first, ok := firstSeen[id]; ok {
			if !sameContent(order[first].block.BlockNumber, order[first].block.Swaps, p.block) {
				return nil, &LineError{Line: p.line, Err: fmt.Errorf(
					"block %s/%s conflicts with line %d", id.chainID, id.blockHash, order[first].line)}
			}
			continue
		}
		firstSeen[id] = len(order)
		order = append(order, occurrence{block: p.block, line: p.line})
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	// Read each registered version as its raw stored document, so a
	// wrong-typed, null or missing field is judged as that version's
	// corruption rather than failing the archive decode or silently
	// becoming a zero value (a zero displacement multiplier even crashes
	// detection).
	raw, err := readArchiveBytes(dir)
	if err != nil {
		return nil, err
	}
	var doc replayArchiveDoc
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("archive is corrupted: %w", err)
		}
	}
	// Resolve the version once, while the exclusive lock is held: every
	// new block in this run is judged under the same rules even if another
	// process enables a different version right after we finish. The
	// selected version's stored document must still satisfy every
	// registration rule; this is decided before any block is judged or any
	// report produced, so a corrupt version fails the whole replay even
	// for an empty-swaps block, a block already archived or blank input,
	// and the corrupt content is never replaced by the enabled version,
	// the built-in rules or defaults.
	version, err := resolveReplayVersion(doc, versionID)
	if err != nil {
		return nil, err
	}
	archived := make(map[blockID]int, len(doc.Records))
	for i, rec := range doc.Records {
		archived[rec.id()] = i
	}

	reports := make([]Report, 0, len(order))
	changed := false
	for _, occ := range order {
		id := blockID{occ.block.ChainID, occ.block.BlockHash}
		if idx, ok := archived[id]; ok {
			rec := doc.Records[idx]
			if !sameContent(rec.BlockNumber, rec.Swaps, occ.block) {
				return nil, &LineError{Line: occ.line, Err: fmt.Errorf(
					"block %s/%s conflicts with the archived record", id.chainID, id.blockHash)}
			}
			// Identical re-import: return the original report, add nothing.
			reports = append(reports, rec.report())
			continue
		}
		rec := record{
			ChainID:     occ.block.ChainID,
			BlockHash:   occ.block.BlockHash,
			BlockNumber: occ.block.BlockNumber,
			Swaps:       occ.block.Swaps,
			Findings:    DetectBlockWithRules(occ.block.Swaps, version.Rules),
			Version:     &version,
		}
		archived[id] = len(doc.Records)
		doc.Records = append(doc.Records, rec)
		reports = append(reports, rec.report())
		changed = true
	}
	if changed {
		if err := writeReplayArchive(dir, doc); err != nil {
			return nil, err
		}
	}
	return reports, nil
}

// resolveReplayVersion picks the rule version for one replay run: the
// explicitly requested one, or the archive's currently enabled version
// (which is the built-in rules in archives written before rule versions
// existed). Either way the chosen registered version's stored document is
// re-validated from its raw bytes with the same parser registrations pass,
// so a document missing a rule object or required field, carrying null, a
// wrong type or an out-of-range number fails the run as a corrupt version
// — never as an unknown one, and never replaced by the built-in rules or
// defaults. An explicitly declared enabled:false is a valid off state and
// passes like any other in-range value.
func resolveReplayVersion(doc replayArchiveDoc, versionID string) (RuleVersion, error) {
	if versionID != "" {
		return intactVersion(doc.Versions, versionID)
	}
	if doc.EnabledVersion == "" {
		return BuiltinVersion(), nil
	}
	return intactVersion(doc.Versions, doc.EnabledVersion)
}

// Query returns the archived report for one block identity. It only reads
// the archive; the original input file is not needed.
func Query(dir, chainID, blockHash string) (Report, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Report{}, ErrUnknownBlock
		}
		return Report{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return Report{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return Report{}, err
	}
	for _, rec := range data.Records {
		if rec.ChainID == chainID && rec.BlockHash == blockHash {
			return rec.report(), nil
		}
	}
	return Report{}, ErrUnknownBlock
}
