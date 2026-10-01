package mevwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrBusy is returned when another process holds the archive lock.
var ErrBusy = errors.New("archive is busy")

// ErrNotFound is returned when no archived block matches the identity.
var ErrNotFound = errors.New("block not found in archive")

// Archive is an offline, content-addressed store of block reports.
type Archive struct {
	dir string
}

// OpenArchive returns a handle for the archive rooted at dir. The
// directory is created on the first replay; report-only reads never create
// it.
func OpenArchive(dir string) *Archive {
	return &Archive{dir: dir}
}

// Report is the user-facing JSON report for one block.
type Report struct {
	ChainID     string          `json:"chainId"`
	BlockHash   string          `json:"blockHash"`
	BlockNumber int64           `json:"blockNumber"`
	SwapCount   int             `json:"swapCount"`
	Findings    []ReportFinding `json:"findings"`
}

// ReportFinding is one conclusion together with the raw swap fields that
// produced it, so the judgment can be checked against the record.
type ReportFinding struct {
	Kind     string `json:"kind"`
	Severity int    `json:"severity"`
	TxHash   string `json:"txHash"`
	Swaps    []Swap `json:"swaps"`
}

// storedBlock is the on-disk object: the deduped swap set plus the
// conclusions computed from it.
type storedBlock struct {
	ChainID     string          `json:"chainId"`
	BlockHash   string          `json:"blockHash"`
	BlockNumber int64           `json:"blockNumber"`
	Swaps       []Swap          `json:"swaps"`
	Findings    []ReportFinding `json:"findings"`
}

type archiveIndex struct {
	Version int            `json:"version"`
	Blocks  []archiveEntry `json:"blocks"`
}

type archiveEntry struct {
	ChainID   string `json:"chainId"`
	BlockHash string `json:"blockHash"`
}

// Replay imports every block in r. All new reports from this replay take
// effect together: on any parse, validation or conflict error the archive
// is left unchanged and no reports are returned. Re-importing a block
// whose identity already exists returns the stored report without adding
// a record; a changed block number or swap set is rejected as a conflict.
func (a *Archive) Replay(r io.Reader) ([]Report, error) {
	blocks, err := ParseReplayInput(r)
	if err != nil {
		return nil, err
	}

	lock, err := a.acquireLock()
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	a.cleanTemps()

	idx, err := a.loadIndex()
	if err != nil {
		return nil, err
	}
	known := make(map[string]int, len(idx.Blocks))
	for i, entry := range idx.Blocks {
		known[identityKey(entry.ChainID, entry.BlockHash)] = i
	}

	reports := make([]Report, 0, len(blocks))
	handled := make(map[string]bool, len(blocks))
	firstSeen := make(map[string]storedBlock, len(blocks))
	var newEntries []archiveEntry
	var newObjects []storedBlock

	// Phase 1: validate and compare everything before mutating anything.
	for _, block := range blocks {
		key := identityKey(block.ChainID, block.BlockHash)
		deduped, err := ValidateBlock(block)
		if err != nil {
			return nil, &LineError{Line: block.Line, Err: err}
		}

		if _, ok := known[key]; ok {
			stored, err := a.loadStored(block.ChainID, block.BlockHash)
			if err != nil {
				return nil, err
			}
			if stored.BlockNumber != block.BlockNumber || !swapSetsEqual(stored.Swaps, deduped) {
				return nil, &LineError{Line: block.Line, Err: fmt.Errorf(
					"block conflict for chainId=%q blockHash=%q: height or swap content changed",
					block.ChainID, block.BlockHash)}
			}
			if !handled[key] {
				reports = append(reports, reportFromStored(stored))
				handled[key] = true
			}
			continue
		}

		if handled[key] {
			// Same identity repeated inside this replay: it must match the
			// first occurrence exactly.
			first := firstSeen[key]
			if first.BlockNumber != block.BlockNumber || !swapSetsEqual(first.Swaps, deduped) {
				return nil, &LineError{Line: block.Line, Err: fmt.Errorf(
					"block conflict for chainId=%q blockHash=%q: repeated with different height or swap content",
					block.ChainID, block.BlockHash)}
			}
			continue
		}

		findings := buildReportFindings(deduped)
		stored := storedBlock{
			ChainID:     block.ChainID,
			BlockHash:   block.BlockHash,
			BlockNumber: block.BlockNumber,
			Swaps:       deduped,
			Findings:    findings,
		}
		firstSeen[key] = stored
		newObjects = append(newObjects, stored)
		newEntries = append(newEntries, archiveEntry{ChainID: block.ChainID, BlockHash: block.BlockHash})
		reports = append(reports, reportFromStored(stored))
		handled[key] = true
	}

	// Phase 2: write all new objects to temp files (no visible effect yet).
	type pendingObject struct {
		path string
		data []byte
	}
	var pending []pendingObject
	for _, stored := range newObjects {
		data, err := json.MarshalIndent(stored, "", "  ")
		if err != nil {
			return nil, err
		}
		pending = append(pending, pendingObject{path: a.objectPath(stored.ChainID, stored.BlockHash), data: data})
	}
	tempPaths := make([]string, 0, len(pending)+1)
	for _, obj := range pending {
		temp, err := writeTempFile(a.dir, "objects", obj.data)
		if err != nil {
			return nil, err
		}
		tempPaths = append(tempPaths, temp)
	}

	// Phase 3: commit objects first, then the index as the commit marker.
	// A crash before the index rename leaves the new blocks invisible; a
	// crash after it leaves a fully committed archive.
	for i, obj := range pending {
		if err := os.Rename(tempPaths[i], obj.path); err != nil {
			return nil, err
		}
	}

	idx.Blocks = append(idx.Blocks, newEntries...)
	indexData, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return nil, err
	}
	indexTemp, err := writeTempFile(a.dir, "", indexData)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(indexTemp, filepath.Join(a.dir, "index.json")); err != nil {
		return nil, err
	}

	a.syncDir()
	return reports, nil
}

// Report returns the archived report for the given block identity. It
// reads only the archive, never the original input file.
func (a *Archive) Report(chainID, blockHash string) (Report, error) {
	idx, err := a.loadIndex()
	if err != nil {
		return Report{}, err
	}
	found := false
	for _, entry := range idx.Blocks {
		if entry.ChainID == chainID && entry.BlockHash == blockHash {
			found = true
			break
		}
	}
	if !found {
		return Report{}, ErrNotFound
	}
	stored, err := a.loadStored(chainID, blockHash)
	if err != nil {
		return Report{}, err
	}
	return reportFromStored(stored), nil
}

// buildReportFindings runs the detector and projects findings into the
// report shape, ordered by severity descending then tx hash ascending.
func buildReportFindings(swaps []Swap) []ReportFinding {
	findings := Rank(DetectAll(swaps))
	out := make([]ReportFinding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, ReportFinding{
			Kind:     finding.Kind,
			Severity: finding.Severity,
			TxHash:   finding.TxHash,
			Swaps:    append([]Swap(nil), finding.Swaps...),
		})
	}
	return out
}

func reportFromStored(stored storedBlock) Report {
	findings := stored.Findings
	if findings == nil {
		findings = []ReportFinding{}
	}
	return Report{
		ChainID:     stored.ChainID,
		BlockHash:   stored.BlockHash,
		BlockNumber: stored.BlockNumber,
		SwapCount:   len(stored.Swaps),
		Findings:    findings,
	}
}

func (a *Archive) loadStored(chainID, blockHash string) (storedBlock, error) {
	data, err := os.ReadFile(a.objectPath(chainID, blockHash))
	if err != nil {
		return storedBlock{}, err
	}
	var stored storedBlock
	if err := json.Unmarshal(data, &stored); err != nil {
		return storedBlock{}, fmt.Errorf("corrupt object for chainId=%q blockHash=%q: %w",
			chainID, blockHash, err)
	}
	return stored, nil
}

func (a *Archive) loadIndex() (archiveIndex, error) {
	data, err := os.ReadFile(filepath.Join(a.dir, "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return archiveIndex{Version: 1}, nil
	}
	if err != nil {
		return archiveIndex{}, err
	}
	var idx archiveIndex
	if err := json.Unmarshal(data, &idx); err != nil {
		return archiveIndex{}, fmt.Errorf("corrupt archive index: %w", err)
	}
	if idx.Version == 0 {
		idx.Version = 1
	}
	return idx, nil
}

// acquireLock takes an exclusive advisory lock without blocking. A short
// retry window lets concurrent replays serialize instead of failing the
// first time the lock is held.
func (a *Archive) acquireLock() (*os.File, error) {
	if err := os.MkdirAll(a.dir, 0o755); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(a.dir, "lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			file.Close()
			return nil, fmt.Errorf("%w: another replay is in progress", ErrBusy)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// cleanTemps removes leftover temp files from an interrupted commit.
func (a *Archive) cleanTemps() {
	for _, dir := range []string{a.dir, filepath.Join(a.dir, "objects")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".tmp-") {
				os.Remove(filepath.Join(dir, entry.Name()))
			}
		}
	}
}

func (a *Archive) syncDir() {
	dir, err := os.Open(a.dir)
	if err != nil {
		return
	}
	dir.Sync()
	dir.Close()
}

// objectPath is content-addressed by the block identity, so unusual
// characters in chainId/blockHash can never escape the objects dir.
func (a *Archive) objectPath(chainID, blockHash string) string {
	sum := sha256.Sum256([]byte(identityKey(chainID, blockHash)))
	return filepath.Join(a.dir, "objects", hex.EncodeToString(sum[:])+".json")
}

func identityKey(chainID, blockHash string) string {
	return chainID + "\x00" + blockHash
}

// writeTempFile writes data to a new temp file inside dir (relative to the
// archive root), fsyncs it and returns its path.
func writeTempFile(archiveDir, dir string, data []byte) (string, error) {
	targetDir := archiveDir
	if dir != "" {
		targetDir = filepath.Join(archiveDir, dir)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(targetDir, ".tmp-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return "", err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// swapSetsEqual reports whether two deduped swap sets contain exactly the
// same records, regardless of order.
func swapSetsEqual(a, b []Swap) bool {
	if len(a) != len(b) {
		return false
	}
	ka := sortedSwapKeys(a)
	kb := sortedSwapKeys(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func sortedSwapKeys(swaps []Swap) []string {
	keys := make([]string, len(swaps))
	for i, swap := range swaps {
		keys[i] = swapKey(swap)
	}
	sort.Strings(keys)
	return keys
}

func swapKey(swap Swap) string {
	return strings.Join([]string{
		swap.TxHash, swap.Pool, swap.Trader,
		strconv.FormatInt(swap.In, 10),
		strconv.FormatInt(swap.Out, 10),
		strconv.FormatInt(swap.GasPrice, 10),
		strconv.Itoa(swap.Index),
	}, "\x00")
}
