package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
)

// Human review adds a manual verdict on top of an archived risk conclusion.
// A review object is identified by (chain, block hash, victim tx hash,
// conclusion kind) — never by alert channel — and survives rule-version
// switches and restarts. Reviews never withdraw or re-issue alerts.

// Review statuses. A conclusion is "real-risk" (a true positive),
// "false-positive" (a false alarm), or "unreviewed" (the verdict was
// withdrawn; the object is treated as if never reviewed).
const (
	ReviewRealRisk      = "real-risk"
	ReviewFalsePositive = "false-positive"
	ReviewUnreviewed    = "unreviewed"
)

// ErrReviewConflict reports a submission that violates the optimistic
// concurrency or idempotency rules: a stale expected version, or reusing a
// commit ID with different content.
var ErrReviewConflict = errors.New("review conflict")

// ErrUnknownConclusion reports a review target that does not exist in the
// archive.
var ErrUnknownConclusion = errors.New("unknown conclusion")

// ReviewRevision is one immutable submission. Every successful submit
// appends a new revision; overturning a verdict and withdrawing both add a
// revision, old ones are retained. The revision keeps the full submission
// content: the unique commit ID, operator, reason, verdict status, the
// expected version the submit was based on, and the revision's own version
// number.
type ReviewRevision struct {
	CommitID        string `json:"commitId"`
	Operator        string `json:"operator"`
	Reason          string `json:"reason"`
	Status          string `json:"status"`
	ExpectedVersion int    `json:"expectedVersion"`
	Version         int    `json:"version"`
}

// ReviewState is the current review state of one conclusion. Version is the
// object's revision count (0 when never reviewed); Revisions holds every
// revision in version order.
type ReviewState struct {
	ChainID   string           `json:"chainId"`
	BlockHash string           `json:"blockHash"`
	TxHash    string           `json:"txHash"`
	Kind      string           `json:"kind"`
	Version   int              `json:"version"`
	Revisions []ReviewRevision `json:"revisions"`
}

func (s ReviewState) key() reviewKey {
	return reviewKey{s.ChainID, s.BlockHash, s.TxHash, s.Kind}
}

// currentStatus returns the verdict of the latest revision, or unreviewed
// when no revision exists.
func (s ReviewState) currentStatus() string {
	if len(s.Revisions) == 0 {
		return ReviewUnreviewed
	}
	return s.Revisions[len(s.Revisions)-1].Status
}

// adoptedRevision returns the latest revision (the one that determines the
// current verdict), or nil when the object has no revisions.
func (s ReviewState) adoptedRevision() *ReviewRevision {
	if len(s.Revisions) == 0 {
		return nil
	}
	r := s.Revisions[len(s.Revisions)-1]
	return &r
}

// reviewKey identifies one review object. Channel is deliberately absent:
// the same conclusion is reviewed once regardless of how many alert channels
// processed it.
type reviewKey struct {
	chainID   string
	blockHash string
	txHash    string
	kind      string
}

// reviewSpec mirrors one review submission document. Pointers distinguish a
// missing field from an explicit zero value.
type reviewSpec struct {
	ChainID         *string `json:"chainId"`
	BlockHash       *string `json:"blockHash"`
	TxHash          *string `json:"txHash"`
	Kind            *string `json:"kind"`
	CommitID        *string `json:"commitId"`
	Operator        *string `json:"operator"`
	Reason          *string `json:"reason"`
	ExpectedVersion *int    `json:"expectedVersion"`
	Status          *string `json:"status"`
}

func parseReviewSpec(raw []byte) (reviewSpec, error) {
	var spec reviewSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return reviewSpec{}, fmt.Errorf("invalid review spec: %w", err)
	}
	if dec.More() {
		return reviewSpec{}, errors.New("invalid review spec: unexpected trailing data")
	}
	return spec, nil
}

// validateReviewSpec checks every submission field. All text fields must be
// non-empty, the status must be one of the three verdicts, and the expected
// version must be a non-negative integer.
func validateReviewSpec(spec reviewSpec) (reviewKey, string, string, string, int, string, error) {
	chainID, err := nonEmpty("chainId", spec.ChainID)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	blockHash, err := nonEmpty("blockHash", spec.BlockHash)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	txHash, err := nonEmpty("txHash", spec.TxHash)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	kind, err := nonEmpty("kind", spec.Kind)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	commitID, err := nonEmpty("commitId", spec.CommitID)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	operator, err := nonEmpty("operator", spec.Operator)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	reason, err := nonEmpty("reason", spec.Reason)
	if err != nil {
		return reviewKey{}, "", "", "", 0, "", err
	}
	if spec.Status == nil {
		return reviewKey{}, "", "", "", 0, "", errors.New("status is required (real-risk, false-positive or unreviewed)")
	}
	status := *spec.Status
	if status != ReviewRealRisk && status != ReviewFalsePositive && status != ReviewUnreviewed {
		return reviewKey{}, "", "", "", 0, "", fmt.Errorf("status must be one of real-risk, false-positive, unreviewed, got %q", status)
	}
	if spec.ExpectedVersion == nil {
		return reviewKey{}, "", "", "", 0, "", errors.New("expectedVersion is required (non-negative integer)")
	}
	if *spec.ExpectedVersion < 0 {
		return reviewKey{}, "", "", "", 0, "", fmt.Errorf("expectedVersion must be non-negative, got %d", *spec.ExpectedVersion)
	}
	return reviewKey{chainID, blockHash, txHash, kind}, commitID, operator, reason, *spec.ExpectedVersion, status, nil
}

// findRecord returns the archived record for (chainID, blockHash), or nil.
func findRecord(data archiveData, chainID, blockHash string) *record {
	for i := range data.Records {
		if data.Records[i].ChainID == chainID && data.Records[i].BlockHash == blockHash {
			return &data.Records[i]
		}
	}
	return nil
}

// SubmitReview validates raw and appends one review revision to the object
// identified by the spec. The conclusion must already exist in the archive.
//
// Optimistic concurrency: a new commit ID is accepted only when its expected
// version equals the object's current version (0 for the first submission);
// a stale expected version is a conflict. Idempotency: re-submitting the same
// commit ID with identical content returns the original revision without
// appending, even after later overturns; the same commit ID with different
// content is a conflict. Concurrent submissions are serialized by the
// archive lock, so no revision can overwrite another. Any failure leaves the
// archive untouched.
func SubmitReview(dir string, raw []byte) (ReviewState, error) {
	spec, err := parseReviewSpec(raw)
	if err != nil {
		return ReviewState{}, err
	}
	key, commitID, operator, reason, expectedVersion, status, err := validateReviewSpec(spec)
	if err != nil {
		return ReviewState{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ReviewState{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return ReviewState{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return ReviewState{}, err
	}
	rec := findRecord(data, key.chainID, key.blockHash)
	if rec == nil {
		return ReviewState{}, fmt.Errorf("%w: %s/%s", ErrUnknownConclusion, key.chainID, key.blockHash)
	}
	var finding *ReportFinding
	for i := range rec.Findings {
		if rec.Findings[i].TxHash == key.txHash && rec.Findings[i].Kind == key.kind {
			finding = &rec.Findings[i]
			break
		}
	}
	if finding == nil {
		return ReviewState{}, fmt.Errorf("%w: %s/%s tx %s kind %s",
			ErrUnknownConclusion, key.chainID, key.blockHash, key.txHash, key.kind)
	}

	stateIdx := -1
	for i := range data.Reviews {
		if data.Reviews[i].key() == key {
			stateIdx = i
			break
		}
	}
	if stateIdx >= 0 {
		state := data.Reviews[stateIdx]
		// Idempotent retry: the same commit ID with identical content returns
		// the original revision without appending, even after later overturns.
		for _, rev := range state.Revisions {
			if rev.CommitID == commitID {
				if rev.Operator == operator && rev.Reason == reason && rev.Status == status {
					return state, nil
				}
				return ReviewState{}, fmt.Errorf("%w: commitId %s already used with different content", ErrReviewConflict, commitID)
			}
		}
		// New commit: the expected version must match the current object
		// version, otherwise the submitter based its decision on stale state.
		if expectedVersion != state.Version {
			return ReviewState{}, fmt.Errorf("%w: expected version %d, current version %d",
				ErrReviewConflict, expectedVersion, state.Version)
		}
		rev := ReviewRevision{
			CommitID: commitID, Operator: operator, Reason: reason, Status: status,
			ExpectedVersion: expectedVersion, Version: state.Version + 1,
		}
		state.Revisions = append(state.Revisions, rev)
		state.Version++
		data.Reviews[stateIdx] = state
		if err := writeArchiveAtomic(dir, data); err != nil {
			return ReviewState{}, err
		}
		return state, nil
	}
	// First submission: the expected version must be 0.
	if expectedVersion != 0 {
		return ReviewState{}, fmt.Errorf("%w: first submission expects version 0, got %d",
			ErrReviewConflict, expectedVersion)
	}
	state := ReviewState{
		ChainID: key.chainID, BlockHash: key.blockHash, TxHash: key.txHash, Kind: key.kind,
		Version: 1,
		Revisions: []ReviewRevision{{
			CommitID: commitID, Operator: operator, Reason: reason, Status: status,
			ExpectedVersion: 0, Version: 1,
		}},
	}
	data.Reviews = append(data.Reviews, state)
	if err := writeArchiveAtomic(dir, data); err != nil {
		return ReviewState{}, err
	}
	return state, nil
}

// ReviewHistory is the full review state of one conclusion: the current
// verdict and version, every revision in ascending version order, and the
// original conclusion, its detection version parameters and the raw exchange
// evidence. A conclusion that was never reviewed reports status unreviewed,
// version 0 and an empty revision list; a conclusion that does not exist in
// the archive reports null for the conclusion, version and evidence.
type ReviewHistory struct {
	ChainID     string           `json:"chainId"`
	BlockHash   string           `json:"blockHash"`
	TxHash      string           `json:"txHash"`
	Kind        string           `json:"kind"`
	Status      string           `json:"status"`
	Version     int              `json:"version"`
	Revisions   []ReviewRevision `json:"revisions"`
	Finding     *ReportFinding   `json:"finding"`
	RuleVersion *RuleVersion     `json:"ruleVersion"`
	Swaps       []Swap           `json:"swaps"`
}

// GetReviewHistory returns the review state of one conclusion plus the
// archived conclusion, its detection version and the raw exchange evidence.
// It only reads the archive; the original input file is not needed.
func GetReviewHistory(dir, chainID, blockHash, txHash, kind string) (ReviewHistory, error) {
	if strings.TrimSpace(chainID) == "" || strings.TrimSpace(blockHash) == "" ||
		strings.TrimSpace(txHash) == "" || strings.TrimSpace(kind) == "" {
		return ReviewHistory{}, errors.New("chainId, blockHash, txHash and kind must be non-empty strings")
	}
	out := ReviewHistory{
		ChainID: chainID, BlockHash: blockHash, TxHash: txHash, Kind: kind,
		Status: ReviewUnreviewed, Version: 0,
		Revisions: []ReviewRevision{}, Swaps: []Swap{},
	}
	if _, serr := os.Stat(dir); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return out, nil
		}
		return ReviewHistory{}, serr
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return ReviewHistory{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return ReviewHistory{}, err
	}
	key := reviewKey{chainID, blockHash, txHash, kind}
	for _, s := range data.Reviews {
		if s.key() == key {
			out.Status = s.currentStatus()
			out.Version = s.Version
			out.Revisions = append([]ReviewRevision(nil), s.Revisions...)
			break
		}
	}
	if rec := findRecord(data, chainID, blockHash); rec != nil {
		out.Swaps = append([]Swap(nil), rec.Swaps...)
		rv := rec.ruleVersion()
		out.RuleVersion = &rv
		for i := range rec.Findings {
			if rec.Findings[i].TxHash == txHash && rec.Findings[i].Kind == kind {
				f := rec.Findings[i]
				out.Finding = &f
				break
			}
		}
	}
	return out, nil
}

// EvalDetail is one entry of the false-positive analysis. It carries the
// block identity, the adopted review revision (null when unreviewed), the
// original and candidate conclusions (null when absent), the original and
// candidate rule parameters, and the exchange evidence inside each
// conclusion.
type EvalDetail struct {
	ChainID          string          `json:"chainId"`
	BlockHash        string          `json:"blockHash"`
	BlockNumber      int64           `json:"blockNumber"`
	TxHash           string          `json:"txHash"`
	Kind             string          `json:"kind"`
	Category         string          `json:"category"`
	Review           *ReviewRevision `json:"review"`
	Original         *ReportFinding  `json:"original"`
	Candidate        *ReportFinding  `json:"candidate"`
	OriginalVersion  *RuleVersion    `json:"originalVersion"`
	CandidateVersion RuleVersion     `json:"candidateVersion"`
}

// EvalResult is the outcome of re-judging an inclusive height range under one
// registered rule version, using the archive's latest review state. Kept and
// missed count reviewed real-risk conclusions that the candidate still flags
// or drops; stillHit and eliminated count reviewed false-positive conclusions
// that the candidate still flags or drops; pending counts candidate hits with
// no valid review. Withdrawn objects are treated as unreviewed.
type EvalResult struct {
	ChainID       string       `json:"chainId"`
	StartHeight   uint64       `json:"startHeight"`
	EndHeight     uint64       `json:"endHeight"`
	Version       RuleVersion  `json:"version"`
	Kept          int          `json:"kept"`
	Missed        int          `json:"missed"`
	StillHit      int          `json:"stillHit"`
	Eliminated    int          `json:"eliminated"`
	PendingReview int          `json:"pendingReview"`
	Details       []EvalDetail `json:"details"`
}

// EvaluateReviews re-judges every block on chainID in the inclusive range
// [startHeight, endHeight] under the registered versionID and diffs the
// candidate conclusions against the archived originals using the latest
// review state. The archive and review state are read once under a shared
// lock, so the whole evaluation uses one consistent snapshot. Only reviewed
// real-risk and false-positive conclusions enter the four counts; candidate
// hits without a valid review are listed as pending. The archive is never
// modified.
func EvaluateReviews(dir, chainID string, startHeight, endHeight uint64, versionID string) (EvalResult, error) {
	if strings.TrimSpace(chainID) == "" {
		return EvalResult{}, errors.New("chainId must be a non-empty string")
	}
	if startHeight > endHeight {
		return EvalResult{}, fmt.Errorf("startHeight %d must not exceed endHeight %d", startHeight, endHeight)
	}
	if versionID == "" {
		return EvalResult{}, errors.New("version id must not be empty")
	}
	result := EvalResult{
		ChainID: chainID, StartHeight: startHeight, EndHeight: endHeight,
		Details: []EvalDetail{},
	}
	if _, serr := os.Stat(dir); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			// No archive: the range holds no blocks.
			result.Version = BuiltinVersion()
			return result, nil
		}
		return EvalResult{}, serr
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return EvalResult{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return EvalResult{}, err
	}
	candidate, err := findVersion(data, versionID)
	if err != nil {
		return EvalResult{}, err
	}
	result.Version = candidate

	reviewByKey := make(map[reviewKey]ReviewState, len(data.Reviews))
	for _, s := range data.Reviews {
		reviewByKey[s.key()] = s
	}

	details := []EvalDetail{}
	for _, rec := range data.Records {
		if rec.ChainID != chainID {
			continue
		}
		height := uint64(rec.BlockNumber)
		if height < startHeight || height > endHeight {
			continue
		}
		candFindings := DetectBlockWithRules(rec.Swaps, candidate.Rules)
		candByKey := make(map[reviewKey]ReportFinding, len(candFindings))
		for _, f := range candFindings {
			candByKey[reviewKey{rec.ChainID, rec.BlockHash, f.TxHash, f.Kind}] = f
		}
		origByKey := make(map[reviewKey]ReportFinding, len(rec.Findings))
		for _, f := range rec.Findings {
			origByKey[reviewKey{rec.ChainID, rec.BlockHash, f.TxHash, f.Kind}] = f
		}
		// The four counts come from reviewed original conclusions. Matching
		// requires the same tx hash and the same kind; a severity change does
		// not affect the match. A kind change leaves the original kind
		// unmatched (missed/eliminated) and lists the new kind as pending.
		for _, f := range rec.Findings {
			key := reviewKey{rec.ChainID, rec.BlockHash, f.TxHash, f.Kind}
			state, reviewed := reviewByKey[key]
			if !reviewed {
				continue
			}
			status := state.currentStatus()
			if status != ReviewRealRisk && status != ReviewFalsePositive {
				continue // withdrawn: treated as unreviewed
			}
			cand, hit := candByKey[key]
			category := ""
			switch {
			case status == ReviewRealRisk && hit:
				category = "kept"
				result.Kept++
			case status == ReviewRealRisk && !hit:
				category = "missed"
				result.Missed++
			case status == ReviewFalsePositive && hit:
				category = "still-hit"
				result.StillHit++
			case status == ReviewFalsePositive && !hit:
				category = "eliminated"
				result.Eliminated++
			}
			detail := EvalDetail{
				ChainID: rec.ChainID, BlockHash: rec.BlockHash, BlockNumber: rec.BlockNumber,
				TxHash: f.TxHash, Kind: f.Kind, Category: category,
				Review: state.adoptedRevision(),
				Original: ptrFinding(f),
				OriginalVersion: ptrVersion(rec.ruleVersion()),
				CandidateVersion: candidate,
			}
			if hit {
				detail.Candidate = ptrFinding(cand)
			}
			details = append(details, detail)
		}
		// Pending: candidate hits with no valid review. This includes new
		// conclusions, kind-change new kinds, and unreviewed originals that
		// the candidate still flags.
		for _, f := range candFindings {
			key := reviewKey{rec.ChainID, rec.BlockHash, f.TxHash, f.Kind}
			if state, reviewed := reviewByKey[key]; reviewed {
				status := state.currentStatus()
				if status == ReviewRealRisk || status == ReviewFalsePositive {
					continue // already counted among the four
				}
			}
			result.PendingReview++
			detail := EvalDetail{
				ChainID: rec.ChainID, BlockHash: rec.BlockHash, BlockNumber: rec.BlockNumber,
				TxHash: f.TxHash, Kind: f.Kind, Category: "pending",
				Candidate: ptrFinding(f), CandidateVersion: candidate,
			}
			if orig, ok := origByKey[key]; ok {
				detail.Original = ptrFinding(orig)
				detail.OriginalVersion = ptrVersion(rec.ruleVersion())
			}
			details = append(details, detail)
		}
	}
	sortEvalDetails(details)
	result.Details = details
	return result, nil
}

// sortEvalDetails orders details by height, block hash, tx hash and kind
// ascending.
func sortEvalDetails(details []EvalDetail) {
	sort.Slice(details, func(i, j int) bool {
		a, b := details[i], details[j]
		if a.BlockNumber != b.BlockNumber {
			return a.BlockNumber < b.BlockNumber
		}
		if a.BlockHash != b.BlockHash {
			return a.BlockHash < b.BlockHash
		}
		if a.TxHash != b.TxHash {
			return a.TxHash < b.TxHash
		}
		return a.Kind < b.Kind
	})
}

func ptrFinding(f ReportFinding) *ReportFinding { return &f }
func ptrVersion(v RuleVersion) *RuleVersion     { return &v }

// validateReviewStates checks the structural integrity of every review state
// read from the archive: non-empty identity fields, the version matching the
// revision count, revision versions in order, unique commit IDs and valid
// statuses. A violation means the archive is corrupted.
func validateReviewStates(states []ReviewState) error {
	seen := make(map[reviewKey]struct{})
	for i, s := range states {
		if strings.TrimSpace(s.ChainID) == "" || strings.TrimSpace(s.BlockHash) == "" ||
			strings.TrimSpace(s.TxHash) == "" || strings.TrimSpace(s.Kind) == "" {
			return fmt.Errorf("reviews[%d]: missing identity field", i)
		}
		if s.Version < 0 {
			return fmt.Errorf("reviews[%d]: version must be non-negative, got %d", i, s.Version)
		}
		if len(s.Revisions) != s.Version {
			return fmt.Errorf("reviews[%d]: version %d does not match %d revisions", i, s.Version, len(s.Revisions))
		}
		commits := make(map[string]struct{})
		for j, rev := range s.Revisions {
			if rev.Version != j+1 {
				return fmt.Errorf("reviews[%d]: revision %d has version %d", i, j, rev.Version)
			}
			if strings.TrimSpace(rev.CommitID) == "" || strings.TrimSpace(rev.Operator) == "" ||
				strings.TrimSpace(rev.Reason) == "" {
				return fmt.Errorf("reviews[%d]: revision %d has empty submission field", i, j)
			}
			if rev.Status != ReviewRealRisk && rev.Status != ReviewFalsePositive && rev.Status != ReviewUnreviewed {
				return fmt.Errorf("reviews[%d]: revision %d has invalid status %q", i, j, rev.Status)
			}
			if _, ok := commits[rev.CommitID]; ok {
				return fmt.Errorf("reviews[%d]: duplicate commitId %s", i, rev.CommitID)
			}
			commits[rev.CommitID] = struct{}{}
		}
		k := s.key()
		if _, ok := seen[k]; ok {
			return fmt.Errorf("reviews[%d]: duplicate review state for %s/%s tx %s kind %s",
				i, k.chainID, k.blockHash, k.txHash, k.kind)
		}
		seen[k] = struct{}{}
	}
	return nil
}
