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

// Manual review and false-positive analysis work strictly on top of
// archived evidence: submitting a review, querying revision history and
// re-evaluating a height range never need the original input files, never
// contact any network, never re-write a report, the enabled version or an
// alert record, and never trigger or revoke alerts.

// Review statuses. A human marks an archived conclusion either as a real
// risk or as a false positive; submitting "unreviewed" withdraws earlier
// judgments of the same object without deleting the history.
const (
	ReviewStatusReal          = "real"
	ReviewStatusFalsePositive = "false_positive"
	ReviewStatusUnreviewed    = "unreviewed"
)

// Evaluation buckets for original conclusions carrying a valid review:
// real risks split into retained vs missed, false positives into still hit
// vs eliminated. Candidate hits without a valid review are pending.
const (
	BucketRetained   = "retained"
	BucketMissed     = "missed"
	BucketStillHit   = "stillHit"
	BucketEliminated = "eliminated"
	BucketPending    = "pending"
)

// ErrUnknownConclusion reports a review action targeting a conclusion that
// no archived report carries.
var ErrUnknownConclusion = errors.New("unknown conclusion")

// ErrReviewConflict reports a submission whose expectedVersion is behind the
// object's current version.
var ErrReviewConflict = errors.New("review version conflict")

// ErrSubmissionConflict reports a submission ID already stored with
// different field values. Submission IDs are unique archive-wide.
var ErrSubmissionConflict = errors.New("submission id already used with different content")

// conclusionKey is the reviewed object's identity: chain, block hash,
// victim tx hash and conclusion kind. It deliberately excludes the alert
// channel, and blocks at the same height with different hashes are
// different objects.
type conclusionKey struct {
	chainID   string
	blockHash string
	txHash    string
	kind      string
}

// ReviewRevision is one immutable submission. Revisions are append-only:
// rejudgments and withdrawals add a new revision while every earlier one is
// retained. ExpectedVersion records the optimistic-concurrency base the
// submitter believed in (0 for the first submission), keeping each
// revision's full submission content auditable.
type ReviewRevision struct {
	Version         int    `json:"version"`
	SubmissionID    string `json:"submissionId"`
	Operator        string `json:"operator"`
	Reason          string `json:"reason"`
	Status          string `json:"status"`
	ExpectedVersion int    `json:"expectedVersion"`
}

// ReviewObject is the append-only revision stream for one conclusion
// identity. The current version is len(Revisions); the current status is
// the last revision's status (an "unreviewed" tail means withdrawn).
type ReviewObject struct {
	ChainID   string           `json:"chainId"`
	BlockHash string           `json:"blockHash"`
	TxHash    string           `json:"txHash"`
	Kind      string           `json:"kind"`
	Revisions []ReviewRevision `json:"revisions"`
}

func (o ReviewObject) key() conclusionKey {
	return conclusionKey{o.ChainID, o.BlockHash, o.TxHash, o.Kind}
}

// ReviewSubmission is one submitted review.
type ReviewSubmission struct {
	ChainID         string
	BlockHash       string
	TxHash          string
	Kind            string
	SubmissionID    string
	Operator        string
	Reason          string
	Status          string
	ExpectedVersion int
}

func (s ReviewSubmission) key() conclusionKey {
	return conclusionKey{s.ChainID, s.BlockHash, s.TxHash, s.Kind}
}

// contentEqual reports whether two submissions carry identical field
// values, including the target identity and the expected version.
func (s ReviewSubmission) contentEqual(o ReviewSubmission) bool {
	return s == o
}

func (s ReviewSubmission) revision(version int) ReviewRevision {
	return ReviewRevision{
		Version:         version,
		SubmissionID:    s.SubmissionID,
		Operator:        s.Operator,
		Reason:          s.Reason,
		Status:          s.Status,
		ExpectedVersion: s.ExpectedVersion,
	}
}

// reviewSpec mirrors one submission document. Pointers distinguish missing
// fields from explicit zero values; the decoder rejects unknown fields.
type reviewSpec struct {
	ChainID         *string `json:"chainId"`
	BlockHash       *string `json:"blockHash"`
	TxHash          *string `json:"txHash"`
	Kind            *string `json:"kind"`
	SubmissionID    *string `json:"submissionId"`
	Operator        *string `json:"operator"`
	Reason          *string `json:"reason"`
	Status          *string `json:"status"`
	ExpectedVersion *int    `json:"expectedVersion"`
}

// ParseReviewSubmission validates one submission document. Identity fields
// and operator/reason/submissionId must be non-empty, the status must be
// one of real, false_positive or unreviewed, expectedVersion must be a
// non-negative integer, and the kind must be a known conclusion kind.
func ParseReviewSubmission(raw []byte) (ReviewSubmission, error) {
	var spec reviewSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return ReviewSubmission{}, fmt.Errorf("invalid review spec: %w", err)
	}
	if dec.More() {
		return ReviewSubmission{}, errors.New("invalid review spec: unexpected trailing data")
	}
	chainID, err := nonEmpty("chainId", spec.ChainID)
	if err != nil {
		return ReviewSubmission{}, err
	}
	blockHash, err := nonEmpty("blockHash", spec.BlockHash)
	if err != nil {
		return ReviewSubmission{}, err
	}
	txHash, err := nonEmpty("txHash", spec.TxHash)
	if err != nil {
		return ReviewSubmission{}, err
	}
	kind, err := nonEmpty("kind", spec.Kind)
	if err != nil {
		return ReviewSubmission{}, err
	}
	if kind != SuppressSandwich && kind != SuppressDisplacement {
		return ReviewSubmission{}, fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, kind)
	}
	submissionID, err := nonEmpty("submissionId", spec.SubmissionID)
	if err != nil {
		return ReviewSubmission{}, err
	}
	operator, err := nonEmpty("operator", spec.Operator)
	if err != nil {
		return ReviewSubmission{}, err
	}
	reason, err := nonEmpty("reason", spec.Reason)
	if err != nil {
		return ReviewSubmission{}, err
	}
	status, err := nonEmpty("status", spec.Status)
	if err != nil {
		return ReviewSubmission{}, err
	}
	switch status {
	case ReviewStatusReal, ReviewStatusFalsePositive, ReviewStatusUnreviewed:
	default:
		return ReviewSubmission{}, fmt.Errorf("invalid status %q (want %s, %s or %s)",
			status, ReviewStatusReal, ReviewStatusFalsePositive, ReviewStatusUnreviewed)
	}
	if spec.ExpectedVersion == nil {
		return ReviewSubmission{}, errors.New("expectedVersion is required (non-negative integer)")
	}
	if *spec.ExpectedVersion < 0 {
		return ReviewSubmission{}, fmt.Errorf("expectedVersion must be non-negative, got %d", *spec.ExpectedVersion)
	}
	return ReviewSubmission{
		ChainID:         chainID,
		BlockHash:       blockHash,
		TxHash:          txHash,
		Kind:            kind,
		SubmissionID:    submissionID,
		Operator:        operator,
		Reason:          reason,
		Status:          status,
		ExpectedVersion: *spec.ExpectedVersion,
	}, nil
}

// SubmitReviewResult is the outcome of one submission attempt. Created is
// false when an identical submission (same ID and same field values) was
// retried: in that case Revision is the original revision and no new one is
// appended, even when the object was rejudged or withdrawn later.
type SubmitReviewResult struct {
	Created   bool           `json:"created"`
	ChainID   string         `json:"chainId"`
	BlockHash string         `json:"blockHash"`
	TxHash    string         `json:"txHash"`
	Kind      string         `json:"kind"`
	Status    string         `json:"status"`
	Version   int            `json:"version"`
	Revision  ReviewRevision `json:"revision"`
}

// SubmitReview validates and stores one review revision. The target
// conclusion must exist in the archive. The first submission for an object
// must carry expectedVersion 0; every later one must carry the object's
// current version, otherwise the submission is rejected without touching
// stored data. Rejudgments and withdrawals append; older revisions stay.
// Identical retries (same archive-unique submission ID and identical
// fields) return the original revision. The whole update is one atomic
// commit under the archive lock, so concurrent submissions serialize and a
// stale concurrent submission can never overwrite another operator's
// revision.
func SubmitReview(dir string, sub ReviewSubmission) (SubmitReviewResult, error) {
	if err := validateReviewIdentity(sub); err != nil {
		return SubmitReviewResult{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return SubmitReviewResult{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return SubmitReviewResult{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return SubmitReviewResult{}, err
	}
	if _, _, ok := findArchivedConclusion(data, sub.key()); !ok {
		return SubmitReviewResult{}, fmt.Errorf("%w: %s/%s tx %s %s",
			ErrUnknownConclusion, sub.ChainID, sub.BlockHash, sub.TxHash, sub.Kind)
	}

	// Submission IDs are unique archive-wide. An ID reuse with identical
	// content is an idempotent retry of the original revision; it must
	// succeed (and append nothing) even when the object has since moved on.
	for i := range data.Reviews {
		obj := &data.Reviews[i]
		for _, rev := range obj.Revisions {
			if rev.SubmissionID != sub.SubmissionID {
				continue
			}
			existing := ReviewSubmission{
				ChainID:         obj.ChainID,
				BlockHash:       obj.BlockHash,
				TxHash:          obj.TxHash,
				Kind:            obj.Kind,
				SubmissionID:    rev.SubmissionID,
				Operator:        rev.Operator,
				Reason:          rev.Reason,
				Status:          rev.Status,
				ExpectedVersion: rev.ExpectedVersion,
			}
			if !sub.contentEqual(existing) {
				return SubmitReviewResult{}, fmt.Errorf("%w: %s", ErrSubmissionConflict, sub.SubmissionID)
			}
			return SubmitReviewResult{
				Created:   false,
				ChainID:   obj.ChainID,
				BlockHash: obj.BlockHash,
				TxHash:    obj.TxHash,
				Kind:      obj.Kind,
				Status:    currentReviewStatus(*obj),
				Version:   len(obj.Revisions),
				Revision:  rev,
			}, nil
		}
	}

	idx := -1
	for i := range data.Reviews {
		if data.Reviews[i].key() == sub.key() {
			idx = i
			break
		}
	}
	if idx >= 0 && data.Reviews[idx].Revisions == nil {
		data.Reviews[idx].Revisions = []ReviewRevision{}
	}
	currentVersion := 0
	if idx >= 0 {
		currentVersion = len(data.Reviews[idx].Revisions)
	}
	if sub.ExpectedVersion != currentVersion {
		return SubmitReviewResult{}, fmt.Errorf("%w: %s/%s tx %s %s is at version %d, submission expected %d",
			ErrReviewConflict, sub.ChainID, sub.BlockHash, sub.TxHash, sub.Kind, currentVersion, sub.ExpectedVersion)
	}
	rev := sub.revision(currentVersion + 1)
	if idx < 0 {
		data.Reviews = append(data.Reviews, ReviewObject{
			ChainID:   sub.ChainID,
			BlockHash: sub.BlockHash,
			TxHash:    sub.TxHash,
			Kind:      sub.Kind,
			Revisions: []ReviewRevision{rev},
		})
	} else {
		data.Reviews[idx].Revisions = append(data.Reviews[idx].Revisions, rev)
	}
	if err := writeArchiveAtomic(dir, data); err != nil {
		return SubmitReviewResult{}, err
	}
	return SubmitReviewResult{
		Created:   true,
		ChainID:   sub.ChainID,
		BlockHash: sub.BlockHash,
		TxHash:    sub.TxHash,
		Kind:      sub.Kind,
		Status:    sub.Status,
		Version:   currentVersion + 1,
		Revision:  rev,
	}, nil
}

func validateReviewIdentity(sub ReviewSubmission) error {
	if strings.TrimSpace(sub.ChainID) == "" {
		return errors.New("chainId must be a non-empty string")
	}
	if strings.TrimSpace(sub.BlockHash) == "" {
		return errors.New("blockHash must be a non-empty string")
	}
	if strings.TrimSpace(sub.TxHash) == "" {
		return errors.New("txHash must be a non-empty string")
	}
	if sub.Kind != SuppressSandwich && sub.Kind != SuppressDisplacement {
		return fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, sub.Kind)
	}
	if strings.TrimSpace(sub.SubmissionID) == "" {
		return errors.New("submissionId must be a non-empty string")
	}
	if strings.TrimSpace(sub.Operator) == "" {
		return errors.New("operator must be a non-empty string")
	}
	if strings.TrimSpace(sub.Reason) == "" {
		return errors.New("reason must be a non-empty string")
	}
	switch sub.Status {
	case ReviewStatusReal, ReviewStatusFalsePositive, ReviewStatusUnreviewed:
	default:
		return fmt.Errorf("invalid status %q", sub.Status)
	}
	if sub.ExpectedVersion < 0 {
		return fmt.Errorf("expectedVersion must be non-negative, got %d", sub.ExpectedVersion)
	}
	return nil
}

// ReviewOriginal pairs the archived conclusion with the detection version
// (full parameters) that produced it.
type ReviewOriginal struct {
	BlockNumber int64         `json:"blockNumber"`
	Finding     ReportFinding `json:"finding"`
	Version     RuleVersion   `json:"version"`
}

// ReviewHistory is the full revision view of one conclusion object.
type ReviewHistory struct {
	ChainID   string           `json:"chainId"`
	BlockHash string           `json:"blockHash"`
	TxHash    string           `json:"txHash"`
	Kind      string           `json:"kind"`
	Status    string           `json:"status"`
	Version   int              `json:"version"`
	Original  *ReviewOriginal  `json:"original"`
	Revisions []ReviewRevision `json:"revisions"`
}

// currentReviewStatus returns the latest revision's status. A trailing
// "unreviewed" revision means an earlier judgment was withdrawn.
func currentReviewStatus(obj ReviewObject) string {
	if len(obj.Revisions) == 0 {
		return ReviewStatusUnreviewed
	}
	return obj.Revisions[len(obj.Revisions)-1].Status
}

// ReviewHistoryQuery returns the current status and version of one
// conclusion object plus every revision in ascending version order. Each
// revision keeps its full submission content, and the response carries the
// original archived conclusion, the detection version parameters and the
// raw swap evidence. An identity without review data reports status
// unreviewed, version 0 and an empty list; when no archived conclusion
// matches the identity, original is null.
func ReviewHistoryQuery(dir, chainID, blockHash, txHash, kind string) (ReviewHistory, error) {
	if strings.TrimSpace(chainID) == "" || strings.TrimSpace(blockHash) == "" ||
		strings.TrimSpace(txHash) == "" {
		return ReviewHistory{}, errors.New("chainId, blockHash and txHash must be non-empty strings")
	}
	if kind != SuppressSandwich && kind != SuppressDisplacement {
		return ReviewHistory{}, fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, kind)
	}
	out := ReviewHistory{
		ChainID:   chainID,
		BlockHash: blockHash,
		TxHash:    txHash,
		Kind:      kind,
		Status:    ReviewStatusUnreviewed,
		Version:   0,
		Original:  nil,
		Revisions: []ReviewRevision{},
	}
	key := conclusionKey{chainID, blockHash, txHash, kind}
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
	if rec, f, ok := findArchivedConclusion(data, key); ok {
		out.Original = &ReviewOriginal{
			BlockNumber: rec.BlockNumber,
			Finding:     f,
			Version:     rec.ruleVersion(),
		}
	}
	for i := range data.Reviews {
		obj := data.Reviews[i]
		if obj.key() != key {
			continue
		}
		out.Version = len(obj.Revisions)
		out.Status = currentReviewStatus(obj)
		out.Revisions = append([]ReviewRevision(nil), obj.Revisions...)
		break
	}
	if out.Revisions == nil {
		out.Revisions = []ReviewRevision{}
	}
	return out, nil
}

// findArchivedConclusion locates the record and the finding for an identity.
func findArchivedConclusion(data archiveData, key conclusionKey) (record, ReportFinding, bool) {
	for _, rec := range data.Records {
		if rec.ChainID != key.chainID || rec.BlockHash != key.blockHash {
			continue
		}
		for _, f := range rec.Findings {
			if f.TxHash == key.txHash && f.Kind == key.kind {
				return rec, f, true
			}
		}
	}
	return record{}, ReportFinding{}, false
}

// ReviewConclusion pairs a conclusion with the rule version whose
// parameters produced it. The finding itself carries the raw swap evidence.
type ReviewConclusion struct {
	Finding ReportFinding `json:"finding"`
	Version RuleVersion   `json:"version"`
}

// ReviewDetail is one evaluated conclusion with its bucket, the revision
// that decided it (null when there is no valid review), the original and
// candidate conclusions (either side may be null), their rule parameters
// and their swap evidence.
type ReviewDetail struct {
	ChainID         string            `json:"chainId"`
	BlockHash       string            `json:"blockHash"`
	BlockNumber     int64             `json:"blockNumber"`
	TxHash          string            `json:"txHash"`
	Kind            string            `json:"kind"`
	Bucket          string            `json:"bucket"`
	AppliedRevision *ReviewRevision   `json:"appliedRevision"`
	Original        *ReviewConclusion `json:"original"`
	Candidate       *ReviewConclusion `json:"candidate"`
}

// ReviewEvaluation is the false-positive analysis over one inclusive height
// range, judged consistently against one archive snapshot and its latest
// review state.
type ReviewEvaluation struct {
	ChainID     string         `json:"chainId"`
	StartHeight uint64         `json:"startHeight"`
	EndHeight   uint64         `json:"endHeight"`
	Version     RuleVersion    `json:"version"`
	Retained    int            `json:"retained"`
	Missed      int            `json:"missed"`
	StillHit    int            `json:"stillHit"`
	Eliminated  int            `json:"eliminated"`
	Pending     int            `json:"pending"`
	Details     []ReviewDetail `json:"details"`
}

// sortReviewDetails orders by height, block hash, tx hash and kind.
func sortReviewDetails(details []ReviewDetail) {
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

// EvaluateReviews re-judges every archived block on chainID in the inclusive
// range [startHeight, endHeight] under the given registered rule version and
// compares the candidate conclusions against archived originals, using only
// archived evidence and the latest review state. Only original conclusions
// marked real or false positive feed the four counts: real risks split into
// retained (same tx and same kind still hits; severity changes do not
// matter) and missed; false positives split into still hit and eliminated.
// A candidate hit on the same tx and kind without a valid (non-withdrawn)
// review counts as pending, as does the new kind when the candidate changes
// a tx's conclusion type; withdrawn objects behave as unreviewed. The call
// is read-only: reports, the enabled version, reviews and alert records are
// never modified. An empty range yields zero counts and an empty list.
func EvaluateReviews(dir, chainID string, startHeight, endHeight uint64, versionID string) (ReviewEvaluation, error) {
	if strings.TrimSpace(chainID) == "" {
		return ReviewEvaluation{}, errors.New("chainId must be a non-empty string")
	}
	if strings.TrimSpace(versionID) == "" {
		return ReviewEvaluation{}, errors.New("version id must not be empty")
	}
	if startHeight > endHeight {
		return ReviewEvaluation{}, fmt.Errorf("startHeight %d must not exceed endHeight %d", startHeight, endHeight)
	}
	result := ReviewEvaluation{
		ChainID:     chainID,
		StartHeight: startHeight,
		EndHeight:   endHeight,
		Details:     []ReviewDetail{},
	}
	if _, serr := os.Stat(dir); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			// An absent archive has only the built-in version registered, so
			// any other id is an unknown version even though the range would
			// match no blocks.
			if versionID != BuiltinVersionID {
				return ReviewEvaluation{}, fmt.Errorf("%w: %s", ErrUnknownVersion, versionID)
			}
			result.Version = BuiltinVersion()
			return result, nil
		}
		return ReviewEvaluation{}, serr
	}
	// One shared lock for the whole evaluation: the archive snapshot and the
	// latest review state stay consistent across every block.
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return ReviewEvaluation{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return ReviewEvaluation{}, err
	}
	candidate, err := findVersion(data, versionID)
	if err != nil {
		return ReviewEvaluation{}, err
	}
	result.Version = candidate

	reviews := make(map[conclusionKey]*ReviewObject, len(data.Reviews))
	for i := range data.Reviews {
		reviews[data.Reviews[i].key()] = &data.Reviews[i]
	}

	details := []ReviewDetail{}
	for _, rec := range data.Records {
		if rec.ChainID != chainID {
			continue
		}
		height := uint64(rec.BlockNumber)
		if height < startHeight || height > endHeight {
			continue
		}
		originalVersion := rec.ruleVersion()
		candidateFindings := DetectBlockWithRules(rec.Swaps, candidate.Rules)
		candByKey := make(map[conclusionKey]ReportFinding, len(candidateFindings))
		candByTx := make(map[string]ReportFinding, len(candidateFindings))
		for _, cf := range candidateFindings {
			candByKey[conclusionKey{rec.ChainID, rec.BlockHash, cf.TxHash, cf.Kind}] = cf
			candByTx[cf.TxHash] = cf
		}

		// Original conclusions: only reviewed (real/false-positive) ones
		// enter the four counts; same-kind candidate hits without a valid
		// review are pending; originals that simply vanished without review
		// are not counted anywhere.
		for _, of := range rec.Findings {
			key := conclusionKey{rec.ChainID, rec.BlockHash, of.TxHash, of.Kind}
			obj := reviews[key]
			original := &ReviewConclusion{Finding: of, Version: originalVersion}
			if obj == nil || currentReviewStatus(*obj) == ReviewStatusUnreviewed {
				if cf, ok := candByKey[key]; ok {
					details = append(details, ReviewDetail{
						ChainID: rec.ChainID, BlockHash: rec.BlockHash, BlockNumber: rec.BlockNumber,
						TxHash: of.TxHash, Kind: of.Kind, Bucket: BucketPending,
						Original: original, Candidate: &ReviewConclusion{Finding: cf, Version: candidate},
					})
				}
				continue
			}
			rev := obj.Revisions[len(obj.Revisions)-1]
			detail := ReviewDetail{
				ChainID: rec.ChainID, BlockHash: rec.BlockHash, BlockNumber: rec.BlockNumber,
				TxHash: of.TxHash, Kind: of.Kind, AppliedRevision: &rev, Original: original,
			}
			cf, hit := candByKey[key]
			if hit {
				detail.Candidate = &ReviewConclusion{Finding: cf, Version: candidate}
			}
			switch rev.Status {
			case ReviewStatusReal:
				if hit {
					detail.Bucket = BucketRetained
				} else {
					detail.Bucket = BucketMissed
				}
			case ReviewStatusFalsePositive:
				if hit {
					detail.Bucket = BucketStillHit
				} else {
					detail.Bucket = BucketEliminated
				}
			}
			details = append(details, detail)
		}

		// Candidate conclusions whose (tx, kind) matches no original: when
		// the same tx carried a different original kind this is the "new
		// type" side of a type change; either way it is unreviewed and
		// pending.
		for _, cf := range candidateFindings {
			if _, sameKind := findOriginalFinding(rec, cf.TxHash, cf.Kind); sameKind {
				continue
			}
			details = append(details, ReviewDetail{
				ChainID: rec.ChainID, BlockHash: rec.BlockHash, BlockNumber: rec.BlockNumber,
				TxHash: cf.TxHash, Kind: cf.Kind, Bucket: BucketPending,
				Original: nil, Candidate: &ReviewConclusion{Finding: cf, Version: candidate},
			})
		}
	}

	for _, d := range details {
		switch d.Bucket {
		case BucketRetained:
			result.Retained++
		case BucketMissed:
			result.Missed++
		case BucketStillHit:
			result.StillHit++
		case BucketEliminated:
			result.Eliminated++
		case BucketPending:
			result.Pending++
		}
	}
	sortReviewDetails(details)
	result.Details = details
	return result, nil
}

func findOriginalFinding(rec record, txHash, kind string) (ReportFinding, bool) {
	for _, f := range rec.Findings {
		if f.TxHash == txHash && f.Kind == kind {
			return f, true
		}
	}
	return ReportFinding{}, false
}
