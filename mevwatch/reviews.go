package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// reviewRule identifies one business limit every review submission must
// satisfy, however it was supplied (JSON spec or direct call).
type reviewRule int

const (
	ruleBlankString        reviewRule = iota // a text field is empty or all whitespace
	ruleKnownKind                            // the conclusion kind is not sandwich/displacement
	ruleKnownStatus                          // the status is not real/false_positive/unreviewed
	ruleNonNegativeVersion                   // the expected version is negative
)

// reviewViolation is the first business limit a submission breaks. Both
// submission entries render it with their own longstanding wording.
type reviewViolation struct {
	rule    reviewRule
	field   string // the submission field the rule rejected, in JSON spelling
	value   string // the offending kind, status or text value
	version int    // the offending expected version
}

// validateReviewSubmission applies the business limits every review
// submission must satisfy, in the order both entries have always reported
// them: chain, block hash, victim tx hash, kind, submission id, operator,
// reason, status, then the expected version. It only judges the values —
// nothing is trimmed, re-cased or replaced — and returns the first
// violation, or nil when the submission is valid.
func validateReviewSubmission(sub ReviewSubmission) *reviewViolation {
	for _, f := range []struct{ field, value string }{
		{"chainId", sub.ChainID},
		{"blockHash", sub.BlockHash},
		{"txHash", sub.TxHash},
		{"kind", sub.Kind},
	} {
		if strings.TrimSpace(f.value) == "" {
			return &reviewViolation{rule: ruleBlankString, field: f.field, value: f.value}
		}
	}
	if sub.Kind != SuppressSandwich && sub.Kind != SuppressDisplacement {
		return &reviewViolation{rule: ruleKnownKind, field: "kind", value: sub.Kind}
	}
	for _, f := range []struct{ field, value string }{
		{"submissionId", sub.SubmissionID},
		{"operator", sub.Operator},
		{"reason", sub.Reason},
		{"status", sub.Status},
	} {
		if strings.TrimSpace(f.value) == "" {
			return &reviewViolation{rule: ruleBlankString, field: f.field, value: f.value}
		}
	}
	switch sub.Status {
	case ReviewStatusReal, ReviewStatusFalsePositive, ReviewStatusUnreviewed:
	default:
		return &reviewViolation{rule: ruleKnownStatus, field: "status", value: sub.Status}
	}
	if sub.ExpectedVersion < 0 {
		return &reviewViolation{rule: ruleNonNegativeVersion, field: "expectedVersion", version: sub.ExpectedVersion}
	}
	return nil
}

// specError renders the violation with the JSON spec entry's wording.
func (v *reviewViolation) specError() error {
	switch v.rule {
	case ruleBlankString:
		return fmt.Errorf("%s must be a non-empty string", v.field)
	case ruleKnownKind:
		return fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, v.value)
	case ruleKnownStatus:
		return fmt.Errorf("invalid status %q (want %s, %s or %s)",
			v.value, ReviewStatusReal, ReviewStatusFalsePositive, ReviewStatusUnreviewed)
	case ruleNonNegativeVersion:
		return fmt.Errorf("expectedVersion must be non-negative, got %d", v.version)
	}
	return nil
}

// submitError renders the violation with the direct submission entry's
// wording. That entry never blank-checked kind and status separately: a
// blank kind reads as an unknown kind and a blank status as an invalid one,
// and its invalid-status message carries no candidate list.
func (v *reviewViolation) submitError() error {
	switch v.rule {
	case ruleBlankString:
		switch v.field {
		case "kind":
			return fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, v.value)
		case "status":
			return fmt.Errorf("invalid status %q", v.value)
		default:
			return fmt.Errorf("%s must be a non-empty string", v.field)
		}
	case ruleKnownStatus:
		return fmt.Errorf("invalid status %q", v.value)
	default:
		return v.specError()
	}
}

// ErrReviewTrailingData reports non-whitespace content after the single JSON
// object that makes up a review submission: a second object, an unmatched
// } or ], another JSON value or any other character.
var ErrReviewTrailingData = errors.New("unexpected trailing data after review spec")

// reviewFields lists every field name a review submission document may
// declare, in the struct's JSON spelling. The scanner uses the table both
// to know which values are ordinary scalars and to catch a known field
// declared twice; a review document is flat, so no nested table exists.
var reviewFields = []string{
	"chainId", "blockHash", "txHash", "kind",
	"submissionId", "operator", "reason", "status", "expectedVersion",
}

// reviewScanPolicy validates the shape of a review document with the shared
// scanner, the same machine rule-version and suppression registrations use.
// A review document is flat, so no nested table exists, and only known
// fields take part in duplicate detection (an unknown key is left for the
// typed decoder to reject).
var reviewScanPolicy = specPolicy{
	topObject:          "review spec",
	known:              fieldTable(reviewFields...),
	rejectExactUnknown: false,
	firstTokenError: func(err error) error {
		if errors.Is(err, io.EOF) {
			return errors.New("review spec must be a JSON object, got empty input")
		}
		return fmt.Errorf("invalid review spec: %w", err)
	},
	nonObject: func(tok json.Token) error {
		if tok == nil {
			return errors.New("review spec must be a single JSON object, got null")
		}
		if d, ok := tok.(json.Delim); ok && d == '[' {
			return errors.New("review spec must be a single JSON object, got array")
		}
		return fmt.Errorf("review spec must be a single JSON object, got %s", jsonTokenName(tok))
	},
	wrap: func(err error) error {
		return fmt.Errorf("invalid review spec: %w", err)
	},
	duplicate: func(_ string, canonical, first, spelling string) error {
		return fmt.Errorf("invalid review spec: duplicate field %q (declared as %q and %q)", canonical, first, spelling)
	},
	trailing: reviewTrailingData,
}

// reviewTrailingData names the first non-whitespace byte after the closed
// object, so an unmatched '}' or ']' is reported as trailing content rather
// than as a syntax error; only whitespace may follow the object.
func reviewTrailingData(raw []byte, offset int) error {
	rest := bytes.TrimLeft(raw[offset:], " \t\n\r")
	if len(rest) > 0 {
		return fmt.Errorf("%w: %s after closing object", ErrReviewTrailingData, trailingTokenName(rest[0]))
	}
	return nil
}

// validateReviewDocument proves raw holds exactly one complete JSON object
// — leading and trailing whitespace is fine, but empty input, whitespace
// only, arrays, null, scalars and unclosed objects are not — and that no
// byte other than whitespace follows the closing brace. Inside the object
// every known field may be declared at most once: field names are compared
// after JSON unescaping with the decoder's own field-name folding, so two
// spellings that resolve to the same field — differing only in case, like
// status and STATUS, or in a compatibility character, like U+017F for s —
// count as one duplicate declaration even when both carry the same value,
// and the whole document is rejected rather than one value silently
// winning. Brackets inside string values are field content, not structure:
// the tokenizer only treats delimiters outside strings as object
// boundaries.
func validateReviewDocument(raw []byte) error {
	return scanJSONObject(raw, reviewScanPolicy)
}

// ParseReviewSubmission validates one submission document. The document
// must contain exactly one complete JSON object (leading and trailing
// spaces, tabs and newlines allowed): empty input, whitespace only, an
// array, null, any other standalone value or an unclosed object fail, and
// a second object or value, an unmatched } or ] or any other non-whitespace
// byte after the closing brace fails as trailing data — the valid prefix is
// never accepted on its own. Every supported field may be declared at most
// once: two declarations of the same field — under any spellings the
// decoder folds together, and even when both carry the same value or one
// carries null — are a duplicate and reject the whole document rather than
// letting a later value override an earlier one. Identity fields and
// operator/reason/submissionId must be non-empty, the status must be one of
// real, false_positive or unreviewed, expectedVersion must be a
// non-negative integer, and the kind must be a known conclusion kind.
func ParseReviewSubmission(raw []byte) (ReviewSubmission, error) {
	if err := validateReviewDocument(raw); err != nil {
		return ReviewSubmission{}, err
	}
	var spec reviewSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return ReviewSubmission{}, fmt.Errorf("invalid review spec: %w", err)
	}
	// A field the document never declares decodes as a nil pointer and
	// reaches the shared business check as the empty value. The document's
	// own missing-field error for that field precedes its content check, so
	// a blank-value violation on an undeclared field is reported as the
	// missing field instead.
	missing := map[string]bool{}
	value := func(field string, p *string) string {
		if p == nil {
			missing[field] = true
			return ""
		}
		return *p
	}
	sub := ReviewSubmission{
		ChainID:      value("chainId", spec.ChainID),
		BlockHash:    value("blockHash", spec.BlockHash),
		TxHash:       value("txHash", spec.TxHash),
		Kind:         value("kind", spec.Kind),
		SubmissionID: value("submissionId", spec.SubmissionID),
		Operator:     value("operator", spec.Operator),
		Reason:       value("reason", spec.Reason),
		Status:       value("status", spec.Status),
	}
	if spec.ExpectedVersion != nil {
		sub.ExpectedVersion = *spec.ExpectedVersion
	}
	if v := validateReviewSubmission(sub); v != nil {
		if v.rule == ruleBlankString && missing[v.field] {
			return ReviewSubmission{}, fmt.Errorf("%s is required (non-empty string)", v.field)
		}
		return ReviewSubmission{}, v.specError()
	}
	if spec.ExpectedVersion == nil {
		return ReviewSubmission{}, errors.New("expectedVersion is required (non-negative integer)")
	}
	return sub, nil
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
	if v := validateReviewSubmission(sub); v != nil {
		return SubmitReviewResult{}, v.submitError()
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

// rawVersionArchiveDoc mirrors the archive file the way a review-range
// evaluation reads it: records and reviews are fully decoded, but each
// registered version is kept as its raw stored document. A corrupt version
// entry — a wrong-typed field, say — then cannot break the read or
// masquerade as whole-archive corruption; it is judged on its own by
// intactVersion, so a corrupt sibling never contaminates an intact
// candidate or the built-in version.
type rawVersionArchiveDoc struct {
	Records  []record          `json:"records"`
	Versions []json.RawMessage `json:"versions"`
	Reviews  []ReviewObject    `json:"reviews"`
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
// never modified. An empty range yields zero counts and an empty list. The
// named candidate's stored document must still satisfy the registration
// rules in full — both rules declared with non-null, well-typed, in-range
// parameters, including a rule explicitly disabled (enabled:false) — or the
// whole evaluation fails with ErrCorruptVersion before any judgment, even
// when the range contains no blocks; the corrupt content is never replaced
// by defaults, the currently enabled version or the built-in rules. A
// corrupt version the call does not name never blocks an intact candidate.
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

	// Decode with each registered version kept as its raw stored document,
	// so a wrong-typed field in one version is that version's corruption,
	// not whole-archive corruption, and the candidate's document can be
	// re-validated from its bytes the same way a single-block comparison
	// proves its version intact.
	raw, err := readArchiveBytes(dir)
	if err != nil {
		return ReviewEvaluation{}, err
	}
	var doc rawVersionArchiveDoc
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return ReviewEvaluation{}, fmt.Errorf("archive is corrupted: %w", err)
		}
	}
	// The requested version must be intact in the archive: re-validate its
	// stored document before judging anything, so a corrupt version fails
	// the same way even when the range matches no blocks, has no swaps or
	// carries no valid manual review.
	candidate, err := intactVersion(doc.Versions, versionID)
	if err != nil {
		return ReviewEvaluation{}, err
	}
	result.Version = candidate

	reviews := make(map[conclusionKey]*ReviewObject, len(doc.Reviews))
	for i := range doc.Reviews {
		reviews[doc.Reviews[i].key()] = &doc.Reviews[i]
	}

	details := []ReviewDetail{}
	for _, rec := range doc.Records {
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
