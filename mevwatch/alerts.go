package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Offline alerting turns conclusions already stored in an archive into
// alert processing records. It never re-runs detection: a record always
// reflects the finding, the rule version and the parameters that were in
// force when the block was archived.

// Alert statuses. A finding above the generation threshold becomes an
// "alert"; a finding that matches one or more registered suppression
// conditions at its block height becomes "suppressed" instead.
const (
	AlertStatusAlert      = "alert"
	AlertStatusSuppressed = "suppressed"
)

// Suppression condition kinds.
const (
	SuppressSandwich     = "sandwich"
	SuppressDisplacement = "displacement"
)

// ErrUnknownKind reports a conclusion/condition kind that is neither
// sandwich nor displacement.
var ErrUnknownKind = errors.New("unknown kind")

// ErrSuppressionConflict reports re-registering an existing suppression ID
// with different content.
var ErrSuppressionConflict = errors.New("suppression already registered with different content")

// ErrUnknownSuppression reports revoking a condition ID that is not
// registered in the archive (including the empty archive).
var ErrUnknownSuppression = errors.New("unknown suppression condition")

// SuppressionHit records one suppression condition that matched an event.
type SuppressionHit struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// ProcessingRecord is one fully resolved alerting outcome. Its identity is
// (chain, block hash, victim tx hash, conclusion kind, channel): once a
// record exists for that identity, no later import, wider or overlapping
// height range, rule-version switch or restart can produce it again. The
// record keeps the complete block identity, pool, conclusion, raw swap
// evidence, the detection version and its parameters, the threshold used at
// generation time, and every suppression condition that matched.
type ProcessingRecord struct {
	ChainID      string           `json:"chainId"`
	BlockHash    string           `json:"blockHash"`
	BlockNumber  uint64           `json:"blockNumber"`
	Pool         string           `json:"pool"`
	Channel      string           `json:"channel"`
	Finding      ReportFinding    `json:"finding"`
	Version      RuleVersion      `json:"version"`
	MinSeverity  int              `json:"minSeverity"`
	Status       string           `json:"status"`
	Suppressions []SuppressionHit `json:"suppressions"`
}

func (r ProcessingRecord) identity() alertKey {
	return alertKey{
		chainID:   r.ChainID,
		blockHash: r.BlockHash,
		txHash:    r.Finding.TxHash,
		kind:      r.Finding.Kind,
		channel:   r.Channel,
	}
}

// Suppression is one registered suppression condition. Every field matches
// exactly (the pool is matched against the pool of the victim swap's
// original exchange record), and an event at height h is covered when
// StartHeight <= h <= EndHeight.
//
// Revoked marks a condition whose user has withdrawn it. A revoked
// condition is kept for audit but never matches later processing; the
// field is always serialized (an absent value in an old archive decodes
// to false, i.e. not revoked) and cannot be set through a registration
// document. Revocation applies to findings processed afterwards only —
// event height never decides when it takes effect.
type Suppression struct {
	ID          string `json:"id"`
	ChainID     string `json:"chainId"`
	Pool        string `json:"pool"`
	Kind        string `json:"kind"`
	Channel     string `json:"channel"`
	StartHeight uint64 `json:"startHeight"`
	EndHeight   uint64 `json:"endHeight"`
	Reason      string `json:"reason"`
	Revoked     bool   `json:"revoked"`
}

// covers reports whether the suppression applies to an event on chain at
// height in the given pool/kind/channel. Matching depends only on the
// event's height, never on operation time, import order or the archive's
// highest block.
func (s Suppression) covers(chainID, pool, kind, channel string, height uint64) bool {
	return s.ChainID == chainID && s.Pool == pool && s.Kind == kind && s.Channel == channel &&
		s.StartHeight <= height && height <= s.EndHeight
}

// alertKey is the deduplication identity of a processing record.
type alertKey struct {
	chainID   string
	blockHash string
	txHash    string
	kind      string
	channel   string
}

// suppressionSpec mirrors one suppression registration document. Pointers
// distinguish missing fields from explicit zero values; heights are parsed
// separately as unsigned 64-bit integers. The struct is filled by
// parseSuppressionSpec, never by encoding/json directly, so duplicate and
// case-variant field declarations can be rejected instead of silently
// overwritten.
type suppressionSpec struct {
	ID          *string
	ChainID     *string
	Pool        *string
	Kind        *string
	Channel     *string
	StartHeight *uint64
	EndHeight   *uint64
	Reason      *string
}

// suppressionFields lists the canonical registration field names. Field
// names in a document are matched against these case-insensitively (the
// same compatibility encoding/json's struct decoding offered), after JSON
// string unescaping.
var suppressionFields = []string{
	"id", "chainId", "pool", "kind", "channel", "startHeight", "endHeight", "reason",
}

// canonicalSuppressionField resolves a document field name to its canonical
// registration field, or "" when the field is unknown (this includes
// "revoked", which a registration document can never set).
func canonicalSuppressionField(key string) string {
	for _, name := range suppressionFields {
		if strings.EqualFold(key, name) {
			return name
		}
	}
	return ""
}

// decodeSuppressionField decodes one field value into the spec.
func decodeSuppressionField(dec *json.Decoder, spec *suppressionSpec, field string) error {
	switch field {
	case "id":
		return dec.Decode(&spec.ID)
	case "chainId":
		return dec.Decode(&spec.ChainID)
	case "pool":
		return dec.Decode(&spec.Pool)
	case "kind":
		return dec.Decode(&spec.Kind)
	case "channel":
		return dec.Decode(&spec.Channel)
	case "startHeight":
		return dec.Decode(&spec.StartHeight)
	case "endHeight":
		return dec.Decode(&spec.EndHeight)
	case "reason":
		return dec.Decode(&spec.Reason)
	}
	return fmt.Errorf("unhandled field %q", field)
}

// parseSuppressionSpec decodes raw as exactly one complete JSON object.
// Leading and trailing whitespace is allowed; anything else after the
// closing brace — an extra delimiter, a second object, any other value — is
// a trailing-data error. Empty input, arrays, null, scalars and incomplete
// objects are rejected, as is every field declared twice, even with an
// identical value or under a different-but-equivalent spelling (case
// variants, escape sequences). A duplicate is reported by canonical field
// name so it cannot be confused with a trailing-data error or with a
// conflict against an already registered condition.
func parseSuppressionSpec(raw []byte) (suppressionSpec, error) {
	var spec suppressionSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return spec, fmt.Errorf("invalid suppression spec: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return spec, errors.New("invalid suppression spec: want a single JSON object")
	}
	seen := make(map[string]string, len(suppressionFields))
	for dec.More() {
		ktok, err := dec.Token()
		if err != nil {
			return spec, fmt.Errorf("invalid suppression spec: %w", err)
		}
		key, ok := ktok.(string)
		if !ok {
			return spec, errors.New("invalid suppression spec: object key must be a string")
		}
		field := canonicalSuppressionField(key)
		if field == "" {
			return spec, fmt.Errorf("invalid suppression spec: unknown field %q", key)
		}
		if first, dup := seen[field]; dup {
			return spec, fmt.Errorf("invalid suppression spec: duplicate field %q (first declared as %q)", field, first)
		}
		seen[field] = key
		if err := decodeSuppressionField(dec, &spec, field); err != nil {
			return spec, fmt.Errorf("invalid suppression spec: field %q: %w", field, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return spec, fmt.Errorf("invalid suppression spec: %w", err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return spec, fmt.Errorf("invalid suppression spec: unexpected trailing data after the JSON object (%v)", tok)
		}
		return spec, fmt.Errorf("invalid suppression spec: unexpected trailing data after the JSON object: %w", err)
	}
	return spec, nil
}

func nonEmpty(field string, v *string) (string, error) {
	if v == nil {
		return "", fmt.Errorf("%s is required (non-empty string)", field)
	}
	if strings.TrimSpace(*v) == "" {
		return "", fmt.Errorf("%s must be a non-empty string", field)
	}
	return *v, nil
}

// ParseSuppression validates one registration document. The document must
// be exactly one complete JSON object (surrounding whitespace allowed) with
// no trailing content and no field declared more than once. Only sandwich
// and displacement kinds exist, every text field must be non-empty, heights
// are unsigned 64-bit integers and the start height must not exceed the end
// height.
func ParseSuppression(raw []byte) (Suppression, error) {
	spec, err := parseSuppressionSpec(raw)
	if err != nil {
		return Suppression{}, err
	}
	id, err := nonEmpty("id", spec.ID)
	if err != nil {
		return Suppression{}, err
	}
	chainID, err := nonEmpty("chainId", spec.ChainID)
	if err != nil {
		return Suppression{}, err
	}
	pool, err := nonEmpty("pool", spec.Pool)
	if err != nil {
		return Suppression{}, err
	}
	kind, err := nonEmpty("kind", spec.Kind)
	if err != nil {
		return Suppression{}, err
	}
	if kind != SuppressSandwich && kind != SuppressDisplacement {
		return Suppression{}, fmt.Errorf("%w: %q (want sandwich or displacement)", ErrUnknownKind, kind)
	}
	channel, err := nonEmpty("channel", spec.Channel)
	if err != nil {
		return Suppression{}, err
	}
	if spec.StartHeight == nil {
		return Suppression{}, errors.New("startHeight is required (unsigned 64-bit integer)")
	}
	if spec.EndHeight == nil {
		return Suppression{}, errors.New("endHeight is required (unsigned 64-bit integer)")
	}
	if *spec.StartHeight > *spec.EndHeight {
		return Suppression{}, fmt.Errorf("startHeight %d must not exceed endHeight %d", *spec.StartHeight, *spec.EndHeight)
	}
	reason, err := nonEmpty("reason", spec.Reason)
	if err != nil {
		return Suppression{}, err
	}
	return Suppression{
		ID:          id,
		ChainID:     chainID,
		Pool:        pool,
		Kind:        kind,
		Channel:     channel,
		StartHeight: *spec.StartHeight,
		EndHeight:   *spec.EndHeight,
		Reason:      reason,
	}, nil
}

// ParseHeight parses a non-negative 64-bit integer height. Signs, fractions,
// blanks and values above 2^64-1 are rejected.
func ParseHeight(text string) (uint64, error) {
	if text == "" {
		return 0, errors.New("height must be a non-empty unsigned 64-bit integer")
	}
	h, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid height %q: %w", text, err)
	}
	return h, nil
}

// ValidateSeverity accepts the integer threshold range 1..5 inclusive; the
// threshold itself counts as a hit.
func ValidateSeverity(severity int) error {
	if severity < 1 || severity > 5 {
		return fmt.Errorf("minSeverity must be between 1 and 5, got %d", severity)
	}
	return nil
}

// suppressionEqual reports whether two conditions carry identical
// registration content. Revoked state is intentionally excluded: retrying
// the same document is idempotent even after the condition was revoked
// (and never re-enables it), while differing content still conflicts.
func suppressionEqual(a, b Suppression) bool {
	return a.ID == b.ID &&
		a.ChainID == b.ChainID &&
		a.Pool == b.Pool &&
		a.Kind == b.Kind &&
		a.Channel == b.Channel &&
		a.StartHeight == b.StartHeight &&
		a.EndHeight == b.EndHeight &&
		a.Reason == b.Reason
}

// matchSuppressions returns every active condition covering the event,
// sorted by ID in lexicographic order so overlapping conditions are
// reported deterministically. Revoked conditions are skipped: they no
// longer apply to conclusions processed after the revocation.
func matchSuppressions(conds []Suppression, chainID, pool, kind, channel string, height uint64) []SuppressionHit {
	hits := []SuppressionHit{}
	for _, s := range conds {
		if s.Revoked {
			continue
		}
		if s.covers(chainID, pool, kind, channel, height) {
			hits = append(hits, SuppressionHit{ID: s.ID, Reason: s.Reason})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	return hits
}

// victimPool returns the pool of the victim swap inside the finding's raw
// evidence. The victim is the swap whose TxHash matches the finding; the
// evidence ordering and count vary by conclusion kind, so the pool is read
// off the original exchange record rather than inferred from position.
func victimPool(f ReportFinding) (string, bool) {
	for _, s := range f.Evidence {
		if s.TxHash == f.TxHash {
			return s.Pool, true
		}
	}
	return "", false
}

// sortRecords orders processing records by height, block hash, tx hash and
// kind ascending. Channel stays out of the ordering key: generation runs for
// one channel, history may span several.
func sortRecords(records []ProcessingRecord) {
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.BlockNumber != b.BlockNumber {
			return a.BlockNumber < b.BlockNumber
		}
		if a.BlockHash != b.BlockHash {
			return a.BlockHash < b.BlockHash
		}
		if a.Finding.TxHash != b.Finding.TxHash {
			return a.Finding.TxHash < b.Finding.TxHash
		}
		return a.Finding.Kind < b.Finding.Kind
	})
}

// GenerateAlerts turns archived conclusions in the inclusive range
// [startHeight, endHeight] on chainID for channel into new processing
// records. Detection is not re-run: the archived finding, evidence and rule
// version are reused. A finding at least minSeverity is processed; findings
// below the threshold leave no record, so lowering the threshold later can
// still produce them. Every already-processed identity is skipped, which
// makes repeated imports, repeated generation, wider or overlapping ranges,
// version switches and restarts idempotent. Channels are independent, and
// blocks at the same height with different hashes are handled separately.
//
// All new records of one call are committed together or not at all. The
// returned slice contains only records created by this call (alerts and
// suppressions distinguished), sorted by height, block hash, tx hash and
// kind; an empty result serializes as [].
func GenerateAlerts(dir, chainID, channel string, startHeight, endHeight uint64, minSeverity int) ([]ProcessingRecord, error) {
	if strings.TrimSpace(chainID) == "" {
		return nil, errors.New("chainId must be a non-empty string")
	}
	if strings.TrimSpace(channel) == "" {
		return nil, errors.New("channel must be a non-empty name")
	}
	if err := ValidateSeverity(minSeverity); err != nil {
		return nil, err
	}
	if startHeight > endHeight {
		return nil, fmt.Errorf("startHeight %d must not exceed endHeight %d", startHeight, endHeight)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return nil, err
	}
	processed := make(map[alertKey]struct{}, len(data.AlertRecords))
	for _, r := range data.AlertRecords {
		processed[r.identity()] = struct{}{}
	}

	created := []ProcessingRecord{}
	for _, rec := range data.Records {
		if rec.ChainID != chainID {
			continue
		}
		height := uint64(rec.BlockNumber)
		if height < startHeight || height > endHeight {
			continue
		}
		version := rec.ruleVersion()
		for _, f := range rec.Findings {
			if f.Severity < minSeverity {
				// Below the threshold: no record is written, so the event
				// stays eligible after a later threshold reduction.
				continue
			}
			key := alertKey{
				chainID:   rec.ChainID,
				blockHash: rec.BlockHash,
				txHash:    f.TxHash,
				kind:      f.Kind,
				channel:   channel,
			}
			if _, ok := processed[key]; ok {
				continue
			}
			pool, ok := victimPool(f)
			if !ok {
				return nil, fmt.Errorf("archive is corrupted: archived finding for block %s/%s tx %s has no victim swap in its evidence",
					rec.ChainID, rec.BlockHash, f.TxHash)
			}
			hits := matchSuppressions(data.Suppressions, rec.ChainID, pool, f.Kind, channel, height)
			status := AlertStatusAlert
			if len(hits) > 0 {
				status = AlertStatusSuppressed
			}
			record := ProcessingRecord{
				ChainID:      rec.ChainID,
				BlockHash:    rec.BlockHash,
				BlockNumber:  height,
				Pool:         pool,
				Channel:      channel,
				Finding:      f,
				Version:      version,
				MinSeverity:  minSeverity,
				Status:       status,
				Suppressions: hits,
			}
			created = append(created, record)
			processed[key] = struct{}{}
		}
	}
	sortRecords(created)
	if len(created) > 0 {
		data.AlertRecords = append(data.AlertRecords, created...)
		if err := writeArchiveAtomic(dir, data); err != nil {
			return nil, err
		}
	}
	return created, nil
}

// AlertHistory returns stored processing records on chainID for channel in
// the inclusive range [startHeight, endHeight]. It only reads the archive;
// suppressions registered afterwards cannot alter the stored content.
func AlertHistory(dir, chainID, channel string, startHeight, endHeight uint64) ([]ProcessingRecord, error) {
	if strings.TrimSpace(chainID) == "" {
		return nil, errors.New("chainId must be a non-empty string")
	}
	if strings.TrimSpace(channel) == "" {
		return nil, errors.New("channel must be a non-empty name")
	}
	if startHeight > endHeight {
		return nil, fmt.Errorf("startHeight %d must not exceed endHeight %d", startHeight, endHeight)
	}
	if _, serr := os.Stat(dir); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return []ProcessingRecord{}, nil
		}
		return nil, serr
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return nil, err
	}
	out := []ProcessingRecord{}
	for _, r := range data.AlertRecords {
		if r.ChainID != chainID || r.Channel != channel {
			continue
		}
		if r.BlockNumber < startHeight || r.BlockNumber > endHeight {
			continue
		}
		out = append(out, r)
	}
	sortRecords(out)
	return out, nil
}

// RegisterSuppression validates raw and stores one suppression condition in
// the archive. Re-registering the same ID with identical content succeeds
// without adding anything (created is false) — this stays true after the
// condition was revoked and never re-enables it; the same ID with different
// content is rejected. New conditions only affect conclusions that have not
// been processed yet: historical alerts are never rewritten as suppressed,
// and suppressed records are not re-alerted when a condition's range ends.
// The registration document cannot set revoked state.
func RegisterSuppression(dir string, raw []byte) (s Suppression, created bool, err error) {
	s, err = ParseSuppression(raw)
	if err != nil {
		return Suppression{}, false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Suppression{}, false, err
	}
	lock, lerr := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if lerr != nil {
		return Suppression{}, false, lerr
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return Suppression{}, false, err
	}
	for _, existing := range data.Suppressions {
		if existing.ID == s.ID {
			if suppressionEqual(existing, s) {
				return existing, false, nil
			}
			return Suppression{}, false, fmt.Errorf("%w: %s", ErrSuppressionConflict, s.ID)
		}
	}
	data.Suppressions = append(data.Suppressions, s)
	if err := writeArchiveAtomic(dir, data); err != nil {
		return Suppression{}, false, err
	}
	return s, true, nil
}

// RevokeSuppression withdraws the condition with the given exact ID. The
// first successful revocation returns changed=true and the full condition
// with Revoked set; revoking the same ID again succeeds with changed=false.
// A blank ID is rejected, and an ID that was never registered — including
// any ID in an empty archive — returns ErrUnknownSuppression. The revoked
// condition is retained (still listed) but stops matching conclusions
// processed from now on; it cannot be revived, a fresh ID is required to
// suppress again.
//
// The revocation is committed atomically under the archive lock: a busy
// archive, a corrupted one or a failed save leaves every condition, report
// and processing record untouched. One generation run always sees either
// the pre- or the post-revocation condition set in full.
func RevokeSuppression(dir, id string) (s Suppression, changed bool, err error) {
	if strings.TrimSpace(id) == "" {
		return Suppression{}, false, errors.New("suppression id must be a non-empty string")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Suppression{}, false, err
	}
	lock, lerr := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if lerr != nil {
		return Suppression{}, false, lerr
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return Suppression{}, false, err
	}
	for i := range data.Suppressions {
		if data.Suppressions[i].ID != id {
			continue
		}
		if data.Suppressions[i].Revoked {
			return data.Suppressions[i], false, nil
		}
		data.Suppressions[i].Revoked = true
		if err := writeArchiveAtomic(dir, data); err != nil {
			return Suppression{}, false, err
		}
		return data.Suppressions[i], true, nil
	}
	return Suppression{}, false, fmt.Errorf("%w: %s", ErrUnknownSuppression, id)
}

// ListSuppressions returns every suppression condition stored in the
// archive, ordered by ID. A read on an absent archive returns an empty list.
func ListSuppressions(dir string) ([]Suppression, error) {
	if _, serr := os.Stat(dir); serr != nil {
		if errors.Is(serr, os.ErrNotExist) {
			return []Suppression{}, nil
		}
		return nil, serr
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return nil, err
	}
	out := append([]Suppression(nil), data.Suppressions...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if out == nil {
		out = []Suppression{}
	}
	return out, nil
}
