package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"syscall"
)

// Conclusion kinds that suppression conditions can match.
const (
	KindSandwich     = "sandwich"
	KindDisplacement = "displacement"
)

// Processing statuses of one conclusion for one channel.
const (
	StatusAlerted    = "alerted"
	StatusSuppressed = "suppressed"
)

// ErrSuppressionConflict reports a registration of an existing suppression
// id with different content.
var ErrSuppressionConflict = errors.New("suppression id already registered with different content")

// Suppression is a condition that suppresses matching conclusions instead
// of alerting them. Every field is an exact match against the conclusion;
// the victim's pool is taken from its original swap record. The height
// interval is inclusive at both ends.
type Suppression struct {
	ID      string `json:"id"`
	ChainID string `json:"chainId"`
	Pool    string `json:"pool"`
	Kind    string `json:"kind"`
	Channel string `json:"channel"`
	Start   int64  `json:"start"`
	End     int64  `json:"end"`
	Reason  string `json:"reason"`
}

// SuppressionHit records one condition that matched a conclusion, with the
// reason archived at generation time.
type SuppressionHit struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// AlertRecord is one processed conclusion for one channel. It stores the
// full block identity, the victim pool, the conclusion, the raw swap
// evidence, the detection version and parameters, the severity threshold
// applied at generation time, and every suppression condition that hit.
type AlertRecord struct {
	ChainID      string           `json:"chainId"`
	BlockHash    string           `json:"blockHash"`
	BlockNumber  int64            `json:"blockNumber"`
	Pool         string           `json:"pool"`
	TxHash       string           `json:"txHash"`
	Kind         string           `json:"kind"`
	Severity     int              `json:"severity"`
	Evidence     []Swap           `json:"evidence"`
	Version      RuleVersion      `json:"version"`
	MinSeverity  int              `json:"minSeverity"`
	Channel      string           `json:"channel"`
	Status       string           `json:"status"`
	SuppressedBy []SuppressionHit `json:"suppressedBy"`
}

// alertKey identifies one processing record: the same chain, block hash,
// victim transaction, conclusion kind and channel is processed at most
// once.
type alertKey struct {
	chainID   string
	blockHash string
	txHash    string
	kind      string
	channel   string
}

func (a AlertRecord) key() alertKey {
	return alertKey{a.ChainID, a.BlockHash, a.TxHash, a.Kind, a.Channel}
}

// sortAlerts orders processing records by height, block hash, transaction
// hash and kind, all ascending. Generation and query share this order.
func sortAlerts(alerts []AlertRecord) {
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].BlockNumber != alerts[j].BlockNumber {
			return alerts[i].BlockNumber < alerts[j].BlockNumber
		}
		if alerts[i].BlockHash != alerts[j].BlockHash {
			return alerts[i].BlockHash < alerts[j].BlockHash
		}
		if alerts[i].TxHash != alerts[j].TxHash {
			return alerts[i].TxHash < alerts[j].TxHash
		}
		return alerts[i].Kind < alerts[j].Kind
	})
}

// validateHeightBounds checks an inclusive, non-negative 64-bit height
// interval with start not above end.
func validateHeightBounds(start, end int64) error {
	if start < 0 || end < 0 {
		return fmt.Errorf("height bounds must be non-negative, got [%d, %d]", start, end)
	}
	if start > end {
		return fmt.Errorf("start height %d must not exceed end height %d", start, end)
	}
	return nil
}

// victimPool returns the pool of the victim transaction's original swap
// record. The canonical swaps are consulted first; the raw evidence swap
// is the same record and is used as a fallback. A finding whose victim
// appears nowhere is inconsistent archive data.
func victimPool(rec record, f ReportFinding) (string, error) {
	for _, s := range rec.Swaps {
		if s.TxHash == f.TxHash {
			return s.Pool, nil
		}
	}
	for _, s := range f.Evidence {
		if s.TxHash == f.TxHash {
			return s.Pool, nil
		}
	}
	return "", fmt.Errorf("archive is corrupted: finding %s/%s (%s) has no swap record",
		rec.ChainID, rec.BlockHash, f.TxHash)
}

// matchSuppressions returns all conditions that exactly match the
// conclusion's chain, pool, kind and channel and whose inclusive height
// interval covers the event height. Hits are sorted by condition id.
func matchSuppressions(conds []Suppression, chainID, pool, kind, channel string, height int64) []SuppressionHit {
	var hits []SuppressionHit
	for _, c := range conds {
		if c.ChainID == chainID && c.Pool == pool && c.Kind == kind && c.Channel == channel &&
			c.Start <= height && height <= c.End {
			hits = append(hits, SuppressionHit{ID: c.ID, Reason: c.Reason})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].ID < hits[j].ID })
	return hits
}

// GenerateAlerts turns the archived conclusions of one chain and height
// range into processing records for one channel. It never re-detects:
// conclusions are read from the archived reports as-is. Only conclusions
// whose severity is at least minSeverity are considered (equal counts as
// a hit); lower-severity conclusions leave no processing record, so a
// later, lower threshold can still issue them.
//
// A conclusion already processed for the channel — alerted or suppressed,
// under any threshold, version or height range — is never processed again.
// New records are committed together in one atomic write; the returned
// slice holds only the records created by this call, sorted by height,
// block hash, transaction hash and kind.
func GenerateAlerts(dir, chainID string, start, end int64, minSeverity int, channel string) ([]AlertRecord, error) {
	if chainID == "" {
		return nil, errors.New("chainId must be a non-empty string")
	}
	if channel == "" {
		return nil, errors.New("channel must be a non-empty string")
	}
	if minSeverity < 1 || minSeverity > 5 {
		return nil, fmt.Errorf("minSeverity must be between 1 and 5, got %d", minSeverity)
	}
	if err := validateHeightBounds(start, end); err != nil {
		return nil, err
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

	existing := make(map[alertKey]bool, len(data.Alerts))
	for _, a := range data.Alerts {
		existing[a.key()] = true
	}

	added := []AlertRecord{}
	batch := make(map[alertKey]bool)
	for _, rec := range data.Records {
		if rec.ChainID != chainID || rec.BlockNumber < start || rec.BlockNumber > end {
			continue
		}
		for _, f := range rec.Findings {
			if f.Severity < minSeverity {
				continue
			}
			k := alertKey{rec.ChainID, rec.BlockHash, f.TxHash, f.Kind, channel}
			if existing[k] || batch[k] {
				continue
			}
			pool, err := victimPool(rec, f)
			if err != nil {
				return nil, err
			}
			hits := matchSuppressions(data.Suppressions, rec.ChainID, pool, f.Kind, channel, rec.BlockNumber)
			if hits == nil {
				hits = []SuppressionHit{}
			}
			status := StatusAlerted
			if len(hits) > 0 {
				status = StatusSuppressed
			}
			evidence := f.Evidence
			if evidence == nil {
				evidence = []Swap{}
			}
			added = append(added, AlertRecord{
				ChainID:      rec.ChainID,
				BlockHash:    rec.BlockHash,
				BlockNumber:  rec.BlockNumber,
				Pool:         pool,
				TxHash:       f.TxHash,
				Kind:         f.Kind,
				Severity:     f.Severity,
				Evidence:     evidence,
				Version:      rec.ruleVersion(),
				MinSeverity:  minSeverity,
				Channel:      channel,
				Status:       status,
				SuppressedBy: hits,
			})
			batch[k] = true
		}
	}
	if len(added) == 0 {
		return []AlertRecord{}, nil
	}
	data.Alerts = append(data.Alerts, added...)
	sortAlerts(data.Alerts)
	if err := writeArchiveAtomic(dir, data); err != nil {
		return nil, err
	}
	out := append([]AlertRecord(nil), added...)
	sortAlerts(out)
	return out, nil
}

// QueryAlerts returns the processing records for one chain and channel
// within the inclusive height range, sorted by height, block hash,
// transaction hash and kind. It only reads the archive. An empty result
// is an empty array, never nil. Later-registered suppression conditions
// do not change the returned history.
func QueryAlerts(dir, chainID, channel string, start, end int64) ([]AlertRecord, error) {
	if chainID == "" {
		return nil, errors.New("chainId must be a non-empty string")
	}
	if channel == "" {
		return nil, errors.New("channel must be a non-empty string")
	}
	if err := validateHeightBounds(start, end); err != nil {
		return nil, err
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return []AlertRecord{}, nil
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
	out := []AlertRecord{}
	for _, a := range data.Alerts {
		if a.ChainID == chainID && a.Channel == channel && a.BlockNumber >= start && a.BlockNumber <= end {
			if a.SuppressedBy == nil {
				a.SuppressedBy = []SuppressionHit{}
			}
			out = append(out, a)
		}
	}
	sortAlerts(out)
	return out, nil
}

// suppressionSpec mirrors the registration JSON. Pointers distinguish a
// missing field from an explicit zero value, and the decoder rejects
// unknown fields.
type suppressionSpec struct {
	ID      *string `json:"id"`
	ChainID *string `json:"chainId"`
	Pool    *string `json:"pool"`
	Kind    *string `json:"kind"`
	Channel *string `json:"channel"`
	Start   *int64  `json:"start"`
	End     *int64  `json:"end"`
	Reason  *string `json:"reason"`
}

// ParseSuppression validates a suppression registration document. Missing
// fields, wrong types, empty names, unknown kinds, out-of-range heights
// and unknown fields all fail with a reason.
func ParseSuppression(raw []byte) (Suppression, error) {
	var spec suppressionSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return Suppression{}, fmt.Errorf("invalid suppression spec: %w", err)
	}
	if dec.More() {
		return Suppression{}, errors.New("invalid suppression spec: unexpected trailing data")
	}
	if spec.ID == nil || *spec.ID == "" {
		return Suppression{}, errors.New("id must be a non-empty string")
	}
	if spec.ChainID == nil || *spec.ChainID == "" {
		return Suppression{}, errors.New("chainId must be a non-empty string")
	}
	if spec.Pool == nil || *spec.Pool == "" {
		return Suppression{}, errors.New("pool must be a non-empty string")
	}
	if spec.Kind == nil || (*spec.Kind != KindSandwich && *spec.Kind != KindDisplacement) {
		return Suppression{}, fmt.Errorf("kind must be %q or %q", KindSandwich, KindDisplacement)
	}
	if spec.Channel == nil || *spec.Channel == "" {
		return Suppression{}, errors.New("channel must be a non-empty string")
	}
	if spec.Start == nil {
		return Suppression{}, errors.New("start is required (non-negative integer)")
	}
	if spec.End == nil {
		return Suppression{}, errors.New("end is required (non-negative integer)")
	}
	if err := validateHeightBounds(*spec.Start, *spec.End); err != nil {
		return Suppression{}, err
	}
	if spec.Reason == nil || *spec.Reason == "" {
		return Suppression{}, errors.New("reason must be a non-empty string")
	}
	return Suppression{
		ID:      *spec.ID,
		ChainID: *spec.ChainID,
		Pool:    *spec.Pool,
		Kind:    *spec.Kind,
		Channel: *spec.Channel,
		Start:   *spec.Start,
		End:     *spec.End,
		Reason:  *spec.Reason,
	}, nil
}

// RegisterSuppression validates raw as a suppression condition and stores
// it in the archive. Re-registering the same id with identical content
// succeeds without adding a condition (created is false); the same id
// with different content is rejected. Conditions only affect conclusions
// processed after registration. Any failure leaves the archive untouched.
func RegisterSuppression(dir string, raw []byte) (s Suppression, created bool, err error) {
	s, err = ParseSuppression(raw)
	if err != nil {
		return Suppression{}, false, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Suppression{}, false, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return Suppression{}, false, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return Suppression{}, false, err
	}
	for _, existing := range data.Suppressions {
		if existing.ID == s.ID {
			if existing == s {
				return existing, false, nil
			}
			return Suppression{}, false, fmt.Errorf("%w: %s", ErrSuppressionConflict, s.ID)
		}
	}
	data.Suppressions = append(data.Suppressions, s)
	sort.Slice(data.Suppressions, func(i, j int) bool {
		return data.Suppressions[i].ID < data.Suppressions[j].ID
	})
	if err := writeArchiveAtomic(dir, data); err != nil {
		return Suppression{}, false, err
	}
	return s, true, nil
}

// ListSuppressions returns every registered condition, sorted by id.
func ListSuppressions(dir string) ([]Suppression, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return []Suppression{}, nil
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
	return out, nil
}
