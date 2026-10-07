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
// separately as unsigned 64-bit integers.
type suppressionSpec struct {
	ID          *string `json:"id"`
	ChainID     *string `json:"chainId"`
	Pool        *string `json:"pool"`
	Kind        *string `json:"kind"`
	Channel     *string `json:"channel"`
	StartHeight *uint64 `json:"startHeight"`
	EndHeight   *uint64 `json:"endHeight"`
	Reason      *string `json:"reason"`
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

// suppressionFields lists every field name a registration document may
// declare, in the struct's JSON spelling.
var suppressionFields = []string{"id", "chainId", "pool", "kind", "channel", "startHeight", "endHeight", "reason"}

// suppressionScanPolicy validates the shape of a suppression document with
// the shared scanner. Unlike the version document, a suppression document
// is flat: nested values carry no field table of their own, and only known
// fields take part in duplicate detection (an unknown key is left for the
// typed decoder to reject).
var suppressionScanPolicy = specPolicy{
	topObject:          "suppression spec",
	known:              fieldTable(suppressionFields...),
	rejectExactUnknown: false,
	firstTokenError: func(err error) error {
		return fmt.Errorf("invalid suppression spec: %w", err)
	},
	nonObject: func(json.Token) error {
		return errors.New("invalid suppression spec: expected a single JSON object")
	},
	wrap: func(err error) error {
		return fmt.Errorf("invalid suppression spec: %w", err)
	},
	duplicate: func(_ string, canonical, first, spelling string) error {
		return fmt.Errorf("invalid suppression spec: duplicate field %q (declared as %q and %q)", canonical, first, spelling)
	},
	trailing: suppressionTrailingData,
}

// validateSuppressionDocument checks the raw registration input
// structurally before any field is read: it must hold exactly one complete
// JSON object — leading and trailing whitespace is fine, but empty input,
// arrays, null, scalars and incomplete objects are not, and no byte other
// than whitespace may follow the closing brace (a second object, an extra
// } or ] or any other JSON value is rejected). Inside the object every
// known field may be declared at most once: field names are compared after
// JSON unescaping with the decoder's own field-name folding, and two
// spellings that resolve to the same field — differing only in case, like
// channel and CHANNEL, or in a compatibility character, like U+017F for
// s — count as one duplicate declaration even when both carry the same
// value.
func validateSuppressionDocument(raw []byte) error {
	return scanJSONObject(raw, suppressionScanPolicy)
}

// suppressionTrailingData mirrors decoding one more value after the
// object: the only legal remainder is whitespace, which reports io.EOF;
// a second value or an unmatched bracket yields any other error and is
// trailing data.
func suppressionTrailingData(raw []byte, offset int) error {
	dec := json.NewDecoder(bytes.NewReader(raw[offset:]))
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("invalid suppression spec: unexpected trailing data")
	}
	return nil
}

// ParseSuppression validates one registration document. Only sandwich and
// displacement kinds exist, every text field must be non-empty, heights are
// unsigned 64-bit integers and the start height must not exceed the end
// height.
func ParseSuppression(raw []byte) (Suppression, error) {
	if err := validateSuppressionDocument(raw); err != nil {
		return Suppression{}, err
	}
	var spec suppressionSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return Suppression{}, fmt.Errorf("invalid suppression spec: %w", err)
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

// alertRecord mirrors one archived record the way alert generation reads
// and writes it: every business field is decoded normally, but the embedded
// rule-version declaration is kept as its raw stored document — the same
// shape a report query keeps it in. The decoded struct cannot tell a
// missing field, an explicit null or a wrong-typed value from a real one,
// so decoding the version into the struct would process a decayed report
// under silently zeroed parameters (enabled false, severity 0, a zero
// displacement multiplier) or explain a null declaration as the built-in
// rules. A wholly absent "version" key is the only legacy shape; anything
// actually saved is kept byte for byte and re-validated before the report's
// conclusions are processed, and written back unchanged.
type alertRecord struct {
	ChainID     string          `json:"chainId"`
	BlockHash   string          `json:"blockHash"`
	BlockNumber int64           `json:"blockNumber"`
	Swaps       []Swap          `json:"swaps"`
	Findings    []ReportFinding `json:"findings"`
	Version     json.RawMessage `json:"version,omitempty"`
}

// alertArchiveDoc mirrors the archive file the way alert generation reads
// and writes it: records keep their embedded version declarations as raw
// stored documents, and registered versions are kept raw too — generation
// never consults the registry, so a corrupt registered version is that
// version's damage, not whole-archive corruption, and is written back byte
// for byte. Suppressions, processing records and reviews are decoded fully.
type alertArchiveDoc struct {
	Records        []alertRecord      `json:"records"`
	Versions       []json.RawMessage  `json:"versions,omitempty"`
	EnabledVersion string             `json:"enabledVersion,omitempty"`
	Suppressions   []Suppression      `json:"suppressions,omitempty"`
	AlertRecords   []ProcessingRecord `json:"alerts,omitempty"`
	Reviews        []ReviewObject     `json:"reviews,omitempty"`
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
//
// Every archived report in the range must still carry an intact version
// declaration — the same proof a report query demands, re-validated from
// the raw stored document with the parser registrations pass. A missing or
// null field or rule object, a wrong type, an out-of-range number, an
// unknown field or rule, or a field declared twice in one object makes the
// whole generation fail with ErrCorruptVersion naming the chain, the block,
// the readable saved version id and the offending rule or field — even when
// that report has no conclusions, every conclusion is below the threshold,
// or every conclusion was already processed. Only an old-format record with
// no "version" key at all keeps the built-in interpretation; an explicit
// null, an empty object or a partial declaration is corruption, and an id
// of "builtin" is validated like any other. A legal declaration is used
// exactly as saved: parameters are never completed from the enabled or a
// registered version, and the id need not still be registered. A failed
// generation changes nothing: reports, existing processing records and
// suppressions are all left untouched.
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

	// Decode with each record's embedded version declaration kept as its
	// raw stored document, the same shape a report query uses: a decayed
	// declaration is that report's corruption, judged on its own below,
	// rather than whole-archive corruption or silently zeroed parameters.
	raw, err := readArchiveBytes(dir)
	if err != nil {
		return nil, err
	}
	data := alertArchiveDoc{Records: []alertRecord{}}
	if raw != nil {
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("archive is corrupted: %w", err)
		}
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
		// Prove the saved declaration before any of the report's
		// conclusions is processed — and even when none would be. A wholly
		// absent version key is the only legacy shape and means builtin;
		// every declaration that was actually written must stand on its
		// own, and a corrupt one fails the whole generation before
		// anything is written.
		version, err := archivedReportVersion(rec.Version)
		if err != nil {
			return nil, corruptReportError(chainID, rec.BlockHash, rec.Version, err)
		}
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
//
// Before any judgment about the submitted condition — and therefore before
// a new condition is appended, an identical retry is reported or a conflict
// returned — every archived report's saved version declaration is
// re-validated from its raw bytes with the exact integrity proof a report
// query enforces: a non-empty version identifier, both the sandwich and
// displacement rules each with a boolean enabled and an integer severity
// 1-5, and a displacement multiplier 2-100. A missing or null field or rule
// object, a wrong type, an out-of-range number, an unknown field or rule, or
// a field declared twice in one object (an exact repeat, an escaped spelling
// or a case-only spelling naming the same field, even with identical values)
// makes the saved declaration corrupt; an explicit enabled:false is a legal
// off state but the disabled rule still has to carry complete, in-range
// parameters. Only an old-format record with no "version" key at all keeps
// the built-in interpretation: a written null, an empty object or a partial
// declaration is corruption, and an id of "builtin" is validated like every
// other id rather than bypassing the check. The proof covers every report
// in the archive, not just ones on the new condition's chain, pool or height
// range, and a report without conclusions is opened too; a legal
// declaration is used exactly as saved, never completed from defaults, the
// currently enabled or a same-id registered version, and its id need not
// still be registered.
//
// The reason the proof gates registration is that a successful registration
// rewrites the archive: decoding the embedded declarations into structs
// would let that save change history. A written null would resurface as a
// wholly absent version key — the one legacy shape a later report query
// explains with the built-in rules, masking what should read as corruption
// — and a partial declaration as silently zeroed parameters. Records are
// therefore kept as their raw stored documents and written back byte for
// byte, and any corrupt report fails the whole registration with
// ErrCorruptVersion naming the chain and block of the damaged report, the
// readable saved version id and the offending rule or field. On failure no
// condition is added and the archive — the original nulls, missing fields
// and repeated declarations included — is left exactly as it was. A
// successful registration only appends the one condition: report
// conclusions, swap evidence, the versions registry, other conditions,
// existing processing records and review history are written back
// unchanged.
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

	// Decode with every stored record and registered version kept as its
	// raw stored document, the same shape a revocation and a replay read and
	// write. Decoding the embedded declarations into structs would let the
	// save below rewrite history: a written null would resurface as a
	// wholly absent version key — the one legacy shape — and a partial
	// declaration as silently zeroed parameters. Kept raw, every report is
	// written back byte for byte and judged from its own bytes first.
	archiveRaw, rerr := readArchiveBytes(dir)
	if rerr != nil {
		return Suppression{}, false, rerr
	}
	data := replayArchiveDoc{Records: []json.RawMessage{}}
	if archiveRaw != nil {
		if err := json.Unmarshal(archiveRaw, &data); err != nil {
			return Suppression{}, false, fmt.Errorf("archive is corrupted: %w", err)
		}
	}
	// Prove every archived report before anything is decided about the
	// submitted condition: a corrupt report fails the whole registration
	// here, before an append, an identical-retry no-op or a conflict
	// judgment, and nothing is written. Every report is opened — one on
	// another chain, outside the condition's coverage or without
	// conclusions is not skipped.
	if err := proveAllReportsIntact(data); err != nil {
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
// Once the condition is found, every archived report's saved version
// declaration is re-validated from its raw bytes with the exact integrity
// proof a report query enforces — a non-empty version identifier, both the
// sandwich and displacement rules each with a boolean enabled and an
// integer severity 1-5, and a displacement multiplier 2-100 — before the
// revocation is committed or an already-revoked state is reported. A
// missing or null field or rule object, a wrong type, an out-of-range
// number, an unknown field or rule, or a field declared twice in one object
// (an exact repeat, an escaped spelling or a case-only spelling naming the
// same field, even with identical values) makes the saved declaration
// corrupt; an explicit enabled:false is a legal off state but the disabled
// rule still has to carry complete, in-range parameters. Only an old-format
// record with no "version" key at all keeps the built-in interpretation: a
// written null, an empty object or a partial declaration is corruption, and
// an id of "builtin" is validated like every other id rather than bypassing
// the check. The proof covers every report in the archive — a report on
// another chain, outside the condition's coverage or carrying no
// conclusions is never skipped — and a legal declaration is used exactly as
// saved, never completed from defaults, the currently enabled or a same-id
// registered version.
//
// On corruption the whole revocation fails with ErrCorruptVersion naming
// the chain and block of the damaged report, the readable saved version id
// and the offending rule or field: no result is produced and the archive —
// every condition's revoked state included — is left byte for byte
// untouched, so a written null can never be dropped into a missing version
// key by the save. A failed revocation rewrites nothing, and a successful
// one changes only the target condition's state: reports, swap evidence,
// other conditions, existing processing records and review history are
// written back unchanged.
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

	// Decode with every stored record and registered version kept as its
	// raw stored document, the same shape a replay or a review submission
	// reads and writes. Decoding the embedded declarations into structs
	// would let the save below rewrite history: a written null would
	// resurface as a wholly absent version key — the one legacy shape —
	// and a partial declaration as silently zeroed parameters. Kept raw,
	// every report is written back byte for byte and judged from its own
	// bytes instead.
	raw, rerr := readArchiveBytes(dir)
	if rerr != nil {
		return Suppression{}, false, rerr
	}
	data := replayArchiveDoc{Records: []json.RawMessage{}}
	if raw != nil {
		if err := json.Unmarshal(raw, &data); err != nil {
			return Suppression{}, false, fmt.Errorf("archive is corrupted: %w", err)
		}
	}
	for i := range data.Suppressions {
		if data.Suppressions[i].ID != id {
			continue
		}
		// The condition is registered: prove every archived report's saved
		// declaration before the revocation is committed or an
		// already-revoked state is reported, so the state change never
		// rewrites — and thereby repairs or further decays — a damaged
		// report, and an idempotent re-revoke cannot mask existing damage.
		// Every report is opened: one on another chain, outside the
		// condition's coverage or without conclusions is not skipped. A
		// wholly absent version key is the only legacy shape and means
		// builtin; anything actually saved must stand on its own, and a
		// corrupt one fails the whole revocation here, before anything is
		// written.
		if err := proveAllReportsIntact(data); err != nil {
			return Suppression{}, false, err
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
