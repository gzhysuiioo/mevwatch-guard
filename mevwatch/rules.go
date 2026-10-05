package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"syscall"
)

// BuiltinVersionID identifies the built-in rule version, which reproduces
// the original fixed rules. It is always available, its parameters are
// queryable, and it cannot be overridden.
const BuiltinVersionID = "builtin"

// ErrUnknownVersion reports a reference to a rule version that was never
// registered in the archive.
var ErrUnknownVersion = errors.New("unknown version")

// ErrVersionConflict reports a re-registration of an existing version ID
// with different parameters.
var ErrVersionConflict = errors.New("version already registered with different parameters")

// ErrCorruptVersion reports a version whose stored archive document no
// longer satisfies the registration rules: a rule object or a required
// field is missing or null, a value has the wrong type, or a severity or
// multiplier is out of range. The decoded struct cannot tell a missing
// field from an explicit zero value, so such an archive would otherwise
// run under silently zeroed parameters (a zero displacement multiplier
// even crashes detection). A comparison, review-range evaluation or replay
// naming a corrupt version is refused; the corrupt content is never
// replaced by the enabled version, the built-in rules or defaults.
var ErrCorruptVersion = errors.New("archived rule version is corrupted")

// SandwichRule configures the sandwich rule: whether it runs and the
// severity of its conclusions.
type SandwichRule struct {
	Enabled  bool `json:"enabled"`
	Severity int  `json:"severity"`
}

// DisplacementRule configures the displacement rule. A victim is flagged
// only when the previous swap's GasPrice strictly exceeds Multiplier times
// the victim's.
type DisplacementRule struct {
	Enabled    bool `json:"enabled"`
	Severity   int  `json:"severity"`
	Multiplier int  `json:"multiplier"`
}

// RuleSet is the complete declaration of both detection rules. Every
// version must declare both rules in full.
type RuleSet struct {
	Sandwich     SandwichRule     `json:"sandwich"`
	Displacement DisplacementRule `json:"displacement"`
}

// RuleVersion is a named, immutable set of rule parameters.
type RuleVersion struct {
	ID    string  `json:"id"`
	Rules RuleSet `json:"rules"`
}

// BuiltinVersion returns the version representing the original fixed
// rules: sandwich severity 3, displacement severity 2 with multiplier 2.
func BuiltinVersion() RuleVersion {
	return RuleVersion{
		ID: BuiltinVersionID,
		Rules: RuleSet{
			Sandwich:     SandwichRule{Enabled: true, Severity: 3},
			Displacement: DisplacementRule{Enabled: true, Severity: 2, Multiplier: 2},
		},
	}
}

// toggleSpec and displacementSpec mirror the registration JSON. Pointers
// distinguish a missing field from an explicit zero value, and the decoder
// rejects unknown fields (including unknown rule names).
type toggleSpec struct {
	Enabled  *bool `json:"enabled"`
	Severity *int  `json:"severity"`
}

type displacementSpec struct {
	Enabled    *bool `json:"enabled"`
	Severity   *int  `json:"severity"`
	Multiplier *int  `json:"multiplier"`
}

type versionSpec struct {
	ID    *string `json:"id"`
	Rules *struct {
		Sandwich     *toggleSpec       `json:"sandwich"`
		Displacement *displacementSpec `json:"displacement"`
	} `json:"rules"`
}

func parseEnabled(name string, v *bool) (bool, error) {
	if v == nil {
		return false, fmt.Errorf("rules.%s.enabled is required (boolean)", name)
	}
	return *v, nil
}

func parseSeverity(name string, v *int) (int, error) {
	if v == nil {
		return 0, fmt.Errorf("rules.%s.severity is required (integer 1-5)", name)
	}
	if *v < 1 || *v > 5 {
		return 0, fmt.Errorf("rules.%s.severity must be between 1 and 5, got %d", name, *v)
	}
	return *v, nil
}

// ErrDuplicateField reports a JSON object in a registration spec that
// names the same field twice. Field names are compared the way JSON
// decoding matches struct fields, so two spellings the decoder folds
// together — differing only in case, like "severity" and "Severity", or
// using a compatibility character, like "ſeverity" (U+017F for s) — are
// also duplicates.
var ErrDuplicateField = errors.New("duplicate field in version spec")

// ErrTrailingData reports non-whitespace content after the single JSON
// object that makes up a registration spec: a second object, another
// JSON value, an unmatched bracket or any other character.
var ErrTrailingData = errors.New("unexpected trailing data after version spec")

// versionScanPolicy validates the shape of a rule version document with
// the shared scanner while keeping version-spec wording and sentinel
// errors.
var versionScanPolicy = specPolicy{
	topObject:          "version spec",
	known:              versionFields,
	nested:             versionNestedTables,
	rejectExactUnknown: true,
	firstTokenError: func(err error) error {
		if errors.Is(err, io.EOF) {
			return errors.New("version spec must be a JSON object, got empty input")
		}
		return fmt.Errorf("invalid version spec: %w", err)
	},
	nonObject: func(tok json.Token) error {
		if tok == nil {
			return errors.New("version spec must be a JSON object, got null")
		}
		if d, ok := tok.(json.Delim); ok && d == '[' {
			return errors.New("version spec must be a single JSON object, got array")
		}
		return fmt.Errorf("version spec must be a single JSON object, got %s", jsonTokenName(tok))
	},
	wrap: func(err error) error {
		return fmt.Errorf("invalid version spec: %w", err)
	},
	duplicate: func(obj, field, first, _ string) error {
		return fmt.Errorf("%w: %s field %q (also written %q)", ErrDuplicateField, obj, field, first)
	},
	trailing: versionTrailingData,
}

// validateSpecStructure proves raw contains exactly one JSON object with
// no repeated fields anywhere in it, and nothing but whitespace around
// it. Keys are matched against the known fields of the version, rules,
// sandwich and displacement objects with the decoder's own field-name
// folding: "SEVERITY", "severity" and "ſeverity" (U+017F for s) all point
// at the same field and cannot share one object. Escaped key spellings
// are decoded before comparison, so "severity" cannot evade it.
func validateSpecStructure(raw []byte) error {
	return scanJSONObject(raw, versionScanPolicy)
}

// versionTrailingData names the first non-whitespace byte after the
// closed object, so an unmatched '}' or ']' is reported directly rather
// than as a syntax error; only whitespace may follow the object.
func versionTrailingData(raw []byte, offset int) error {
	rest := bytes.TrimLeft(raw[offset:], " \t\n\r")
	if len(rest) > 0 {
		return fmt.Errorf("%w: %s after closing object", ErrTrailingData, trailingTokenName(rest[0]))
	}
	return nil
}

var (
	versionFields       = fieldTable("id", "rules")
	rulesFields         = fieldTable("sandwich", "displacement")
	sandwichFields      = fieldTable("enabled", "severity")
	displacementFields  = fieldTable("enabled", "severity", "multiplier")
	versionNestedTables = map[string]nestedObjectSpec{
		"rules":        {rulesFields, "rules object"},
		"sandwich":     {sandwichFields, "rules.sandwich"},
		"displacement": {displacementFields, "rules.displacement"},
	}
)

// ParseRuleVersion validates a registration document. It must contain
// exactly one complete JSON object (leading and trailing whitespace
// allowed): a second object or value, an unmatched bracket or any other
// trailing character fails, and empty input, arrays and null are not
// specs. Duplicate fields are rejected at the top level, in rules and in
// each rule's parameters, including any spellings the decoder folds onto
// the same known field (case variants, U+017F for s, and the like). Missing fields, wrong types, out-of-range values and unknown
// rules or fields all fail with a reason.
func ParseRuleVersion(raw []byte) (RuleVersion, error) {
	if err := validateSpecStructure(raw); err != nil {
		return RuleVersion{}, err
	}
	var spec versionSpec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		return RuleVersion{}, fmt.Errorf("invalid version spec: %w", err)
	}
	if spec.ID == nil || *spec.ID == "" {
		return RuleVersion{}, errors.New("id must be a non-empty string")
	}
	if spec.Rules == nil {
		return RuleVersion{}, errors.New("rules must declare sandwich and displacement")
	}
	if spec.Rules.Sandwich == nil {
		return RuleVersion{}, errors.New("rules.sandwich is required")
	}
	if spec.Rules.Displacement == nil {
		return RuleVersion{}, errors.New("rules.displacement is required")
	}
	sandwichOn, err := parseEnabled("sandwich", spec.Rules.Sandwich.Enabled)
	if err != nil {
		return RuleVersion{}, err
	}
	sandwichSev, err := parseSeverity("sandwich", spec.Rules.Sandwich.Severity)
	if err != nil {
		return RuleVersion{}, err
	}
	dispOn, err := parseEnabled("displacement", spec.Rules.Displacement.Enabled)
	if err != nil {
		return RuleVersion{}, err
	}
	dispSev, err := parseSeverity("displacement", spec.Rules.Displacement.Severity)
	if err != nil {
		return RuleVersion{}, err
	}
	mult := spec.Rules.Displacement.Multiplier
	if mult == nil {
		return RuleVersion{}, errors.New("rules.displacement.multiplier is required (integer 2-100)")
	}
	if *mult < 2 || *mult > 100 {
		return RuleVersion{}, fmt.Errorf("rules.displacement.multiplier must be between 2 and 100, got %d", *mult)
	}
	return RuleVersion{
		ID: *spec.ID,
		Rules: RuleSet{
			Sandwich:     SandwichRule{Enabled: sandwichOn, Severity: sandwichSev},
			Displacement: DisplacementRule{Enabled: dispOn, Severity: dispSev, Multiplier: *mult},
		},
	}, nil
}

// findVersion resolves id against the built-in version and the archive's
// registered versions.
func findVersion(data archiveData, id string) (RuleVersion, error) {
	if id == BuiltinVersionID {
		return BuiltinVersion(), nil
	}
	for _, v := range data.Versions {
		if v.ID == id {
			return v, nil
		}
	}
	return RuleVersion{}, fmt.Errorf("%w: %s", ErrUnknownVersion, id)
}

// intactVersion resolves id for a comparison and proves the version's
// stored archive document still satisfies every registration rule,
// re-validating the raw document with the same parser registrations pass.
// The decoded struct cannot do this: a missing enabled, severity or
// multiplier field unmarshals as the zero value and is indistinguishable
// from an explicitly declared one, and a wrong-typed field fails the
// whole-archive decode before any judgment can run. An explicitly
// declared false or any in-range value is valid; a missing or null field,
// a wrong type or an out-of-range number makes the version corrupt, and
// the failure names the version and the offending rule or field. The
// built-in version is constructed in code and always intact.
func intactVersion(versions []json.RawMessage, id string) (RuleVersion, error) {
	if id == BuiltinVersionID {
		return BuiltinVersion(), nil
	}
	for _, entry := range versions {
		var meta struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(entry, &meta); err != nil || meta.ID != id {
			continue
		}
		v, err := ParseRuleVersion(entry)
		if err != nil {
			return RuleVersion{}, fmt.Errorf("%w: %s: %w", ErrCorruptVersion, id, err)
		}
		return v, nil
	}
	return RuleVersion{}, fmt.Errorf("%w: %s", ErrUnknownVersion, id)
}

// RegisterVersion validates raw as a rule version spec and stores it in the
// archive at dir. Re-registering the same ID with identical parameters
// succeeds without adding a version (created is false); the same ID with
// different parameters is rejected. The built-in version ID is reserved.
// Any failure leaves the archive untouched.
func RegisterVersion(dir string, raw []byte) (v RuleVersion, created bool, err error) {
	v, err = ParseRuleVersion(raw)
	if err != nil {
		return RuleVersion{}, false, err
	}
	if v.ID == BuiltinVersionID {
		return RuleVersion{}, false, fmt.Errorf("version id %q is reserved for the built-in rules", BuiltinVersionID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return RuleVersion{}, false, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return RuleVersion{}, false, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return RuleVersion{}, false, err
	}
	for _, existing := range data.Versions {
		if existing.ID == v.ID {
			if existing.Rules == v.Rules {
				return existing, false, nil
			}
			return RuleVersion{}, false, fmt.Errorf("%w: %s", ErrVersionConflict, v.ID)
		}
	}
	data.Versions = append(data.Versions, v)
	if err := writeArchiveAtomic(dir, data); err != nil {
		return RuleVersion{}, false, err
	}
	return v, true, nil
}

// EnableVersion makes id the archive's active version for later replays.
// Enabling an unknown version fails and leaves the current enabled version
// unchanged.
func EnableVersion(dir, id string) (RuleVersion, error) {
	if id == "" {
		return RuleVersion{}, errors.New("version id must not be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return RuleVersion{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return RuleVersion{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return RuleVersion{}, err
	}
	v, err := findVersion(data, id)
	if err != nil {
		return RuleVersion{}, err
	}
	if data.EnabledVersion == id {
		return v, nil
	}
	data.EnabledVersion = id
	if err := writeArchiveAtomic(dir, data); err != nil {
		return RuleVersion{}, err
	}
	return v, nil
}

// ListVersions returns the built-in version plus every version registered
// in the archive, along with the currently enabled version ID.
func ListVersions(dir string) (versions []RuleVersion, enabled string, err error) {
	if _, serr := os.Stat(dir); errors.Is(serr, os.ErrNotExist) {
		return []RuleVersion{BuiltinVersion()}, BuiltinVersionID, nil
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return nil, "", err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return nil, "", err
	}
	versions = append([]RuleVersion{BuiltinVersion()}, data.Versions...)
	enabled = data.EnabledVersion
	if enabled == "" {
		enabled = BuiltinVersionID
	}
	return versions, enabled, nil
}

// GetVersion returns one version's full parameters by ID.
func GetVersion(dir, id string) (RuleVersion, error) {
	if id == BuiltinVersionID {
		return BuiltinVersion(), nil
	}
	if _, serr := os.Stat(dir); errors.Is(serr, os.ErrNotExist) {
		return RuleVersion{}, fmt.Errorf("%w: %s", ErrUnknownVersion, id)
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return RuleVersion{}, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return RuleVersion{}, err
	}
	return findVersion(data, id)
}

// FindingChange pairs the archived and compared conclusions for one
// transaction whose kind or severity differs between the two versions.
type FindingChange struct {
	TxHash   string        `json:"txHash"`
	Original ReportFinding `json:"original"`
	Compared ReportFinding `json:"compared"`
}

// CompareResult is the outcome of re-judging one archived block under a
// different rule version. It carries both versions' parameters, both full
// conclusion sets, the raw swap evidence, and the per-transaction diff.
type CompareResult struct {
	ChainID          string          `json:"chainId"`
	BlockHash        string          `json:"blockHash"`
	BlockNumber      int64           `json:"blockNumber"`
	OriginalVersion  RuleVersion     `json:"originalVersion"`
	ComparedVersion  RuleVersion     `json:"comparedVersion"`
	OriginalFindings []ReportFinding `json:"originalFindings"`
	ComparedFindings []ReportFinding `json:"comparedFindings"`
	Swaps            []Swap          `json:"swaps"`
	Added            []ReportFinding `json:"added"`
	Removed          []ReportFinding `json:"removed"`
	Changed          []FindingChange `json:"changed"`
}

// rawVersionArchiveDoc mirrors the archive file the way a comparison and a
// review-range evaluation read it: records and reviews are fully decoded,
// but each registered version is kept as its raw stored document. A corrupt
// version entry — a wrong-typed field, say — then cannot break the read or
// masquerade as whole-archive corruption; it is judged on its own by
// intactVersion, so a corrupt sibling never contaminates an intact
// candidate or the built-in version.
type rawVersionArchiveDoc struct {
	Records  []record          `json:"records"`
	Versions []json.RawMessage `json:"versions"`
	Reviews  []ReviewObject    `json:"reviews"`
}

// Compare re-runs detection for one archived block under the given
// registered version and diffs the conclusions against the archived
// report. It only reads the archive: the original input file is not
// needed, and neither the archived report nor the enabled version is
// modified. The named version's stored document must still satisfy the
// registration rules in full; a corrupt one fails with ErrCorruptVersion
// rather than comparing under zeroed or substituted parameters.
func Compare(dir, chainID, blockHash, versionID string) (CompareResult, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CompareResult{}, ErrUnknownBlock
		}
		return CompareResult{}, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH)
	if err != nil {
		return CompareResult{}, err
	}
	defer lock.Close()

	raw, err := readArchiveBytes(dir)
	if err != nil {
		return CompareResult{}, err
	}
	var doc rawVersionArchiveDoc
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return CompareResult{}, fmt.Errorf("archive is corrupted: %w", err)
		}
	}
	var rec *record
	for i := range doc.Records {
		if doc.Records[i].ChainID == chainID && doc.Records[i].BlockHash == blockHash {
			rec = &doc.Records[i]
			break
		}
	}
	if rec == nil {
		return CompareResult{}, ErrUnknownBlock
	}
	// The requested version must be intact in the archive: re-validate its
	// stored document before judging anything, so a corrupt version fails
	// the same way even when the block has no swaps and detection would
	// produce no conclusions at all.
	compared, err := intactVersion(doc.Versions, versionID)
	if err != nil {
		return CompareResult{}, err
	}
	original := rec.Findings
	if original == nil {
		original = []ReportFinding{}
	}
	rejudged := DetectBlockWithRules(rec.Swaps, compared.Rules)
	swaps := rec.Swaps
	if swaps == nil {
		swaps = []Swap{}
	}

	origByTx := make(map[string]ReportFinding, len(original))
	for _, f := range original {
		origByTx[f.TxHash] = f
	}
	compByTx := make(map[string]ReportFinding, len(rejudged))
	for _, f := range rejudged {
		compByTx[f.TxHash] = f
	}
	added := []ReportFinding{}
	removed := []ReportFinding{}
	changed := []FindingChange{}
	for _, f := range rejudged {
		if o, ok := origByTx[f.TxHash]; ok {
			// A transaction present on both sides with a different kind or
			// severity is a change, never an add plus a remove.
			if o.Kind != f.Kind || o.Severity != f.Severity {
				changed = append(changed, FindingChange{TxHash: f.TxHash, Original: o, Compared: f})
			}
		} else {
			added = append(added, f)
		}
	}
	for _, f := range original {
		if _, ok := compByTx[f.TxHash]; !ok {
			removed = append(removed, f)
		}
	}
	byTx := func(fs []ReportFinding) {
		sort.Slice(fs, func(i, j int) bool { return fs[i].TxHash < fs[j].TxHash })
	}
	byTx(added)
	byTx(removed)
	sort.Slice(changed, func(i, j int) bool { return changed[i].TxHash < changed[j].TxHash })

	return CompareResult{
		ChainID:          rec.ChainID,
		BlockHash:        rec.BlockHash,
		BlockNumber:      rec.BlockNumber,
		OriginalVersion:  rec.ruleVersion(),
		ComparedVersion:  compared,
		OriginalFindings: original,
		ComparedFindings: rejudged,
		Swaps:            swaps,
		Added:            added,
		Removed:          removed,
		Changed:          changed,
	}, nil
}
