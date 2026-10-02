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
// decoding matches struct fields, so two spellings that differ only in
// case (for example "severity" and "Severity") are also duplicates.
var ErrDuplicateField = errors.New("duplicate field in version spec")

// ErrTrailingData reports non-whitespace content after the single JSON
// object that makes up a registration spec: a second object, another
// JSON value, an unmatched bracket or any other character.
var ErrTrailingData = errors.New("unexpected trailing data after version spec")

// validateSpecStructure proves raw contains exactly one JSON object with
// no repeated fields anywhere in it, and nothing but whitespace around
// it. Keys are matched case-insensitively against the known fields of
// the version, rules, sandwich and displacement objects, preserving the
// decoder's case-compatible field matching: "SEVERITY" and "severity"
// point at the same field and cannot both appear. Escaped key spellings
// are decoded before comparison, so "severity" cannot evade it.
func validateSpecStructure(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("version spec must be a JSON object, got empty input")
		}
		return fmt.Errorf("invalid version spec: %w", err)
	}
	if first != json.Delim('{') {
		if first == nil {
			return errors.New("version spec must be a JSON object, got null")
		}
		if d, ok := first.(json.Delim); ok && d == '[' {
			return errors.New("version spec must be a single JSON object, got array")
		}
		return fmt.Errorf("version spec must be a single JSON object, got %s", jsonTokenName(first))
	}
	if err := scanObject(dec, versionFields, "version spec"); err != nil {
		return err
	}
	// Inspect the raw remainder instead of decoding another token: the
	// only legal content after the object is JSON whitespace, and this
	// names an unmatched '}' or ']' directly rather than as a syntax error.
	rest := bytes.TrimLeft(raw[dec.InputOffset():], " \t\n\r")
	if len(rest) > 0 {
		return fmt.Errorf("%w: %s after closing object", ErrTrailingData, trailingTokenName(rest[0]))
	}
	return nil
}

func trailingTokenName(b byte) string {
	switch b {
	case '{':
		return "object"
	case '[':
		return "array"
	case '}':
		return "extra closing brace '}'"
	case ']':
		return "extra closing bracket ']'"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		if (b >= '0' && b <= '9') || b == '-' {
			return "number"
		}
		return fmt.Sprintf("unexpected character %q", rune(b))
	}
}

// scanObject consumes one open object (its opening brace already read)
// and checks its keys against known. obj names the object for duplicate
// error messages. Nested "rules", "sandwich" and "displacement" objects
// are scanned with their own field tables; any other nested container is
// skipped without duplicate checking.
func scanObject(dec *json.Decoder, known map[string]string, obj string) error {
	seen := make(map[string]string, len(known))
	spellings := make(map[string]string)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid version spec: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("invalid version spec: object key is %s, want string", jsonTokenName(keyTok))
		}
		// Exact repeat of a decoded key name (any field, known or unknown)
		// is a duplicate; escapes are decoded first, so "id" == "id".
		if first, dup := spellings[key]; dup {
			return fmt.Errorf("%w: %s field %q (also written %q)", ErrDuplicateField, obj, key, first)
		}
		spellings[key] = key
		target, knownKey := known[strings.ToLower(key)]
		if knownKey {
			// A case-only spelling of the same known field is the same
			// field: "Severity" and "severity" cannot share one object.
			if first, dup := seen[target]; dup {
				return fmt.Errorf("%w: %s field %q (also written %q)", ErrDuplicateField, obj, target, first)
			}
			seen[target] = key
		}
		start, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid version spec: %w", err)
		}
		if d, isDelim := start.(json.Delim); isDelim {
			switch d {
			case '{':
				nested, hasShape := nestedObjectTables[target]
				if !knownKey || !hasShape {
					if err := skipValue(dec, '{'); err != nil {
						return err
					}
					continue
				}
				if err := scanObject(dec, nested.fields, nested.label); err != nil {
					return err
				}
			case '[':
				if err := skipValue(dec, '['); err != nil {
					return err
				}
			}
			continue
		}
	}
	closeTok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("invalid version spec: %w", err)
	}
	if closeTok != json.Delim('}') {
		return fmt.Errorf("invalid version spec: expected closing brace, got %s", jsonTokenName(closeTok))
	}
	return nil
}

// skipValue consumes the remainder of one container whose opening
// delimiter has already been read, balancing nested brackets.
func skipValue(dec *json.Decoder, open json.Delim) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("invalid version spec: %w", err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 && d != openBracketClose(open) {
					return fmt.Errorf("invalid version spec: mismatched closing %s", jsonTokenName(d))
				}
			}
		}
	}
	return nil
}

func openBracketClose(open json.Delim) json.Delim {
	if open == '[' {
		return ']'
	}
	return '}'
}

func jsonTokenName(tok json.Token) string {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '[':
			return "array"
		case '{':
			return "object"
		case ']':
			return "extra closing bracket ']'"
		case '}':
			return "extra closing brace '}'"
		}
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		return "number"
	case float64:
		return "number"
	case int64:
		return "number"
	}
	return "value"
}

// fieldTable maps the case-insensitive spellings of a struct object's
// JSON fields to their canonical names.
func fieldTable(fields ...string) map[string]string {
	table := make(map[string]string, len(fields))
	for _, f := range fields {
		table[strings.ToLower(f)] = f
	}
	return table
}

type nestedObjectSpec struct {
	fields map[string]string
	label  string
}

var (
	versionFields      = fieldTable("id", "rules")
	rulesFields        = fieldTable("sandwich", "displacement")
	sandwichFields     = fieldTable("enabled", "severity")
	displacementFields = fieldTable("enabled", "severity", "multiplier")
	nestedObjectTables = map[string]nestedObjectSpec{
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
// each rule's parameters, including case-only variants of the same known
// field. Missing fields, wrong types, out-of-range values and unknown
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

// enabledVersion resolves the archive's currently enabled version. Archives
// written before rule versions existed have no marker and run the built-in
// rules.
func (d archiveData) enabledVersion() (RuleVersion, error) {
	if d.EnabledVersion == "" {
		return BuiltinVersion(), nil
	}
	return findVersion(d, d.EnabledVersion)
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

// Compare re-runs detection for one archived block under the given
// registered version and diffs the conclusions against the archived
// report. It only reads the archive: the original input file is not
// needed, and neither the archived report nor the enabled version is
// modified.
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

	data, err := readArchive(dir)
	if err != nil {
		return CompareResult{}, err
	}
	var rec *record
	for i := range data.Records {
		if data.Records[i].ChainID == chainID && data.Records[i].BlockHash == blockHash {
			rec = &data.Records[i]
			break
		}
	}
	if rec == nil {
		return CompareResult{}, ErrUnknownBlock
	}
	compared, err := findVersion(data, versionID)
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
