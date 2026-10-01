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

// RuleParams is the enablement and severity of one rule. The displacement
// rule additionally carries the gas-price multiplier that the previous swap
// must strictly exceed.
type RuleParams struct {
	Enabled    bool `json:"enabled"`
	Severity   int  `json:"severity"`
	Multiplier int  `json:"multiplier,omitempty"`
}

// RuleVersion fully declares the two detection rules: their enablement and
// severity, plus the displacement multiplier.
type RuleVersion struct {
	ID           string     `json:"id"`
	Sandwich     RuleParams `json:"sandwich"`
	Displacement RuleParams `json:"displacement"`
}

// BuiltinVersion represents the fixed rules that predate versioning:
// sandwich severity 3, displacement severity 2 with a 2x multiplier. It is
// always available, cannot be overwritten, and is how old-format archives
// are interpreted.
var BuiltinVersion = RuleVersion{
	ID: "builtin",
	Sandwich: RuleParams{
		Enabled:  true,
		Severity: 3,
	},
	Displacement: RuleParams{
		Enabled:    true,
		Severity:   2,
		Multiplier: 2,
	},
}

// ruleParamsInput mirrors one rule's JSON. Pointers distinguish a missing
// field from an explicit zero value.
type ruleParamsInput struct {
	Enabled    *bool `json:"enabled"`
	Severity   *int  `json:"severity"`
	Multiplier *int  `json:"multiplier"`
}

// ruleVersionInput mirrors the version JSON. DisallowUnknownFields rejects
// unknown rule names and stray fields.
type ruleVersionInput struct {
	ID           *string          `json:"id"`
	Sandwich     *ruleParamsInput `json:"sandwich"`
	Displacement *ruleParamsInput `json:"displacement"`
}

// ParseVersionJSON parses and validates a version declaration without
// touching any archive. It reports a reason for missing fields, type
// errors, out-of-range values, or unknown rules.
func ParseVersionJSON(data []byte) (RuleVersion, error) {
	var raw ruleVersionInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return RuleVersion{}, fmt.Errorf("invalid version JSON: %w", err)
	}
	if raw.ID == nil || *raw.ID == "" {
		return RuleVersion{}, errors.New("version id must be a non-empty string")
	}
	if raw.Sandwich == nil {
		return RuleVersion{}, errors.New("sandwich rule is required")
	}
	if raw.Displacement == nil {
		return RuleVersion{}, errors.New("displacement rule is required")
	}
	v := RuleVersion{ID: *raw.ID}
	var err error
	if v.Sandwich, err = parseRuleParams("sandwich", raw.Sandwich, false); err != nil {
		return RuleVersion{}, err
	}
	if v.Displacement, err = parseRuleParams("displacement", raw.Displacement, true); err != nil {
		return RuleVersion{}, err
	}
	return v, nil
}

func parseRuleParams(name string, p *ruleParamsInput, hasMultiplier bool) (RuleParams, error) {
	if p.Enabled == nil {
		return RuleParams{}, fmt.Errorf("%s: enabled is required", name)
	}
	if p.Severity == nil {
		return RuleParams{}, fmt.Errorf("%s: severity is required", name)
	}
	if *p.Severity < 1 || *p.Severity > 5 {
		return RuleParams{}, fmt.Errorf("%s: severity must be between 1 and 5, got %d", name, *p.Severity)
	}
	rp := RuleParams{Enabled: *p.Enabled, Severity: *p.Severity}
	if hasMultiplier {
		if p.Multiplier == nil {
			return RuleParams{}, fmt.Errorf("%s: multiplier is required", name)
		}
		if *p.Multiplier < 2 || *p.Multiplier > 100 {
			return RuleParams{}, fmt.Errorf("%s: multiplier must be between 2 and 100, got %d", name, *p.Multiplier)
		}
		rp.Multiplier = *p.Multiplier
	} else if p.Multiplier != nil {
		return RuleParams{}, fmt.Errorf("%s: multiplier is not allowed", name)
	}
	return rp, nil
}

// validateVersion checks a version that was constructed directly (for
// example in tests) rather than parsed from JSON.
func validateVersion(v RuleVersion) error {
	if v.ID == "" {
		return errors.New("version id must be non-empty")
	}
	if err := validateRuleParams("sandwich", v.Sandwich, false); err != nil {
		return err
	}
	if err := validateRuleParams("displacement", v.Displacement, true); err != nil {
		return err
	}
	return nil
}

func validateRuleParams(name string, p RuleParams, hasMultiplier bool) error {
	if p.Severity < 1 || p.Severity > 5 {
		return fmt.Errorf("%s: severity must be between 1 and 5, got %d", name, p.Severity)
	}
	if hasMultiplier {
		if p.Multiplier < 2 || p.Multiplier > 100 {
			return fmt.Errorf("%s: multiplier must be between 2 and 100, got %d", name, p.Multiplier)
		}
	} else if p.Multiplier != 0 {
		return fmt.Errorf("%s: multiplier is not allowed", name)
	}
	return nil
}

// RegisterVersion stores a version in the archive. Re-registering the same
// id with identical parameters succeeds without adding a duplicate; the
// same id with different parameters is rejected. The built-in id cannot be
// overwritten. A failed registration leaves the archive unchanged.
func RegisterVersion(dir string, v RuleVersion) error {
	if v.ID == "" {
		return errors.New("version id must be non-empty")
	}
	if v.ID == BuiltinVersion.ID {
		return errors.New("cannot overwrite built-in version")
	}
	if err := validateVersion(v); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return err
	}
	for _, existing := range data.Versions {
		if existing.ID == v.ID {
			if existing == v {
				return nil // identical re-registration
			}
			return fmt.Errorf("version %q already exists with different parameters", v.ID)
		}
	}
	data.Versions = append(data.Versions, v)
	sort.Slice(data.Versions, func(i, j int) bool { return data.Versions[i].ID < data.Versions[j].ID })
	return writeArchiveAtomic(dir, data)
}

// ListVersions returns the built-in version followed by the registered
// versions sorted by id. It only reads the archive.
func ListVersions(dir string) ([]RuleVersion, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []RuleVersion{BuiltinVersion}, nil
		}
		return nil, err
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return nil, err
	}
	out := make([]RuleVersion, 0, len(data.Versions)+1)
	out = append(out, BuiltinVersion)
	out = append(out, data.Versions...)
	return out, nil
}

// EnabledVersion returns the id of the currently enabled version,
// normalized to "builtin" when the archive has no explicit choice.
func EnabledVersion(dir string) (string, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BuiltinVersion.ID, nil
		}
		return "", err
	}
	lock, err := lockArchive(dir, syscall.LOCK_SH|syscall.LOCK_NB)
	if err != nil {
		return "", err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return "", err
	}
	if data.EnabledVersion == "" {
		return BuiltinVersion.ID, nil
	}
	return data.EnabledVersion, nil
}

// EnableVersion sets the enabled version. Enabling an unknown id fails and
// leaves the previous choice unchanged.
func EnableVersion(dir, id string) error {
	if id == "" {
		return errors.New("version id must be non-empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	lock, err := lockArchive(dir, syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return err
	}
	defer lock.Close()

	data, err := readArchive(dir)
	if err != nil {
		return err
	}
	if id != BuiltinVersion.ID {
		found := false
		for _, v := range data.Versions {
			if v.ID == id {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown version %q", id)
		}
	}
	data.EnabledVersion = id
	return writeArchiveAtomic(dir, data)
}

// resolveVersion picks the version to use: an explicit id, the archive's
// enabled version, or the built-in default. It must be called under the
// archive lock so the choice stays consistent across one replay.
func resolveVersion(data archiveData, id string) (RuleVersion, error) {
	if id == "" {
		id = data.EnabledVersion
	}
	if id == "" || id == BuiltinVersion.ID {
		return BuiltinVersion, nil
	}
	for _, v := range data.Versions {
		if v.ID == id {
			return v, nil
		}
	}
	return RuleVersion{}, fmt.Errorf("%w: %q", ErrUnknownVersion, id)
}
