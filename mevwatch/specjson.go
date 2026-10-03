package mevwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Shared structural validation for registration documents (rule versions
// and suppression conditions). Both kinds of input must contain exactly
// one JSON object with no field repeated inside any one object, surrounded
// only by whitespace; the two registrations differ only in their field
// tables, their nested-object shapes and the wording of their errors.

// ErrDuplicateField reports a JSON object in a registration spec that
// names the same field twice. Field names are compared the way JSON
// decoding matches struct fields, so two spellings that differ only in
// case (for example "severity" and "Severity") are also duplicates.
var ErrDuplicateField = errors.New("duplicate field in version spec")

// ErrTrailingData reports non-whitespace content after the single JSON
// object that makes up a registration spec: a second object, another
// JSON value, an unmatched bracket or any other character.
var ErrTrailingData = errors.New("unexpected trailing data after version spec")

// fieldTable maps the case-insensitive spellings of a struct object's
// JSON fields to their canonical names.
func fieldTable(fields ...string) map[string]string {
	table := make(map[string]string, len(fields))
	for _, f := range fields {
		table[strings.ToLower(f)] = f
	}
	return table
}

// nestedObjectSpec describes one known nested object: the field table of
// the object it contains and the label used to name it in errors.
type nestedObjectSpec struct {
	fields map[string]string
	label  string
}

type specStructure struct {
	// topLabel names the outermost object in duplicate errors ("version
	// spec" for versions, "suppression object" for suppressions).
	topLabel string
	// top is the field table of the outermost object.
	top map[string]string
	// nested maps the canonical name of a known object-valued field to the
	// shape of the object it must contain; an absent entry means any
	// object value is skipped without per-field duplicate checking.
	nested map[string]nestedObjectSpec
	// dupUnknownKeys records exact repeats even of keys that match no
	// known field. Version specs reject those as duplicates directly;
	// suppression specs leave unknown keys to the decoder, which reports
	// the unknown field.
	dupUnknownKeys bool
	// syntaxError wraps a JSON syntax/IO error, e.g.
	// `fmt.Errorf("invalid version spec: %w", err)`.
	syntaxError func(error) error
	// emptyInput reports blank input.
	emptyInput error
	// nonObject reports a first token that is not '{' (never called with
	// the opening brace).
	nonObject func(json.Token) error
	// badClose reports a closing token other than '}' after an object's
	// members (unreachable with the standard decoder, kept for parity).
	badClose func(json.Token) error
	// duplicateError reports the same field twice in one object; obj is
	// the object label, field the canonical field name, first the
	// spelling seen earlier and current the repeated spelling.
	duplicateError func(obj, field, first, current string) error
	// trailingData reports non-whitespace after the object; b is its first
	// byte. It is never reached with no trailing bytes.
	trailingData func(b byte) error
}

// validateSingleObject proves raw contains exactly one JSON object with
// no repeated fields in any of its checked objects, and nothing but
// whitespace around it. Keys are matched case-insensitively against the
// configured known fields, preserving the decoder's case-compatible field
// matching: "SEVERITY" and "severity" point at the same field and cannot
// both appear in one object. Escaped key spellings are decoded before
// comparison, so "severity" cannot evade the check by escaping a letter.
// Duplicate detection is scoped to the object the keys belong to: the
// same field name inside two sibling objects is not a duplicate.
func validateSingleObject(raw []byte, s specStructure) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return s.emptyInput
		}
		return s.syntaxError(err)
	}
	if first != json.Delim('{') {
		return s.nonObject(first)
	}
	if err := scanObject(dec, s, s.top, s.topLabel); err != nil {
		return err
	}
	// Inspect the raw remainder instead of decoding another token: the
	// only legal content after the object is JSON whitespace, and this
	// names an unmatched '}' or ']' directly rather than as a syntax error.
	rest := bytes.TrimLeft(raw[dec.InputOffset():], " \t\n\r")
	if len(rest) > 0 {
		return s.trailingData(rest[0])
	}
	return nil
}

// scanObject consumes one open object (its opening brace already read)
// and checks its keys against known. obj names the object for duplicate
// error messages. Nested objects listed in the structure's shape table
// are scanned with their own field tables and labels; any other nested
// container is skipped without duplicate checking.
func scanObject(dec *json.Decoder, s specStructure, known map[string]string, obj string) error {
	spellings := make(map[string]string)
	seen := make(map[string]string, len(known))
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return s.syntaxError(err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return s.syntaxError(fmt.Errorf("object key is %s, want string", jsonTokenName(keyTok)))
		}
		// An exact repeat of a decoded key name is a duplicate; escapes
		// are decoded first, so "id" and "id" compare equal. Unknown keys
		// are only tracked for specs that reject their repeats directly;
		// otherwise the decoder names them as unknown fields.
		if first, dup := spellings[key]; dup {
			if s.dupUnknownKeys {
				return s.duplicateError(obj, key, first, key)
			}
		} else {
			spellings[key] = key
		}
		target, knownKey := known[strings.ToLower(key)]
		if knownKey {
			// A case-only spelling of the same known field is the same
			// field: "Severity" and "severity" cannot share one object.
			if first, dup := seen[target]; dup {
				return s.duplicateError(obj, target, first, key)
			}
			seen[target] = key
		}
		start, err := dec.Token()
		if err != nil {
			return s.syntaxError(err)
		}
		if d, isDelim := start.(json.Delim); isDelim {
			switch d {
			case '{':
				nested, hasShape := s.nested[target]
				if !knownKey || !hasShape {
					if err := skipValue(dec, s, '{'); err != nil {
						return err
					}
					continue
				}
				if err := scanObject(dec, s, nested.fields, nested.label); err != nil {
					return err
				}
			case '[':
				if err := skipValue(dec, s, '['); err != nil {
					return err
				}
			}
			continue
		}
	}
	closeTok, err := dec.Token()
	if err != nil {
		return s.syntaxError(err)
	}
	if closeTok != json.Delim('}') {
		return s.badClose(closeTok)
	}
	return nil
}

// skipValue consumes the remainder of one container whose opening
// delimiter has already been read, balancing nested brackets.
func skipValue(dec *json.Decoder, s specStructure, open json.Delim) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return s.syntaxError(err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 && d != openBracketClose(open) {
					return s.syntaxError(fmt.Errorf("mismatched closing %s", jsonTokenName(d)))
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

// trailingTokenName describes what kind of JSON content starts with b for
// trailing-data errors.
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
