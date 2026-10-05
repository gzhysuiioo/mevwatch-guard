package mevwatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// This file holds the shared structural validation for the single-object
// JSON registration documents: rule versions (rules.go) and suppression
// conditions (alerts.go). Both must contain exactly one JSON object with
// nothing but whitespace around it and with no field declared twice in the
// same object; the scan runs before the typed decoder reads any business
// value, so strings and numbers are never normalized here.
//
// The two document families keep their own public wording and sentinel
// errors, their own idea of which nested objects carry a field table of
// their own, and their own way of detecting content after the closing
// brace. Those differences are injected through specPolicy; the tokenizing
// machinery below exists once.

// specPolicy configures scanJSONObject for one registration document
// family.
type specPolicy struct {
	// topObject labels the root object in duplicate-field errors.
	topObject string
	// known maps the case-folded spelling of every accepted root field to
	// its canonical name. Folding matches the decoder's field matching, so
	// spellings like "ſeverity" (U+017F for s) fold onto "severity".
	known map[string]string
	// nested names the known fields whose value is itself an object that
	// must carry its own per-object duplicate table. Any other object or
	// array value is consumed without looking inside.
	nested map[string]nestedObjectSpec
	// rejectExactUnknown makes an exact re-spelling of even an unknown key
	// (same bytes after JSON unescaping) a duplicate. Case-only variants of
	// unknown keys stay undetected here and surface as unknown fields in
	// the typed decode.
	rejectExactUnknown bool

	// firstTokenError reports a failure to read any first token (including
	// empty input, which surfaces as io.EOF).
	firstTokenError func(err error) error
	// nonObject reports a first token that is not an opening brace.
	nonObject func(tok json.Token) error
	// wrap prefixes syntax errors found while scanning the object.
	wrap func(err error) error
	// duplicate reports a repeated field. For known fields field is the
	// canonical name; for an exact unknown-key repeat it is the key itself.
	// first is the earlier spelling, spelling the current one. A nil hook
	// disables duplicate detection entirely: the scanner then proves shape
	// (one object, balanced brackets, no trailing content) only.
	duplicate func(obj, field, first, spelling string) error
	// trailing reports content after the closing brace, given the raw
	// document and the byte offset just past it.
	trailing func(raw []byte, offset int) error
}

// scanJSONObject proves raw holds exactly one JSON object with no repeated
// field in any scanned object and with no content after it beyond what the
// policy's trailing check allows. It never interprets values.
func scanJSONObject(raw []byte, p specPolicy) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	first, err := dec.Token()
	if err != nil {
		return p.firstTokenError(err)
	}
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return p.nonObject(first)
	}
	if err := scanObject(dec, p, p.known, p.topObject); err != nil {
		return err
	}
	return p.trailing(raw, int(dec.InputOffset()))
}

// scanObject consumes one object whose opening brace has already been read
// and checks its keys against known. obj names the object for duplicate
// errors. Objects named in the policy's nested table are scanned with that
// table; every other container is skipped without looking inside.
func scanObject(dec *json.Decoder, p specPolicy, known map[string]string, obj string) error {
	seen := make(map[string]string, len(known))
	spellings := make(map[string]string)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return p.wrap(err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return p.wrap(fmt.Errorf("object key is %s, want string", jsonTokenName(keyTok)))
		}
		target, knownKey := known[foldName(key)]
		if p.duplicate != nil {
			if p.rejectExactUnknown {
				// An exact repeat of a decoded key name (known or unknown) is a
				// duplicate; escapes are decoded first, so "id" == "id".
				if first, dup := spellings[key]; dup {
					return p.duplicate(obj, key, first, key)
				}
				spellings[key] = key
			}
			if knownKey {
				// Another spelling of the same known field is the same field:
				// "Severity", "severity" and "ſeverity" cannot share one object.
				if first, dup := seen[target]; dup {
					return p.duplicate(obj, target, first, key)
				}
				seen[target] = key
			}
		}
		start, err := dec.Token()
		if err != nil {
			return p.wrap(err)
		}
		if d, isDelim := start.(json.Delim); isDelim {
			switch d {
			case '{':
				nested, hasShape := p.nested[target]
				if !knownKey || !hasShape {
					if err := skipContainer(dec, p); err != nil {
						return err
					}
					continue
				}
				if err := scanObject(dec, p, nested.fields, nested.label); err != nil {
					return err
				}
			case '[':
				if err := skipContainer(dec, p); err != nil {
					return err
				}
			}
			continue
		}
	}
	closeTok, err := dec.Token()
	if err != nil {
		return p.wrap(err)
	}
	if closeTok != json.Delim('}') {
		return p.wrap(fmt.Errorf("expected closing brace, got %s", jsonTokenName(closeTok)))
	}
	return nil
}

// skipContainer consumes the remainder of one object or array whose
// opening delimiter has already been read, balancing nested brackets. The
// scanner itself rejects mismatched brackets, so only depth bookkeeping is
// needed here.
func skipContainer(dec *json.Decoder, p specPolicy) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			return p.wrap(err)
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

// jsonTokenName describes a token the way the structural error messages do.
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

// trailingTokenName identifies the kind of JSON token started by the first
// non-whitespace byte after a closed object.
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

// fieldTable maps the case-folded spellings of a struct object's JSON
// fields to their canonical names. Folding follows the decoder's field
// matching (see foldName), not plain lowercasing.
func fieldTable(fields ...string) map[string]string {
	table := make(map[string]string, len(fields))
	for _, f := range fields {
		table[foldName(f)] = f
	}
	return table
}

// foldName normalizes a JSON object key the way encoding/json matches
// struct field names: every rune is replaced by the smallest rune of its
// Unicode simple case-folding orbit. Besides ASCII case this also folds
// compatibility spellings the decoder accepts, such as "ſ" (U+017F, Latin
// small long s) onto "s" and "K" (U+212A, Kelvin sign) onto "k", so a key
// like "ſeverity" names the same field as "severity" here too.
func foldName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

// foldRune returns the smallest rune in r's simple case-folding orbit,
// mirroring the fold encoding/json applies to field names.
func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}

// nestedObjectSpec pairs a nested object's field table with the label used
// in its duplicate-field errors.
type nestedObjectSpec struct {
	fields map[string]string
	label  string
}
