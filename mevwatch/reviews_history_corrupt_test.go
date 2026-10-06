package mevwatch

// Regression coverage for the historical side of `reviews evaluate`: when
// a user re-evaluates an inclusive height range on one chain against a
// candidate rule version, every archived report the judgment reads inside
// that chain and range must first pass the exact integrity proof a
// `report` query enforces. A written null used to be explained as the
// built-in rules and an incomplete declaration used to evaluate under
// silently zeroed parameters; a legal candidate can never make the
// damaged history participate. Only an old-format record with no version
// key at all keeps the built-in interpretation. One damaged report fails
// the whole evaluation with ErrCorruptVersion naming the chain, the
// block, the readable saved version id and the offending rule or field —
// no statistics and no partial details for the intact blocks. Reports on
// other chains or outside the range are never read and cannot block the
// evaluation. The evaluation stays read-only.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// assertEvaluateRefused runs one failing EvaluateReviews and pins the
// failure shape: ErrCorruptVersion wrapping the cause, never an
// unknown-version misread, naming the target chain and block plus every
// required extra substring, returning no partial result and leaving the
// archive byte-identical. A second attempt fails the same way: the
// declaration is neither repaired nor completed.
func assertEvaluateRefused(t *testing.T, dir, chain string, start, end uint64, candidate string, want ...string) {
	t.Helper()
	before := readArchiveFile(t, dir)
	result, err := EvaluateReviews(dir, chain, start, end, candidate)
	if err == nil {
		t.Fatalf("corrupt historical declaration evaluated successfully: %+v", result)
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("corrupt historical declaration misreported as an unknown version: %v", err)
	}
	msg := err.Error()
	for _, sub := range append([]string{"archived report", "chain " + chain}, want...) {
		if !strings.Contains(msg, sub) {
			t.Fatalf("error %q must name %q", msg, sub)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed evaluation changed the archive")
	}
	if _, err := EvaluateReviews(dir, chain, start, end, candidate); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("second evaluation did not fail the same way: %v", err)
	}
}

// TestEvaluateCorruptSavedVersionRefused runs the full corruption matrix
// against the declaration embedded in the in-range archived report (the
// versions registry and the candidate stay intact): every way the saved
// document can stop satisfying the registration rules must fail the
// whole evaluation, naming chain, block, the readable saved id
// ("builtin" — an id written as builtin must not bypass the check) and
// the offending rule or field.
func TestEvaluateCorruptSavedVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupReviewCorruptArchive(t)
			submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
			rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			// The candidate (mult3) is itself intact; its legality must
			// not rescue the damaged historical declaration.
			assertEvaluateRefused(t, dir, "1", 0, 100, "mult3",
				"block 0xa", BuiltinVersionID, tc.wantErr)
		})
	}
}

// TestEvaluateNullAndEmptySavedVersionCorrupt pins the exact misread
// being fixed: version:null used to leave the decoded version pointer
// nil and be explained as the built-in rules, and {} or an incomplete
// object evaluated under zeroed parameters. All of these fail; only a
// wholly missing version key is the legacy built-in shape.
func TestEvaluateNullAndEmptySavedVersionCorrupt(t *testing.T) {
	cases := []struct {
		name        string
		value       any
		idReachable bool
	}{
		{"null", nil, false},
		{"empty object", map[string]any{}, false},
		{"incomplete object", map[string]any{"id": "archA"}, true},
		{"non-object number", 5, false},
		{"non-object string", "builtin", false},
		{"array", []any{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupReviewCorruptArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xa", tc.value)
			want := []string{"block 0xa"}
			if tc.idReachable {
				want = append(want, "archA")
			}
			assertEvaluateRefused(t, dir, "1", 0, 100, "mult3", want...)
		})
	}
}

// TestEvaluateMissingAndEmptyVersionIDCorrupt covers an object that is
// otherwise complete but loses its identifier: the failure still has to
// say which report's declaration is broken even though no id can be
// read, and an explicit empty id is not the legacy shape.
func TestEvaluateMissingAndEmptyVersionIDCorrupt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"id missing", map[string]any{
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
			},
		}},
		{"id empty", map[string]any{
			"id": "",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
			},
		}},
		{"id null", map[string]any{
			"id": nil,
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupReviewCorruptArchive(t)
			replaceStoredReportVersion(t, dir, "1", "0xa", tc.value)
			// No id is readable, but the message still names the report.
			assertEvaluateRefused(t, dir, "1", 0, 100, "mult3", "block 0xa")
		})
	}
}

// TestEvaluateBuiltinIDDoesNotBypassValidation proves an id of
// "builtin" names the same saved declaration as any other id and is
// validated in full rather than substituting the in-code builtin rules.
func TestEvaluateBuiltinIDDoesNotBypassValidation(t *testing.T) {
	dir := setupReviewCorruptArchive(t)
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))

	builtinFull := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", builtinFull)
	got, err := EvaluateReviews(dir, "1", 0, 100, "mult3")
	if err != nil {
		t.Fatalf("a complete builtin-id declaration must evaluate: %v", err)
	}
	if got.Version.ID != "mult3" || got.StillHit != 1 || got.Pending != 1 {
		t.Fatalf("complete builtin-id history counts wrong: %+v", got)
	}
	var original RuleVersion
	for _, d := range got.Details {
		if d.Original != nil {
			original = d.Original.Version
			break
		}
	}
	if original != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin parameters", original)
	}

	// The same id with a missing field is corrupt and names "builtin"
	// rather than silently substituting it.
	builtinDamaged := map[string]any{
		"id": "builtin",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 3},
			"displacement": map[string]any{"enabled": true, "severity": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", builtinDamaged)
	assertEvaluateRefused(t, dir, "1", 0, 100, "builtin",
		"block 0xa", BuiltinVersionID, "multiplier")
}

// patchSavedReportDeclaration rewrites raw bytes inside the embedded
// declaration of record chain/hash, used for decay a JSON decoder would
// silently collapse (repeated fields). The record also carries
// per-finding "severity" keys before its version object, so the anchor is
// searched only after the embedded declaration's own id key.
func patchSavedReportDeclaration(t *testing.T, dir, chain, hash, id, anchor, insert string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	versionsAt := strings.Index(text, `"versions":`)
	if versionsAt < 0 {
		versionsAt = len(text)
	}
	recordMark := `"blockHash": "` + hash + `"`
	at := strings.Index(text[:versionsAt], recordMark)
	if at < 0 {
		t.Fatalf("record for chain %s block %s not found", chain, hash)
	}
	idMark := `"id": "` + id + `"`
	idAt := strings.Index(text[at:versionsAt], idMark)
	if idAt < 0 {
		t.Fatalf("embedded declaration id %q not found in record %s/%s", id, chain, hash)
	}
	declAt := at + idAt
	field := strings.Index(text[declAt:versionsAt], anchor)
	if field < 0 {
		t.Fatalf("anchor %q not found in embedded declaration", anchor)
	}
	pos := declAt + field
	patched := text[:pos] + insert + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestEvaluateDuplicateFieldsInSavedVersionRefused covers decay
// registration could never have produced: a repeated field in the saved
// declaration, including an escaped spelling and a case-only spelling
// naming the same field, even when both values agree. The two rules each
// declaring their own enabled/severity is not a repeat.
func TestEvaluateDuplicateFieldsInSavedVersionRefused(t *testing.T) {
	cases := []struct{ name, field string }{
		{"exact", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupReviewCorruptArchive(t)
			submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
			patchSavedReportDeclaration(t, dir, "1", "0xa", BuiltinVersionID, `"severity": 3`, dup.field)
			_, err := EvaluateReviews(dir, "1", 0, 100, "mult3")
			if err == nil {
				t.Fatalf("duplicate-field declaration evaluated")
			}
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
			if !strings.Contains(err.Error(), "0xa") || !strings.Contains(err.Error(), "severity") {
				t.Fatalf("error must name block 0xa and severity, got %v", err)
			}
			if after := readArchiveFile(t, dir); !strings.Contains(string(after), dup.field) {
				t.Fatalf("failed evaluation repaired the duplicate field")
			}
		})
	}
}

// TestEvaluateExplicitlyDisabledHistoricalRulesAccepted proves
// enabled:false is a legal historical off state, but a disabled rule
// still has to carry complete, in-range parameters.
func TestEvaluateExplicitlyDisabledHistoricalRulesAccepted(t *testing.T) {
	dir := setupReviewCorruptArchive(t)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))
	off := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false, "severity": 1},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", off)
	got, err := EvaluateReviews(dir, "1", 0, 100, "mult3")
	if err != nil {
		t.Fatalf("an explicitly disabled, complete declaration must evaluate: %v", err)
	}
	// History says both rules off; the stored sandwich conclusion under
	// mult3 (candidate) still fires, so the reviewed real risk is
	// retained, and its historical parameters are carried as saved.
	if got.Retained != 1 {
		t.Fatalf("disabled-history counts = %+v", got)
	}
	for _, d := range got.Details {
		if d.Original != nil && d.Original.Version.ID != "off" {
			t.Fatalf("historical parameters not carried: %+v", d.Original.Version)
		}
		if d.Original != nil && (d.Original.Version.Rules.Sandwich.Enabled ||
			d.Original.Version.Rules.Displacement.Enabled) {
			t.Fatalf("historical off state not carried: %+v", d.Original.Version)
		}
	}

	offBroken := map[string]any{
		"id": "off",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": false},
			"displacement": map[string]any{"enabled": false, "severity": 1, "multiplier": 2},
		},
	}
	replaceStoredReportVersion(t, dir, "1", "0xa", offBroken)
	assertEvaluateRefused(t, dir, "1", 0, 100, "mult3",
		"block 0xa", "off", "sandwich", "severity")
}

// TestEvaluateCorruptHistoryEmptyAndNoReviewBlocks proves the
// historical proof cannot be skipped by an empty judgment: a block with
// no swaps and a block whose findings are empty (archived under a
// both-off version) both fail outright when their declaration is
// damaged, and so does a block that never carried any manual review.
func TestEvaluateCorruptHistoryEmptyAndNoReviewBlocks(t *testing.T) {
	bothOff := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`

	t.Run("no swaps block", func(t *testing.T) {
		dir := t.TempDir()
		mustRegisterVersion(t, dir, bothOff)
		input := `{"chainId":"1","blockHash":"0empty","blockNumber":3,"swaps":[]}`
		if _, err := ReplayWithVersion(strings.NewReader(input), dir, "off"); err != nil {
			t.Fatalf("ReplayWithVersion: %v", err)
		}
		rewriteStoredReportVersion(t, dir, "1", "0empty", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		assertEvaluateRefused(t, dir, "1", 0, 100, BuiltinVersionID, "block 0empty", "multiplier")
	})

	t.Run("no findings block", func(t *testing.T) {
		dir := t.TempDir()
		mustRegisterVersion(t, dir, bothOff)
		// 15 does not dominate 10 even under multiplier 2: no conclusions.
		input := `{"chainId":"1","blockHash":"0quiet","blockNumber":4,"swaps":[` +
			`{"TxHash":"0g0","Pool":"p","Trader":"w","In":1,"Out":1,"GasPrice":15,"Index":0},` +
			`{"TxHash":"0g1","Pool":"p","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`
		if _, err := ReplayWithVersion(strings.NewReader(input), dir, "off"); err != nil {
			t.Fatalf("ReplayWithVersion: %v", err)
		}
		rewriteStoredReportVersion(t, dir, "1", "0quiet", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["severity"] = 0
		})
		assertEvaluateRefused(t, dir, "1", 0, 100, BuiltinVersionID, "block 0quiet", "severity")
	})

	t.Run("block without any review", func(t *testing.T) {
		dir := setupReviewCorruptArchive(t)
		rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		assertEvaluateRefused(t, dir, "1", 0, 100, "mult3", "block 0xa", "multiplier")
	})
}

// TestEvaluateCorruptHistoryRangeAndChainScoping pins that only reports
// on the selected chain inside the inclusive range are read: a damaged
// declaration on another chain or outside the range must not block the
// evaluation, while a record exactly on either boundary is proved.
func TestEvaluateCorruptHistoryRangeAndChainScoping(t *testing.T) {
	t.Run("other chain corrupt never blocks", func(t *testing.T) {
		dir := setupReviewCorruptArchive(t)
		submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
		// A second block at the same height on another chain with a
		// damaged declaration.
		mustReplay(t, dir, strings.Replace(strings.Replace(twoFindingsInput,
			`"chainId":"1"`, `"chainId":"2"`, 1), `"blockHash":"0xa"`, `"blockHash":"0xa2"`, 1))
		rewriteStoredReportVersion(t, dir, "2", "0xa2", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		got, err := EvaluateReviews(dir, "1", 0, 100, "mult3")
		if err != nil {
			t.Fatalf("a corrupt other-chain report must not block: %v", err)
		}
		if got.StillHit != 1 || got.Pending != 1 {
			t.Fatalf("chain-1 counts = %+v", got)
		}
		for _, d := range got.Details {
			if d.ChainID != "1" {
				t.Fatalf("other-chain detail leaked in: %+v", d)
			}
		}
		// Evaluating the damaged chain still fails outright.
		assertEvaluateRefused(t, dir, "2", 0, 100, "mult3", "block 0xa2", "multiplier")
	})

	t.Run("out of range corrupt never blocks", func(t *testing.T) {
		dir := setupReviewCorruptArchive(t) // block at height 10
		rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
		got, err := EvaluateReviews(dir, "1", 11, 100, "mult3")
		if err != nil {
			t.Fatalf("a corrupt out-of-range report must not block: %v", err)
		}
		if len(got.Details) != 0 || got.Pending != 0 {
			t.Fatalf("range above the corrupt record must be empty: %+v", got)
		}
		got, err = EvaluateReviews(dir, "1", 0, 9, "mult3")
		if err != nil {
			t.Fatalf("a corrupt out-of-range report must not block: %v", err)
		}
		if len(got.Details) != 0 {
			t.Fatalf("range below the corrupt record must be empty: %+v", got)
		}
	})

	t.Run("inclusive boundaries are proved", func(t *testing.T) {
		dir := setupReviewCorruptArchive(t) // block at height 10
		rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
			storedRule(t, ver, "displacement")["multiplier"] = 0
		})
		for _, r := range [][2]uint64{{10, 10}, {0, 10}, {10, 100}} {
			if _, err := EvaluateReviews(dir, "1", r[0], r[1], "mult3"); !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("range %d..%d must prove the boundary block, got %v", r[0], r[1], err)
			}
		}
	})
}

// TestEvaluateCorruptHistoryNoPartialResults proves one damaged report
// fails the whole evaluation even when intact blocks sit beside it:
// there are never statistics or details for the intact blocks, and the
// error names the damaged report specifically.
func TestEvaluateCorruptHistoryNoPartialResults(t *testing.T) {
	dir := t.TempDir()
	mustRegisterVersion(t, dir, mult3Spec)
	// Intact block at height 8 hash 0xc.
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xc","blockNumber":8,"swaps":[`+
		`{"TxHash":"0xf1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0h1","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0z1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":80,"Index":2}]}`)
	// Damaged block at height 10 hash 0xa.
	mustReplay(t, dir, twoFindingsInput)
	submit(t, dir, reviewSub("1", "0xc", "0h1", "sandwich", "r", "a", "real", ReviewStatusReal, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
	rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	result, err := EvaluateReviews(dir, "1", 0, 100, "mult3")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if result.Details != nil || result.Retained+result.Missed+result.StillHit+result.Eliminated+result.Pending != 0 {
		t.Fatalf("damaged history must yield no partial result, got %+v", result)
	}
	if !strings.Contains(err.Error(), "block 0xa") || strings.Contains(err.Error(), "0xc") {
		t.Fatalf("error must name the damaged block 0xa, got %v", err)
	}

	// Same height, a different hash is an independent report: damaging
	// only one of them fails naming that hash and never the intact one.
	mustReplay(t, dir, strings.Replace(twoFindingsInput, `"blockHash":"0xa"`, `"blockHash":"0xb"`, 1))
	_, err = EvaluateReviews(dir, "1", 0, 100, "mult3")
	if !errors.Is(err, ErrCorruptVersion) || !strings.Contains(err.Error(), "0xa") {
		t.Fatalf("error must stay pinned to the damaged hash 0xa, got %v", err)
	}
}

// TestEvaluateUsesSavedParametersNotRegistry proves the historical side
// is explained by the declaration the report archived: a same-id
// registry entry is neither consulted nor able to complete the saved
// parameters, and a complete saved id the registry never carried is
// still valid on its own.
func TestEvaluateUsesSavedParametersNotRegistry(t *testing.T) {
	// Damage the registered builtin... builtin is in code; instead damage
	// the mult3 registry entry while the report's own embedded
	// declaration (builtin) stays intact: evaluation still works.
	dir := setupReviewCorruptArchive(t)
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
	rewriteStoredVersion(t, dir, "mult3", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatalf("a corrupt registry sibling must not block an intact builtin evaluation: %v", err)
	}
	if got.StillHit != 1 {
		t.Fatalf("intact-history counts = %+v", got)
	}

	// Conversely, an intact registry cannot rescue a corrupt report:
	// damage only the report's own copy while the candidate stays intact.
	dir2 := setupReviewCorruptArchive(t)
	rewriteStoredReportVersion(t, dir2, "1", "0xa", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	assertEvaluateRefused(t, dir2, "1", 0, 100, "mult3", "block 0xa", "multiplier")

	// A complete declaration with an id the registry never carried is
	// valid on its own; its parameters (multiplier 9) are carried into
	// the details and need no registry backing.
	dir3 := setupReviewCorruptArchive(t)
	stray := map[string]any{
		"id": "never-registered",
		"rules": map[string]any{
			"sandwich":     map[string]any{"enabled": true, "severity": 5},
			"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
		},
	}
	replaceStoredReportVersion(t, dir3, "1", "0xa", stray)
	r3, err := EvaluateReviews(dir3, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatalf("a complete self-contained declaration must not need registry backing: %v", err)
	}
	found := false
	for _, d := range r3.Details {
		if d.Original == nil {
			continue
		}
		if d.Original.Version.ID != "never-registered" ||
			d.Original.Version.Rules.Displacement.Multiplier != 9 ||
			d.Original.Version.Rules.Sandwich.Severity != 5 {
			t.Fatalf("saved historical parameters not carried: %+v", d.Original.Version)
		}
		found = true
	}
	if !found {
		t.Fatalf("no detail carried the historical version: %+v", r3.Details)
	}
}

// TestEvaluateLegacyRecordStillBuiltin proves the single carve-out is
// unchanged by the fix: a record with no version key at all evaluates
// with the built-in historical side, its stored conclusions, review
// classifications and swap evidence intact.
func TestEvaluateLegacyRecordStillBuiltin(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[` +
		`{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	submit(t, dir, reviewSub("1", "0old", "0v", "sandwich", "s", "a", "r", ReviewStatusReal, 0))
	got, err := EvaluateReviews(dir, "1", 0, 100, BuiltinVersionID)
	if err != nil {
		t.Fatalf("legacy record must evaluate under builtin: %v", err)
	}
	if got.Retained != 1 || len(got.Details) != 1 {
		t.Fatalf("legacy evaluation = %+v", got)
	}
	d := got.Details[0]
	if d.Original == nil || d.Original.Version != BuiltinVersion() {
		t.Fatalf("historical side = %+v, want builtin", d.Original)
	}
	if d.Original.Finding.Severity != 3 || len(d.Original.Finding.Evidence) != 3 {
		t.Fatalf("legacy findings/evidence damaged: %+v", d.Original.Finding)
	}
}

// TestEvaluateCorruptHistoryReadOnly proves a refused evaluation
// rewrites neither reports, reviews, the enabled version nor the
// archive bytes, and the same declaration keeps failing through the
// other read entries (report query, compare).
func TestEvaluateCorruptHistoryReadOnly(t *testing.T) {
	dir := setupReviewCorruptArchive(t)
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
	rewriteStoredReportVersion(t, dir, "1", "0xa", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	corruptBytes := readArchiveFile(t, dir)
	if _, err := EvaluateReviews(dir, "1", 0, 100, "mult3"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(corruptBytes, after) {
		t.Fatalf("failed evaluation modified the archive")
	}
	// The review revision stays stored and the candidate registry is
	// untouched.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xd", "displacement")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Version != 1 || hist.Status != ReviewStatusFalsePositive {
		t.Fatalf("review changed after refused evaluation: %+v", hist)
	}
	if _, err := Query(dir, "1", "0xa"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("report query on the same corrupt declaration changed shape: %v", err)
	}
	if _, err := Compare(dir, "1", "0xa", "mult3"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("compare on the same corrupt declaration changed shape: %v", err)
	}
}
