package mevwatch

// Regression coverage for the per-block report query behind the `report`
// entry. A query must prove the version declaration the record was
// archived with still satisfies the registration rules in full before the
// report is returned, exactly the way a replay, a comparison and a
// review-range evaluation already refuse corrupt versions. A record whose
// saved parameters decayed — a missing, null, wrong-typed or out-of-range
// field, an unknown field, or a field declared twice in one object — fails
// with ErrCorruptVersion instead of being shown with silently zeroed or
// substituted parameters; only a record with no version field at all keeps
// the legacy built-in interpretation. The query never re-detects, never
// completes parameters from the registry or the enabled version, and never
// modifies the archive.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// queryRecordRules is the rules half of the candC declaration the fixture
// records are archived under: sandwich explicitly off, displacement
// severity 4 with multiplier 2.
const queryRecordRules = `"rules":{"sandwich":{"enabled":false,"severity":3},` +
	`"displacement":{"enabled":true,"severity":4,"multiplier":2}}`

// setupQueryArchive registers candC and archives one block under it,
// returning the archive dir and the report the replay produced. The
// record's stored version document is the exact candC declaration.
func setupQueryArchive(t *testing.T) (dir string, want Report) {
	t.Helper()
	dir = t.TempDir()
	register(t, dir, candidateVersionSpec)
	reports, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC")
	if err != nil {
		t.Fatalf("ReplayWithVersion: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	return dir, reports[0]
}

// setStoredRecordVersion replaces the stored version document of one
// archived record with rawVersion, simulating an archive whose record
// declaration no longer satisfies the registration rules even though the
// file is still valid JSON. The raw text is spliced in verbatim, so
// documents a decoded struct could never represent — repeated fields,
// escaped spellings — are expressible.
func setStoredRecordVersion(t *testing.T, dir, chainID, blockHash, rawVersion string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(doc["records"], &records); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, rec := range records {
		var cid, bh string
		if err := json.Unmarshal(rec["chainId"], &cid); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(rec["blockHash"], &bh); err != nil {
			t.Fatal(err)
		}
		if cid == chainID && bh == blockHash {
			rec["version"] = json.RawMessage(rawVersion)
			found = true
		}
	}
	if !found {
		t.Fatalf("record %s/%s not archived", chainID, blockHash)
	}
	recRaw, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	doc["records"] = recRaw
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// queryCorruptVersionDocs is the full matrix of ways an archived record's
// stored version document can stop satisfying the registration rules:
// missing, null, wrong-typed or out-of-range fields on either rule
// (including a rule explicitly disabled), missing rule/rules objects,
// unknown fields or rules, and fields declared twice in one object —
// exactly, through escapes, or through the case-folded spellings the
// decoder treats as one name. A present but empty or null version and an
// id reading "builtin" are corruption too, never the legacy or the
// built-in interpretation.
var queryCorruptVersionDocs = []struct {
	name    string
	doc     string
	wantErr string // substring naming the offending rule or field
	wantID  string // version id the document still carries, "" when unreadable
}{
	{"version null", `null`, "null", ""},
	{"version string", `"candC"`, "object", ""},
	{"version array", `[]`, "array", ""},
	{"version empty object", `{}`, "id", ""},
	{"id empty", `{"id":"",` + queryRecordRules + `}`, "id", ""},
	{"id missing", `{` + queryRecordRules + `}`, "id", ""},
	{"id null", `{"id":null,` + queryRecordRules + `}`, "id", ""},
	{"rules missing", `{"id":"candC"}`, "rules", "candC"},
	{"rules null", `{"id":"candC","rules":null}`, "rules", "candC"},
	{"sandwich missing",
		`{"id":"candC","rules":{"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`,
		"sandwich", "candC"},
	{"sandwich null",
		`{"id":"candC","rules":{"sandwich":null,"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`,
		"sandwich", "candC"},
	{"displacement missing",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3}}}`,
		"displacement", "candC"},
	{"multiplier missing",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4}}}`,
		"multiplier", "candC"},
	{"multiplier zero",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":0}}}`,
		"multiplier", "candC"},
	{"multiplier below range",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":1}}}`,
		"multiplier", "candC"},
	{"multiplier above range",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":101}}}`,
		"multiplier", "candC"},
	{"multiplier null",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":null}}}`,
		"multiplier", "candC"},
	{"multiplier wrong type",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":"2"}}}`,
		"multiplier", "candC"},
	{"displacement severity missing",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"multiplier":2}}}`,
		"severity", "candC"},
	{"displacement severity zero",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":0,"multiplier":2}}}`,
		"severity", "candC"},
	{"displacement severity above range",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":6,"multiplier":2}}}`,
		"severity", "candC"},
	{"displacement severity null",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":null,"multiplier":2}}}`,
		"severity", "candC"},
	{"displacement enabled missing",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"severity":4,"multiplier":2}}}`,
		"enabled", "candC"},
	{"displacement enabled null",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":null,"severity":4,"multiplier":2}}}`,
		"enabled", "candC"},
	{"displacement enabled wrong type",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":"true","severity":4,"multiplier":2}}}`,
		"enabled", "candC"},
	// The sandwich rule is disabled in candC, but a disabled rule must
	// still declare complete, in-range parameters; an explicit false is a
	// legal off state and stays valid.
	{"disabled sandwich severity zero",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":0},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`,
		"severity", "candC"},
	{"disabled sandwich enabled missing",
		`{"id":"candC","rules":{"sandwich":{"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`,
		"enabled", "candC"},
	{"unknown field",
		`{"id":"candC","extra":1,` + queryRecordRules + `}`, "extra", "candC"},
	{"unknown rule",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},` +
			`"displacement":{"enabled":true,"severity":4,"multiplier":2},` +
			`"frontrun":{"enabled":true,"severity":1}}}`,
		"frontrun", "candC"},
	// A field declared twice in one object is damage even when both
	// occurrences carry the same value: exact repeats, escape-encoded
	// repeats and case-folded spellings of one known name alike.
	{"duplicate id same value",
		`{"id":"candC","id":"candC",` + queryRecordRules + `}`, "duplicate", "candC"},
	{"duplicate id escaped",
		`{"id":"candC","\u0069d":"candC",` + queryRecordRules + `}`, "duplicate", "candC"},
	{"duplicate severity case-folded",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3,"Severity":3},` +
			`"displacement":{"enabled":true,"severity":4,"multiplier":2}}}`,
		"duplicate", "candC"},
	// An id reading "builtin" does not bypass the validation of the saved
	// declaration: an incomplete one is corruption like any other.
	{"builtin id incomplete", `{"id":"builtin"}`, "rules", "builtin"},
	{"builtin id null rules", `{"id":"builtin","rules":null}`, "rules", "builtin"},
}

// TestQueryCorruptRecordVersionRefused runs the full corruption matrix
// against the record's stored version declaration: every shape must fail
// the query with ErrCorruptVersion naming the chain, the block, the
// offending rule or field, and the stored version id whenever the document
// still carries a readable one — never an unknown-version or unknown-block
// error, and never a report built from zeroed or substituted parameters.
func TestQueryCorruptRecordVersionRefused(t *testing.T) {
	for _, tc := range queryCorruptVersionDocs {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := setupQueryArchive(t)
			setStoredRecordVersion(t, dir, "1", "0xa", tc.doc)
			before := readArchiveFile(t, dir)

			report, err := Query(dir, "1", "0xa")
			if err == nil {
				t.Fatalf("corrupt record version queried successfully: %+v", report)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrUnknownBlock) {
				t.Fatalf("corruption misreported as unknown version/block: %v", err)
			}
			for _, want := range []string{"1", "0xa", tc.wantErr} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error must name %q, got %v", want, err)
				}
			}
			if tc.wantID != "" && !strings.Contains(err.Error(), tc.wantID) {
				t.Fatalf("error must name the stored version id %q, got %v", tc.wantID, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused query changed the archive")
			}
		})
	}
}

// TestQueryCorruptRecordVersionDuplicateEscaped pins the escaped-spelling
// case separately so the raw document keeps its exact bytes: "id" and
// "\u0069d" decode to the same name and cannot share one object even
// with identical values.
func TestQueryCorruptRecordVersionDuplicateEscaped(t *testing.T) {
	dir, _ := setupQueryArchive(t)
	setStoredRecordVersion(t, dir, "1", "0xa",
		`{"id":"candC","\u0069d":"candC",`+queryRecordRules+`}`)
	_, err := Query(dir, "1", "0xa")
	if !errors.Is(err, ErrCorruptVersion) || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("escaped duplicate id error = %v, want ErrCorruptVersion naming the duplicate", err)
	}
}

// TestQueryIntactRecordVersion proves the successful path returns the
// archived report exactly as the replay produced it — identity, height,
// swap count, conclusions and evidence in their archived order — judged by
// the record's own saved parameters, with no re-detection.
func TestQueryIntactRecordVersion(t *testing.T) {
	dir, want := setupQueryArchive(t)
	got, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report changed between replay and query:\nreplay=%+v\nquery =%+v", want, got)
	}
	if got.ChainID != "1" || got.BlockHash != "0xa" || got.BlockNumber != 10 || got.SwapCount != 3 {
		t.Fatalf("block identity wrong: %+v", got)
	}
	if got.Version.ID != "candC" || got.Version.Rules.Sandwich.Enabled ||
		got.Version.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("report does not carry its own saved parameters: %+v", got.Version)
	}
	if len(got.Findings) != 1 || got.Findings[0].Kind != "displacement" ||
		got.Findings[0].Severity != 4 || len(got.Findings[0].Evidence) != 2 {
		t.Fatalf("archived conclusions damaged: %+v", got.Findings)
	}
}

// TestQueryRecordVersionSelfContained proves the report uses the
// declaration saved inside the record and nothing else: a corrupt
// registered version of the same id in the versions section and a later
// enabled-version change never alter the returned parameters, and a saved
// declaration whose id reads "builtin" is returned with its own stored
// parameters, not the built-in ones.
func TestQueryRecordVersionSelfContained(t *testing.T) {
	dir, want := setupQueryArchive(t)
	// Damage the registered candC in the versions section; the record's own
	// declaration stays intact and must be all the query consults.
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	register(t, dir, enabledVersionSpec)
	if _, err := EnableVersion(dir, "liveB"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	got, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatalf("query must not consult the registry or the enabled version: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("report parameters followed the registry or the enabled version:\nwant %+v\ngot  %+v", want, got)
	}

	// A complete saved declaration whose id reads "builtin" is judged on
	// its own bytes and returned with its own parameters.
	setStoredRecordVersion(t, dir, "1", "0xa",
		`{"id":"builtin","rules":{"sandwich":{"enabled":true,"severity":5},`+
			`"displacement":{"enabled":false,"severity":1,"multiplier":100}}}`)
	got, err = Query(dir, "1", "0xa")
	if err != nil {
		t.Fatalf("complete saved declaration refused: %v", err)
	}
	if got.Version.ID != "builtin" || got.Version.Rules.Sandwich.Severity != 5 ||
		got.Version.Rules.Displacement.Enabled || got.Version.Rules.Displacement.Multiplier != 100 {
		t.Fatalf("saved declaration replaced by the built-in parameters: %+v", got.Version)
	}
}

// TestQueryLegacyRecordWithoutVersion confirms a record with no version
// field at all — archives written before rule versions existed — keeps the
// built-in interpretation, while an explicit null, an empty object or an
// incomplete declaration on the same shape of record is corruption.
func TestQueryLegacyRecordWithoutVersion(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"records":[{"chainId":"1","blockHash":"0old","blockNumber":5,` +
		`"swaps":[{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0v","evidence":[` +
		`{"TxHash":"0f","Pool":"p1","Trader":"bot","In":7,"Out":6,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0v","Pool":"p1","Trader":"user","In":5,"Out":4,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0b","Pool":"p1","Trader":"bot","In":3,"Out":5,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Query(dir, "1", "0old")
	if err != nil {
		t.Fatalf("legacy record query failed: %v", err)
	}
	if !reflect.DeepEqual(report.Version, BuiltinVersion()) {
		t.Fatalf("legacy record must be explained as builtin: %+v", report.Version)
	}
	if report.SwapCount != 3 || len(report.Findings) != 1 || report.Findings[0].Kind != "sandwich" {
		t.Fatalf("legacy report content damaged: %+v", report)
	}
}

// TestQueryCorruptRecordDoesNotBlockSibling proves one record's corrupt
// version declaration is that record's damage only: an intact sibling
// block on the same chain still queries normally, and an unknown identity
// stays an unknown-block failure.
func TestQueryCorruptRecordDoesNotBlockSibling(t *testing.T) {
	dir, _ := setupQueryArchive(t)
	second := cmpBlockLine("1", "0xb", 11,
		cmpSwap("0xg", "p1", "w", 40, 0),
		cmpSwap("0xh", "p1", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(second), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	setStoredRecordVersion(t, dir, "1", "0xa",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4}}}`)

	if _, err := Query(dir, "1", "0xa"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt record error = %v, want ErrCorruptVersion", err)
	}
	report, err := Query(dir, "1", "0xb")
	if err != nil {
		t.Fatalf("corrupt sibling blocked an intact record: %v", err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" {
		t.Fatalf("sibling report damaged: %+v", report)
	}
	if _, err := Query(dir, "1", "0xghost"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block error = %v, want ErrUnknownBlock", err)
	}
	if _, err := Query(dir, "2", "0xa"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown chain error = %v, want ErrUnknownBlock", err)
	}
}

// TestQueryReadOnly proves the query never writes: success, corruption
// refusal and unknown-block failure all leave the archive file byte for
// byte identical.
func TestQueryReadOnly(t *testing.T) {
	dir, _ := setupQueryArchive(t)
	setStoredRecordVersion(t, dir, "1", "0xa",
		`{"id":"candC","rules":{"sandwich":{"enabled":false,"severity":3},"displacement":{"enabled":true,"severity":4,"multiplier":0}}}`)
	second := cmpBlockLine("1", "0xb", 11,
		cmpSwap("0xg", "p1", "w", 40, 0),
		cmpSwap("0xh", "p1", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(second), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)

	if _, err := Query(dir, "1", "0xa"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt record error = %v", err)
	}
	if _, err := Query(dir, "1", "0xb"); err != nil {
		t.Fatalf("intact record query failed: %v", err)
	}
	if _, err := Query(dir, "1", "0xghost"); !errors.Is(err, ErrUnknownBlock) {
		t.Fatalf("unknown block error = %v", err)
	}

	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("queries changed the archive")
	}
}
