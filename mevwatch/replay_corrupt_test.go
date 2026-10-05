package mevwatch

// Regression coverage for replaying against a corrupt archived rule
// version. A replay must prove the version it selected — explicitly via
// --version or implicitly through the archive's enabled marker — still
// satisfies the registration rules in full before it produces any report,
// exactly the way a single-block comparison and a review-range evaluation
// already refuse such versions. The corrupt content is never replaced by
// the enabled version, the built-in rules or defaults; a corrupt version
// is never misreported as unknown; and a refused replay leaves the archive
// — reports, rules, the enabled marker, alert records and reviews — byte
// for byte untouched.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// replayCorruptInput is one new block whose adjacent same-pool swaps hit
// displacement under any intact multiplier — the input shape that crashed
// detection when a stored multiplier decayed to zero.
var replayCorruptInput = cmpBlockLine("1", "0xnew", 8,
	cmpSwap("0xn1", "p1", "w", 40, 0),
	cmpSwap("0xn2", "p1", "u", 10, 1),
)

// readArchiveFile returns the archive file's exact bytes.
func readArchiveFile(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestReplayCorruptVersionRefused runs the full corruption matrix against
// an explicitly named replay version: every way a stored version document
// can stop satisfying the registration rules must fail the whole replay
// with ErrCorruptVersion before any report is produced.
func TestReplayCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			reports, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "candC")
			if err == nil {
				t.Fatalf("corrupt version replayed successfully: %+v", reports)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corruption misreported as unknown version: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the selected version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if reports != nil {
				t.Fatalf("a refused replay must return no reports, got %+v", reports)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused replay changed the archive")
			}
		})
	}
}

// TestReplayCorruptEnabledVersionRefused runs the same matrix against the
// archive's enabled version: a plain replay without --version selects it
// and must refuse it just the same. The version is enabled before the
// stored document is damaged.
func TestReplayCorruptEnabledVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			if _, err := EnableVersion(dir, "candC"); err != nil {
				t.Fatalf("EnableVersion: %v", err)
			}
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			// Blank-lines-only input: the refusal is decided by the selected
			// version, never by whether any input block triggers the rule.
			_, err := Replay(strings.NewReader("\n  \n"), dir)
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name version candC and field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused replay changed the archive")
			}
		})
	}
}

// TestReplayCorruptVersionInputShapes proves the refusal is independent of
// the input: an empty-swaps block, a block already archived with identical
// content, and a file holding only blank lines all fail the same way, and
// a batch mixing an already archived block with a new one produces no
// partial success — no report for the old block, no archived new block.
func TestReplayCorruptVersionInputShapes(t *testing.T) {
	archivedLine := cmpBlockLine("1", "0xblk", 7,
		cmpSwap("0xf", "p1", "w", 40, 0),
		cmpSwap("0xv", "p1", "u", 10, 1),
	)
	cases := []struct {
		name  string
		input string
	}{
		{"empty swaps block", `{"chainId":"1","blockHash":"0xempty","blockNumber":3,"swaps":[]}`},
		{"identical archived block", archivedLine},
		{"blank lines only", "\n   \n\t\n"},
		{"archived block then new block", archivedLine + "\n" + replayCorruptInput},
		{"new block then archived block", replayCorruptInput + "\n" + archivedLine},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				delete(storedRule(t, ver, "displacement"), "multiplier")
			})
			before := readArchiveFile(t, dir)

			reports, err := ReplayWithVersion(strings.NewReader(tc.input), dir, "candC")
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if reports != nil {
				t.Fatalf("partial success leaked reports: %+v", reports)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused replay changed the archive")
			}
			// The new block from the mixed batches was never archived.
			if _, err := Query(dir, "1", "0xnew"); !errors.Is(err, ErrUnknownBlock) {
				t.Fatalf("new block archived by a refused replay: %v", err)
			}
		})
	}
}

// TestReplayCorruptVersionDistinctFromUnknown pins the boundary: a version
// that was never registered stays an unknown-version failure, a corrupt
// registered version is never misreported as unknown, and a corrupt
// sibling blocks neither an explicitly named intact version nor the
// enabled one.
func TestReplayCorruptVersionDistinctFromUnknown(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	if _, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown version error = %v", err)
	}

	// An explicit replay under the intact twin succeeds against the same
	// archive and judges under twin's parameters.
	reports, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "twin")
	if err != nil {
		t.Fatalf("replay under intact twin failed: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != "twin" ||
		len(reports[0].Findings) != 1 || reports[0].Findings[0].Kind != "displacement" {
		t.Fatalf("replay under twin misjudged: %+v", reports)
	}

	// A plain replay selects the enabled version; with intact twin enabled
	// the corrupt sibling never interferes.
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("EnableVersion: %v", err)
	}
	input2 := cmpBlockLine("1", "0xnew2", 9,
		cmpSwap("0xn3", "p1", "w", 40, 0),
		cmpSwap("0xn4", "p1", "u", 10, 1),
	)
	reports, err = Replay(strings.NewReader(input2), dir)
	if err != nil {
		t.Fatalf("replay under enabled twin failed: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != "twin" {
		t.Fatalf("plain replay did not use the enabled version: %+v", reports)
	}
}

// TestReplayCorruptSiblingPreservedVerbatim proves a successful replay
// under an intact version neither repairs nor drops a corrupt sibling: the
// stored versions section, the enabled marker and every prior record come
// through byte for byte, and the run only appends its new record.
func TestReplayCorruptSiblingPreservedVerbatim(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	// Records are compared semantically: the corruption helper re-marshals
	// the whole file with map key order, the replay write uses struct field
	// order, and both are the same content. The versions section, by
	// contrast, must survive byte for byte.
	type archiveSkeleton struct {
		Records        []record          `json:"records"`
		Versions       []json.RawMessage `json:"versions"`
		EnabledVersion string            `json:"enabledVersion"`
	}
	skeleton := func() archiveSkeleton {
		var s archiveSkeleton
		if err := json.Unmarshal(readArchiveFile(t, dir), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := skeleton()

	if _, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "twin"); err != nil {
		t.Fatalf("replay under intact twin failed: %v", err)
	}

	after := skeleton()
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatalf("stored versions rewritten:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
	if before.EnabledVersion != after.EnabledVersion {
		t.Fatalf("enabled marker changed: %q -> %q", before.EnabledVersion, after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.Records, after.Records[:len(before.Records)]) {
		t.Fatalf("existing records changed")
	}
	if len(after.Records) != len(before.Records)+1 {
		t.Fatalf("records = %d, want exactly one appended", len(after.Records))
	}
}

// TestReplayCorruptVersionPreservesArchive builds an archive holding every
// kind of state — reports, registered versions, the enabled marker, a
// suppression, alert processing records and manual review history — then
// proves a refused replay leaves the file byte-identical: the refusal
// never completes missing fields or fixes bad values in passing.
func TestReplayCorruptVersionPreservesArchive(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	if _, err := ReplayWithVersion(strings.NewReader(sandwichInput), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterSuppression(dir, []byte(
		`{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":1,"endHeight":100,"reason":"r"}`,
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitReview(dir, ReviewSubmission{
		ChainID: "1", BlockHash: "0xa", TxHash: "0xvictim", Kind: "displacement",
		SubmissionID: "rev-1", Operator: "alice", Reason: "looks fine",
		Status: ReviewStatusFalsePositive, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}

	// Damage the enabled version after all state exists: the displacement
	// multiplier vanishes from the stored document.
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	// Both selection paths refuse: the enabled version implicitly...
	if _, err := Replay(strings.NewReader(replayCorruptInput), dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("enabled-version replay error = %v, want ErrCorruptVersion", err)
	}
	// ...and the same version named explicitly.
	if _, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("explicit-version replay error = %v, want ErrCorruptVersion", err)
	}

	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused replays changed the archive:\nbefore=%s\nafter =%s", before, after)
	}

	// Every piece of prior state is still queryable and unchanged.
	report, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" || report.Findings[0].Severity != 4 {
		t.Fatalf("archived report changed: %+v", report)
	}
	history, err := ReviewHistoryQuery(dir, "1", "0xa", "0xvictim", "displacement")
	if err != nil {
		t.Fatal(err)
	}
	if history.Status != ReviewStatusFalsePositive || history.Version != 1 {
		t.Fatalf("review history changed: %+v", history)
	}
	alerts, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Status != AlertStatusSuppressed {
		t.Fatalf("alert records changed: %+v", alerts)
	}
}

// TestReplayCorruptVersionMultiplierZeroNoCrash pins the original crash:
// displacement enabled with the stored multiplier decayed to zero divided
// by zero as soon as one pool held two adjacent swaps. The replay must now
// fail cleanly with ErrCorruptVersion before detection ever runs.
func TestReplayCorruptVersionMultiplierZeroNoCrash(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	// candC's displacement rule is enabled; the input holds two adjacent
	// same-pool swaps, the exact crash trigger.
	_, err := ReplayWithVersion(strings.NewReader(replayCorruptInput), dir, "candC")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if !strings.Contains(err.Error(), "multiplier") {
		t.Fatalf("error must name the multiplier field, got %v", err)
	}
}

// TestReplayLegacyArchiveWithoutVersions confirms pre-version archives are
// untouched by the integrity check: no versions section and no enabled
// marker still means the built-in rules, and a corrupt-free run behaves
// exactly as before.
func TestReplayLegacyArchiveWithoutVersions(t *testing.T) {
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
	reports, err := Replay(strings.NewReader(replayCorruptInput), dir)
	if err != nil {
		t.Fatalf("legacy archive replay failed: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != BuiltinVersionID {
		t.Fatalf("legacy replay must run under builtin: %+v", reports)
	}
	if len(reports[0].Findings) != 1 || reports[0].Findings[0].Kind != "displacement" ||
		reports[0].Findings[0].Severity != 2 {
		t.Fatalf("legacy replay misjudged under builtin: %+v", reports[0].Findings)
	}
}
