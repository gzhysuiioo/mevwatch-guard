package mevwatch

// Regression coverage for the rule-version integrity gate on the offline
// replay path. A selected version (named explicitly or taken from the
// archive's enabled marker) must still satisfy the full registration
// declaration, re-validated from its raw stored document before this run
// produces any report. This mirrors the single-block comparison and the
// review-range evaluation: a missing/null/wrong-typed/out-of-range field or
// a missing rule object fails the whole replay as a corrupt version, never
// as an unknown one, and is never replaced by the enabled version, the
// built-in rules or defaults.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// replayCorruptTrigger is a fresh (not yet archived) two-swap block whose
// same-pool front/victim pair reaches the displacement judgment. Under
// intact candC (displacement on, multiplier 2) it flags: 40 > 2*10. With a
// decayed zero multiplier the old code panicked dividing MaxInt64 by zero;
// with a missing severity it silently reported severity zero.
const replayCorruptTrigger = `{"chainId":"1","blockHash":"0xtrig","blockNumber":9,"swaps":[` +
	`{"TxHash":"0xf","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":0},` +
	`{"TxHash":"0xv","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`

// setupReplayCorruptArchive registers candC (the version about to be
// damaged) and twin (an intact sibling), optionally making candC the
// enabled version. No block is archived, so a later replay has real new
// work to do.
func setupReplayCorruptArchive(t *testing.T, enable bool) string {
	t.Helper()
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	register(t, dir, twinVersionSpec)
	if enable {
		if _, err := EnableVersion(dir, "candC"); err != nil {
			t.Fatalf("EnableVersion: %v", err)
		}
	}
	return dir
}

func corruptCandC(t *testing.T, dir string, mutate func(ver map[string]any)) {
	t.Helper()
	rewriteStoredVersion(t, dir, "candC", mutate)
}

// assertCorruptVersionError pins the failure shape shared by every replay
// corruption case: the sentinel, no confusion with an unknown version, and
// a message naming both the version id and the offending rule or field.
func assertCorruptVersionError(t *testing.T, err error, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatalf("corrupt version replayed successfully")
	}
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if errors.Is(err, ErrUnknownVersion) {
		t.Fatalf("an existing corrupt version must not be reported unknown: %v", err)
	}
	if !strings.Contains(err.Error(), "candC") {
		t.Fatalf("error must name the selected version, got %v", err)
	}
	if wantField != "" && !strings.Contains(err.Error(), wantField) {
		t.Fatalf("error must name the offending rule or field %q, got %v", wantField, err)
	}
}

// TestReplayCorruptVersionRefused runs the same corruption matrix compare
// and review-evaluate enforce, for both an explicitly named version and the
// archive's enabled one. Each damaged document must fail the whole replay
// cleanly (never panic on the zero multiplier), name candC and the field,
// produce no reports and leave the archive bytes untouched.
func TestReplayCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name+"/explicit", func(t *testing.T) {
			dir := setupReplayCorruptArchive(t, false)
			corruptCandC(t, dir, func(ver map[string]any) { tc.mutate(t, ver) })
			before := readArchiveBytesOrFail(t, dir)

			reports, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "candC")
			assertCorruptVersionError(t, err, tc.wantErr)
			if reports != nil {
				t.Fatalf("corrupt replay returned reports: %+v", reports)
			}
			assertArchiveBytesUnchanged(t, dir, before)
			if archiveHasBlock(t, dir, "1", "0xtrig") {
				t.Fatalf("new block leaked into archive")
			}
		})
		t.Run(tc.name+"/enabled", func(t *testing.T) {
			dir := setupReplayCorruptArchive(t, true)
			corruptCandC(t, dir, func(ver map[string]any) { tc.mutate(t, ver) })
			before := readArchiveBytesOrFail(t, dir)

			reports, err := Replay(strings.NewReader(replayCorruptTrigger), dir)
			assertCorruptVersionError(t, err, tc.wantErr)
			if reports != nil {
				t.Fatalf("corrupt replay returned reports: %+v", reports)
			}
			assertArchiveBytesUnchanged(t, dir, before)
			if archiveHasBlock(t, dir, "1", "0xtrig") {
				t.Fatalf("new block leaked into archive")
			}
		})
	}
}

// TestReplayCorruptVersionIndependentOfInput pins that the integrity gate
// runs before any block is judged or reported, regardless of what the input
// happens to contain: an empty-swaps block, only blank lines, only an
// already-archived identical block, or a batch mixing an old block with a
// new one.
func TestReplayCorruptVersionIndependentOfInput(t *testing.T) {
	const emptySwaps = `{"chainId":"1","blockHash":"0empty","blockNumber":1,"swaps":[]}`

	cases := []struct {
		name  string
		input func(dir string) string
	}{
		{"empty swaps block", func(_ string) string { return emptySwaps }},
		{"blank lines only", func(_ string) string { return "\n  \n\t\n" }},
		{
			"only an already archived identical block",
			func(dir string) string {
				if _, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "candC"); err != nil {
					t.Fatalf("seed replay: %v", err)
				}
				return replayCorruptTrigger
			},
		},
		{
			"old identical block followed by a new block",
			func(dir string) string {
				if _, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "candC"); err != nil {
					t.Fatalf("seed replay: %v", err)
				}
				return replayCorruptTrigger + "\n" + emptySwaps
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/explicit", func(t *testing.T) {
			dir := setupReplayCorruptArchive(t, false)
			input := tc.input(dir)
			corruptCandC(t, dir, func(ver map[string]any) {
				delete(storedRule(t, ver, "displacement"), "multiplier")
			})
			reports, err := ReplayWithVersion(strings.NewReader(input), dir, "candC")
			assertCorruptVersionError(t, err, "multiplier")
			if reports != nil {
				t.Fatalf("no report may be returned before the corrupt failure: %+v", reports)
			}
			if _, qerr := Query(dir, "1", "0empty"); !errors.Is(qerr, ErrUnknownBlock) {
				t.Fatalf("new block from a refused batch leaked into archive: %v", qerr)
			}
		})
		t.Run(tc.name+"/enabled", func(t *testing.T) {
			dir := setupReplayCorruptArchive(t, true)
			input := tc.input(dir)
			corruptCandC(t, dir, func(ver map[string]any) {
				storedRule(t, ver, "displacement")["multiplier"] = 0
			})
			reports, err := Replay(strings.NewReader(input), dir)
			assertCorruptVersionError(t, err, "multiplier")
			if reports != nil {
				t.Fatalf("no report may be returned before the corrupt failure: %+v", reports)
			}
			if _, qerr := Query(dir, "1", "0empty"); !errors.Is(qerr, ErrUnknownBlock) {
				t.Fatalf("new block from a refused batch leaked into archive: %v", qerr)
			}
		})
	}
}

// TestReplayCorruptVersionDistinctFromUnknown checks the boundaries: an
// identifier that was never registered stays an unknown-version failure, an
// intact sibling and builtin still replay correctly, and an intact replay's
// commit neither repairs nor drops the corrupt sibling it did not select.
func TestReplayCorruptVersionDistinctFromUnknown(t *testing.T) {
	dir := setupReplayCorruptArchive(t, false)
	corruptCandC(t, dir, func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})

	// Never registered: unknown version, never corruption.
	if _, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown version error = %v", err)
	}

	// The corrupt sibling does not contaminate builtin or twin; both flag
	// the trigger as a severity-2 displacement (40 > 2*10).
	for _, id := range []string{BuiltinVersionID, "twin"} {
		reports, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, id)
		if err != nil {
			t.Fatalf("replay under intact %s failed: %v", id, err)
		}
		if len(reports) != 1 || len(reports[0].Findings) != 1 ||
			reports[0].Findings[0].Kind != "displacement" || reports[0].Findings[0].Severity != 2 {
			t.Fatalf("replay under intact %s misjudged: %+v", id, reports)
		}
	}

	// The successful commit kept candC's damaged document: the multiplier
	// is still absent rather than silently restored to a default.
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Versions []map[string]any `json:"versions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Versions {
		if v["id"] != "candC" {
			continue
		}
		disp := v["rules"].(map[string]any)["displacement"].(map[string]any)
		if _, ok := disp["multiplier"]; ok {
			t.Fatalf("corrupt sibling was repaired during an intact replay: %v", disp)
		}
		return
	}
	t.Fatal("corrupt candC document vanished during an intact replay")
}

// TestReplayCorruptEnabledVersionRefused proves the enabled marker is
// itself re-validated: a replay with no --version against an archive whose
// enabled version is corrupt must fail, never fall back to builtin.
func TestReplayCorruptEnabledVersionRefused(t *testing.T) {
	dir := setupReplayCorruptArchive(t, true)
	corruptCandC(t, dir, func(ver map[string]any) {
		storedRule(t, ver, "displacement")["severity"] = nil
	})
	if _, err := Replay(strings.NewReader(replayCorruptTrigger), dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("enabled corrupt version error = %v, want ErrCorruptVersion", err)
	}
	_, enabled, err := ListVersions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if enabled != "candC" {
		t.Fatalf("enabled marker changed to %q on refusal", enabled)
	}
}

// TestReplayBlockInputErrorKeepsLineNumberAgainstCorruptVersion pins the
// order: malformed block input is still reported with its line number even
// when the selected version is independently corrupt — block parsing is the
// first gate and its diagnostics are unchanged.
func TestReplayBlockInputErrorKeepsLineNumberAgainstCorruptVersion(t *testing.T) {
	dir := setupReplayCorruptArchive(t, true)
	corruptCandC(t, dir, func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	_, err := Replay(strings.NewReader("\nnot json"), dir)
	var le *LineError
	if !errors.As(err, &le) {
		t.Fatalf("want LineError for bad input, got %v", err)
	}
	if le.Line != 2 {
		t.Fatalf("line = %d, want 2", le.Line)
	}
}

// TestReplayCorruptVersionLeavesWholeArchiveUntouched builds an archive
// carrying every piece of state the requirements name — an existing report,
// registered versions and the enabled marker, a suppression, an alert
// processing record and a manual review — then damages the enabled version.
// A refused replay must leave all of it (and the exact file bytes) as-is,
// without filling the missing field.
func TestReplayCorruptVersionLeavesWholeArchiveUntouched(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	register(t, dir, candidateVersionSpec)
	if _, err := EnableVersion(dir, "candC"); err != nil {
		t.Fatal(err)
	}
	supSpec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"keep"}`
	if _, _, err := RegisterSuppression(dir, []byte(supSpec)); err != nil {
		t.Fatalf("RegisterSuppression: %v", err)
	}
	if recs, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil || len(recs) != 2 {
		t.Fatalf("GenerateAlerts: recs=%d err=%v", len(recs), err)
	}
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "rev-1", "alice", "real", ReviewStatusReal, 0))

	corruptCandC(t, dir, func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveBytesOrFail(t, dir)

	if _, err := Replay(strings.NewReader(replayCorruptTrigger), dir); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}

	// Exact bytes: the refusal performs no write and no field repair.
	assertArchiveBytesUnchanged(t, dir, before)

	// Existing report intact.
	r, err := Query(dir, "1", "0xa")
	if err != nil || len(r.Findings) != 2 {
		t.Fatalf("stored report damaged: %+v err=%v", r, err)
	}
	// Enabled marker and versions intact.
	_, enabled, err := ListVersions(dir)
	if err != nil || enabled != "candC" {
		t.Fatalf("enabled = %q err=%v", enabled, err)
	}
	// Suppression intact.
	conds, err := ListSuppressions(dir)
	if err != nil || len(conds) != 1 || conds[0].ID != "s1" {
		t.Fatalf("suppressions damaged: %+v err=%v", conds, err)
	}
	// Alert processing history intact.
	alerts, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil || len(alerts) != 2 {
		t.Fatalf("alert history damaged: %+v err=%v", alerts, err)
	}
	// Manual review history intact.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil || hist.Version != 1 || hist.Status != ReviewStatusReal {
		t.Fatalf("review history damaged: %+v err=%v", hist, err)
	}
}

// TestReplayExplicitFalseStillValidAfterGate confirms the gate does not
// confuse an explicit enabled:false with a missing field: a version with
// both rules disabled but every parameter present and in range replays
// successfully with no conclusions, and a following identical re-import
// returns that original report.
func TestReplayExplicitFalseStillValidAfterGate(t *testing.T) {
	dir := t.TempDir()
	bothOff := `{"id":"off2","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":5,"multiplier":100}}}`
	register(t, dir, bothOff)
	reports, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "off2")
	if err != nil {
		t.Fatalf("explicit enabled:false must stay valid: %v", err)
	}
	if len(reports) != 1 || len(reports[0].Findings) != 0 || reports[0].Version.ID != "off2" {
		t.Fatalf("rules-off replay wrong: %+v", reports)
	}
	again, err := ReplayWithVersion(strings.NewReader(replayCorruptTrigger), dir, "off2")
	if err != nil || len(again) != 1 || again[0].Version.ID != "off2" {
		t.Fatalf("identical reimport changed: %+v err=%v", again, err)
	}
}

// TestReplayLegacyArchiveUnaffectedByCorruptSibling ensures an old-format
// archive with no version metadata still replays under builtin even if a
// corrupt registered document is (anomalously) present and not enabled.
func TestReplayLegacyArchiveUnaffectedByCorruptSibling(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	corruptCandC(t, dir, func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	// Strip the enabled marker: no enabled version means builtin.
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "enabledVersion")
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), out, 0o644); err != nil {
		t.Fatal(err)
	}
	reports, err := Replay(strings.NewReader(replayCorruptTrigger), dir)
	if err != nil {
		t.Fatalf("legacy-style replay must use builtin despite corrupt sibling: %v", err)
	}
	if len(reports) != 1 || reports[0].Version.ID != BuiltinVersionID ||
		len(reports[0].Findings) != 1 || reports[0].Findings[0].Severity != 2 {
		t.Fatalf("legacy replay wrong: %+v", reports)
	}
}

func readArchiveBytesOrFail(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertArchiveBytesUnchanged(t *testing.T, dir string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("refused replay modified the archive:\nbefore=%s\nafter =%s", want, got)
	}
}

// archiveHasBlock reports presence of a block by reading the raw archive
// document, so it works even when a wrong-typed version field makes the
// typed decoder reject the file.
func archiveHasBlock(t *testing.T, dir, chainID, blockHash string) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Records []struct {
			ChainID   string `json:"chainId"`
			BlockHash string `json:"blockHash"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, rec := range doc.Records {
		if rec.ChainID == chainID && rec.BlockHash == blockHash {
			return true
		}
	}
	return false
}
