package mevwatch

// Regression coverage for `reviews submit` rewriting unrelated alerting
// evidence. A successful submission rewrites the archive to append its
// revision, and the stored alert processing records used to be decoded
// into structs on the way: a saved "version":null came back as an object
// full of zero values, an incomplete declaration as zero-filled
// parameters, and a repeated field collapsed to whichever value won. A
// processing record's saved detection-version declaration is the evidence
// of its generation time — an unrelated review must never repair,
// complete, replace, drop or merge it, and must never borrow parameters
// from the block's report, the currently enabled version or a same-id
// registered version. The declarations themselves stay legal JSON values;
// the submit only has to leave them exactly as stored.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// alertRecordsRaw returns every stored alert processing record as its raw
// stored document, whitespace-normalized so a rewrite that only re-indents
// the archive still compares equal while key order, duplicate fields and
// explicit nulls are preserved exactly.
func alertRecordsRaw(t *testing.T, dir string) []string {
	t.Helper()
	var doc struct {
		Alerts []json.RawMessage `json:"alerts"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Alerts) == 0 {
		t.Fatal("expected stored alert records")
	}
	out := make([]string, len(doc.Alerts))
	for i, raw := range doc.Alerts {
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			t.Fatalf("stored alert record %d is not valid JSON: %v", i, err)
		}
		out[i] = buf.String()
	}
	return out
}

// TestSubmitReviewPreservesAlertRecordDeclarations runs the decay matrix
// over the alert record's saved declaration — an explicit null, a missing
// key, an empty or incomplete object, a wrong-typed parameter — plus a
// complete declaration the registry never carried. A successful review
// submission must leave every one byte for byte in content: nothing is
// completed, zero-filled, replaced, dropped or borrowed from the report,
// the enabled version or the registry.
func TestSubmitReviewPreservesAlertRecordDeclarations(t *testing.T) {
	cases := []struct {
		name  string
		value any  // nil means an explicit JSON null
		drop  bool // remove the version key entirely
	}{
		{"null", nil, false},
		{"missing key", nil, true},
		{"empty object", map[string]any{}, false},
		{"incomplete object", map[string]any{"id": "candC"}, false},
		{"wrong-typed parameter", map[string]any{
			"id": "candC",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": false, "severity": 3},
				"displacement": map[string]any{"enabled": true, "severity": 4, "multiplier": "2"},
			},
		}, false},
		{"complete but never registered", map[string]any{
			"id": "never-registered",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": true, "severity": 5},
				"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 9},
			},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			if tc.drop {
				dropStoredAlertVersionKey(t, dir, alertHistoryChain, alertHistoryBlock,
					alertHistoryTx, alertHistoryKind, alertHistoryChannel)
			} else {
				replaceStoredAlertVersion(t, dir, alertHistoryChain, alertHistoryBlock,
					alertHistoryTx, alertHistoryKind, alertHistoryChannel, tc.value)
			}
			before := alertRecordsRaw(t, dir)

			res, err := SubmitReview(dir, submitTarget("s-1", 0))
			if err != nil || !res.Created || res.Version != 1 {
				t.Fatalf("submission against the intact report = %+v %v", res, err)
			}
			if after := alertRecordsRaw(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("submission rewrote the alert record:\nbefore %s\nafter  %s",
					strings.Join(before, "\n"), strings.Join(after, "\n"))
			}

			// The new revision is visible through the history query.
			hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
			if err != nil || hist.Version != 1 || hist.Status != ReviewStatusReal ||
				len(hist.Revisions) != 1 {
				t.Fatalf("review history = %+v %v", hist, err)
			}

			// The alert history query still judges the record by its own
			// saved declaration: damage the submit preserved is neither
			// repaired into a success nor explained as the built-in rules,
			// and a self-contained declaration is used exactly as saved.
			got, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
			if tc.name == "complete but never registered" {
				if herr != nil || len(got) != 1 || got[0].Version.ID != "never-registered" ||
					got[0].Version.Rules.Displacement.Multiplier != 9 {
					t.Fatalf("alert history = %+v %v, want the saved never-registered parameters", got, herr)
				}
				return
			}
			if !errors.Is(herr, ErrCorruptVersion) {
				t.Fatalf("alert history = %+v %v, want ErrCorruptVersion", got, herr)
			}
		})
	}
}

// TestSubmitReviewPreservesDuplicateFieldsInAlertDeclaration patches the
// stored alert record's declaration with a second multiplier declaration
// carrying a different value — decay no encoder could have produced. The
// submission must keep both declarations, in order and with their own
// values, rather than merging them into one, and the history query must
// still refuse the record as a duplicate.
func TestSubmitReviewPreservesDuplicateFieldsInAlertDeclaration(t *testing.T) {
	dir := setupAlertHistoryCorruptArchive(t)
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	alertsAt := strings.Index(text, `"alerts":`)
	if alertsAt < 0 {
		t.Fatal("alerts section not found")
	}
	anchor := `"multiplier": 2`
	at := strings.Index(text[alertsAt:], anchor)
	if at < 0 {
		t.Fatal("multiplier not found in the alert record's declaration")
	}
	pos := alertsAt + at
	patched := text[:pos] + `"multiplier": 7, ` + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	before := alertRecordsRaw(t, dir)
	if !strings.Contains(before[0], `"multiplier": 7`) {
		t.Fatalf("patch did not land in the alert record: %s", before[0])
	}

	res, err := SubmitReview(dir, submitTarget("s-1", 0))
	if err != nil || !res.Created {
		t.Fatalf("submission against the intact report = %+v %v", res, err)
	}
	after := alertRecordsRaw(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("submission merged or reordered the duplicate declarations:\nbefore %s\nafter  %s",
			before[0], after[0])
	}
	first := strings.Index(after[0], `"multiplier": 7`)
	second := strings.Index(after[0], `"multiplier": 2`)
	if first < 0 || second < 0 || first > second {
		t.Fatalf("duplicate declarations did not keep their order and values: %s", after[0])
	}
	if _, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100); !errors.Is(herr, ErrCorruptVersion) ||
		!errors.Is(herr, ErrDuplicateField) {
		t.Fatalf("alert history = %v, want ErrCorruptVersion wrapping ErrDuplicateField", herr)
	}
}

// TestSubmitReviewRejudgmentAndWithdrawalPreserveAlertRecords proves the
// preservation holds for every append shape: the first judgment, a
// rejudgment and a withdrawal each rewrite the archive, and none of them
// may touch the stored alert record — its identity, conclusion, evidence,
// threshold, status, suppression hits and decayed declaration included.
func TestSubmitReviewRejudgmentAndWithdrawalPreserveAlertRecords(t *testing.T) {
	dir := setupAlertHistoryCorruptArchive(t)
	replaceStoredAlertVersion(t, dir, alertHistoryChain, alertHistoryBlock,
		alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
	first := submit(t, dir, submitTarget("s-1", 0))
	if !first.Created || first.Version != 1 {
		t.Fatalf("first submission = %+v", first)
	}
	before := alertRecordsRaw(t, dir)

	rejudged := submit(t, dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-2", "bob", "second look", ReviewStatusFalsePositive, 1))
	if !rejudged.Created || rejudged.Version != 2 {
		t.Fatalf("rejudgment = %+v", rejudged)
	}
	withdrawn := submit(t, dir, reviewSub("1", "0xblk", historyTargetTx, historyTargetKind,
		"s-3", "carol", "reset", ReviewStatusUnreviewed, 2))
	if !withdrawn.Created || withdrawn.Version != 3 {
		t.Fatalf("withdrawal = %+v", withdrawn)
	}

	if after := alertRecordsRaw(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("appending revisions rewrote the alert record:\nbefore %s\nafter  %s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	hist, err := ReviewHistoryQuery(dir, "1", "0xblk", historyTargetTx, historyTargetKind)
	if err != nil || hist.Version != 3 || hist.Status != ReviewStatusUnreviewed ||
		len(hist.Revisions) != 3 {
		t.Fatalf("review history = %+v %v", hist, err)
	}
	if _, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100); !errors.Is(herr, ErrCorruptVersion) {
		t.Fatalf("alert history = %v, want ErrCorruptVersion", herr)
	}
}
