package mevwatch

// Regression coverage for `suppressions register` rewriting stored alerting
// evidence. A successful registration rewrites the archive to append its
// condition, and the stored alert processing records used to be decoded
// into structs on the way: a saved "version":null came back as an object
// full of zero values, an incomplete declaration as zero-filled
// parameters, and a repeated field collapsed to whichever value won. A
// processing record's saved detection-version declaration is the alerting
// evidence of its generation time — registering a condition must never
// repair, complete, replace, drop or merge it, and must never borrow
// parameters from the block's report, the currently enabled version or a
// same-id registered version. The declarations themselves stay legal JSON
// values; the registration only has to leave them exactly as stored, and
// the alert history query keeps judging every record by its own saved
// declaration.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// registerAlertSpec is a legal condition the alert-history fixture archive
// does not yet carry. It covers the fixture event exactly (displacement in
// pool p1 on chain 1, channel ops, height 7), so its registration also
// proves a condition matching a historical event never rewrites the stored
// outcome: the saved record keeps its alert status and empty suppression
// hits, and only conclusions processed afterwards are suppressed.
const registerAlertSpec = `{"id":"s9","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"known bot war"}`

// TestRegisterSuppressionPreservesAlertRecordDeclarations runs the decay
// matrix over the processing record's saved declaration — an explicit null,
// a missing key, an empty or incomplete object, a wrong-typed parameter —
// plus a complete declaration the registry never carried. A successful
// registration must leave every one byte for byte in content: nothing is
// completed, zero-filled, replaced, dropped or borrowed from the report,
// the enabled version or the registry.
func TestRegisterSuppressionPreservesAlertRecordDeclarations(t *testing.T) {
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

			cond, created, err := RegisterSuppression(dir, []byte(registerAlertSpec))
			if err != nil || !created {
				t.Fatalf("registration over a damaged alert record = created:%v %+v %v", created, cond, err)
			}
			if cond.ID != "s9" || cond.ChainID != "1" || cond.Pool != "p1" ||
				cond.Kind != SuppressDisplacement || cond.Channel != "ops" ||
				cond.StartHeight != 0 || cond.EndHeight != 100 ||
				cond.Reason != "known bot war" || cond.Revoked {
				t.Fatalf("registered condition wrong: %+v", cond)
			}
			if after := alertRecordsRaw(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("registration rewrote the alert record:\nbefore %s\nafter  %s",
					strings.Join(before, "\n"), strings.Join(after, "\n"))
			}

			// The alert history query still judges the record by its own
			// saved declaration: damage the registration preserved is
			// neither repaired into a success nor explained as the built-in
			// rules, and a self-contained declaration is used exactly as
			// saved.
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

// TestRegisterSuppressionPreservesDuplicateFieldsInAlertDeclaration patches
// the stored processing record's declaration with a second multiplier
// declaration carrying a different value — decay no encoder could have
// produced — in its exact, case-variant and escaped spellings. The
// registration must keep both declarations, in order and with their own
// values, rather than merging them into one, and the history query must
// still refuse the record as a duplicate.
func TestRegisterSuppressionPreservesDuplicateFieldsInAlertDeclaration(t *testing.T) {
	cases := []struct{ name, dup string }{
		{"exact", `"multiplier": 7, `},
		{"case variant", `"Multiplier": 7, `},
		{"escaped", "\"multiplie\\u0072\": 7, "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			patched := text[:pos] + tc.dup + text[pos:]
			if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
				t.Fatal(err)
			}
			before := alertRecordsRaw(t, dir)

			if _, created, err := RegisterSuppression(dir, []byte(registerAlertSpec)); err != nil || !created {
				t.Fatalf("registration over a duplicate-field declaration = created:%v %v", created, err)
			}
			after := alertRecordsRaw(t, dir)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("registration merged or reordered the duplicate declarations:\nbefore %s\nafter  %s",
					before[0], after[0])
			}
			dupField := strings.TrimSuffix(strings.TrimSpace(tc.dup), ",")
			first := strings.Index(after[0], dupField)
			second := strings.Index(after[0], `"multiplier": 2`)
			if first < 0 || second < 0 || first > second {
				t.Fatalf("duplicate declarations did not keep their order and values: %s", after[0])
			}
			if _, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100); !errors.Is(herr, ErrCorruptVersion) ||
				!errors.Is(herr, ErrDuplicateField) {
				t.Fatalf("alert history = %v, want ErrCorruptVersion wrapping ErrDuplicateField", herr)
			}
		})
	}
}

// TestRegisterSuppressionCoveringHistoricalEventRewritesNoOutcome proves a
// new condition that covers an already processed event only affects
// conclusions processed afterwards: the stored record keeps its identity,
// pool, channel, conclusion, evidence, threshold, alert status and empty
// suppression hits, while a later generation run for a fresh channel sees
// the condition.
func TestRegisterSuppressionCoveringHistoricalEventRewritesNoOutcome(t *testing.T) {
	dir := setupAlertHistoryCorruptArchive(t)
	before := alertRecordsRaw(t, dir)

	cond, created, err := RegisterSuppression(dir, []byte(registerAlertSpec))
	if err != nil || !created || cond.ID != "s9" {
		t.Fatalf("register = created:%v %+v %v", created, cond, err)
	}
	if after := alertRecordsRaw(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("covering condition rewrote the stored outcome:\nbefore %s\nafter  %s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}

	// The historical record still reads as an alert with no suppression
	// hits; the identical retry is a no-op and different content conflicts.
	hist, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if err != nil || len(hist) != 1 || hist[0].Status != AlertStatusAlert || len(hist[0].Suppressions) != 0 {
		t.Fatalf("alert history = %+v %v, want the stored alert outcome", hist, err)
	}
	if _, created, err := RegisterSuppression(dir, []byte(registerAlertSpec)); err != nil || created {
		t.Fatalf("identical retry = created:%v %v, want created:false", created, err)
	}
	conflict := strings.Replace(registerAlertSpec, `"known bot war"`, `"other reason"`, 1)
	if _, _, err := RegisterSuppression(dir, []byte(conflict)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("different content = %v, want ErrSuppressionConflict", err)
	}

	// A conclusion processed after the registration — a fresh block on the
	// same chain, pool, kind and channel — is suppressed by the condition.
	input := cmpBlockLine("1", "0xblk2", 8,
		cmpSwap("0xf2", "p1", "w", 40, 0),
		cmpSwap("0xv2", "p1", "u", 10, 1),
	)
	if _, err := ReplayWithVersion(strings.NewReader(input), dir, "candC"); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, alertHistoryChain, alertHistoryChannel, 0, 100, 1)
	if err != nil || len(got) != 1 || got[0].Status != AlertStatusSuppressed ||
		len(got[0].Suppressions) != 1 || got[0].Suppressions[0].ID != "s9" {
		t.Fatalf("later generation = %+v %v, want one suppressed record hit by s9", got, err)
	}
}

// TestRegisterSuppressionPreservesAllAlertRecords proves every stored
// processing record survives a registration — across chains, channels and
// conclusion statuses — in its stored order, not just the one the decay
// matrix edits.
func TestRegisterSuppressionPreservesAllAlertRecords(t *testing.T) {
	dir := setupSuppressedAlertHistoryArchive(t)
	// A second, unsuppressed record on another channel.
	if _, err := GenerateAlerts(dir, alertHistoryChain, "alerts", 0, 100, 1); err != nil {
		t.Fatal(err)
	}
	replaceStoredAlertVersion(t, dir, alertHistoryChain, alertHistoryBlock,
		alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
	before := alertRecordsRaw(t, dir)
	if len(before) != 2 {
		t.Fatalf("precondition: want two stored records, got %d", len(before))
	}

	if _, created, err := RegisterSuppression(dir, []byte(registerAlertSpec)); err != nil || !created {
		t.Fatalf("register = created:%v %v", created, err)
	}
	if after := alertRecordsRaw(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("registration rewrote the processing records:\nbefore %s\nafter  %s",
			strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
	// The suppressed record's saved hits are intact, and the damaged
	// declaration on the other record still fails its history query.
	hist, err := AlertHistory(dir, alertHistoryChain, "alerts", 0, 100)
	if err != nil || len(hist) != 1 || hist[0].Status != AlertStatusAlert {
		t.Fatalf("intact channel history = %+v %v", hist, err)
	}
	if _, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100); !errors.Is(herr, ErrCorruptVersion) {
		t.Fatalf("damaged channel history = %v, want ErrCorruptVersion", herr)
	}
	var doc struct {
		Alerts []map[string]any `json:"alerts"`
	}
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	supp, ok := doc.Alerts[0]["suppressions"].([]any)
	if !ok || len(supp) != 1 || supp[0].(map[string]any)["id"] != "s1" {
		t.Fatalf("stored suppression hits changed: %v", doc.Alerts[0]["suppressions"])
	}
}
