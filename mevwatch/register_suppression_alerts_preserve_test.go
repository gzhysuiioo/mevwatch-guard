package mevwatch

// Regression coverage for `suppressions register` over an archive whose
// stored processing records carry decayed detection-version declarations.
// Registering a new condition rewrites the archive, but it must never
// re-interpret another operation's evidence: unlike block reports, a
// processing record's saved version declaration is not proved during
// registration (a history query proves it when the record is returned), so
// a missing version key, a written null, an incomplete declaration or a
// repeated field (a case-folded or escaped spelling included) must neither
// block the registration nor be "repaired" by the save — null stays null,
// the gap stays open and the repeated fields keep their names, values and
// order. The historical record itself (identity, channel, conclusion, full
// swap evidence, generation threshold, status and the suppression hits of
// the time) is preserved in order, and a new condition that covers an
// already-processed event still changes only conclusions processed
// afterwards. Registration's pre-save proof over the block reports keeps
// running unchanged.

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

// alertBytesSection decodes just the archive's alerts section, returning
// each processing record compacted to its semantic bytes — indentation
// differences are ignored, but a null, a missing field, a zero value or a
// repeated key all change the comparison.
func alertBytesSection(t *testing.T, dir string) [][]byte {
	t.Helper()
	raw := readArchiveFile(t, dir)
	var doc struct {
		Alerts []json.RawMessage `json:"alerts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(doc.Alerts))
	for i, rec := range doc.Alerts {
		var buf bytes.Buffer
		if err := json.Compact(&buf, rec); err != nil {
			t.Fatalf("alert %d is not parseable JSON: %v", i, err)
		}
		out[i] = bytes.Clone(buf.Bytes())
	}
	return out
}

// decodedAlerts decodes the alerts section the way a history query does,
// so a before/after comparison covers every business field plus the raw
// (compacted) version declaration without having to parse it.
func decodedAlerts(t *testing.T, dir string) []storedAlertRecord {
	t.Helper()
	var doc alertHistoryArchiveDoc
	if err := json.Unmarshal(readArchiveFile(t, dir), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.AlertRecords
}

// assertAlertsSemanticallyEqual pins the preservation contract: the same
// records in the same order, every business field identical and each
// version declaration identical token for token (whitespace aside) —
// null stays null, a gap stays a gap, a repeated field stays repeated.
func assertAlertsSemanticallyEqual(t *testing.T, before, after []storedAlertRecord, beforeBytes, afterBytes [][]byte) {
	t.Helper()
	if len(before) != len(after) || len(beforeBytes) != len(afterBytes) {
		t.Fatalf("alerts section changed length: %d records before, %d after", len(before), len(after))
	}
	for i := range before {
		b, a := before[i], after[i]
		if b.ChainID != a.ChainID || b.BlockHash != a.BlockHash || b.BlockNumber != a.BlockNumber ||
			b.Pool != a.Pool || b.Channel != a.Channel || b.MinSeverity != a.MinSeverity ||
			b.Status != a.Status || !reflect.DeepEqual(b.Finding, a.Finding) ||
			!reflect.DeepEqual(b.Suppressions, a.Suppressions) {
			t.Fatalf("alert record %d changed on registration:\nbefore=%+v\nafter =%+v", i, b, a)
		}
		if !bytes.Equal(beforeBytes[i], afterBytes[i]) {
			t.Fatalf("alert record %d version declaration rewritten:\nbefore=%s\nafter =%s",
				i, beforeBytes[i], afterBytes[i])
		}
	}
}

// registerCoversAlertSpec is a legal condition covering the fixture's
// already-processed event itself (chain 1, pool p1, displacement on ops at
// height 7): registering it after processing must not flip the saved alert
// into a suppression.
const registerCoversAlertSpec = `{"id":"s2","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":0,"endHeight":100,"reason":"later window"}`

// assertRegisterSucceedsOverCorruptAlert runs one registration over a
// damaged processing record and pins the whole contract: created:true with
// the full condition, the alerts section unchanged in content and order,
// the condition appended last, and (when the record stays within a history
// query's scope) the record afterward reported exactly the way stillCorrupt
// says — corrupt as ErrCorruptVersion for every damaged shape, intact for a
// complete self-contained declaration.
func assertRegisterSucceedsOverCorruptAlert(t *testing.T, corrupt func(*testing.T, string), stillCorrupt bool) {
	t.Helper()
	dir := setupAlertHistoryCorruptArchive(t)
	corrupt(t, dir)
	beforeBytes := alertBytesSection(t, dir)
	beforeRecs := decodedAlerts(t, dir)

	cond, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec))
	if err != nil || !created {
		t.Fatalf("registration over a corrupt processing record: created=%v err=%v %+v", created, err, cond)
	}
	if cond.ID != "s2" || cond.Revoked || cond.Reason != "later window" ||
		cond.StartHeight != 0 || cond.EndHeight != 100 {
		t.Fatalf("registered condition wrong: %+v", cond)
	}

	afterBytes := alertBytesSection(t, dir)
	afterRecs := decodedAlerts(t, dir)
	assertAlertsSemanticallyEqual(t, beforeRecs, afterRecs, beforeBytes, afterBytes)

	// The new condition only affects conclusions processed from now on:
	// the historical record keeps its alert status and no suppression hits,
	// and a repeated generation still skips the already-processed identity.
	r := afterRecs[0]
	if r.Status != AlertStatusAlert || len(r.Suppressions) != 0 {
		t.Fatalf("historical outcome rewritten by the new condition: status=%q hits=%+v",
			r.Status, r.Suppressions)
	}
	if got, err := GenerateAlerts(dir, alertHistoryChain, alertHistoryChannel, 0, 100, 1); err != nil {
		t.Fatalf("repeated generation failed: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("new condition re-processed history: %+v", got)
	}

	// A history query still judges the record from its own bytes: damage
	// stays damage (no partial history), and a complete self-contained
	// declaration still returns its own parameters.
	history, herr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
	if stillCorrupt {
		if !errors.Is(herr, ErrCorruptVersion) {
			t.Fatalf("damaged record masked by registration: history=%+v err=%v", history, herr)
		}
		if history != nil {
			t.Fatalf("corrupt history returned partial records: %+v", history)
		}
		return
	}
	if herr != nil {
		t.Fatalf("intact record must still query after registration: %v", herr)
	}
	if len(history) != 1 {
		t.Fatalf("history = %+v, want the one original record", history)
	}
}

// TestRegisterSuppressionPreservesCorruptAlertRecord runs the damage matrix
// through a successful registration: every shape of a decayed declaration
// survives the save exactly as stored and still fails a history query.
func TestRegisterSuppressionPreservesCorruptAlertRecord(t *testing.T) {
	corruptShapes := []struct {
		name    string
		corrupt func(*testing.T, string)
	}{
		{"written null", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
		}},
		{"missing version key", func(t *testing.T, dir string) {
			dropStoredAlertVersionKey(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel)
		}},
		{"empty object", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				map[string]any{})
		}},
		{"incomplete object", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				map[string]any{"id": "candC"})
		}},
		{"non-object number", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, 5)
		}},
		{"non-object string", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				"builtin")
		}},
		{"array", func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				[]any{})
		}},
		{"multiplier zero", func(t *testing.T, dir string) {
			rewriteStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				func(ver map[string]any) {
					storedRule(t, ver, "displacement")["multiplier"] = 0
				})
		}},
		{"severity missing", func(t *testing.T, dir string) {
			rewriteStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel,
				func(ver map[string]any) {
					delete(storedRule(t, ver, "sandwich"), "severity")
				})
		}},
	}
	for _, tc := range corruptShapes {
		t.Run(tc.name, func(t *testing.T) {
			assertRegisterSucceedsOverCorruptAlert(t, tc.corrupt, true)
		})
	}
}

// patchAlertRecordVersionRaw inserts insert right before anchor inside the
// single fixture alert record's version declaration, simulating a repeated
// field a JSON map cannot hold. The alerts section follows records and
// versions in the archive.
func patchAlertRecordVersionRaw(t *testing.T, dir, anchor, insert string) {
	t.Helper()
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	alertsAt := strings.Index(text, `"alerts":`)
	if alertsAt < 0 {
		t.Fatal("alerts section not found")
	}
	at := strings.Index(text[alertsAt:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("alert record's candC declaration not found")
	}
	at += alertsAt
	field := strings.Index(text[at:], anchor)
	if field < 0 {
		t.Fatalf("anchor %q not found in alert record declaration", anchor)
	}
	pos := at + field
	patched := text[:pos] + insert + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRegisterSuppressionPreservesRepeatedAlertFields covers decay a normal
// decode could never produce or retain: a repeated field in the record's
// declaration — an exact repeat, a case-only spelling and an escaped
// spelling — must survive registration with every occurrence's name, value
// and order, and still fail the history query as a duplicate field.
func TestRegisterSuppressionPreservesRepeatedAlertFields(t *testing.T) {
	cases := []struct{ name, insert string }{
		{"exact same value", `"severity": 4, `},
		{"case variant", `"Severity": 4, `},
		{"escaped", "\"se\\u0076erity\": 4, "},
	}
	for _, dup := range cases {
		t.Run(dup.name, func(t *testing.T) {
			dir := setupAlertHistoryCorruptArchive(t)
			patchAlertRecordVersionRaw(t, dir, `"severity": 4,`, dup.insert)
			if !strings.Contains(string(readArchiveFile(t, dir)), dup.insert) {
				t.Fatal("precondition: duplicate field not present before registration")
			}
			beforeBytes := alertBytesSection(t, dir)

			if _, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec)); err != nil || !created {
				t.Fatalf("registration: created=%v err=%v", created, err)
			}

			afterBytes := alertBytesSection(t, dir)
			// Every occurrence survives with its own spelling and value and
			// in its original position (the semantic-bytes comparison pins
			// order; the counts pin the number of each spelling).
			if !bytes.Equal(beforeBytes[0], afterBytes[0]) {
				t.Fatalf("alert record bytes changed:\nbefore=%s\nafter =%s", beforeBytes[0], afterBytes[0])
			}
			// Count occurrences only inside the version declaration: the
			// finding also carries a "severity" field. A stored record's
			// fields serialize in struct order, so the declaration is the
			// object following "version": and ending before "minSeverity".
			start := bytes.Index(afterBytes[0], []byte(`"version":`))
			end := bytes.Index(afterBytes[0], []byte(`,"minSeverity"`))
			if start < 0 || end < 0 || end < start {
				t.Fatalf("could not locate version declaration in %s", afterBytes[0])
			}
			decl := afterBytes[0][start:end]
			escapedSpelling := []byte("\"se\\u0076erity\":4")
			lower := bytes.Count(decl, []byte(`"severity":4`))
			caseVar := bytes.Count(decl, []byte(`"Severity":4`))
			escapedVar := bytes.Count(decl, escapedSpelling)
			switch dup.name {
			case "exact same value":
				if lower != 2 || caseVar != 0 || escapedVar != 0 {
					t.Fatalf("occurrences after registration: lower=%d case=%d escaped=%d", lower, caseVar, escapedVar)
				}
			case "case variant":
				if lower != 1 || caseVar != 1 || escapedVar != 0 {
					t.Fatalf("occurrences after registration: lower=%d case=%d escaped=%d", lower, caseVar, escapedVar)
				}
			case "escaped":
				if lower != 1 || caseVar != 0 || escapedVar != 1 {
					t.Fatalf("occurrences after registration: lower=%d case=%d escaped=%d", lower, caseVar, escapedVar)
				}
			}
			_, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
			if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
				t.Fatalf("history over the repeated-field record: %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
			}
		})
	}
}

// TestRegisterSuppressionKeepsIntactAndSuppressedRecords proves healthy
// history is returned exactly as saved after a registration: the complete
// detection parameters (including a self-contained unregistered id and an
// explicit disabled rule), the generation threshold, the suppressed status
// and the suppression hits with their reasons, all unchanged and in order.
func TestRegisterSuppressionKeepsIntactAndSuppressedRecords(t *testing.T) {
	t.Run("complete unregistered id keeps its own parameters", func(t *testing.T) {
		ghost := map[string]any{
			"id": "never-registered",
			"rules": map[string]any{
				"sandwich":     map[string]any{"enabled": false, "severity": 1},
				"displacement": map[string]any{"enabled": true, "severity": 5, "multiplier": 100},
			},
		}
		assertRegisterSucceedsOverCorruptAlert(t, func(t *testing.T, dir string) {
			replaceStoredAlertVersion(t, dir,
				alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, ghost)
		}, false)
	})

	t.Run("suppressed record keeps status hits and reason", func(t *testing.T) {
		dir := setupSuppressedAlertHistoryArchive(t)
		before, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		beforeBytes := alertBytesSection(t, dir)

		// A second, disjoint condition registers successfully and touches
		// nothing in the saved record — including its s1 hit and reason.
		other := `{"id":"s9","chainId":"2","pool":"p9","kind":"sandwich","channel":"audit","startHeight":0,"endHeight":5,"reason":"other"}`
		if _, created, rerr := RegisterSuppression(dir, []byte(other)); rerr != nil || !created {
			t.Fatalf("register disjoint condition: created=%v err=%v", created, rerr)
		}

		after, aerr := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100)
		if aerr != nil {
			t.Fatalf("history after registration: %v", aerr)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("history changed on registration:\nbefore=%+v\nafter =%+v", before, after)
		}
		r := after[0]
		if r.Status != AlertStatusSuppressed || len(r.Suppressions) != 1 ||
			r.Suppressions[0].ID != "s1" || r.Suppressions[0].Reason != "known bot war" {
			t.Fatalf("historical suppression hits changed: %+v", r.Suppressions)
		}
		if !reflect.DeepEqual(beforeBytes, alertBytesSection(t, dir)) {
			t.Fatal("the suppressed record's stored bytes changed on registration")
		}
	})

	t.Run("new condition leaves a fresh conclusion suppressed going forward", func(t *testing.T) {
		// The future-facing half of the rule: an event processed only after
		// registration still gets suppressed by the new condition.
		dir := setupAlertHistoryCorruptArchive(t)
		// 0xv at height 7 is already an alert; re-import nothing new yet.
		if _, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec)); err != nil || !created {
			t.Fatalf("register: created=%v err=%v", created, err)
		}
		// A new block with a matching displacement conclusion is archived
		// afterwards and processed once: it must be suppressed by s2.
		later := `{"chainId":"1","blockHash":"0xlater","blockNumber":8,"swaps":[` +
			`{"TxHash":"0+f","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":40,"Index":0},` +
			`{"TxHash":"0+u","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`
		mustReplay(t, dir, later)
		got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].BlockHash != "0xlater" || got[0].Status != AlertStatusSuppressed {
			t.Fatalf("new conclusion not processed under the new condition: %+v", got)
		}
		if len(got[0].Suppressions) != 1 || got[0].Suppressions[0].ID != "s2" {
			t.Fatalf("new conclusion hits wrong: %+v", got[0].Suppressions)
		}
		// The old record still reads "alert" with no hits.
		hist, err := AlertHistory(dir, "1", "ops", 7, 7)
		if err != nil {
			t.Fatal(err)
		}
		if len(hist) != 1 || hist[0].Status != AlertStatusAlert || len(hist[0].Suppressions) != 0 {
			t.Fatalf("historical record changed: %+v", hist)
		}
	})
}

// TestRegisterSuppressionOverCorruptAlertKeepsOutcomes proves the
// pre-decision outcomes (identical retry created:false, different content
// conflict) and the failed cases (invalid spec, unparseable archive) leave
// the damaged processing record exactly as stored, and that a damaged
// alert record never substitutes for the block-report proof, which keeps
// rejecting registration on its own.
func TestRegisterSuppressionOverCorruptAlertKeepsOutcomes(t *testing.T) {
	t.Run("identical retry and conflict do not touch the record", func(t *testing.T) {
		dir := setupAlertHistoryCorruptArchive(t)
		if _, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec)); err != nil || !created {
			t.Fatalf("setup register: created=%v err=%v", created, err)
		}
		patchAlertRecordVersionRaw(t, dir, `"severity": 4,`, `"severity": 4, `)
		beforeBytes := alertBytesSection(t, dir)

		again, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec))
		if err != nil || created {
			t.Fatalf("identical retry: created=%v err=%v %+v", created, err, again)
		}
		conflict := strings.Replace(registerCoversAlertSpec, `"later window"`, `"other"`, 1)
		if _, _, cerr := RegisterSuppression(dir, []byte(conflict)); !errors.Is(cerr, ErrSuppressionConflict) {
			t.Fatalf("conflict spec over a corrupt record: %v", cerr)
		}
		if !bytes.Equal(beforeBytes[0], alertBytesSection(t, dir)[0]) {
			t.Fatal("retry/conflict rewrote the corrupt processing record")
		}
	})

	t.Run("invalid spec changes nothing", func(t *testing.T) {
		dir := setupAlertHistoryCorruptArchive(t)
		replaceStoredAlertVersion(t, dir,
			alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
		before := readArchiveFile(t, dir)
		if _, created, err := RegisterSuppression(dir, []byte(`{"id":"","chainId":"1"}`)); err == nil || created {
			t.Fatalf("invalid spec accepted: created=%v err=%v", created, err)
		}
		if after := readArchiveFile(t, dir); !bytes.Equal(before, after) {
			t.Fatal("failed validation changed the archive")
		}
	})

	t.Run("unparseable archive reported as corruption", func(t *testing.T) {
		dir := setupAlertHistoryCorruptArchive(t)
		before := []byte("{not json")
		if err := os.WriteFile(filepath.Join(dir, archiveFileName), before, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec)); err == nil || created {
			t.Fatalf("unparseable archive accepted: created=%v err=%v", created, err)
		} else if !strings.Contains(err.Error(), "corrupted") {
			t.Fatalf("error = %v, want archive corruption", err)
		}
		if after := readArchiveFile(t, dir); !bytes.Equal(before, after) {
			t.Fatal("failed registration rewrote the unparseable archive")
		}
	})

	t.Run("corrupt block report still rejects the registration", func(t *testing.T) {
		// Both damages at once: a null report declaration must fail
		// registration even while a null processing record is left alone.
		dir := setupAlertHistoryCorruptArchive(t)
		replaceStoredAlertVersion(t, dir,
			alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
		replaceStoredReportVersion(t, dir, "1", alertHistoryBlock, nil)
		before := readArchiveFile(t, dir)
		if _, created, err := RegisterSuppression(dir, []byte(registerCoversAlertSpec)); !errors.Is(err, ErrCorruptVersion) || created {
			t.Fatalf("registration over a corrupt report: created=%v err=%v", created, err)
		}
		if after := readArchiveFile(t, dir); !bytes.Equal(before, after) {
			t.Fatal("refused registration changed the archive")
		}
	})
}

// TestGenerateAlertsAppendsBesideCorruptAlertRecords proves generation also
// keeps earlier records raw: one damaged record stays exactly as stored
// while new conclusions are appended, the damaged identity is still skipped
// on regeneration, and the history query fails on the damaged record rather
// than returning the new records as a partial history.
func TestGenerateAlertsAppendsBesideCorruptAlertRecords(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput) // 0xa at height 10: sandwich 0xv, displacement 0xd
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil {
		t.Fatal(err)
	}
	// Damage the sandwich record only.
	replaceStoredAlertVersion(t, dir, "1", "0xa", "0xv", SuppressSandwich, "ops", nil)
	beforeBytes := alertBytesSection(t, dir)
	beforeRecs := decodedAlerts(t, dir)

	// Archive a second block with two new conclusions and process them:
	// only the two new records are created; the damaged record is neither
	// reprocessed (dedupe reads identity fields only) nor re-encoded.
	second := strings.NewReplacer(`"blockHash":"0xa"`, `"blockHash":"0xb"`, `"blockNumber":10`, `"blockNumber":11`).
		Replace(twoFindingsInput)
	mustReplay(t, dir, second)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatalf("generation beside a corrupt record failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("new records = %+v, want the two new conclusions", got)
	}
	for _, r := range got {
		if r.BlockHash != "0xb" {
			t.Fatalf("old conclusion reprocessed: %+v", r)
		}
	}
	afterRecs := decodedAlerts(t, dir)
	afterBytes := alertBytesSection(t, dir)
	if len(afterRecs) != len(beforeRecs)+2 {
		t.Fatalf("record count = %d, want %d (append only)", len(afterRecs), len(beforeRecs)+2)
	}
	assertAlertsSemanticallyEqual(t, beforeRecs, afterRecs[:len(beforeRecs)], beforeBytes, afterBytes[:len(beforeBytes)])

	// The damaged sandwich record keeps failing a history query over the
	// whole range — no partial history — even though new intact records now
	// sit beside it, and regenerating adds nothing.
	if _, err := AlertHistory(dir, "1", "ops", 0, 100); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("history over the damaged record: %v, want ErrCorruptVersion", err)
	}
	if again, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err != nil || len(again) != 0 {
		t.Fatalf("regeneration created records: %+v err=%v", again, err)
	}
}

// TestRevokeSuppressionPreservesCorruptAlertRecord proves the other writer
// sharing the same raw archive shape keeps processing records byte for byte
// in content as well.
func TestRevokeSuppressionPreservesCorruptAlertRecord(t *testing.T) {
	dir := setupSuppressedAlertHistoryArchive(t)
	if _, _, err := RegisterSuppression(dir, []byte(`{"id":"s9","chainId":"2","pool":"p9","kind":"sandwich","channel":"audit","startHeight":0,"endHeight":5,"reason":"r"}`)); err != nil {
		t.Fatal(err)
	}
	replaceStoredAlertVersion(t, dir,
		alertHistoryChain, alertHistoryBlock, alertHistoryTx, alertHistoryKind, alertHistoryChannel, nil)
	beforeBytes := alertBytesSection(t, dir)

	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}
	if !bytes.Equal(beforeBytes[0], alertBytesSection(t, dir)[0]) {
		t.Fatalf("revocation rewrote the null declaration:\n%s", alertBytesSection(t, dir)[0])
	}
	if _, err := AlertHistory(dir, alertHistoryChain, alertHistoryChannel, 0, 100); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("damaged record masked by revocation: %v", err)
	}
	// The revoked condition is still listed with its flag, the other one
	// untouched.
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]bool{}
	for _, c := range conds {
		status[c.ID] = c.Revoked
	}
	if !status["s1"] || status["s9"] {
		t.Fatalf("revocation states wrong: %+v", status)
	}
}
