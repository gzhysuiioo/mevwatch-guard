package mevwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// twoBlockInput holds one sandwich (severity 3, pool p1, victim 0xv) and
// one displacement (severity 2, pool p2, victim 0xd):
//
//	p1: 0xf (gas 90) / 0xv (gas 10) / 0+k (gas 80)  -> sandwich on 0xv
//	p2: 0+w (gas 50) / 0xd (gas 10)                 -> displacement on 0xd
const twoFindingsInput = `{"chainId":"1","blockHash":"0xa","blockNumber":10,` +
	`"swaps":[` +
	`{"TxHash":"0xf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
	`{"TxHash":"0xv","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
	`{"TxHash":"0+k","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},` +
	`{"TxHash":"0+w","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":50,"Index":3},` +
	`{"TxHash":"0xd","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4}]}`

func mustReplay(t *testing.T, dir, input string) {
	t.Helper()
	if _, err := Replay(strings.NewReader(input), dir); err != nil {
		t.Fatalf("Replay: %v", err)
	}
}

func TestGenerateAlertsBasic(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (only sandwich meets severity 3): %+v", len(got), got)
	}
	r := got[0]
	if r.Status != AlertStatusAlert {
		t.Fatalf("status = %q, want alert", r.Status)
	}
	if r.ChainID != "1" || r.BlockHash != "0xa" || r.BlockNumber != 10 {
		t.Fatalf("bad block identity: %+v", r)
	}
	if r.Pool != "p1" || r.Channel != "ops" {
		t.Fatalf("bad pool/channel: %+v", r)
	}
	if r.Finding.Kind != "sandwich" || r.Finding.TxHash != "0xv" || r.Finding.Severity != 3 {
		t.Fatalf("bad finding: %+v", r.Finding)
	}
	if r.MinSeverity != 3 {
		t.Fatalf("MinSeverity = %d, want 3", r.MinSeverity)
	}
	if r.Version.ID != BuiltinVersionID {
		t.Fatalf("version = %q, want builtin (no re-detection)", r.Version.ID)
	}
	if len(r.Finding.Evidence) != 3 || r.Finding.Evidence[1].TxHash != "0xv" {
		t.Fatalf("raw evidence not preserved: %+v", r.Finding.Evidence)
	}
	if r.Suppressions == nil || len(r.Suppressions) != 0 {
		t.Fatalf("alerts carry an empty suppression list, got %+v", r.Suppressions)
	}
}

func TestGenerateAlertsEmptyIsArray(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	got, err := GenerateAlerts(dir, "1", "ops", 100, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d records, want 0", len(got))
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("empty result must serialize as [], got %s", raw)
	}
}

func TestGenerateAlertsIdempotent(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	first, err := GenerateAlerts(dir, "1", "ops", 10, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("first run: got %d, want 1", len(first))
	}
	// Repeated generation, wider range, overlapping range, and a "restart"
	// (fresh call against the same on-disk archive) create nothing new while
	// the threshold stays at 3 (the severity-2 displacement is simply
	// ineligible, not processed).
	for _, bounds := range [][2]uint64{{10, 10}, {0, 100}, {5, 15}, {10, 10}} {
		again, err := GenerateAlerts(dir, "1", "ops", bounds[0], bounds[1], 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(again) != 0 {
			t.Fatalf("range %d-%d re-generated %d records: %+v", bounds[0], bounds[1], len(again), again)
		}
	}
	// Re-importing the same block still cannot make the sandwich alert twice.
	mustReplay(t, dir, twoFindingsInput)
	again, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("re-import re-generated records: %+v", again)
	}
	// Lowering the threshold backfills the displacement once, then never again.
	backfill, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(backfill) != 1 || backfill[0].Finding.Kind != "displacement" {
		t.Fatalf("threshold backfill: got %+v, want the one displacement", backfill)
	}
	after, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("backfilled displacement re-generated: %+v", after)
	}
}

func TestGenerateAlertsBelowThresholdLeavesNoRecord(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("severity-3 finding under threshold 5 produced %d records", len(got))
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.AlertRecords) != 0 {
		t.Fatalf("below-threshold finding left a record: %+v", data.AlertRecords)
	}
	// Lowering the threshold backfills it.
	got, err = GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Status != AlertStatusAlert {
		t.Fatalf("threshold backfill produced %+v", got)
	}
}

func TestGenerateAlertsThresholdInclusive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// Severity exactly equal to the threshold counts as a hit.
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("threshold 2 should include severities 2 and 3, got %d", len(got))
	}
}

func TestGenerateAlertsSuppressed(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":10,"endHeight":10,"reason":"known bot war"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]ProcessingRecord{}
	for _, r := range got {
		byKey[r.Finding.TxHash] = r
	}
	sup, ok := byKey["0xv"]
	if !ok {
		t.Fatal("sandwich record missing")
	}
	if sup.Status != AlertStatusSuppressed {
		t.Fatalf("sandwich status = %q, want suppressed", sup.Status)
	}
	if len(sup.Suppressions) != 1 || sup.Suppressions[0].ID != "s1" || sup.Suppressions[0].Reason != "known bot war" {
		t.Fatalf("bad suppression hits: %+v", sup.Suppressions)
	}
	// The displacement in pool p2 is unaffected and still alerts.
	if byKey["0xd"].Status != AlertStatusAlert {
		t.Fatalf("displacement status = %q, want alert", byKey["0xd"].Status)
	}
}

func TestSuppressionExactMatchAndInclusiveBounds(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	base := Suppression{ID: "s", ChainID: "1", Pool: "p1", Kind: "sandwich", Channel: "ops", Reason: "r"}
	cases := []struct {
		name   string
		mutate func(*Suppression)
		hit    bool
	}{
		{"exact at start", func(s *Suppression) { s.StartHeight, s.EndHeight = 10, 10 }, true},
		{"covering range", func(s *Suppression) { s.StartHeight, s.EndHeight = 9, 11 }, true},
		{"ends just before", func(s *Suppression) { s.StartHeight, s.EndHeight = 1, 9 }, false},
		{"starts just after", func(s *Suppression) { s.StartHeight, s.EndHeight = 11, 20 }, false},
		{"other pool", func(s *Suppression) { s.StartHeight, s.EndHeight = 10, 10; s.Pool = "p2" }, false},
		{"other kind", func(s *Suppression) { s.StartHeight, s.EndHeight = 10, 10; s.Kind = "displacement" }, false},
		{"other channel", func(s *Suppression) { s.StartHeight, s.EndHeight = 10, 10; s.Channel = "other" }, false},
		{"other chain", func(s *Suppression) { s.StartHeight, s.EndHeight = 10, 10; s.ChainID = "2" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.mutate(&s)
			got := s.covers("1", "p1", "sandwich", "ops", 10)
			if got != tc.hit {
				t.Fatalf("covers = %v, want %v", got, tc.hit)
			}
		})
	}
}

func TestSuppressionOverlappingHitsSorted(t *testing.T) {
	conds := []Suppression{
		{ID: "b-second", ChainID: "1", Pool: "p1", Kind: "sandwich", Channel: "ops", StartHeight: 0, EndHeight: 20, Reason: "rb"},
		{ID: "a-first", ChainID: "1", Pool: "p1", Kind: "sandwich", Channel: "ops", StartHeight: 10, EndHeight: 10, Reason: "ra"},
	}
	hits := matchSuppressions(conds, "1", "p1", "sandwich", "ops", 10)
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(hits))
	}
	if hits[0].ID != "a-first" || hits[1].ID != "b-second" {
		t.Fatalf("hits not sorted lexicographically: %+v", hits)
	}
}

func TestSuppressionDoesNotRewriteHistory(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	got, err := GenerateAlerts(dir, "1", "ops", 10, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Status != AlertStatusAlert {
		t.Fatalf("precondition: want alert, got %q", got[0].Status)
	}
	// Registering a condition covering the already-processed event changes
	// nothing historical and never re-generates.
	spec := `{"id":"late","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":100,"reason":"too late"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	again, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range again {
		if r.Finding.TxHash == "0xv" {
			t.Fatalf("already-alerted sandwich was reprocessed: %+v", r)
		}
	}
	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range hist {
		if r.Finding.TxHash == "0xv" && r.Status != AlertStatusAlert {
			t.Fatalf("historical alert rewritten to %q", r.Status)
		}
	}
}

func TestSuppressedStaysSuppressedAfterRangeEnds(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	spec := `{"id":"temp","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":10,"endHeight":10,"reason":"temporary"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	var sandwich *ProcessingRecord
	for i := range got {
		if got[i].Finding.TxHash == "0xv" {
			sandwich = &got[i]
		}
	}
	if sandwich == nil || sandwich.Status != AlertStatusSuppressed {
		t.Fatalf("precondition failed: %+v", got)
	}
	// Generate again "after the condition's window": nothing is backfilled.
	again, err := GenerateAlerts(dir, "1", "ops", 11, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("expired suppression window re-alerted a suppressed record: %+v", again)
	}
}

func TestChannelsAndBlockHashesIndependent(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// Two blocks at the same height with different hashes are separate.
	other := strings.Replace(twoFindingsInput, `"blockHash":"0xa"`, `"blockHash":"0xb"`, 1)
	mustReplay(t, dir, other)

	ops, err := GenerateAlerts(dir, "1", "ops", 10, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("ops: got %d records, want one sandwich per distinct block hash", len(ops))
	}
	if ops[0].BlockHash == ops[1].BlockHash {
		t.Fatalf("same-height distinct-hash blocks collapsed: %+v", ops)
	}
	oncall, err := GenerateAlerts(dir, "1", "oncall", 10, 10, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(oncall) != 2 {
		t.Fatalf("oncall channel: got %d records, want 2 independently processed", len(oncall))
	}
	histOps, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	histOncall, err := AlertHistory(dir, "1", "oncall", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(histOps) != 2 || len(histOncall) != 2 {
		t.Fatalf("channel isolation broken in history: ops=%d oncall=%d", len(histOps), len(histOncall))
	}
}

func TestGenerateUsesArchivedVersionWithoutRedetection(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// Enable stricter rules after archival: alerting must reuse the archived
	// built-in conclusion, never re-judge.
	if _, err := EnableVersion(dir, registerStrict(t, dir)); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Version.ID != BuiltinVersionID {
			t.Fatalf("record re-judged under %q instead of archived builtin", r.Version.ID)
		}
		if r.Finding.Kind == "sandwich" && r.Finding.Severity != 3 {
			t.Fatalf("archived sandwich severity changed to %d", r.Finding.Severity)
		}
	}
}

func registerStrict(t *testing.T, dir string) string {
	t.Helper()
	v, _, err := RegisterVersion(dir, []byte(strictSpec))
	if err != nil {
		t.Fatal(err)
	}
	return v.ID
}

func TestGenerateAndHistorySorting(t *testing.T) {
	dir := t.TempDir()
	// Height 5 hashes 0xa and 0xb; height 1 hash 0xc.
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xc","blockNumber":1,"swaps":[`+
		`{"TxHash":"0xf1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0+h1","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+z1","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":80,"Index":2}]}`)
	mustReplay(t, dir, twoFindingsInput) // hash 0xa, height 10
	// hash 0xb at height 5 (displacement only, one victim).
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xb","blockNumber":5,"swaps":[`+
		`{"TxHash":"0+g","Pool":"p1","Trader":"w","In":1,"Out":1,"GasPrice":50,"Index":0},`+
		`{"TxHash":"0+h","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1}]}`)
	// hash 0xa2 at height 5 with sandwich victim 0xv2 (same height as 0xb,
	// different hash: separate identity, ordered by hash).
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xa2","blockNumber":5,"swaps":[`+
		`{"TxHash":"0xf2","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0xv2","Pool":"p1","Trader":"u","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0+z2","Pool":"p1","Trader":"b","In":1,"Out":1,"GasPrice":80,"Index":2}]}`)

	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		height uint64
		hash   string
		tx     string
		kind   string
	}{
		{1, "0xc", "0+h1", "sandwich"},
		{5, "0xa2", "0xv2", "sandwich"},
		{5, "0xb", "0+h", "displacement"},
		{10, "0xa", "0xd", "displacement"},
		{10, "0xa", "0xv", "sandwich"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i].BlockNumber != w.height || got[i].BlockHash != w.hash ||
			got[i].Finding.TxHash != w.tx || got[i].Finding.Kind != w.kind {
			t.Fatalf("record %d = height %d hash %s tx %s kind %s, want %+v",
				i, got[i].BlockNumber, got[i].BlockHash, got[i].Finding.TxHash, got[i].Finding.Kind, w)
		}
	}
	// History must use the same ordering.
	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hist, got) {
		t.Fatalf("history order differs from generation order\n%+v\n%+v", hist, got)
	}
}

func TestAlertHistoryFiltersAndEmpty(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	if _, err := GenerateAlerts(dir, "1", "ops", 10, 10, 2); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		chain      string
		channel    string
		start, end uint64
		want       int
	}{
		{"exact", "1", "ops", 10, 10, 2},
		{"before range", "1", "ops", 0, 9, 0},
		{"after range", "1", "ops", 11, 100, 0},
		{"other channel", "1", "other", 0, 100, 0},
		{"other chain", "2", "ops", 0, 100, 0},
		{"missing archive", "1", "ops", 0, 100, 0},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := dir
			if i == len(cases)-1 {
				d = filepath.Join(t.TempDir(), "absent")
			}
			got, err := AlertHistory(d, tc.chain, tc.channel, tc.start, tc.end)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d records, want %d", len(got), tc.want)
			}
			if len(got) == 0 {
				raw, _ := json.Marshal(got)
				if string(raw) != "[]" {
					t.Fatalf("empty history must serialize as [], got %s", raw)
				}
			}
		})
	}
}

func TestGenerateValidation(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	cases := []struct {
		name    string
		chain   string
		channel string
		sev     int
		start   uint64
		end     uint64
	}{
		{"empty channel", "1", "  ", 1, 0, 100},
		{"empty chain", " ", "ops", 1, 0, 100},
		{"severity zero", "1", "ops", 0, 0, 100},
		{"severity six", "1", "ops", 6, 0, 100},
		{"negative-looking start", "1", "ops", 1, 5, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GenerateAlerts(dir, tc.chain, tc.channel, tc.start, tc.end, tc.sev); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestParseHeight(t *testing.T) {
	good := map[string]uint64{"0": 0, "18446744073709551615": 1<<64 - 1, "007": 7}
	for in, want := range good {
		got, err := ParseHeight(in)
		if err != nil || got != want {
			t.Fatalf("ParseHeight(%q) = %d, %v want %d", in, got, err, want)
		}
	}
	bad := []string{"", "-1", "1.5", "0x10", "18446744073709551616", "  3", "abc"}
	for _, in := range bad {
		if _, err := ParseHeight(in); err == nil {
			t.Fatalf("ParseHeight(%q) succeeded, want error", in)
		}
	}
}

func TestParseSuppressionValidation(t *testing.T) {
	good := `{"id":"s","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":18446744073709551615,"reason":"r"}`
	s, err := ParseSuppression([]byte(good))
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if s.StartHeight != 0 || s.EndHeight != 1<<64-1 {
		t.Fatalf("uint64 bounds lost: %+v", s)
	}
	bad := []struct {
		name string
		spec string
	}{
		{"not json", `{"id":`},
		{"trailing garbage", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"} x`},
		{"missing id", `{"chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"blank id", `{"id":"  ","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"missing chain", `{"id":"s","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"missing pool", `{"id":"s","chainId":"1","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"unknown kind", `{"id":"s","chainId":"1","pool":"p","kind":"rugpull","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"missing kind", `{"id":"s","chainId":"1","pool":"p","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"missing channel", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"missing start", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","endHeight":2,"reason":"r"}`},
		{"negative start", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":-1,"endHeight":2,"reason":"r"}`},
		{"fractional end", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2.5,"reason":"r"}`},
		{"overflow end", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":18446744073709551616,"reason":"r"}`},
		{"start after end", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":3,"endHeight":2,"reason":"r"}`},
		{"missing reason", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2}`},
		{"blank reason", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":""}`},
		{"unknown field", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r","extra":1}`},
		{"empty input", ``},
		{"whitespace only", "  \n\t "},
		{"null", `null`},
		{"array", `[{"id":"s"}]`},
		{"scalar", `5`},
		{"incomplete object", `{"id":"s","chainId":"1"`},
		{"trailing brace", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}}`},
		{"trailing bracket", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}]`},
		{"second object", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"} {"id":"t"}`},
		{"trailing value", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"} null`},
		{"duplicate id same value", `{"id":"s","id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"duplicate id different value", `{"id":"s","id":"t","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"duplicate channel case variant", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"ops","CHANNEL":"audit","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"duplicate via escape", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"ops","ch\u0061nnel":"audit","startHeight":1,"endHeight":2,"reason":"r"}`},
		{"revoked not settable", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r","revoked":false}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseSuppression([]byte(tc.spec)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseSuppressionStrictDocument(t *testing.T) {
	// Surrounding whitespace is fine; field names keep their historical
	// case-insensitive compatibility; string values are stored verbatim.
	doc := "\t\n {\"ID\":\"s\",\"ChainID\":\" 1 \",\"pool\":\"p1\",\"kind\":\"sandwich\",\"channel\":\"ops\",\"startHeight\":1,\"endHeight\":2,\"reason\":\"  keep me  \"} \n\t"
	s, err := ParseSuppression([]byte(doc))
	if err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	if s.ID != "s" || s.ChainID != " 1 " || s.Reason != "  keep me  " {
		t.Fatalf("string values must be stored verbatim: %+v", s)
	}
	// Escaped field names are recognized after unescaping.
	esc := `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","ch\u0061nnel":"c","startHeight":1,"endHeight":2,"reason":"r"}`
	if _, err := ParseSuppression([]byte(esc)); err != nil {
		t.Fatalf("escaped field names must be recognized: %v", err)
	}
}

func TestParseSuppressionErrorCausesDistinct(t *testing.T) {
	base := `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"ops","startHeight":1,"endHeight":2,"reason":"r"}`
	_, dupErr := ParseSuppression([]byte(strings.TrimSuffix(base, "}") + `,"CHANNEL":"audit"}`))
	if dupErr == nil || !strings.Contains(dupErr.Error(), "duplicate") ||
		!strings.Contains(dupErr.Error(), "channel") {
		t.Fatalf("duplicate error must name the field: %v", dupErr)
	}
	_, trailErr := ParseSuppression([]byte(base + "}"))
	if trailErr == nil || !strings.Contains(trailErr.Error(), "trailing") {
		t.Fatalf("trailing-content error must be distinguishable: %v", trailErr)
	}
	for _, err := range []error{dupErr, trailErr} {
		if errors.Is(err, ErrSuppressionConflict) {
			t.Fatalf("spec error %v must not look like a registration conflict", err)
		}
	}
}

func TestRegisterSuppressionInvalidSpecWithExistingID(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"s","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":1,"endHeight":2,"reason":"r"}`
	if _, created, err := RegisterSuppression(dir, []byte(spec)); err != nil || !created {
		t.Fatalf("first register: created=%v err=%v", created, err)
	}
	// The same document with a duplicate field or trailing content reuses the
	// registered id, but must be rejected as an invalid spec — never reported
	// as an idempotent created:false retry.
	invalid := []string{
		strings.TrimSuffix(spec, "}") + `,"reason":"r"}`,
		spec + "}",
		spec + spec,
	}
	for _, doc := range invalid {
		if _, created, err := RegisterSuppression(dir, []byte(doc)); err == nil || created {
			t.Fatalf("invalid spec %q: created=%v err=%v, want rejection", doc, created, err)
		}
	}
	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Revoked {
		t.Fatalf("rejected specs must not alter stored conditions: %+v", listed)
	}
}

func TestRegisterSuppressionIdempotentAndConflict(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"s","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":1,"endHeight":2,"reason":"r"}`
	first, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil || !created {
		t.Fatalf("first register: created=%v err=%v", created, err)
	}
	again, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil || created {
		t.Fatalf("identical re-register: created=%v err=%v", created, err)
	}
	if !reflect.DeepEqual(again, first) {
		t.Fatalf("re-register returned %+v, want %+v", again, first)
	}
	conflict := `{"id":"s","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":1,"endHeight":2,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(conflict)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("got %v, want ErrSuppressionConflict", err)
	}
	// Failed registration must not change stored data.
	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Kind != "sandwich" {
		t.Fatalf("conflict mutated stored suppressions: %+v", listed)
	}
}

func TestListSuppressionsSortedAndEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := ListSuppressions(filepath.Join(dir, "absent"))
	if err != nil || len(got) != 0 {
		t.Fatalf("absent archive: got %+v err=%v", got, err)
	}
	raw, _ := json.Marshal(got)
	if string(raw) != "[]" {
		t.Fatalf("empty list must serialize as [], got %s", raw)
	}
	mk := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`, id)
	}
	if _, _, err := RegisterSuppression(dir, []byte(mk("z"))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterSuppression(dir, []byte(mk("a"))); err != nil {
		t.Fatal(err)
	}
	got, err = ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "z" {
		t.Fatalf("suppressions not sorted by id: %+v", got)
	}
}

func TestAlertsBusyArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); !errors.Is(err, ErrBusy) {
		t.Fatalf("generate: got %v, want ErrBusy", err)
	}
	spec := `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","startHeight":1,"endHeight":2,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); !errors.Is(err, ErrBusy) {
		t.Fatalf("register: got %v, want ErrBusy", err)
	}
}

func TestAlertsCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("got %v, want corrupted-archive error", err)
	}
	if _, err := AlertHistory(dir, "1", "ops", 0, 100); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("history: got %v, want corrupted-archive error", err)
	}
}

func TestAlertsWorkOnOldArchive(t *testing.T) {
	dir := t.TempDir()
	// An archive written before alerting existed: only records, no alerts or
	// suppression fields.
	data := archiveData{Records: []record{{
		ChainID:     "1",
		BlockHash:   "0xa",
		BlockNumber: 10,
		Swaps:       []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}, {TxHash: "0xv", Pool: "p1", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 1}, {TxHash: "0+k", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 80, Index: 2}},
		Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0xv",
			Evidence: []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}, {TxHash: "0xv", Pool: "p1", Trader: "u", In: 1, Out: 1, GasPrice: 10, Index: 1}, {TxHash: "0+k", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 80, Index: 2}}}},
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 3)
	if err != nil {
		t.Fatalf("old archive must support alerting: %v", err)
	}
	if len(got) != 1 || got[0].Version.ID != BuiltinVersionID {
		t.Fatalf("old archive alert wrong: %+v", got)
	}
}

func TestGenerateCorruptedFindingEvidenceLeavesDataUntouched(t *testing.T) {
	dir := t.TempDir()
	// Archived finding whose evidence lost the victim swap itself: the pool
	// cannot be derived, generation must fail without writing anything.
	data := archiveData{Records: []record{{
		ChainID: "1", BlockHash: "0xa", BlockNumber: 10,
		Swaps: []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}},
		Findings: []ReportFinding{{Kind: "sandwich", Severity: 3, TxHash: "0xv",
			Evidence: []Swap{{TxHash: "0xf", Pool: "p1", Trader: "b", In: 1, Out: 1, GasPrice: 90, Index: 0}}}},
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, gerr := GenerateAlerts(dir, "1", "ops", 0, 100, 1); gerr == nil ||
		!strings.Contains(gerr.Error(), "corrupted") {
		t.Fatalf("got %v, want corrupted-archive error", gerr)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed generation modified the archive")
	}
}

func TestGenerateConcurrentNoDuplicates(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)

	const n = 12
	var wg sync.WaitGroup
	results := make([][]ProcessingRecord, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = GenerateAlerts(dir, "1", "ops", 0, 100, 1)
		}(i)
	}
	close(start)
	wg.Wait()

	succeeded, busy := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrBusy):
			busy++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if succeeded != 1 {
		t.Fatalf("got %d successful generators and %d busy, want exactly 1 success", succeeded, busy)
	}
	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 {
		t.Fatalf("history holds %d records, want exactly 2 (no duplicates, no loss)", len(hist))
	}
	seen := map[alertKey]bool{}
	for _, r := range hist {
		k := r.identity()
		if seen[k] {
			t.Fatalf("duplicate processing record: %+v", k)
		}
		seen[k] = true
	}
}

func TestGenerateOnlyReturnsNewRecords(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	// First generation with a suppression in place: one alert, one suppressed.
	spec := `{"id":"s","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":10,"endHeight":10,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, r := range got {
		statuses[r.Finding.Kind] = r.Status
	}
	if statuses["sandwich"] != AlertStatusSuppressed || statuses["displacement"] != AlertStatusAlert {
		t.Fatalf("same call must distinguish alert and suppressed: %+v", statuses)
	}
}

const revocationSpec = `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"known bot war"}`

func registerRevocationSpec(t *testing.T, dir string) Suppression {
	t.Helper()
	cond, created, err := RegisterSuppression(dir, []byte(revocationSpec))
	if err != nil || !created {
		t.Fatalf("RegisterSuppression: created=%v err=%v", created, err)
	}
	if cond.Revoked {
		t.Fatalf("newly registered condition must report revoked:false, got %+v", cond)
	}
	return cond
}

func TestRevokeSuppressionFirstAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	original := registerRevocationSpec(t, dir)

	first, changed, err := RevokeSuppression(dir, "s1")
	if err != nil || !changed {
		t.Fatalf("first revoke: changed=%v err=%v", changed, err)
	}
	if !first.Revoked {
		t.Fatalf("revoked condition must carry revoked:true, got %+v", first)
	}
	// Every original field is preserved.
	first.Revoked = false
	if !reflect.DeepEqual(first, original) {
		t.Fatalf("revocation lost fields: got %+v, want %+v", first, original)
	}
	// Revoking the same condition again succeeds with changed=false.
	again, changed, err := RevokeSuppression(dir, "s1")
	if err != nil || changed {
		t.Fatalf("second revoke: changed=%v err=%v", changed, err)
	}
	if !again.Revoked {
		t.Fatalf("second revoke must still report revoked:true, got %+v", again)
	}
}

func TestRevokeSuppressionBlankAndUnknown(t *testing.T) {
	dir := t.TempDir()
	registerRevocationSpec(t, dir)
	for _, id := range []string{"", "   ", "\t\n"} {
		if _, _, err := RevokeSuppression(dir, id); err == nil {
			t.Fatalf("blank id %q must error", id)
		}
	}
	// Exact matching: lookalikes do not revoke s1.
	for _, id := range []string{"S1", "s1 ", " s1", "s1\n", "s10", "s"} {
		if _, _, err := RevokeSuppression(dir, id); !errors.Is(err, ErrUnknownSuppression) {
			t.Fatalf("id %q: got %v, want ErrUnknownSuppression", id, err)
		}
	}
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(conds) != 1 || conds[0].Revoked {
		t.Fatalf("failed revokes must not alter the condition: %+v", conds)
	}
	// An unknown id on an empty archive reports unknown, too.
	empty := t.TempDir()
	if _, _, err := RevokeSuppression(empty, "missing"); !errors.Is(err, ErrUnknownSuppression) {
		t.Fatalf("empty archive revoke: got %v, want ErrUnknownSuppression", err)
	}
}

func TestRevokeSuppressionPersistenceAndList(t *testing.T) {
	dir := t.TempDir()
	registerRevocationSpec(t, dir)
	spec2 := `{"id":"a2","chainId":"1","pool":"p2","kind":"displacement","channel":"ops","startHeight":1,"endHeight":2,"reason":"r2"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec2)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	// Reopen the archive: revoked state survives; list keeps both entries in
	// ID order, each carrying a boolean revoked field.
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(conds) != 2 || conds[0].ID != "a2" || conds[1].ID != "s1" {
		t.Fatalf("revoked conditions must stay listed in id order: %+v", conds)
	}
	byID := map[string]Suppression{}
	for _, c := range conds {
		byID[c.ID] = c
	}
	if !byID["s1"].Revoked || byID["a2"].Revoked {
		t.Fatalf("bad revoked flags after reopen: %+v", byID)
	}
	// The persisted JSON carries an explicit revoked field on every entry.
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"revoked": false`) ||
		!strings.Contains(string(raw), `"revoked": true`) {
		t.Fatalf("archive entries must serialize a boolean revoked field:\n%s", raw)
	}
}

func TestRevokeSuppressionOldArchiveDefaultsToNotRevoked(t *testing.T) {
	dir := t.TempDir()
	data := archiveData{Suppressions: []Suppression{{
		ID: "old", ChainID: "1", Pool: "p1", Kind: "sandwich", Channel: "ops",
		StartHeight: 0, EndHeight: 200, Reason: "old-style",
	}}}
	if err := writeArchiveAtomic(dir, data); err != nil {
		t.Fatal(err)
	}
	conds, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(conds) != 1 || conds[0].Revoked {
		t.Fatalf("conditions without revoked state are not revoked: %+v", conds)
	}
	// And the old condition still matches conclusions in range.
	mustReplay(t, dir, twoFindingsInput)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Finding.TxHash == "0xv" && r.Status != AlertStatusSuppressed {
			t.Fatalf("old condition should still suppress, got %+v", r)
		}
	}
}

func TestRevokeSuppressionRegistrationRulesUnchanged(t *testing.T) {
	dir := t.TempDir()
	registerRevocationSpec(t, dir)
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	// Same id, same spec is still an idempotent no-op (created:false) and
	// must not revive the revoked condition.
	cond, created, err := RegisterSuppression(dir, []byte(revocationSpec))
	if err != nil || created {
		t.Fatalf("identical retry after revoke: created=%v err=%v", created, err)
	}
	if !cond.Revoked {
		t.Fatalf("identical retry must not re-enable a revoked condition: %+v", cond)
	}
	// Same id, different spec still conflicts.
	conflict := strings.Replace(revocationSpec, `"pool":"p1"`, `"pool":"p9"`, 1)
	if _, _, err := RegisterSuppression(dir, []byte(conflict)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("got %v, want ErrSuppressionConflict", err)
	}
	// revoked is not a registration field.
	withFlag := strings.TrimSuffix(revocationSpec, "}") + `,"revoked":false}`
	if _, _, err := RegisterSuppression(dir, []byte(withFlag)); err == nil {
		t.Fatal("a spec setting revoked must be rejected as an unknown field")
	}
	// A fresh id can suppress the same events again.
	fresh := strings.Replace(revocationSpec, `"id":"s1"`, `"id":"s2"`, 1)
	c2, created, err := RegisterSuppression(dir, []byte(fresh))
	if err != nil || !created || c2.Revoked {
		t.Fatalf("fresh id register: created=%v revoked=%v err=%v", created, c2.Revoked, err)
	}
}

func TestRevokeAppliesToProcessingTimeNotHeight(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput) // sandwich on 0xv at height 10, pool p1
	// Condition covers heights 100..200; the block at height 10 is out of
	// range either way. Use a covering condition to establish history first.
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	// Before the revocation: block 0xa at height 10 is processed suppressed.
	first, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	var historical *ProcessingRecord
	for i := range first {
		if first[i].Finding.TxHash == "0xv" {
			historical = &first[i]
		}
	}
	if historical == nil || historical.Status != AlertStatusSuppressed ||
		len(historical.Suppressions) != 1 || historical.Suppressions[0].ID != "s1" {
		t.Fatalf("precondition: want s1-suppressed record, got %+v", first)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	// A different block at the same height, imported long after the archive
	// contained the original: revocation still applies even though the block
	// "was already archived" is irrelevant — what matters is processing time.
	other := strings.Replace(twoFindingsInput, `"blockHash":"0xa"`, `"blockHash":"0xb"`, 1)
	other = strings.Replace(other, `"0xv"`, `"0xv2"`, -1)
	mustReplay(t, dir, other)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	var later *ProcessingRecord
	for i := range got {
		if got[i].BlockHash == "0xb" {
			later = &got[i]
		}
	}
	if later == nil {
		t.Fatalf("new block produced no records: %+v", got)
	}
	for _, r := range got {
		if r.Status == AlertStatusSuppressed {
			t.Fatalf("after revocation nothing should be suppressed: %+v", r)
		}
	}
	// The historical record is unchanged and still visible in history.
	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var seen *ProcessingRecord
	for i := range hist {
		if hist[i].BlockHash == "0xa" && hist[i].Finding.TxHash == "0xv" {
			seen = &hist[i]
		}
	}
	if seen == nil || seen.Status != AlertStatusSuppressed ||
		len(seen.Suppressions) != 1 || seen.Suppressions[0].ID != "s1" {
		t.Fatalf("historical record altered by revocation: %+v", seen)
	}
	// Re-generating over overlapping ranges still skips processed findings.
	again, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("overlapping generation reprocessed findings: %+v", again)
	}
}

func TestRevokeWithOtherActiveConditionStaysSuppressed(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	s1 := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"first"}`
	s2 := `{"id":"s2","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"second"}`
	if _, _, err := RegisterSuppression(dir, []byte(s1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RegisterSuppression(dir, []byte(s2)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Finding.TxHash != "0xv" {
			continue
		}
		if r.Status != AlertStatusSuppressed {
			t.Fatalf("with s2 active the finding stays suppressed, got %q", r.Status)
		}
		if len(r.Suppressions) != 1 || r.Suppressions[0].ID != "s2" {
			t.Fatalf("only the active condition's id/reason is saved: %+v", r.Suppressions)
		}
		return
	}
	t.Fatal("sandwich record missing")
}

func TestRevokeThenImportAndProcessNewBlock(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	// A block imported after the revocation at a height the condition
	// covered is processed as an alert, not suppressed.
	mustReplay(t, dir, twoFindingsInput)
	got, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	var sandwich *ProcessingRecord
	for i := range got {
		if got[i].Finding.TxHash == "0xv" {
			sandwich = &got[i]
		}
	}
	if sandwich == nil || sandwich.Status != AlertStatusAlert {
		t.Fatalf("post-revocation import must alert, got %+v", got)
	}
	if len(sandwich.Suppressions) != 0 {
		t.Fatalf("alert must not name the revoked condition: %+v", sandwich.Suppressions)
	}
}

func TestRevokeBelowThresholdStillLeavesNoRecord(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", "ops", 0, 100, 5); err != nil {
		t.Fatal(err)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.AlertRecords) != 0 {
		t.Fatalf("findings below the threshold leave no record even after revoke: %+v", data.AlertRecords)
	}
}

func TestRevokeChannelsIndependent(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	for _, ch := range []string{"ops", "oncall"} {
		spec := fmt.Sprintf(`{"id":"s-%s","chainId":"1","pool":"p1","kind":"sandwich","channel":"%s","startHeight":0,"endHeight":200,"reason":"r"}`, ch, ch)
		if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := RevokeSuppression(dir, "s-ops"); err != nil {
		t.Fatal(err)
	}
	ops, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	oncall, err := GenerateAlerts(dir, "1", "oncall", 0, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	status := func(records []ProcessingRecord) string {
		for _, r := range records {
			if r.Finding.TxHash == "0xv" {
				return r.Status
			}
		}
		return ""
	}
	if status(ops) != AlertStatusAlert {
		t.Fatalf("revoked ops condition: ops status = %q, want alert", status(ops))
	}
	if status(oncall) != AlertStatusSuppressed {
		t.Fatalf("oncall condition untouched: status = %q, want suppressed", status(oncall))
	}
}

func TestRevokeSuppressionBusyAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	registerRevocationSpec(t, dir)
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: got %v, want ErrBusy", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{broken")
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "s1"); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("corrupt: got %v, want corrupted-archive error", err)
	}
	// The failed revocation must not have rewritten the corrupt file.
	raw, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(raw, corrupt) {
		t.Fatalf("failed revocation changed the archive: %q", raw)
	}
}

func TestRevokeSuppressionConcurrentConsistent(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":0,"endHeight":200,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}

	const n = 12
	var wg sync.WaitGroup
	genErrs := make([]error, n)
	statuses := make([]string, n)
	start := make(chan struct{})
	// Half the goroutines generate, half revoke, all retrying through busy
	// errors the way a real caller does. Each generation must observe one
	// consistent condition set (suppressed pre-revoke or alert post-revoke),
	// never a half state.
	retryBusy := func(op func() error) error {
		for attempt := 0; attempt < 1000; attempt++ {
			err := op()
			if errors.Is(err, ErrBusy) {
				time.Sleep(time.Millisecond)
				continue
			}
			return err
		}
		return ErrBusy
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if i%2 == 0 {
				genErrs[i] = retryBusy(func() error {
					recs, err := GenerateAlerts(dir, "1", "ops", 0, 100, 1)
					if err == nil {
						for _, r := range recs {
							if r.Finding.TxHash == "0xv" {
								statuses[i] = r.Status
							}
						}
					}
					return err
				})
			} else {
				genErrs[i] = retryBusy(func() error {
					_, _, err := RevokeSuppression(dir, "s1")
					return err
				})
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range genErrs {
		if err != nil {
			t.Fatalf("goroutine %d unexpected error: %v", i, err)
		}
	}
	// Exactly one generation creates the sandwich record; its status must be
	// one coherent outcome, and only the matching condition ids are stored.
	hist, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	final := ""
	count := 0
	for _, r := range hist {
		if r.Finding.TxHash == "0xv" {
			count++
			final = r.Status
			if len(r.Suppressions) > 1 {
				t.Fatalf("inconsistent hit set: %+v", r.Suppressions)
			}
		}
	}
	if count != 1 {
		t.Fatalf("sandwich processed %d times, want exactly 1", count)
	}
	if final != AlertStatusAlert && final != AlertStatusSuppressed {
		t.Fatalf("final status %q is neither coherent pre/post-revocation state", final)
	}
	// The generator that created the record reports the same status it
	// committed; no generator may return an incoherent status.
	nonEmpty := 0
	for i, s := range statuses {
		if s == "" {
			continue
		}
		nonEmpty++
		if s != final {
			t.Fatalf("generator %d observed status %q but history holds %q", i, s, final)
		}
	}
	if nonEmpty != 1 {
		t.Fatalf("exactly one generation must create the record, %d reported it", nonEmpty)
	}
}
