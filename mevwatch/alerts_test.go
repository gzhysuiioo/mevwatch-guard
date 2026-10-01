package mevwatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// twoFindingsBlock has a sandwich (sev 3) in pool p1 and a displacement
// (sev 2) in pool p2 at the given height.
func twoFindingsBlock(blockHash string, height int64) string {
	return fmt.Sprintf(`{"chainId":"1","blockHash":%q,"blockNumber":%d,"swaps":[`+
		`{"TxHash":"0xf1","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},`+
		`{"TxHash":"0xv1","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},`+
		`{"TxHash":"0xb1","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},`+
		`{"TxHash":"0xf2","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":40,"Index":3},`+
		`{"TxHash":"0xv2","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4}]}`,
		blockHash, height)
}

func replayBlocks(t *testing.T, dir string, blocks ...string) {
	t.Helper()
	input := strings.Join(blocks, "\n")
	if _, err := Replay(strings.NewReader(input), dir); err != nil {
		t.Fatalf("Replay: %v", err)
	}
}

func generate(t *testing.T, dir, chainID string, start, end int64, minSeverity int, channel string) []AlertRecord {
	t.Helper()
	got, err := GenerateAlerts(dir, chainID, start, end, minSeverity, channel)
	if err != nil {
		t.Fatalf("GenerateAlerts: %v", err)
	}
	return got
}

func suppression(t *testing.T, dir, spec string) Suppression {
	t.Helper()
	s, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil {
		t.Fatalf("RegisterSuppression: %v", err)
	}
	if !created {
		t.Fatal("first registration must report created")
	}
	return s
}

func TestGenerateAlertsBasicFields(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1))
	got := generate(t, dir, "1", 0, 100, 3, "webhook")
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (sev3 sandwich only)", len(got))
	}
	a := got[0]
	if a.ChainID != "1" || a.BlockHash != "0x1" || a.BlockNumber != 1 {
		t.Fatalf("block identity wrong: %+v", a)
	}
	if a.Pool != "p1" || a.TxHash != "0xv1" || a.Kind != "sandwich" || a.Severity != 3 {
		t.Fatalf("conclusion wrong: %+v", a)
	}
	if len(a.Evidence) != 3 {
		t.Fatalf("evidence has %d swaps, want 3", len(a.Evidence))
	}
	if a.Version.ID != BuiltinVersionID || a.Version.Rules.Sandwich.Severity != 3 {
		t.Fatalf("version wrong: %+v", a.Version)
	}
	if a.MinSeverity != 3 || a.Channel != "webhook" || a.Status != StatusAlerted {
		t.Fatalf("generation metadata wrong: %+v", a)
	}
	if a.SuppressedBy == nil || len(a.SuppressedBy) != 0 {
		t.Fatalf("suppressedBy must be an empty array, got %+v", a.SuppressedBy)
	}
}

func TestGenerateAlertsThresholdEdges(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1))
	// Equal to threshold counts: sev3 sandwich at threshold 3.
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 1 || got[0].TxHash != "0xv1" {
		t.Fatalf("threshold equal must hit: %+v", got)
	}
	// Below threshold leaves no record; lowering the threshold reissues.
	got = generate(t, dir, "1", 0, 100, 2, "ch")
	if len(got) != 1 || got[0].TxHash != "0xv2" || got[0].Severity != 2 {
		t.Fatalf("lower threshold must reissue sev2 displacement: %+v", got)
	}
	// Everything processed now.
	got = generate(t, dir, "1", 0, 100, 1, "ch")
	if len(got) != 0 {
		t.Fatalf("expected empty after all processed, got %+v", got)
	}
	// Threshold above every conclusion: nothing.
	got = generate(t, dir, "1", 0, 100, 5, "ch2")
	if len(got) != 0 {
		t.Fatalf("threshold 5 must hit nothing, got %+v", got)
	}
}

func TestGenerateAlertsDedup(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1), twoFindingsBlock("0x2", 2))
	first := generate(t, dir, "1", 1, 1, 3, "ch")
	if len(first) != 1 {
		t.Fatalf("first run: %+v", first)
	}
	// Expanded range: already-processed records do not reissue, but 0x2
	// (never covered before) is legitimately new.
	expanded := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(expanded) != 1 || expanded[0].BlockHash != "0x2" {
		t.Fatalf("expanded range must only add the unprocessed block: %+v", expanded)
	}
	// A third run over the same range: nothing new.
	if got := generate(t, dir, "1", 0, 100, 3, "ch"); len(got) != 0 {
		t.Fatalf("repeat generation reissued: %+v", got)
	}
	// Re-import of the same blocks does not reissue either.
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1), twoFindingsBlock("0x2", 2))
	if got := generate(t, dir, "1", 0, 100, 3, "ch"); len(got) != 0 {
		t.Fatalf("reimport reissued: %+v", got)
	}
	// A different channel is processed separately.
	other := generate(t, dir, "1", 0, 100, 3, "other")
	if len(other) != 2 {
		t.Fatalf("different channel must process separately: %+v", other)
	}
	// Same height, different block hash: separate records.
	replayBlocks(t, dir, twoFindingsBlock("0x3", 1))
	got := generate(t, dir, "1", 1, 1, 3, "ch")
	if len(got) != 1 || got[0].BlockHash != "0x3" {
		t.Fatalf("same height different hash must process separately: %+v", got)
	}
	// The archive holds exactly one record per (chain,hash,tx,kind,channel).
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Alerts) != 5 {
		t.Fatalf("archive holds %d alerts, want 5 (ch: 0x1/0x2/0x3, other: 0x1/0x2): %+v", len(data.Alerts), data.Alerts)
	}
}

func TestGenerateAlertsRangeBoundaries(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 10), twoFindingsBlock("0x2", 20))
	// Inclusive both ends.
	got := generate(t, dir, "1", 10, 20, 3, "ch")
	if len(got) != 2 {
		t.Fatalf("inclusive range got %d, want 2", len(got))
	}
	// Outside the range: nothing.
	if got := generate(t, dir, "1", 11, 19, 3, "ch2"); len(got) != 0 {
		t.Fatalf("out-of-range must not hit: %+v", got)
	}
	// Single height.
	got = generate(t, dir, "1", 20, 20, 3, "ch3")
	if len(got) != 1 || got[0].BlockHash != "0x2" {
		t.Fatalf("single-height range wrong: %+v", got)
	}
}

func TestGenerateAlertsSorted(t *testing.T) {
	dir := t.TempDir()
	// Two blocks, each with a sev3 finding; order of replay is reversed.
	replayBlocks(t, dir, twoFindingsBlock("0xb", 2), twoFindingsBlock("0xa", 1))
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].BlockNumber != 1 || got[0].BlockHash != "0xa" ||
		got[1].BlockNumber != 2 || got[1].BlockHash != "0xb" {
		t.Fatalf("not sorted by height/hash: %+v", got)
	}
}

func TestGenerateAlertsNoRedetection(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1))
	// Enable a strict version after the fact: generation must still use the
	// archived findings (sev3 sandwich), not re-detect under strict.
	spec := `{"id":"strict","rules":{"sandwich":{"enabled":true,"severity":5},"displacement":{"enabled":true,"severity":4,"multiplier":5}}}`
	if _, _, err := RegisterVersion(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(dir, "strict"); err != nil {
		t.Fatal(err)
	}
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].Severity != 3 || got[0].Version.ID != BuiltinVersionID {
		t.Fatalf("generation must use archived conclusion/version: %+v", got[0])
	}
}

func TestGenerateAlertsSuppression(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 10))
	sup := suppression(t, dir,
		`{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"webhook","start":10,"end":10,"reason":"known bot"}`)
	got := generate(t, dir, "1", 0, 100, 3, "webhook")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1 suppressed record", len(got))
	}
	a := got[0]
	if a.Status != StatusSuppressed {
		t.Fatalf("status = %q, want suppressed", a.Status)
	}
	if len(a.SuppressedBy) != 1 || a.SuppressedBy[0].ID != "s1" || a.SuppressedBy[0].Reason != sup.Reason {
		t.Fatalf("suppression hits wrong: %+v", a.SuppressedBy)
	}
	// The displacement in pool p2 is not suppressed.
	got = generate(t, dir, "1", 0, 100, 2, "webhook")
	if len(got) != 1 || got[0].Status != StatusAlerted || got[0].Pool != "p2" {
		t.Fatalf("p2 displacement must alert: %+v", got)
	}
}

func TestSuppressionExactMatch(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"wrong chain", `{"id":"s1","chainId":"2","pool":"p1","kind":"sandwich","channel":"ch","start":0,"end":100,"reason":"r"}`},
		{"wrong pool", `{"id":"s1","chainId":"1","pool":"other","kind":"sandwich","channel":"ch","start":0,"end":100,"reason":"r"}`},
		{"wrong kind", `{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ch","start":0,"end":100,"reason":"r"}`},
		{"wrong channel", `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"other","start":0,"end":100,"reason":"r"}`},
		{"outside interval", `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":11,"end":20,"reason":"r"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			replayBlocks(t, dir, twoFindingsBlock("0x1", 10))
			suppression(t, dir, tc.spec)
			got := generate(t, dir, "1", 0, 100, 3, "ch")
			if len(got) != 1 || got[0].Status != StatusAlerted {
				t.Fatalf("condition must not match: %+v", got)
			}
		})
	}
}

func TestSuppressionBoundariesAndEventHeight(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 10), twoFindingsBlock("0x2", 20))
	// Interval covers only height 10, inclusive at both ends.
	suppression(t, dir,
		`{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":10,"end":10,"reason":"r"}`)
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Status != StatusSuppressed || got[1].Status != StatusAlerted {
		t.Fatalf("interval must judge by event height: %+v", got)
	}
	// Suppressed record is never reissued, even after the interval ends.
	if again := generate(t, dir, "1", 0, 100, 3, "ch"); len(again) != 0 {
		t.Fatalf("suppressed record reissued: %+v", again)
	}
}

func TestSuppressionOverlappingHitsSorted(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 10))
	suppression(t, dir,
		`{"id":"b","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":0,"end":100,"reason":"r-b"}`)
	suppression(t, dir,
		`{"id":"a","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":10,"end":10,"reason":"r-a"}`)
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 1 || got[0].Status != StatusSuppressed {
		t.Fatalf("got %+v", got)
	}
	hits := got[0].SuppressedBy
	if len(hits) != 2 || hits[0].ID != "a" || hits[1].ID != "b" ||
		hits[0].Reason != "r-a" || hits[1].Reason != "r-b" {
		t.Fatalf("overlapping hits must be saved and sorted by id: %+v", hits)
	}
}

func TestSuppressionDoesNotRewriteHistory(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 10))
	// Alert first, register a covering condition afterwards.
	first := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(first) != 1 || first[0].Status != StatusAlerted {
		t.Fatalf("setup: %+v", first)
	}
	suppression(t, dir,
		`{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":0,"end":100,"reason":"r"}`)
	// History is unchanged; nothing new is processed.
	if again := generate(t, dir, "1", 0, 100, 3, "ch"); len(again) != 0 {
		t.Fatalf("late condition must not reprocess: %+v", again)
	}
	hist, err := QueryAlerts(dir, "1", "ch", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 1 || hist[0].Status != StatusAlerted || len(hist[0].SuppressedBy) != 0 {
		t.Fatalf("history must stay alerted: %+v", hist)
	}
}

func TestSuppressionRegistrationLifecycle(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":1,"end":9,"reason":"r"}`
	s, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil || !created {
		t.Fatalf("first register: %v created=%v", err, created)
	}
	// Same id, same content: success, no new condition.
	if _, created, err := RegisterSuppression(dir, []byte(spec)); err != nil || created {
		t.Fatalf("identical reregister: %v created=%v", err, created)
	}
	// Same id, different content: rejected.
	different := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":1,"end":10,"reason":"r"}`
	if _, _, err := RegisterSuppression(dir, []byte(different)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("want ErrSuppressionConflict, got %v", err)
	}
	// A different id with the same content is a distinct condition.
	other := `{"id":"s2","chainId":"1","pool":"p1","kind":"sandwich","channel":"ch","start":1,"end":9,"reason":"r"}`
	if _, created, err := RegisterSuppression(dir, []byte(other)); err != nil || !created {
		t.Fatalf("distinct id: %v created=%v", err, created)
	}
	list, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "s1" || list[1].ID != "s2" {
		t.Fatalf("list = %+v", list)
	}
	if list[0] != s {
		t.Fatalf("stored condition changed: %+v vs %+v", list[0], s)
	}
}

func TestSuppressionValidation(t *testing.T) {
	bad := []struct {
		name string
		spec string
	}{
		{"not json", `{"id":`},
		{"trailing", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":0,"end":1,"reason":"r"} extra`},
		{"empty id", `{"id":"","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":0,"end":1,"reason":"r"}`},
		{"empty chain", `{"id":"s","chainId":"","pool":"p","kind":"sandwich","channel":"c","start":0,"end":1,"reason":"r"}`},
		{"empty pool", `{"id":"s","chainId":"1","pool":"","kind":"sandwich","channel":"c","start":0,"end":1,"reason":"r"}`},
		{"empty channel", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"","start":0,"end":1,"reason":"r"}`},
		{"empty reason", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":0,"end":1,"reason":""}`},
		{"unknown kind", `{"id":"s","chainId":"1","pool":"p","kind":"frontrun","channel":"c","start":0,"end":1,"reason":"r"}`},
		{"missing kind", `{"id":"s","chainId":"1","pool":"p","channel":"c","start":0,"end":1,"reason":"r"}`},
		{"start above end", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":5,"end":4,"reason":"r"}`},
		{"negative start", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":-1,"end":4,"reason":"r"}`},
		{"negative end", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":0,"end":-1,"reason":"r"}`},
		{"fractional height", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":1.5,"end":4,"reason":"r"}`},
		{"unknown field", `{"id":"s","chainId":"1","pool":"p","kind":"sandwich","channel":"c","start":0,"end":1,"reason":"r","extra":1}`},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, _, err := RegisterSuppression(dir, []byte(tc.spec)); err == nil {
				t.Fatal("expected error")
			}
			if _, err := os.Stat(filepath.Join(dir, archiveFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("archive created after failed registration: %v", err)
			}
		})
	}
}

func TestGenerateAlertsValidation(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1))
	bad := []struct {
		name       string
		chain      string
		start, end int64
		sev        int
		channel    string
	}{
		{"empty chain", "", 0, 10, 3, "ch"},
		{"empty channel", "1", 0, 10, 3, ""},
		{"severity zero", "1", 0, 10, 0, "ch"},
		{"severity six", "1", 0, 10, 6, "ch"},
		{"start above end", "1", 10, 9, 3, "ch"},
		{"negative start", "1", -1, 9, 3, "ch"},
		{"negative end", "1", 0, -1, 3, "ch"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GenerateAlerts(dir, tc.chain, tc.start, tc.end, tc.sev, tc.channel); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	// A failed generation must not create processing records.
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Alerts) != 0 {
		t.Fatalf("failed generation left records: %+v", data.Alerts)
	}
}

func TestQueryAlerts(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0xa", 1), twoFindingsBlock("0xb", 2))
	generate(t, dir, "1", 0, 100, 3, "ch")
	generate(t, dir, "1", 0, 100, 3, "other")
	// Filter by channel.
	got, err := QueryAlerts(dir, "1", "ch", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("channel filter got %d, want 2: %+v", len(got), got)
	}
	// Filter by range.
	got, err = QueryAlerts(dir, "1", "ch", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].BlockHash != "0xb" {
		t.Fatalf("range filter wrong: %+v", got)
	}
	// Unknown channel: empty array, not nil.
	got, err = QueryAlerts(dir, "1", "ghost", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("empty query must be an empty array: %+v", got)
	}
	// Unknown chain: empty array.
	got, err = QueryAlerts(dir, "9", "ch", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unknown chain must be empty: %+v", got)
	}
	// Missing archive directory: empty array.
	got, err = QueryAlerts(filepath.Join(dir, "nope"), "1", "ch", 0, 100)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing archive: %+v %v", got, err)
	}
}

func TestQueryAlertsSortedAcrossKinds(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0xa", 1))
	// Both kinds processed for the channel.
	generate(t, dir, "1", 0, 100, 1, "ch")
	got, err := QueryAlerts(dir, "1", "ch", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	// Same height/hash: ordered by transaction hash (0xv1 before 0xv2),
	// then kind.
	if got[0].TxHash != "0xv1" || got[0].Kind != "sandwich" ||
		got[1].TxHash != "0xv2" || got[1].Kind != "displacement" {
		t.Fatalf("not sorted by tx hash then kind: %+v", got)
	}
}

func TestGenerateAlertsCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(`{"records":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", 0, 10, 3, "ch"); err == nil {
		t.Fatal("corrupted archive must error")
	}
	if _, err := QueryAlerts(dir, "1", "ch", 0, 10); err == nil {
		t.Fatal("corrupted archive query must error")
	}
}

func TestGenerateAlertsBusy(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1))
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateAlerts(dir, "1", 0, 100, 3, "ch"); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
}

func TestConcurrentGenerateAlerts(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0x1", 1), twoFindingsBlock("0x2", 2), twoFindingsBlock("0x3", 3))
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				got, err := GenerateAlerts(dir, "1", 0, 100, 3, "ch")
				if errors.Is(err, ErrBusy) {
					continue
				}
				if err != nil {
					errs <- err
					return
				}
				mu.Lock()
				total += len(got)
				mu.Unlock()
				return
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	// Each distinct conclusion is returned exactly once across all callers.
	if total != 3 {
		t.Fatalf("concurrent generation returned %d records total, want 3", total)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Alerts) != 3 {
		t.Fatalf("archive holds %d alerts, want 3 (no duplicates/loss): %+v", len(data.Alerts), data.Alerts)
	}
}

func TestLegacyArchiveAlerts(t *testing.T) {
	dir := t.TempDir()
	// Hand-write a pre-alert archive: no suppressions/alerts fields.
	legacy := `{"records":[{"chainId":"1","blockHash":"0xleg","blockNumber":5,` +
		`"swaps":[{"TxHash":"0xfront","Pool":"p1","Trader":"bot","In":500,"Out":480,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xback","Pool":"p1","Trader":"bot","In":480,"Out":505,"GasPrice":80,"Index":2}],` +
		`"findings":[{"kind":"sandwich","severity":3,"txHash":"0xvictim","evidence":[` +
		`{"TxHash":"0xfront","Pool":"p1","Trader":"bot","In":500,"Out":480,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xvictim","Pool":"p1","Trader":"user","In":200,"Out":188,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0xback","Pool":"p1","Trader":"bot","In":480,"Out":505,"GasPrice":80,"Index":2}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, archiveFileName), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 1 {
		t.Fatalf("legacy archive must generate alerts: %+v", got)
	}
	a := got[0]
	if a.BlockHash != "0xleg" || a.BlockNumber != 5 || a.Pool != "p1" || a.Status != StatusAlerted {
		t.Fatalf("legacy alert wrong: %+v", a)
	}
	if a.Version != BuiltinVersion() {
		t.Fatalf("legacy alert version = %+v, want builtin", a.Version)
	}
	// Repeated generation is idempotent.
	if again := generate(t, dir, "1", 0, 100, 3, "ch"); len(again) != 0 {
		t.Fatalf("legacy reissue: %+v", again)
	}
}

func TestGenerateAlertsEmptyArchive(t *testing.T) {
	dir := t.TempDir()
	got := generate(t, dir, "1", 0, 100, 3, "ch")
	if len(got) != 0 {
		t.Fatalf("empty archive must return empty: %+v", got)
	}
	// The archive directory is created and holds no alerts.
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Alerts) != 0 || len(data.Records) != 0 {
		t.Fatalf("empty generation wrote data: %+v", data)
	}
}

func TestQueryAlertsMatchesGenerationOrder(t *testing.T) {
	dir := t.TempDir()
	replayBlocks(t, dir, twoFindingsBlock("0xb", 2), twoFindingsBlock("0xa", 1))
	gen := generate(t, dir, "1", 0, 100, 3, "ch")
	q, err := QueryAlerts(dir, "1", "ch", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gen, q) {
		t.Fatalf("query order differs from generation order:\n%+v\n%+v", gen, q)
	}
}
