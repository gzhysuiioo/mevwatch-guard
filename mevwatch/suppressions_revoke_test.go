package mevwatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// revokeBlockInput builds a block at height with one sandwich (severity 3,
// pool p1, victim 0xv) and one displacement (severity 2, pool p2, victim
// 0xd), using hash for the block hash.
func revokeBlockInput(hash string, height uint64) string {
	return fmt.Sprintf(`{"chainId":"1","blockHash":%q,"blockNumber":%d,`, hash, height) +
		`"swaps":[` +
		`{"TxHash":"0xf","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":0},` +
		`{"TxHash":"0xv","Pool":"p1","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},` +
		`{"TxHash":"0+k","Pool":"p1","Trader":"bot","In":1,"Out":1,"GasPrice":80,"Index":2},` +
		`{"TxHash":"0+w","Pool":"p2","Trader":"whale","In":1,"Out":1,"GasPrice":50,"Index":3},` +
		`{"TxHash":"0xd","Pool":"p2","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":4}]}`
}

func registerRevokeSpec(t *testing.T, dir, id string) {
	t.Helper()
	spec := fmt.Sprintf(`{"id":%q,"chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"maintenance"}`, id)
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeSuppressionBasic(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"ops-1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"maintenance"}`
	cond, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil || !created {
		t.Fatalf("register: created=%v err=%v", created, err)
	}
	if cond.Revoked {
		t.Fatal("newly registered condition must not be revoked")
	}

	revoked, changed, err := RevokeSuppression(dir, "ops-1")
	if err != nil || !changed {
		t.Fatalf("first revoke: changed=%v err=%v", changed, err)
	}
	if !revoked.Revoked {
		t.Fatal("revoked condition must carry revoked=true")
	}
	if revoked.ID != "ops-1" || revoked.ChainID != "1" || revoked.Pool != "p1" ||
		revoked.Kind != "sandwich" || revoked.Channel != "ops" ||
		revoked.StartHeight != 100 || revoked.EndHeight != 200 || revoked.Reason != "maintenance" {
		t.Fatalf("revoked condition lost original fields: %+v", revoked)
	}

	again, changed, err := RevokeSuppression(dir, "ops-1")
	if err != nil || changed {
		t.Fatalf("second revoke: changed=%v err=%v, want changed=false", changed, err)
	}
	if !again.Revoked {
		t.Fatal("second revoke must return the still-revoked condition")
	}

	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].Revoked || listed[0].ID != "ops-1" {
		t.Fatalf("list must keep the revoked condition with revoked=true: %+v", listed)
	}
}

func TestRevokeSuppressionUnknownID(t *testing.T) {
	dir := t.TempDir()
	// Empty archive: directory exists, no conditions registered.
	if _, _, err := RevokeSuppression(dir, "nope"); !errors.Is(err, ErrUnknownSuppression) {
		t.Fatalf("empty archive: got %v, want ErrUnknownSuppression", err)
	}
	// Absent archive directory is still an unknown condition, not a
	// not-found block error.
	if _, _, err := RevokeSuppression(filepath.Join(dir, "absent"), "nope"); !errors.Is(err, ErrUnknownSuppression) {
		t.Fatalf("absent archive: got %v, want ErrUnknownSuppression", err)
	}
	// Populated archive: an ID that was never registered is unknown.
	mustReplay(t, dir, revokeBlockInput("0xa", 150))
	registerRevokeSpec(t, dir, "ops-1")
	if _, _, err := RevokeSuppression(dir, "other"); !errors.Is(err, ErrUnknownSuppression) {
		t.Fatalf("populated archive: got %v, want ErrUnknownSuppression", err)
	}
	// The known ID still works.
	if _, changed, err := RevokeSuppression(dir, "ops-1"); err != nil || !changed {
		t.Fatalf("known ID revoke: changed=%v err=%v", changed, err)
	}
}

func TestRevokeSuppressionBlankID(t *testing.T) {
	dir := t.TempDir()
	for _, id := range []string{"", "   ", "\t", "\n"} {
		if _, _, err := RevokeSuppression(dir, id); err == nil {
			t.Fatalf("blank id %q accepted", id)
		}
	}
}

// TestRevokeSuppressionAffectsOnlyUnprocessed is the core semantic:
// revocation only touches conclusions that have not been processed yet,
// independently of event height. A conclusion suppressed before revocation
// stays suppressed in history; a conclusion processed afterwards can no
// longer match the condition even if its block was archived long ago; blocks
// imported later follow the same rule.
func TestRevokeSuppressionAffectsOnlyUnprocessed(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, revokeBlockInput("0xa", 150))
	registerRevokeSpec(t, dir, "ops-1")

	// Before revocation: block A's sandwich is suppressed.
	got, err := GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("precondition: got %d records, want 2", len(got))
	}
	var preA *ProcessingRecord
	for i := range got {
		if got[i].BlockHash == "0xa" && got[i].Finding.TxHash == "0xv" {
			preA = &got[i]
		}
	}
	if preA == nil || preA.Status != AlertStatusSuppressed {
		t.Fatalf("precondition: block A sandwich must be suppressed, got %+v", got)
	}

	// Revocation changes nothing historical.
	if _, changed, err := RevokeSuppression(dir, "ops-1"); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}

	// Block B was archived before revocation but never processed: it can no
	// longer match the revoked condition, so it becomes an alert.
	mustReplay(t, dir, revokeBlockInput("0xb", 150))
	got, err = GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("post-revoke generation: got %d new records, want 2 (block B)", len(got))
	}
	for _, r := range got {
		if r.BlockHash == "0xb" && r.Finding.TxHash == "0xv" && r.Status != AlertStatusAlert {
			t.Fatalf("unprocessed conclusion must alert after revocation: %+v", r)
		}
	}

	// A block imported after revocation follows the same rule.
	mustReplay(t, dir, revokeBlockInput("0xc", 150))
	got, err = GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("post-revoke import: got %d new records, want 2 (block C)", len(got))
	}
	for _, r := range got {
		if r.BlockHash == "0xc" && r.Status != AlertStatusAlert {
			t.Fatalf("post-revoke import must alert: %+v", r)
		}
	}

	// History keeps the original suppressed record with the condition and
	// reason recorded at generation time.
	hist, err := AlertHistory(dir, "1", "ops", 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	var histA *ProcessingRecord
	for i := range hist {
		if hist[i].BlockHash == "0xa" && hist[i].Finding.TxHash == "0xv" {
			histA = &hist[i]
		}
	}
	if histA == nil || histA.Status != AlertStatusSuppressed {
		t.Fatalf("history must preserve the suppressed record: %+v", histA)
	}
	if len(histA.Suppressions) != 1 || histA.Suppressions[0].ID != "ops-1" ||
		histA.Suppressions[0].Reason != "maintenance" {
		t.Fatalf("history must keep the condition and reason: %+v", histA.Suppressions)
	}
	// Re-generating still creates nothing: processed identities are skipped.
	again, err := GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("re-generation re-created records: %+v", again)
	}
}

// TestRevokeSuppressionOverlappingConditions: with one condition revoked and
// another active, the conclusion stays suppressed but only records the
// active condition's ID and reason.
func TestRevokeSuppressionOverlappingConditions(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, revokeBlockInput("0xa", 150))
	registerRevokeSpec(t, dir, "s1")
	registerRevokeSpec(t, dir, "s2")
	if _, _, err := RevokeSuppression(dir, "s1"); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	var rec *ProcessingRecord
	for i := range got {
		if got[i].Finding.TxHash == "0xv" {
			rec = &got[i]
		}
	}
	if rec == nil || rec.Status != AlertStatusSuppressed {
		t.Fatalf("other active condition must still suppress: %+v", rec)
	}
	if len(rec.Suppressions) != 1 || rec.Suppressions[0].ID != "s2" ||
		rec.Suppressions[0].Reason != "maintenance" {
		t.Fatalf("only s2 must be recorded, got %+v", rec.Suppressions)
	}
}

// TestRevokeSuppressionBelowThresholdStillNoRecord: even after revocation,
// conclusions below the generation threshold leave no processing record at
// all.
func TestRevokeSuppressionBelowThresholdStillNoRecord(t *testing.T) {
	dir := t.TempDir()
	mustReplay(t, dir, revokeBlockInput("0xa", 150))
	registerRevokeSpec(t, dir, "ops-1")
	if _, _, err := RevokeSuppression(dir, "ops-1"); err != nil {
		t.Fatal(err)
	}
	got, err := GenerateAlerts(dir, "1", "ops", 0, 200, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("severity-3 finding under threshold 5 produced records: %+v", got)
	}
	data, err := readArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.AlertRecords) != 0 {
		t.Fatalf("below-threshold conclusion left a record after revoke: %+v", data.AlertRecords)
	}
}

// TestRevokeSuppressionPersistsAcrossReopen: revocation survives closing and
// reopening the archive.
func TestRevokeSuppressionPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	registerRevokeSpec(t, dir, "ops-1")
	if _, _, err := RevokeSuppression(dir, "ops-1"); err != nil {
		t.Fatal(err)
	}
	// Reopen: list still shows the revoked condition.
	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || !listed[0].Revoked {
		t.Fatalf("revocation did not persist into list: %+v", listed)
	}
	// Reopen: generation treats the condition as revoked.
	mustReplay(t, dir, revokeBlockInput("0xa", 150))
	got, err := GenerateAlerts(dir, "1", "ops", 0, 200, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Finding.TxHash == "0xv" && r.Status != AlertStatusAlert {
			t.Fatalf("revoked condition still suppressed after reopen: %+v", r)
		}
	}
}

// TestRevokedConditionCannotReenable: re-registering the same ID with the
// same spec after revocation is an idempotent retry that keeps the condition
// revoked; the same ID with a different spec stays a conflict.
func TestRevokedConditionCannotReenable(t *testing.T) {
	dir := t.TempDir()
	spec := `{"id":"s1","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"maintenance"}`
	if _, _, err := RegisterSuppression(dir, []byte(spec)); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := RevokeSuppression(dir, "s1"); err != nil || !changed {
		t.Fatalf("revoke: changed=%v err=%v", changed, err)
	}
	cond, created, err := RegisterSuppression(dir, []byte(spec))
	if err != nil || created {
		t.Fatalf("re-register after revoke: created=%v err=%v, want created=false", created, err)
	}
	if !cond.Revoked {
		t.Fatalf("re-register must not re-enable the revoked condition: %+v", cond)
	}
	conflict := `{"id":"s1","chainId":"1","pool":"p1","kind":"displacement","channel":"ops","startHeight":100,"endHeight":200,"reason":"maintenance"}`
	if _, _, err := RegisterSuppression(dir, []byte(conflict)); !errors.Is(err, ErrSuppressionConflict) {
		t.Fatalf("same ID different spec: got %v, want ErrSuppressionConflict", err)
	}
	// A new ID registers fresh and active.
	newSpec := `{"id":"s2","chainId":"1","pool":"p1","kind":"sandwich","channel":"ops","startHeight":100,"endHeight":200,"reason":"maintenance"}`
	cond2, created, err := RegisterSuppression(dir, []byte(newSpec))
	if err != nil || !created || cond2.Revoked {
		t.Fatalf("new ID must register active: %+v created=%v err=%v", cond2, created, err)
	}
}

// TestRevokeSuppressionBusyArchive: a busy archive fails without changing
// stored data.
func TestRevokeSuppressionBusyArchive(t *testing.T) {
	dir := t.TempDir()
	registerRevokeSpec(t, dir, "ops-1")
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "ops-1"); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v, want ErrBusy", err)
	}
	// Release the exclusive lock before reading: a shared lock would block
	// against it.
	lock.Close()
	listed, err := ListSuppressions(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Revoked {
		t.Fatalf("busy revoke changed stored data: %+v", listed)
	}
}

// TestRevokeSuppressionCorruptedArchive: a corrupted archive fails without
// changing the file.
func TestRevokeSuppressionCorruptedArchive(t *testing.T) {
	dir := t.TempDir()
	registerRevokeSpec(t, dir, "ops-1")
	archive := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(archive, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RevokeSuppression(dir, "ops-1"); err == nil ||
		!strings.Contains(err.Error(), "corrupted") {
		t.Fatalf("got %v, want corrupted-archive error", err)
	}
	after, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed revoke changed the corrupted archive")
	}
}

// TestRevokeSuppressionConcurrentWithGenerate: generation and revocation
// overlap safely. Each call takes the archive lock for the whole
// read-process-write, so every successful generation observes the complete
// state before or after the revocation: the final history's sandwich records
// are either all suppressed or all alert, never a mix. BUSY responses are
// retried by the caller, as in real use; concurrent revokes flip the flag
// exactly once.
func TestRevokeSuppressionConcurrentWithGenerate(t *testing.T) {
	dir := t.TempDir()
	for h := uint64(100); h <= 200; h++ {
		mustReplay(t, dir, revokeBlockInput(fmt.Sprintf("0x%04x", h), h))
	}
	registerRevokeSpec(t, dir, "s1")

	var wg sync.WaitGroup
	start := make(chan struct{})
	var genErrs, revErrs, revokeChanged int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for {
				_, err := GenerateAlerts(dir, "1", "ops", 0, 300, 1)
				if err == nil {
					return
				}
				if !errors.Is(err, ErrBusy) {
					atomic.AddInt32(&genErrs, 1)
					return
				}
			}
		}()
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, changed, err := RevokeSuppression(dir, "s1")
			if err != nil && !errors.Is(err, ErrBusy) {
				atomic.AddInt32(&revErrs, 1)
			}
			if changed {
				atomic.AddInt32(&revokeChanged, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if genErrs != 0 || revErrs != 0 {
		t.Fatalf("unexpected errors: gen=%d rev=%d", genErrs, revErrs)
	}
	if revokeChanged != 1 {
		t.Fatalf("revoke changed count = %d, want exactly 1", revokeChanged)
	}
	hist, err := AlertHistory(dir, "1", "ops", 0, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 202 {
		t.Fatalf("history holds %d records, want 202 (2 per block)", len(hist))
	}
	// The condition only covers the sandwich in pool p1. The displacement in
	// pool p2 never matches, so it always alerts; the sandwiches are either
	// all suppressed (a generation ran before revocation) or all alert
	// (revocation ran first) — never a mix.
	sandwichSuppressed, sandwichAlert := 0, 0
	for _, r := range hist {
		switch {
		case r.Finding.Kind == "displacement" && r.Status != AlertStatusAlert:
			t.Fatalf("displacement must always alert: %+v", r)
		case r.Finding.Kind == "sandwich" && r.Status == AlertStatusSuppressed:
			sandwichSuppressed++
		case r.Finding.Kind == "sandwich" && r.Status == AlertStatusAlert:
			sandwichAlert++
		}
	}
	if sandwichSuppressed != 101 && sandwichAlert != 101 {
		t.Fatalf("sandwich records observed a mixed revocation state: suppressed=%d alert=%d",
			sandwichSuppressed, sandwichAlert)
	}
}
