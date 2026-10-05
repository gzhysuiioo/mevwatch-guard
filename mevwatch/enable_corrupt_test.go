package mevwatch

// Regression coverage for enabling a rule version whose stored archive
// document has decayed since registration. `rules enable` must validate the
// selected version's actual stored declaration before it moves the enabled
// marker — the same proof a comparison, a review-range evaluation and a
// replay already demand — so a corrupt registered version is refused with
// ErrCorruptVersion (never reported unknown, never substituted with the
// current, built-in or default parameters), even when it is already the
// enabled version. A successful switch changes only the enabled marker:
// the other versions (corrupt siblings included), their fields and order,
// plus reports, suppressions, alert records and reviews are preserved.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// enableSkeleton reads the archive the way EnableVersion writes it:
// versions stay raw stored documents, so the sections can be compared
// byte for byte across a successful switch.
type enableSkeleton struct {
	Records        []record           `json:"records"`
	Versions       []json.RawMessage  `json:"versions"`
	EnabledVersion string             `json:"enabledVersion"`
	Suppressions   []Suppression      `json:"suppressions"`
	AlertRecords   []ProcessingRecord `json:"alerts"`
	Reviews        []ReviewObject     `json:"reviews"`
}

func readEnableSkeleton(t *testing.T, dir string) enableSkeleton {
	t.Helper()
	var s enableSkeleton
	if err := json.Unmarshal(readArchiveFile(t, dir), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestEnableCorruptVersionRefused runs the full corruption matrix against
// enabling a registered version: every way its stored document can stop
// satisfying the registration rules must fail with ErrCorruptVersion, name
// the version and the offending rule or field, and leave the archive —
// including the enabled marker — untouched.
func TestEnableCorruptVersionRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			if _, err := EnableVersion(dir, "twin"); err != nil {
				t.Fatalf("setup: EnableVersion twin: %v", err)
			}
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, err := EnableVersion(dir, "candC")
			if err == nil {
				t.Fatalf("corrupt version enabled successfully: %+v", v)
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("registered-but-corrupt version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") {
				t.Fatalf("error must name the selected version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused enable changed the archive:\nbefore=%s\nafter =%s", before, after)
			}
			if got := readEnableSkeleton(t, dir).EnabledVersion; got != "twin" {
				t.Fatalf("enabled marker changed to %q on refusal", got)
			}
		})
	}
}

// TestEnableCorruptAlreadyEnabledRefused pins the core regression: the
// integrity check runs even when the selected id is already the current
// enabled version. Previously the early return accepted the decayed
// document as a complete version and left replay to fail later.
func TestEnableCorruptAlreadyEnabledRefused(t *testing.T) {
	for _, tc := range corruptVersionCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupCorruptCompareArchive(t)
			if _, err := EnableVersion(dir, "candC"); err != nil {
				t.Fatalf("setup: EnableVersion candC: %v", err)
			}
			rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			before := readArchiveFile(t, dir)

			v, err := EnableVersion(dir, "candC")
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("re-enabling the corrupt enabled version: v=%+v err=%v, want ErrCorruptVersion", v, err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corrupt enabled version misreported as unknown: %v", err)
			}
			if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name version candC and field %q, got %v", tc.wantErr, err)
			}
			if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatalf("refused re-enable changed the archive")
			}
			if got := readEnableSkeleton(t, dir).EnabledVersion; got != "candC" {
				t.Fatalf("enabled marker changed on refusal: %q", got)
			}
		})
	}
}

// TestEnableCorruptSiblingDoesNotBlock proves damage in one registered
// version neither blocks enabling an intact sibling or builtin, nor gets
// repaired, completed, reordered or dropped by the successful switch: the
// versions section survives entry for entry, in order, and the corrupt
// entry is still afterwards refused on its own merits.
func TestEnableCorruptSiblingDoesNotBlock(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	before := readEnableSkeleton(t, dir)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	damaged := readEnableSkeleton(t, dir)

	twin, err := EnableVersion(dir, "twin")
	if err != nil {
		t.Fatalf("enabling intact twin past a corrupt sibling failed: %v", err)
	}
	if twin.ID != "twin" || twin.Rules.Displacement.Multiplier != 2 {
		t.Fatalf("enabled twin returned wrong parameters: %+v", twin)
	}
	after := readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(damaged.Versions, after.Versions) {
		t.Fatalf("successful switch rewrote the versions section:\nbefore=%s\nafter =%s", damaged.Versions, after.Versions)
	}
	if after.EnabledVersion != "twin" {
		t.Fatalf("enabled marker = %q, want twin", after.EnabledVersion)
	}

	// Builtin needs no registration and is enableable with the same corrupt
	// sibling present; its original parameters come back in full.
	b, err := EnableVersion(dir, BuiltinVersionID)
	if err != nil {
		t.Fatalf("enabling builtin past a corrupt sibling failed: %v", err)
	}
	if b != BuiltinVersion() {
		t.Fatalf("builtin parameters wrong: %+v", b)
	}
	after = readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(damaged.Versions, after.Versions) {
		t.Fatalf("enabling builtin rewrote the versions section")
	}
	if after.EnabledVersion != BuiltinVersionID {
		t.Fatalf("enabled marker = %q, want builtin", after.EnabledVersion)
	}

	// The corrupt entry was not repaired: selecting it still fails as
	// corruption, and the intact twin remains usable.
	if _, err := EnableVersion(dir, "candC"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("corrupt sibling was silently repaired: %v", err)
	}
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("intact twin no longer enableable: %v", err)
	}
	// Nothing structural besides the marker ever moved: order and records.
	if len(after.Versions) != len(before.Versions) {
		t.Fatalf("version count changed: %d vs %d", len(after.Versions), len(before.Versions))
	}
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("existing records changed on a version switch")
	}
}

// TestEnableUnknownVersionDistinct pins the boundary: an id that was never
// registered stays an unknown-version failure (never corruption), and the
// failure moves no marker.
func TestEnableUnknownVersionDistinct(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	rewriteStoredVersion(t, dir, "candC", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	before := readArchiveFile(t, dir)

	if _, err := EnableVersion(dir, "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	if _, err := EnableVersion(dir, ""); err == nil {
		t.Fatal("empty version id must fail")
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed enable changed the archive")
	}
	if got := readEnableSkeleton(t, dir).EnabledVersion; got != "" {
		t.Fatalf("enabled marker changed on unknown-version failure: %q", got)
	}
}

// TestEnableExplicitlyDisabledRulesAccepted proves enabled:false is a legal
// off state: a version with both rules disabled still has to carry complete
// parameters, and enabling it returns the full declaration which then
// governs plain (no --version) replays.
func TestEnableExplicitlyDisabledRulesAccepted(t *testing.T) {
	dir := t.TempDir()
	offSpec := `{"id":"off","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`
	register(t, dir, offSpec)
	v, err := EnableVersion(dir, "off")
	if err != nil {
		t.Fatalf("an explicitly disabled version must enable: %v", err)
	}
	want := mustRuleVersion(t, offSpec)
	if !reflect.DeepEqual(v, want) {
		t.Fatalf("enabled version = %+v, want %+v", v, want)
	}
	reports := replay(t, dir, sandwichInput)
	if len(reports[0].Findings) != 0 || reports[0].Version.ID != "off" {
		t.Fatalf("plain replay did not use the enabled disabled version: %+v", reports[0])
	}
}

// TestEnableCorruptDuplicateFieldRefused covers a decay registration could
// never have produced: a repeated field in the stored document. The raw
// bytes are patched directly because a JSON map cannot hold two keys.
func TestEnableCorruptDuplicateFieldRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	raw := readArchiveFile(t, dir)
	text := string(raw)
	// Records precede the versions array and embed a full copy of candC in
	// their "version" field, so anchor past "versions": the duplicate must
	// land in the stored registration document, not in an archived record.
	vsec := strings.Index(text, `"versions":`)
	if vsec < 0 {
		t.Fatal("versions section not found in archive")
	}
	at := strings.Index(text[vsec:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("candC entry not found in versions section")
	}
	at += vsec
	anchor := `"severity": 4,`
	field := strings.Index(text[at:], anchor)
	if field < 0 {
		t.Fatal("candC severity field not found")
	}
	pos := at + field
	patched := text[:pos] + `"severity": 4, ` + text[pos:]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)

	_, err := EnableVersion(dir, "candC")
	if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate-field document: err = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
	}
	if !strings.Contains(err.Error(), "candC") || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("error must name candC and severity, got %v", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused enable changed the archive")
	}
}

// TestEnableCorruptDuplicateIDRefused covers a decayed document that also
// repeats its identity key: "id":"other" arrives last and a plain unmarshal
// would fold the entry onto "other", hiding candC behind an unknown-version
// error. The matcher must still attribute the entry to the registered
// version and refuse it as corruption, under either spelling.
func TestEnableCorruptDuplicateIDRefused(t *testing.T) {
	dir := setupCorruptCompareArchive(t)
	path := filepath.Join(dir, archiveFileName)
	text := string(readArchiveFile(t, dir))
	vsec := strings.Index(text, `"versions":`)
	at := strings.Index(text[vsec:], `"id": "candC"`)
	if at < 0 {
		t.Fatal("candC entry not found in versions section")
	}
	pos := vsec + at
	patched := text[:pos] + `"id": "candC", "id": "other", ` + text[pos+len(`"id": "candC",`):]
	if err := os.WriteFile(path, []byte(patched), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)

	for _, asked := range []string{"candC", "other"} {
		if _, err := EnableVersion(dir, asked); !errors.Is(err, ErrCorruptVersion) ||
			errors.Is(err, ErrUnknownVersion) {
			t.Fatalf("enabling %q against a duplicate-id document: %v", asked, err)
		}
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("refused enable changed the archive")
	}
	// The intact twin is unaffected by the unidentifiable sibling.
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("intact twin blocked by corrupt sibling: %v", err)
	}
}

// TestEnableInvalidAndBusyArchiveReported covers the environment-level
// failures: an archive whose whole file is not valid JSON, or one locked by
// another process, must error clearly and leave the file alone.
func TestEnableInvalidAndBusyArchiveReported(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	path := filepath.Join(dir, archiveFileName)
	if err := os.WriteFile(path, []byte(`{not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := readArchiveFile(t, dir)
	if _, err := EnableVersion(dir, "candC"); err == nil ||
		errors.Is(err, ErrUnknownVersion) || errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("invalid-JSON archive error = %v, want a whole-archive corruption error", err)
	}
	if after := readArchiveFile(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed enable rewrote an invalid archive")
	}

	// Busy archive: the lock failure is reported as such (fixture from the
	// registration tests, version absent there so the lock is hit first).
	busyDir := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(busyDir, lockFileName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := EnableVersion(busyDir, "candC"); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy archive error = %v, want ErrBusy", err)
	}
}

// TestEnableLegacyArchiveAllowsBuiltin proves pre-version archives (no
// versions or enabledVersion fields) can still enable builtin, and the
// marker then drives plain replays without touching the legacy record.
func TestEnableLegacyArchiveAllowsBuiltin(t *testing.T) {
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
	b, err := EnableVersion(dir, BuiltinVersionID)
	if err != nil {
		t.Fatalf("enabling builtin on a legacy archive failed: %v", err)
	}
	if b != BuiltinVersion() {
		t.Fatalf("builtin parameters wrong: %+v", b)
	}
	if got := readEnableSkeleton(t, dir).EnabledVersion; got != BuiltinVersionID {
		t.Fatalf("enabled marker = %q, want builtin", got)
	}
	reports := replay(t, dir, replayCorruptInput)
	if len(reports) != 1 || reports[0].Version.ID != BuiltinVersionID ||
		len(reports[0].Findings) != 1 || reports[0].Findings[0].Kind != "displacement" {
		t.Fatalf("plain replay after enabling builtin misjudged: %+v", reports)
	}
	r, err := Query(dir, "1", "0old")
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != BuiltinVersion() || len(r.Findings) != 1 {
		t.Fatalf("legacy record modified on switch: %+v", r)
	}

	// An empty archive (no file yet) accepts builtin the same way.
	fresh := t.TempDir()
	if _, err := EnableVersion(fresh, BuiltinVersionID); err != nil {
		t.Fatalf("enabling builtin before any archive exists failed: %v", err)
	}
}

// TestEnableSwitchPreservesAllPriorState builds an archive holding every
// kind of state, then switches to an intact version and proves only the
// enabled marker changed: stored versions survive verbatim, and reports,
// suppressions, alert processing records and manual reviews keep their
// historical conclusions — nothing is re-detected or rewritten.
func TestEnableSwitchPreservesAllPriorState(t *testing.T) {
	dir := t.TempDir()
	register(t, dir, candidateVersionSpec)
	register(t, dir, twinVersionSpec)
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
	before := readEnableSkeleton(t, dir)

	if v, err := EnableVersion(dir, "twin"); err != nil || v.ID != "twin" {
		t.Fatalf("switch to twin: v=%+v err=%v", v, err)
	}
	// Switching to the already-enabled marker semantics: re-enabling twin
	// now is a no-write validation path and still succeeds.
	if _, err := EnableVersion(dir, "twin"); err != nil {
		t.Fatalf("re-enabling the current intact version failed: %v", err)
	}

	after := readEnableSkeleton(t, dir)
	if !reflect.DeepEqual(before.Versions, after.Versions) {
		t.Fatalf("switch rewrote stored versions:\nbefore=%s\nafter =%s", before.Versions, after.Versions)
	}
	if after.EnabledVersion != "twin" {
		t.Fatalf("enabled marker = %q, want twin", after.EnabledVersion)
	}
	if !reflect.DeepEqual(before.Records, after.Records) {
		t.Fatalf("historical reports changed on switch: %+v vs %+v", before.Records, after.Records)
	}
	if !reflect.DeepEqual(before.Suppressions, after.Suppressions) {
		t.Fatalf("suppressions changed on switch")
	}
	if !reflect.DeepEqual(before.AlertRecords, after.AlertRecords) {
		t.Fatalf("alert records changed on switch")
	}
	if !reflect.DeepEqual(before.Reviews, after.Reviews) {
		t.Fatalf("manual reviews changed on switch")
	}

	// Historical conclusions keep their candC verdict and are not re-judged.
	report, err := Query(dir, "1", "0xa")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version.ID != "candC" || len(report.Findings) != 1 ||
		report.Findings[0].Kind != "displacement" || report.Findings[0].Severity != 4 {
		t.Fatalf("archived report re-detected on switch: %+v", report)
	}
	history, err := ReviewHistoryQuery(dir, "1", "0xa", "0xvictim", "displacement")
	if err != nil {
		t.Fatal(err)
	}
	if history.Status != ReviewStatusFalsePositive || history.Version != 1 {
		t.Fatalf("review history changed on switch: %+v", history)
	}
	alerts, err := AlertHistory(dir, "1", "ops", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Status != AlertStatusSuppressed {
		t.Fatalf("alert history changed on switch: %+v", alerts)
	}

	// A new block without an explicit version is judged under twin now.
	input := cmpBlockLine("1", "0xnew", 11,
		cmpSwap("0xn1", "p1", "w", 40, 0),
		cmpSwap("0xn2", "p1", "u", 10, 1),
	)
	reports, err := Replay(strings.NewReader(input), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].Version.ID != "twin" {
		t.Fatalf("new block did not replay under the newly enabled version: %+v", reports)
	}
}
