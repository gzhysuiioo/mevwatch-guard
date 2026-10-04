package mevwatch

// Regression coverage for corrupt registered rule versions behind the
// `reviews evaluate` entry. A stored version document that no longer
// satisfies the registration rules (a missing or null field, a wrong type,
// an out-of-range severity or multiplier) must refuse the whole evaluation
// with ErrCorruptVersion — never evaluate under zeroed parameters, never
// fall back to the enabled or built-in version, and never crash on an
// invalid multiplier. This mirrors the single-block compare behaviour and
// holds whether or not the height range contains any block, swap or valid
// review; corrupt versions the caller did not name stay inert.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// setupEvaluateCorruptArchive archives the two-findings block under the
// built-in rules, registers strict (sandwich sev 5, displacement mult 5)
// and mult3, and records one real and one false-positive review, so an
// evaluation has conclusions in every bucket to misjudge if a corrupt
// version silently decayed to zero values.
func setupEvaluateCorruptArchive(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)
	mustRegisterVersion(t, dir, mult3Spec)
	submit(t, dir, reviewSub("1", "0xa", "0xv", "sandwich", "r", "a", "real", ReviewStatusReal, 0))
	submit(t, dir, reviewSub("1", "0xa", "0xd", "displacement", "f", "a", "fp", ReviewStatusFalsePositive, 0))
	return dir
}

func TestEvaluateCorruptVersionRefused(t *testing.T) {
	corruptions := []struct {
		name    string
		mutate  func(t *testing.T, ver map[string]any)
		wantErr string
	}{
		{"multiplier missing", func(t *testing.T, v map[string]any) {
			delete(storedRule(t, v, "displacement"), "multiplier")
		}, "multiplier"},
		{"multiplier zero", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["multiplier"] = 0
		}, "multiplier"},
		{"multiplier below range", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["multiplier"] = 1
		}, "multiplier"},
		{"multiplier above range", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["multiplier"] = 101
		}, "multiplier"},
		{"multiplier null", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["multiplier"] = nil
		}, "multiplier"},
		{"multiplier wrong type", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["multiplier"] = "5"
		}, "multiplier"},
		{"displacement severity missing", func(t *testing.T, v map[string]any) {
			delete(storedRule(t, v, "displacement"), "severity")
		}, "severity"},
		{"displacement severity zero", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["severity"] = 0
		}, "severity"},
		{"displacement severity above range", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["severity"] = 6
		}, "severity"},
		{"displacement enabled missing", func(t *testing.T, v map[string]any) {
			delete(storedRule(t, v, "displacement"), "enabled")
		}, "enabled"},
		{"unknown field", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "displacement")["luck"] = 7
		}, "luck"},
		{"sandwich severity null", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "sandwich")["severity"] = nil
		}, "severity"},
		{"sandwich enabled wrong type", func(t *testing.T, v map[string]any) {
			storedRule(t, v, "sandwich")["enabled"] = "true"
		}, "enabled"},
		{"sandwich object missing", func(t *testing.T, v map[string]any) {
			delete(v["rules"].(map[string]any), "sandwich")
		}, "sandwich"},
		{"displacement object missing", func(t *testing.T, v map[string]any) {
			delete(v["rules"].(map[string]any), "displacement")
		}, "displacement"},
		{"rules object missing", func(t *testing.T, v map[string]any) {
			delete(v, "rules")
		}, "rules"},
	}
	for _, tc := range corruptions {
		t.Run(tc.name, func(t *testing.T) {
			dir := setupEvaluateCorruptArchive(t)
			rewriteStoredVersion(t, dir, "strict", func(ver map[string]any) {
				tc.mutate(t, ver)
			})
			_, err := EvaluateReviews(dir, "1", 0, 100, "strict")
			if err == nil {
				t.Fatalf("corrupt version evaluated successfully")
			}
			if !errors.Is(err, ErrCorruptVersion) {
				t.Fatalf("error = %v, want ErrCorruptVersion", err)
			}
			if errors.Is(err, ErrUnknownVersion) {
				t.Fatalf("corruption misreported as unknown version: %v", err)
			}
			if !strings.Contains(err.Error(), "strict") {
				t.Fatalf("error must name the requested version, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error must name the offending rule or field %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestEvaluateCorruptDuplicateFieldRefused(t *testing.T) {
	// A stored document naming the same field twice is rejected exactly as
	// it would be at registration time.
	dir := setupEvaluateCorruptArchive(t)
	path := filepath.Join(dir, archiveFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dup := strings.Replace(string(raw), `"multiplier": 5`, `"multiplier": 5, "multiplier": 5`, 1)
	if dup == string(raw) {
		t.Fatalf("stored multiplier not found in archive: %s", raw)
	}
	if err := os.WriteFile(path, []byte(dup), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = EvaluateReviews(dir, "1", 0, 100, "strict")
	if !errors.Is(err, ErrCorruptVersion) || !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("error = %v, want ErrCorruptVersion wrapping ErrDuplicateField", err)
	}
	if !strings.Contains(err.Error(), "strict") || !strings.Contains(err.Error(), "multiplier") {
		t.Fatalf("error must name the version and field, got %v", err)
	}
}

func TestEvaluateCorruptDisabledRuleStillRefused(t *testing.T) {
	// nosandwich's sandwich rule is explicitly disabled, but a disabled rule
	// must still declare complete, in-range parameters: an explicit false is
	// a legal off state, a decayed severity is not.
	dir := setupEvaluateCorruptArchive(t)
	mustRegisterVersion(t, dir, noSandwichSpec)
	rewriteStoredVersion(t, dir, "nosandwich", func(ver map[string]any) {
		storedRule(t, ver, "sandwich")["severity"] = 0
	})
	_, err := EvaluateReviews(dir, "1", 0, 100, "nosandwich")
	if !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	if !strings.Contains(err.Error(), "nosandwich") || !strings.Contains(err.Error(), "severity") {
		t.Fatalf("error must name the version and field, got %v", err)
	}
}

func TestEvaluateCorruptVersionRefusedRegardlessOfRange(t *testing.T) {
	corrupt := func(dir string) {
		rewriteStoredVersion(t, dir, "strict", func(ver map[string]any) {
			delete(storedRule(t, ver, "displacement"), "multiplier")
		})
	}

	// A range holding no block at all: the corrupt version is still
	// refused, not reported as an empty success.
	dir := setupEvaluateCorruptArchive(t)
	corrupt(dir)
	if _, err := EvaluateReviews(dir, "1", 50, 100, "strict"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("empty range: error = %v, want ErrCorruptVersion", err)
	}

	// A block with no swaps and no conclusions in range.
	dir = t.TempDir()
	mustRegisterVersion(t, dir, strictSpec)
	mustReplay(t, dir, `{"chainId":"1","blockHash":"0xe","blockNumber":3,"swaps":[]}`)
	corrupt(dir)
	if _, err := EvaluateReviews(dir, "1", 0, 100, "strict"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("empty swaps: error = %v, want ErrCorruptVersion", err)
	}

	// Conclusions in range but no valid review on any of them.
	dir = t.TempDir()
	mustReplay(t, dir, twoFindingsInput)
	mustRegisterVersion(t, dir, strictSpec)
	corrupt(dir)
	if _, err := EvaluateReviews(dir, "1", 0, 100, "strict"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("no reviews: error = %v, want ErrCorruptVersion", err)
	}
}

func TestEvaluateCorruptSiblingDoesNotContaminate(t *testing.T) {
	dir := setupEvaluateCorruptArchive(t)
	// A wrong-typed multiplier previously failed the whole-archive decode,
	// taking every version down with it; a zeroed one crashed detection.
	rewriteStoredVersion(t, dir, "strict", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = "5"
	})

	// The named corrupt version is refused...
	if _, err := EvaluateReviews(dir, "1", 0, 100, "strict"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	// ...but intact registered versions and builtin still evaluate against
	// the same archive, with the same counts an uncorrupted run produces.
	for _, id := range []string{"mult3", BuiltinVersionID} {
		got, err := EvaluateReviews(dir, "1", 0, 100, id)
		if err != nil {
			t.Fatalf("evaluate under intact %s failed: %v", id, err)
		}
		if got.StillHit != 1 || got.Retained != 1 {
			t.Fatalf("evaluate under intact %s misjudged: %+v", id, got)
		}
	}
}

func TestEvaluateCorruptVersionDistinctFromUnknown(t *testing.T) {
	dir := setupEvaluateCorruptArchive(t)
	rewriteStoredVersion(t, dir, "strict", func(ver map[string]any) {
		delete(storedRule(t, ver, "displacement"), "multiplier")
	})
	// A version that was never registered stays an unknown-version failure,
	// never a corruption one.
	if _, err := EvaluateReviews(dir, "1", 0, 100, "ghost"); !errors.Is(err, ErrUnknownVersion) ||
		errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
}

func TestEvaluateCorruptVersionReadOnly(t *testing.T) {
	dir := setupEvaluateCorruptArchive(t)
	rewriteStoredVersion(t, dir, "strict", func(ver map[string]any) {
		storedRule(t, ver, "displacement")["multiplier"] = 0
	})
	before, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateReviews(dir, "1", 0, 100, "strict"); !errors.Is(err, ErrCorruptVersion) {
		t.Fatalf("error = %v, want ErrCorruptVersion", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, archiveFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("failed evaluation against a corrupt version changed the archive")
	}
	// The review history survives the failed evaluation untouched.
	hist, err := ReviewHistoryQuery(dir, "1", "0xa", "0xv", "sandwich")
	if err != nil {
		t.Fatal(err)
	}
	if hist.Status != ReviewStatusReal || hist.Version != 1 {
		t.Fatalf("review state changed: %+v", hist)
	}
}

func TestEvaluateExplicitlyDisabledRulesAreValid(t *testing.T) {
	// Both rules explicitly switched off with complete, in-range parameters
	// is a legal version: the candidate flags nothing, so the real sandwich
	// is missed and the false-positive displacement is eliminated.
	dir := setupEvaluateCorruptArchive(t)
	mustRegisterVersion(t, dir,
		`{"id":"alloff","rules":{"sandwich":{"enabled":false,"severity":1},"displacement":{"enabled":false,"severity":1,"multiplier":2}}}`)
	got, err := EvaluateReviews(dir, "1", 0, 100, "alloff")
	if err != nil {
		t.Fatalf("EvaluateReviews: %v", err)
	}
	if got.Missed != 1 || got.Eliminated != 1 || got.Retained != 0 || got.StillHit != 0 || got.Pending != 0 {
		t.Fatalf("counts = %+v, want missed 1, eliminated 1", got)
	}
	if got.Version.ID != "alloff" || got.Version.Rules.Sandwich.Enabled || got.Version.Rules.Displacement.Enabled {
		t.Fatalf("candidate version not carried through: %+v", got.Version)
	}
}
