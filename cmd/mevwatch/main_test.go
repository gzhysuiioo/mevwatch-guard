package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gzhysuiioo/mevwatch-guard/mevwatch"
)

// buildBinary compiles the CLI into a temp directory and returns its path.
func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "mevwatch")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	stdout, stderr, code, err := runRaw(bin, args...)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	return stdout, stderr, code
}

func runRaw(bin string, args ...string) (string, string, int, error) {
	cmd := exec.Command(bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
			err = nil
		}
	}
	return stdout.String(), stderr.String(), code, err
}

func TestCLIReplayAndReport(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jsonl")
	archive := filepath.Join(dir, "archive")

	line := `{"chainId":"0x1","blockHash":"0xaa","blockNumber":100,"swaps":[{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":100,"Index":0},{"TxHash":"0xd","Pool":"p","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1},{"TxHash":"0xb","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":90,"Index":2}]}`
	if err := os.WriteFile(input, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	stdout, stderr, code := run(t, bin, "replay", input, archive)
	if code != 0 {
		t.Fatalf("replay failed: %s", stderr)
	}
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("replay output is not valid JSON: %v\n%s", err, stdout)
	}
	if report.ChainID != "0x1" || report.BlockHash != "0xaa" || report.BlockNumber != 100 || report.SwapCount != 3 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "sandwich" || report.Findings[0].Severity != 3 {
		t.Fatalf("unexpected findings: %+v", report.Findings)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr, got %q", stderr)
	}

	// Report command reads the archive.
	stdout, stderr, code = run(t, bin, "report", archive, "0x1", "0xaa")
	if code != 0 {
		t.Fatalf("report failed: %s", stderr)
	}
	var got mevwatch.Report
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("report output is not valid JSON: %v", err)
	}
	if got.BlockNumber != 100 || got.SwapCount != 3 {
		t.Fatalf("unexpected report: %+v", got)
	}
}

func TestCLIReportUnknown(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")

	_, stderr, code := run(t, bin, "report", archive, "0x1", "0xzz")
	if code == 0 {
		t.Fatal("expected non-zero exit for unknown block")
	}
	if !strings.Contains(stderr, "unknown block") {
		t.Fatalf("expected unknown block error, got %q", stderr)
	}
}

func TestCLIReplayErrorLineNumber(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	input := filepath.Join(dir, "input.jsonl")
	archive := filepath.Join(dir, "archive")

	content := "  \n{bad json}\n"
	if err := os.WriteFile(input, []byte(content), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	_, stderr, code := run(t, bin, "replay", input, archive)
	if code == 0 {
		t.Fatal("expected non-zero exit")
	}
	if !strings.Contains(stderr, "line 2") {
		t.Fatalf("expected line 2 in error, got %q", stderr)
	}
}

func TestCLIReplayConflict(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")

	line := `{"chainId":"0x1","blockHash":"0xaa","blockNumber":100,"swaps":[]}`
	input := filepath.Join(dir, "input.jsonl")
	if err := os.WriteFile(input, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if _, _, code := run(t, bin, "replay", input, archive); code != 0 {
		t.Fatal("first replay should succeed")
	}

	conflict := `{"chainId":"0x1","blockHash":"0xaa","blockNumber":101,"swaps":[]}`
	if err := os.WriteFile(input, []byte(conflict+"\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	_, stderr, code := run(t, bin, "replay", input, archive)
	if code == 0 {
		t.Fatal("expected non-zero exit for conflict")
	}
	if !strings.Contains(stderr, "block conflict") {
		t.Fatalf("expected block conflict error, got %q", stderr)
	}
}

func TestCLIDemoAndVersion(t *testing.T) {
	bin := buildBinary(t)

	stdout, _, code := run(t, bin, "version")
	if code != 0 || !strings.Contains(stdout, "mevwatch") {
		t.Fatalf("version failed: %q", stdout)
	}

	stdout, _, code = run(t, bin, "demo")
	if code != 0 || !strings.Contains(stdout, "sandwich") {
		t.Fatalf("demo failed: %q", stdout)
	}

	// Default entry (no args) runs demo.
	stdout, _, code = run(t, bin)
	if code != 0 || !strings.Contains(stdout, "sandwich") {
		t.Fatalf("default entry should run demo: %q", stdout)
	}
}

func TestCLIConcurrentReplays(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "archive")

	line := `{"chainId":"0x1","blockHash":"0xaa","blockNumber":100,"swaps":[{"TxHash":"0xf","Pool":"p","Trader":"bot","In":1,"Out":1,"GasPrice":100,"Index":0},{"TxHash":"0xd","Pool":"p","Trader":"user","In":1,"Out":1,"GasPrice":10,"Index":1}]}`
	input := filepath.Join(dir, "input.jsonl")
	if err := os.WriteFile(input, []byte(line+"\n"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	var wg sync.WaitGroup
	var busyOrFailed int64
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, code, err := runRaw(bin, "replay", input, archive)
			if err != nil || code != 0 {
				atomic.AddInt64(&busyOrFailed, 1)
			}
		}()
	}
	wg.Wait()

	// At least one replay must have succeeded; the rest may have reported
	// busy errors but must not have corrupted the archive.
	stdout, stderr, code := run(t, bin, "report", archive, "0x1", "0xaa")
	if code != 0 {
		t.Fatalf("archive unreadable after concurrent replays: %s", stderr)
	}
	var report mevwatch.Report
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("report output is not valid JSON: %v", err)
	}
	if report.SwapCount != 2 {
		t.Fatalf("expected 2 swaps, got %d", report.SwapCount)
	}
}
