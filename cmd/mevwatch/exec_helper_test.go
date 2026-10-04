package main

import (
	"os"
	"os/exec"
	"testing"
)

// execCommand runs the current test binary as a forked helper process
// with cliHelperEnv set so TestMain dispatches straight into main().
// Using the re-compiled test binary (rather than a prebuilt CLI) keeps
// the regression tests fully self-contained and deterministic offline.
func execCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), cliHelperEnv+"=1")
	return cmd
}

// exitCode extracts the process exit code from an *exec.ExitError.
func exitCode(t *testing.T, err error) int {
	t.Helper()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("command failed unexpectedly: %v", err)
	return 0
}
