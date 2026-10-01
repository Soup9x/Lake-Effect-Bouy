package agent_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoProcessExecution enforces CLAUDE.md rule 1: nothing in the agent may
// start processes. It greps every Go source file (tests included) of
// internal/agent and cmd/agent. Do not weaken or delete this test.
func TestNoProcessExecution(t *testing.T) {
	// Built by concatenation so this file does not match itself.
	banned := []string{
		"os/" + "exec",
		"os." + "StartProcess",
		"syscall." + "Exec",
		"syscall." + "ForkExec",
		"syscall." + "StartProcess",
		"windows." + "CreateProcess",
		"Shell" + "Execute",
	}
	roots := []string{".", filepath.Join("..", "..", "cmd", "agent")}
	checked := 0
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			checked++
			for _, s := range banned {
				if strings.Contains(string(b), s) {
					t.Errorf("%s contains banned %q", path, s)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d files checked; walk is broken", checked)
	}
}
