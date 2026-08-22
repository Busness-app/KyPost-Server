package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStringsToArgsRedactsSensitiveValues(t *testing.T) {
	args := stringsToArgs([]string{
		"user_id", "user-1",
		"recipient", "person@example.com",
		"api-key", "secret-value",
		"error", "ordinary failure",
	})

	if got := args[1]; got != "user-1" {
		t.Fatalf("user_id = %v, want unchanged value", got)
	}
	for _, index := range []int{3, 5} {
		if got := args[index]; got != "[REDACTED]" {
			t.Fatalf("sensitive value at index %d = %v, want redacted", index, got)
		}
	}
	if got := args[7]; got != "ordinary failure" {
		t.Fatalf("error = %v, want unchanged value", got)
	}
}

func TestStringsToArgsDropsUnpairedArgument(t *testing.T) {
	args := stringsToArgs([]string{"reason", "failed", "dangling"})
	if len(args) != 2 {
		t.Fatalf("got %d slog arguments, want one complete pair", len(args))
	}
}

// TestNewFailsWhenLogFileCannotBeOpened pins the difference between "logging
// initialized" and "a Logger value exists". app.log being an unwritable path is
// the realistic shape of this (a stale directory left by a bad mount, a
// permission change on the volume), and because slog discards write errors,
// returning success here would mean the process runs with no durable log and no
// symptom.
func TestNewFailsWhenLogFileCannotBeOpened(t *testing.T) {
	logDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(logDir, "app.log"), 0o755); err != nil {
		t.Fatalf("mkdir app.log: %v", err)
	}

	logger, err := New(logDir)
	if err == nil {
		if logger != nil {
			logger.Close()
		}
		t.Fatal("New reported success with an unopenable app.log; startup would proceed with no durable log")
	}
}
