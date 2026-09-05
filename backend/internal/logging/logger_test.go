package logging

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestSuiteJSONLogger(t *testing.T) {
	t.Setenv("KY_LOG_LEVEL", "info")
	var out bytes.Buffer
	logger, err := NewWithOutput(&out)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hello\nforged", "user_id", "u1", "password", "never-emit", "unknown", "never-emit")
	var line map[string]any
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line["app"] != "kypost" || line["facility"] != float64(16) || line["severity"] != float64(6) || line["user_id"] != "u1" {
		t.Fatalf("%v", line)
	}
	if strings.Contains(out.String(), "never-emit") || strings.Count(out.String(), "\n") != 1 {
		t.Fatal(out.String())
	}
	if line["dropped_fields"] != float64(2) {
		t.Fatalf("%v", line)
	}
	t.Setenv("KY_LOG_LEVEL", "invalid")
	if _, err := New(""); err == nil {
		t.Fatal("invalid level accepted")
	}
}

func TestAdmittedFieldsStillRedactCorrespondence(t *testing.T) {
	for _, key := range []string{"raw_label", "addr", "username"} {
		if got := redactValue(key, "person@example.com"); got != "[REDACTED]" {
			t.Fatalf("%s disclosed correspondence", key)
		}
	}
	if got := redactValue("addr", "127.0.0.1:5866"); got != "127.0.0.1:5866" {
		t.Fatal("server bind address lost")
	}
}
