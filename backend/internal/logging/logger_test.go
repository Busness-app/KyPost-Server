package logging

import "testing"

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
