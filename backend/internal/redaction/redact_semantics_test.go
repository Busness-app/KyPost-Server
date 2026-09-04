package redaction

import (
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
)

// Patterns are applied in sequence over the running result, so an earlier
// pattern's replacement text is itself subject to every later pattern. That
// ordering is load-bearing for a privacy control and was untested.
func TestApplyRunsPatternsInOrderOverTheRunningResult(t *testing.T) {
	engine, err := New([]config.Pattern{
		{Name: "first", Regex: `secret`, Replacement: "classified"},
		{Name: "second", Regex: `classified`, Replacement: "[REDACTED]"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const want = "this is [REDACTED]"
	if got := engine.Apply("this is secret"); got != want {
		t.Fatalf("Apply = %q, want %q — later patterns must see earlier replacements", got, want)
	}
}

// Replacements go through Regexp.ReplaceAllString, which EXPANDS $name and
// ${name}. An operator writing a literal '$' in a replacement therefore does
// not get one: "$AMOUNT" parses as a capture-group reference and, with no such
// group, expands to nothing.
//
// Characterization test. It pins current behavior so the footgun is visible in
// the suite, and so a future switch to literal replacement is a deliberate,
// reviewed change rather than a silent one.
func TestApplyExpandsDollarInReplacement(t *testing.T) {
	engine, err := New([]config.Pattern{
		{Name: "money", Regex: `AMOUNT`, Replacement: "$AMOUNT"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := engine.Apply("total AMOUNT here"); strings.Contains(got, "$AMOUNT") {
		t.Fatalf("Apply = %q — if this now preserves a literal $, replacement expansion changed; "+
			"update this test deliberately and tell operators their replacements changed meaning", got)
	}

	// $$ is the documented way to get a literal dollar through expansion.
	escaped, err := New([]config.Pattern{
		{Name: "money", Regex: `AMOUNT`, Replacement: "$$"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := escaped.Apply("total AMOUNT here"); !strings.Contains(got, "$") {
		t.Fatalf("Apply = %q, want $$ to yield a literal $", got)
	}
}

// New must reject a pattern set it cannot compile so callers can refuse the
// config. Poller.UpdateConfig and the settings handler both depend on this
// returning an error rather than a silently-empty engine.
func TestNewRejectsInvalidRegex(t *testing.T) {
	if _, err := New([]config.Pattern{
		{Name: "broken", Regex: "([unclosed", Replacement: "[X]"},
	}); err == nil {
		t.Fatal("New returned a nil error for a regex that cannot compile; callers rely on this to refuse the config")
	}
}

// A pattern set that fails to compile must not leave a partially-built engine
// behind — a caller that ignored the error would otherwise redact with only
// the patterns that happened to precede the broken one.
func TestNewReturnsNoEngineOnError(t *testing.T) {
	engine, err := New([]config.Pattern{
		{Name: "ok", Regex: `secret`, Replacement: "[X]"},
		{Name: "broken", Regex: "([unclosed", Replacement: "[Y]"},
	})
	if err == nil {
		t.Fatal("New: want an error for a pattern set containing an invalid regex")
	}
	if engine != nil {
		t.Fatal("New returned a non-nil engine alongside an error; a caller that ignores err would redact with a partial set")
	}
}

// The zero-pattern case is a real configuration — an operator who cleared the
// list — and must be an identity function rather than a panic.
func TestApplyWithNoPatternsReturnsInputUnchanged(t *testing.T) {
	engine, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	const in = "yoshi@urlxl.com 555-123-4567"
	if got := engine.Apply(in); got != in {
		t.Fatalf("Apply = %q, want the input unchanged when no patterns are configured", got)
	}
}
