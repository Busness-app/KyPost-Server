package redaction

import (
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
)

// Regression test for a bug where the default patterns were defined with
// doubled backslashes (e.g. `\\b`), which RE2 compiles as a literal
// backslash followed by "b" rather than a word boundary — silently
// disabling every default redaction pattern.
func TestDefaultPatternsRedactRealisticPII(t *testing.T) {
	engine, err := New(config.Default().Redaction.Patterns)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"email", "contact me at yoshi@urlxl.com please", "[REDACTED_EMAIL]"},
		{"phone", "call 555-123-4567 now", "[REDACTED_PHONE]"},
		{"ssn", "SSN: 123-45-6789", "[REDACTED_SSN]"},
		{"iban", "IBAN GB29NWBK60161331926819", "[REDACTED_IBAN]"},
		{"card", "card 4111 1111 1111 1111", "[REDACTED_CARD]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Apply(tc.input)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("Apply(%q) = %q, want it to contain %q", tc.input, got, tc.want)
			}
			if got == tc.input {
				t.Fatalf("Apply(%q) left input unredacted", tc.input)
			}
		})
	}
}
