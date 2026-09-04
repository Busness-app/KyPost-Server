package imap

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
)

func TestParseRawMessageRecord(t *testing.T) {
	t.Run("single UID returns its raw body", func(t *testing.T) {
		content := "From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
		raw := fmt.Sprintf("* 1 FETCH (UID 100 BODY[] {%d}\r\n%s)\r\n", len(content), content)
		records := parseRecords(t, raw)
		got, err := parseRawMessageRecord(records, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != content {
			t.Fatalf("got %q, want %q", got, content)
		}
	})

	t.Run("selects the matching UID among multiple records", func(t *testing.T) {
		c1 := "From: a@example.com\r\n\r\nfirst\r\n"
		c2 := "From: b@example.com\r\n\r\nsecond\r\n"
		raw := fmt.Sprintf("* 1 FETCH (UID 200 BODY[] {%d}\r\n%s)\r\n", len(c1), c1) +
			fmt.Sprintf("* 2 FETCH (UID 201 BODY[] {%d}\r\n%s)\r\n", len(c2), c2)
		records := parseRecords(t, raw)

		got, err := parseRawMessageRecord(records, 201)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != c2 {
			t.Fatalf("got %q, want %q", got, c2)
		}
	})

	t.Run("NIL value is returned as empty, not an error", func(t *testing.T) {
		// Mirrors parseHeaderFieldsRecords's convention: NIL means "no
		// content", not a parse failure. Safe downstream since
		// VerifyDKIMForDomain fails closed on an empty raw message anyway.
		raw := "* 1 FETCH (UID 300 BODY[] NIL)\r\n"
		records := parseRecords(t, raw)
		got, err := parseRawMessageRecord(records, 300)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("empty literal value is returned as empty, not an error", func(t *testing.T) {
		raw := "* 1 FETCH (UID 350 BODY[] {0}\r\n)\r\n"
		records := parseRecords(t, raw)
		got, err := parseRawMessageRecord(records, 350)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("no record for the requested UID is an error", func(t *testing.T) {
		content := "From: alice@example.com\r\n\r\nbody\r\n"
		raw := fmt.Sprintf("* 1 FETCH (UID 400 BODY[] {%d}\r\n%s)\r\n", len(content), content)
		records := parseRecords(t, raw)
		if _, err := parseRawMessageRecord(records, 999); err == nil {
			t.Fatal("expected an error when no record matches the requested UID")
		}
	})

	t.Run("record with no UID token is a descriptive error", func(t *testing.T) {
		content := "From: alice@example.com\r\n\r\nbody\r\n"
		raw := fmt.Sprintf("* 1 FETCH (BODY[] {%d}\r\n%s)\r\n", len(content), content)
		records := parseRecords(t, raw)
		if _, err := parseRawMessageRecord(records, 500); err == nil {
			t.Fatal("expected an error for a record missing its UID token")
		}
	})

	t.Run("message over the size cap is rejected with ErrMessageTooLarge", func(t *testing.T) {
		withLoweredMaxInboundMessageBytes(t, 16)
		content := strings.Repeat("a", 17)
		raw := fmt.Sprintf("* 1 FETCH (UID 600 BODY[] {%d}\r\n%s)\r\n", len(content), content)
		records := parseRecords(t, raw)
		_, err := parseRawMessageRecord(records, 600)
		if !errors.Is(err, mailmsg.ErrMessageTooLarge) {
			t.Fatalf("got err %v, want ErrMessageTooLarge", err)
		}
	})

	t.Run("message exactly at the size cap is accepted", func(t *testing.T) {
		withLoweredMaxInboundMessageBytes(t, 16)
		content := strings.Repeat("a", 16)
		raw := fmt.Sprintf("* 1 FETCH (UID 601 BODY[] {%d}\r\n%s)\r\n", len(content), content)
		records := parseRecords(t, raw)
		got, err := parseRawMessageRecord(records, 601)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != content {
			t.Fatalf("got %q, want %q", got, content)
		}
	})
}

// withLoweredMaxInboundMessageBytes temporarily lowers the shared inbound
// size cap so tests can exercise the overflow/boundary behavior without
// allocating megabytes of test data, restoring the original value via
// t.Cleanup.
func withLoweredMaxInboundMessageBytes(t *testing.T, limit int64) {
	t.Helper()
	original := mailmsg.MaxInboundMessageBytes
	mailmsg.MaxInboundMessageBytes = limit
	t.Cleanup(func() { mailmsg.MaxInboundMessageBytes = original })
}
