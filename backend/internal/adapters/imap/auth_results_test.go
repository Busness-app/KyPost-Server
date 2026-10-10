package imap

import (
	"fmt"
	"reflect"
	"testing"

	goimap "github.com/BrianLeishman/go-imap"
)

// fetchLine builds one raw "* N FETCH (...)" response line carrying an IMAP
// literal whose declared byte count is computed from the actual content, so
// the fixture can never drift out of sync with itself.
func fetchLine(uid int, item, content string) string {
	return fmt.Sprintf("* 1 FETCH (UID %d %s {%d}\r\n%s)\r\n", uid, item, len(content), content)
}

const arItem = "BODY[HEADER.FIELDS (AUTHENTICATION-RESULTS)]"

func parseRecords(t *testing.T, raw string) [][]*goimap.Token {
	t.Helper()
	d := &goimap.Dialer{}
	records, err := d.ParseFetchResponse(raw)
	if err != nil {
		t.Fatalf("ParseFetchResponse: %v", err)
	}
	return records
}

func TestParseHeaderFieldsRecords(t *testing.T) {
	t.Run("single UID single Authentication-Results line", func(t *testing.T) {
		content := "Authentication-Results: mx.example.net; dkim=pass header.d=example.com\r\n\r\n"
		records := parseRecords(t, fetchLine(100, arItem, content))
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[int][]string{
			100: {"Authentication-Results: mx.example.net; dkim=pass header.d=example.com"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("folded value unfolds to one logical line", func(t *testing.T) {
		content := "Authentication-Results: mx.google.com;\r\n\tdkim=pass header.d=example.com;\r\n\tspf=pass smtp.mailfrom=alice@example.com\r\n\r\n"
		records := parseRecords(t, fetchLine(200, arItem, content))
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "Authentication-Results: mx.google.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=alice@example.com"
		lines := got[200]
		if len(lines) != 1 {
			t.Fatalf("expected exactly one unfolded line, got %d: %#v", len(lines), lines)
		}
		if lines[0] != want {
			t.Fatalf("unfolded line mismatch:\n got %q\nwant %q", lines[0], want)
		}
	})

	t.Run("two separate occurrences stay separate and in order", func(t *testing.T) {
		content := "Authentication-Results: hop2.example.net; dkim=pass header.d=a.com\r\nAuthentication-Results: hop1.example.net; spf=pass smtp.mailfrom=b@b.com\r\n\r\n"
		records := parseRecords(t, fetchLine(300, arItem, content))
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{
			"Authentication-Results: hop2.example.net; dkim=pass header.d=a.com",
			"Authentication-Results: hop1.example.net; spf=pass smtp.mailfrom=b@b.com",
		}
		if !reflect.DeepEqual(got[300], want) {
			t.Fatalf("got %#v, want %#v", got[300], want)
		}
	})

	t.Run("NIL value is present and empty, not an error", func(t *testing.T) {
		raw := "* 1 FETCH (UID 400 " + arItem + " NIL)\r\n"
		records := parseRecords(t, raw)
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lines, ok := got[400]; !ok || len(lines) != 0 {
			t.Fatalf("expected UID 400 present with no lines, got %#v", got)
		}
	})

	t.Run("empty literal value is present and empty, not an error", func(t *testing.T) {
		raw := "* 1 FETCH (UID 450 " + arItem + " {0}\r\n)\r\n"
		records := parseRecords(t, raw)
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if lines, ok := got[450]; !ok || len(lines) != 0 {
			t.Fatalf("expected UID 450 present with no lines, got %#v", got)
		}
	})

	t.Run("multiple UIDs split correctly", func(t *testing.T) {
		c1 := "Authentication-Results: mx.example.net; dkim=pass header.d=one.com\r\n\r\n"
		c2 := "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=two@two.com\r\n\r\n"
		raw := fetchLine(500, arItem, c1) + fetchLine(501, arItem, c2)
		records := parseRecords(t, raw)
		got, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := map[int][]string{
			500: {"Authentication-Results: mx.example.net; dkim=pass header.d=one.com"},
			501: {"Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=two@two.com"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("unsolicited flag update is skipped, not an error", func(t *testing.T) {
		content := "Authentication-Results: mx.example.net; dkim=pass header.d=example.com\r\n\r\n"
		raw := "* 3 FETCH (FLAGS (\\Seen))\r\n" +
			fmt.Sprintf("* 1 FETCH (UID 500 %s {%d}\r\n%s)\r\n", arItem, len(content), content)
		got, err := parseHeaderFieldsRecords(parseRecords(t, raw), []string{"Authentication-Results"})
		if err != nil {
			t.Fatalf("parseHeaderFieldsRecords: %v", err)
		}
		if len(got[500]) != 1 {
			t.Fatalf("got %#v, want UID 500's header", got)
		}
	})

	t.Run("record with no UID token is a descriptive error", func(t *testing.T) {
		content := "Authentication-Results: mx.example.net; dkim=pass header.d=example.com\r\n\r\n"
		raw := fmt.Sprintf("* 1 FETCH (%s {%d}\r\n%s)\r\n", arItem, len(content), content)
		records := parseRecords(t, raw)
		_, err := parseHeaderFieldsRecords(records, []string{"Authentication-Results"})
		if err == nil {
			t.Fatal("expected an error for a record missing its UID token")
		}
	})
}
