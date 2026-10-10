package imap

import (
	"context"
	"strings"
	"testing"
)

// FetchHeaderFields must tell a message that does not exist (no FETCH record)
// from one that exists without the requested headers (NIL value): callers
// such as reply threading refuse the first and accept the second.
func TestFetchHeaderFieldsDistinguishesMissingMessages(t *testing.T) {
	quietRetries(t, 0)
	server := newFakeIMAPServer(t, "/", true, []fakeFolder{{name: "INBOX"}})
	server.mu.Lock()
	server.commandHook = func(tag, command string) (string, bool) {
		ok := tag + " OK done\r\n"
		switch {
		case strings.HasPrefix(command, "UID SEARCH"):
			return "* SEARCH\r\n" + ok, true
		case strings.HasPrefix(command, "UID FETCH 5,6,7 BODY.PEEK[HEADER.FIELDS"):
			// 5 has the header, 6 exists without it, 7 was deleted (no record).
			return "* 1 FETCH (UID 5 BODY[HEADER.FIELDS (MESSAGE-ID)] {20}\r\nMessage-ID: <a@x.t>\r\n)\r\n" +
				"* 2 FETCH (UID 6 BODY[HEADER.FIELDS (MESSAGE-ID)] NIL)\r\n" + ok, true
		}
		return "", false
	}
	server.mu.Unlock()

	got, err := server.client("INBOX").FetchHeaderFields(context.Background(), "INBOX", []int{5, 6, 7}, "Message-ID")
	if err != nil {
		t.Fatal(err)
	}
	if len(got[5]) != 1 || !strings.Contains(got[5][0], "<a@x.t>") {
		t.Fatalf("uid 5 = %q", got[5])
	}
	if lines, ok := got[6]; !ok || len(lines) != 0 {
		t.Fatalf("uid 6 present=%v lines=%q, want present and empty", ok, lines)
	}
	if _, ok := got[7]; ok {
		t.Fatal("uid 7 has no FETCH record and must be absent")
	}
}
