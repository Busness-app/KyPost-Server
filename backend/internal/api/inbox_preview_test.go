package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	imapadapter "github.com/Busnes-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busnes-app/kypost-server/backend/internal/config"
)

func TestInboxPreview(t *testing.T) {
	cases := []struct{ name, body, mode, want string }{
		{"html drops style and tags", `<html><head><style>p{color:red}</style></head><body><p>Hello <span>there</span></p><script>evil()</script></body></html>`, "html", "Hello there"},
		{"plain keeps angle-bracket address", "Mail <user@example.com>\r\nnext\tline", "plain", "Mail <user@example.com> next line"},
		{"control characters become spaces", "a\x00b\x1bc", "plain", "a b c"},
		{"invalid UTF-8 dropped", "ok\xff\xfeok", "plain", "okok"},
	}
	for _, c := range cases {
		if got := inboxPreview(c.body, c.mode); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	long := inboxPreview(strings.Repeat("é", 1000), "plain")
	if utf8.RuneCountInString(long) != maxPreviewRunes || !utf8.ValidString(long) {
		t.Fatalf("long preview: %d runes, valid=%v", utf8.RuneCountInString(long), utf8.ValidString(long))
	}
	// Work is bounded by the input cap, not by the body.
	huge := strings.Repeat(" ", previewInputBytes) + "tail"
	if got := inboxPreview(huge, "plain"); got != "" {
		t.Fatalf("text past the input cap leaked into the preview: %q", got)
	}
}

// preview=1 adds a snippet to rows whose body the response already had, even
// with bodies=0; without it the wire is unchanged.
func TestServeInboxPreviewOptIn(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID
	run := func(withPreview bool) inboxEmail {
		t.Helper()
		fake := &fakeMailClient{
			overviews: []imapadapter.Overview{{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"}},
			bodies:    map[int]string{1: "first line\nsecond line"},
		}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, testInboxCache(t), config.Default(), "", 10, 0, true, false, withPreview)
		emails := allEmails(decodeInboxResponse(t, rec))
		if len(emails) != 1 {
			t.Fatalf("rows: %s", rec.Body.String())
		}
		return emails[0]
	}
	if got := run(true); got.Preview != "first line second line" || got.Body != "" {
		t.Fatalf("preview=1: preview=%q body=%q", got.Preview, got.Body)
	}
	if got := run(false); got.Preview != "" {
		t.Fatalf("preview sent without opt-in: %q", got.Preview)
	}
}

// A row for encrypted mail never carries a preview, whichever path produced
// its body: here the live path hands back a server-decrypted body.
func TestServeInboxPreviewOmittedForEncryptedMail(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
		{MessageID: "1", Subject: "s", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z",
			Body: "decrypted text", BodyMode: "plain", PGPEncrypted: true},
		{MessageID: "2", Subject: "s", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z",
			Body: "plain text", BodyMode: "plain"},
	}}
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), all[0].ID, fake, testInboxCache(t), config.Default(), "", 10, 0, false, false, true)
	for _, e := range allEmails(decodeInboxResponse(t, rec)) {
		if e.MessageID == "1" && e.Preview != "" {
			t.Fatalf("encrypted row has a preview: %q", e.Preview)
		}
		if e.MessageID == "2" && e.Preview != "plain text" {
			t.Fatalf("plain row preview = %q", e.Preview)
		}
	}
}
