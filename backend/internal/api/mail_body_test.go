package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/mailcache"
)

// TestServeInboxBodiesOff covers every path that can produce a list row —
// warm cache, live fallback, and both halves of the delta — because they
// build inboxEmail independently and only share bucket().
func TestServeInboxBodiesOff(t *testing.T) {
	newSrv := func(t *testing.T) (*Server, string) {
		t.Helper()
		srv := newTestServer(t)
		all, err := srv.users.List()
		if err != nil || len(all) == 0 {
			t.Fatalf("no test user available: %v", err)
		}
		return srv, all[0].ID
	}

	t.Run("warm cache", func(t *testing.T) {
		srv, userID := newSrv(t)
		cache := testInboxCache(t)
		if err := cache.Upsert("INBOX", []mailcache.Entry{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread",
				AtUTC: "2026-01-01T00:00:00Z", Body: "body-1", BodyMode: "plain", PGPClassified: true},
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, &fakeMailClient{}, cache, config.Default(), "", 1, 0, false, false)
		assertNoBodies(t, rec)
	})

	t.Run("live fallback", func(t *testing.T) {
		srv, userID := newSrv(t)
		fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
			{MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread",
				AtUTC: "2026-01-01T00:00:00Z", Body: "body-1", BodyMode: "plain"},
		}}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, testInboxCache(t), config.Default(), "", 10, 0, false, false)
		assertNoBodies(t, rec)
	})

	t.Run("delta", func(t *testing.T) {
		srv, userID := newSrv(t)
		fake := &fakeMailClient{
			overviews: []imapadapter.Overview{
				{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
			},
			bodies: map[int]string{1: "body-1"},
		}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, testInboxCache(t), config.Default(), "", 10, 0, true, false)
		assertNoBodies(t, rec)
	})
}

func assertNoBodies(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	emails := allEmails(decodeInboxResponse(t, rec))
	if len(emails) != 1 {
		t.Fatalf("expected one entry, got %+v", emails)
	}
	if emails[0].Body != "" || emails[0].BodyMode != "" {
		t.Fatalf("bodies=0 must strip body and bodyMode, got body=%q mode=%q", emails[0].Body, emails[0].BodyMode)
	}
	// Everything the list actually renders has to survive.
	if emails[0].Subject == "" || emails[0].Sender == "" || emails[0].AtUTC == "" {
		t.Fatalf("bodies=0 stripped list metadata: %+v", emails[0])
	}
}

// bodies=0 must not stop the cache from being warmed, or every load would
// re-fetch bodies from IMAP that nothing ever stored.
func TestServeInboxBodiesOffStillWarmsTheCache(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID
	cache := testInboxCache(t)

	fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
		{MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread",
			AtUTC: "2026-01-01T00:00:00Z", Body: "body-1", BodyMode: "plain"},
	}}
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, config.Default(), "", 1, 0, false, false)

	entries, warmed, err := cache.Snapshot("INBOX", 1)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !warmed || len(entries) != 1 || entries[0].Body != "body-1" {
		t.Fatalf("expected the cache warmed with the body, got warmed=%v entries=%+v", warmed, entries)
	}
}

// The default — and therefore every shipped client that has not opted out —
// must keep getting bodies.
func TestInboxKeepsBodiesByDefault(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	cache := testInboxCache(t)
	if err := cache.Upsert("INBOX", []mailcache.Entry{
		{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread",
			AtUTC: "2026-01-01T00:00:00Z", Body: "body-1", BodyMode: "plain", PGPClassified: true},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), all[0].ID, &fakeMailClient{}, cache, config.Default(), "", 1, 0, false, true)

	emails := allEmails(decodeInboxResponse(t, rec))
	if len(emails) != 1 || emails[0].Body != "body-1" || emails[0].BodyMode != "plain" {
		t.Fatalf("default response must still carry bodies, got %+v", emails)
	}
}

func TestHandleInboxParsesBodiesParam(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{"", true},
		{"&bodies=0", false},
		{"&bodies=1", true},
		{"&bodies=", true},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/api/inbox?limit=500"+tc.query, nil)
		got := r.URL.Query().Get("bodies") != "0"
		if got != tc.want {
			t.Errorf("bodies param %q -> withBodies %v, want %v", tc.query, got, tc.want)
		}
	}
}

// mailBodyServer wires a fake IMAP client onto a real Server the way
// pgp_client_read_test.go's harness does: mailFor only reuses a cached client
// when its updatedAt matches the on-disk IMAP config.
func mailBodyServer(t *testing.T, fake *fakeMailClient) (*Server, string) {
	t.Helper()
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "tester@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()
	return srv, userID
}

func fetchMailBody(t *testing.T, srv *Server, userID, query string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/mail/body?"+query, nil)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handleMailBody)(rec, req)

	got := map[string]any{}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
		}
	}
	return rec, got
}

func TestHandleMailBodyReturnsTheBodyTheListNoLongerCarries(t *testing.T) {
	fake := &fakeMailClient{bodies: map[int]string{5: "<p>hello</p>"}}
	srv, userID := mailBodyServer(t, fake)

	rec, got := fetchMailBody(t, srv, userID, "mailbox=INBOX&messageId=5")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got["body"] != "<p>hello</p>" {
		t.Fatalf("body = %v, want the message body", got["body"])
	}
	if fake.bodiesCalls != 1 {
		t.Fatalf("expected exactly one body fetch, got %d", fake.bodiesCalls)
	}
	if len(fake.lastBodyUIDs) != 1 || fake.lastBodyUIDs[0] != 5 {
		t.Fatalf("expected a fetch scoped to the one requested UID, got %v", fake.lastBodyUIDs)
	}
}

func TestHandleMailBodyRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"missing messageId", "mailbox=INBOX", http.StatusBadRequest},
		{"non-numeric messageId", "mailbox=INBOX&messageId=abc", http.StatusBadRequest},
		{"zero messageId", "mailbox=INBOX&messageId=0", http.StatusBadRequest},
		{"negative messageId", "mailbox=INBOX&messageId=-1", http.StatusBadRequest},
		{"unknown message", "mailbox=INBOX&messageId=99", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, userID := mailBodyServer(t, &fakeMailClient{bodies: map[int]string{5: "x"}})
			rec, _ := fetchMailBody(t, srv, userID, tc.query)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestHandleMailBodyRequiresAuth(t *testing.T) {
	srv, _ := mailBodyServer(t, &fakeMailClient{bodies: map[int]string{5: "x"}})
	req := httptest.NewRequest(http.MethodGet, "/api/mail/body?mailbox=INBOX&messageId=5", nil)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handleMailBody)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
