package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
)

// What made deleting a message feel slow: the web client reloads the inbox
// after every action, and that reload could not be served cheaply. These two
// tests pin the before and after.
//
// Snapshot only reports a window warm when it holds at least `limit` entries,
// and the browser asks for limit=500 — so any mailbox under 500 messages missed
// the cache on every load and fell to the cold path, which FETCHes every body
// with no size pre-filter. The cursor protocol is the way out, and the second
// test is the one that has to keep passing.

func inboxTestMessages(n int) []imapadapter.UnreadMessage {
	msgs := make([]imapadapter.UnreadMessage, 0, n)
	for i := 1; i <= n; i++ {
		msgs = append(msgs, imapadapter.UnreadMessage{
			MessageID: fmt.Sprintf("%d", i),
			Subject:   "s",
			Sender:    "a@example.com",
			Status:    "unread",
			AtUTC:     "2026-01-01T00:00:00Z",
			Body:      "body",
		})
	}
	return msgs
}

func inboxTestOverviews(n int) []imapadapter.Overview {
	out := make([]imapadapter.Overview, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, imapadapter.Overview{
			UID:       i,
			MessageID: fmt.Sprintf("%d", i),
			Subject:   "s",
			Sender:    "a@example.com",
			Status:    "unread",
			AtUTC:     "2026-01-01T00:00:00Z",
		})
	}
	return out
}

// The cache-first path cannot warm a mailbox smaller than the requested limit,
// so it re-fetches the whole window every time. Documented rather than fixed:
// the cache has no way to tell "small mailbox" from "partially cached window".
func TestServeInbox_SmallMailboxNeverWarmsAtClientLimit(t *testing.T) {
	srv := newTestServer(t)
	userID := testUserID(t, srv)
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{unread: inboxTestMessages(40)}

	const clientLimit = 500
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", clientLimit, 0, false, false)
		if rec.Code != 200 {
			t.Fatalf("call %d: status = %d, body=%s", i, rec.Code, rec.Body.String())
		}
	}

	if fake.unreadCalls != 3 {
		t.Fatalf("expected the classic path to re-fetch every load, got %d live fetches for 3 loads", fake.unreadCalls)
	}
}

// The cursor path is what the browser uses now. A reload that follows a delete
// must cost one bodyless overview fetch and nothing else — no body FETCH at
// all, because nothing in the window is new.
func TestServeInbox_CursorReloadCostsNoBodyFetch(t *testing.T) {
	srv := newTestServer(t)
	userID := testUserID(t, srv)
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{
		overviews: inboxTestOverviews(40),
		bodies:    map[int]string{},
	}
	for i := 1; i <= 40; i++ {
		fake.bodies[i] = "body"
	}

	const clientLimit = 500

	// First load: since=0, a full snapshot. Bodies are fetched once.
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", clientLimit, 0, true, false)
	if rec.Code != 200 {
		t.Fatalf("snapshot: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	first := decodeInboxResponse(t, rec)
	if first.Delta {
		t.Fatal("since=0 must come back as a full snapshot, not a delta")
	}
	if first.Cursor == 0 {
		t.Fatal("snapshot must return a cursor for the client to sync against")
	}
	if fake.bodiesCalls != 1 {
		t.Fatalf("expected one body fetch to populate a cold window, got %d", fake.bodiesCalls)
	}

	// The reload after a delete, carrying the cursor. Nothing is new.
	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", clientLimit, first.Cursor, true, false)
	if rec2.Code != 200 {
		t.Fatalf("delta: status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	if !decodeInboxResponse(t, rec2).Delta {
		t.Fatal("a since>0 request must come back marked as a delta")
	}
	if fake.bodiesCalls != 1 {
		t.Fatalf("post-delete reload fetched bodies again: %d body fetches, want 1", fake.bodiesCalls)
	}
	if fake.unreadCalls != 0 {
		t.Fatalf("the cursor path must never touch the full-body cold path, got %d calls", fake.unreadCalls)
	}
}

// A message that left the mailbox has to be named in `removed`, or the client
// that just deleted it has no way to learn it is gone and the row comes back.
func TestServeInbox_CursorReloadReportsTheDeletedMessage(t *testing.T) {
	srv := newTestServer(t)
	userID := testUserID(t, srv)
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{overviews: inboxTestOverviews(3), bodies: map[int]string{1: "b", 2: "b", 3: "b"}}

	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 500, 0, true, false)
	cursor := decodeInboxResponse(t, rec).Cursor

	// UID 2 is deleted: it is gone from the next overview fetch.
	fake.overviews = []imapadapter.Overview{inboxTestOverviews(3)[0], inboxTestOverviews(3)[2]}

	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", 500, cursor, true, false)
	resp := decodeInboxResponse(t, rec2)

	found := false
	for _, id := range resp.Removed {
		if id == "2" {
			found = true
		}
	}
	if !found {
		t.Fatalf("deleted message not reported in removed: %v", resp.Removed)
	}
}

// The seam between the browser's request and the cheap path. The web client
// sends since=0 on its first load precisely to be handed a cursor; if that were
// read as "no cursor requested" it would take the cache-first path, never
// receive a cursor, and stay on the expensive path for the life of the session.
func TestInboxCursorFromQuery(t *testing.T) {
	for _, tc := range []struct {
		query      string
		wantSince  int64
		wantCursor bool
	}{
		{"", 0, false},
		{"?since=0", 0, true},
		{"?since=42", 42, true},
		{"?since=-1", 0, true},
		{"?since=abc", 0, true},
		{"?limit=500&bodies=0", 0, false},
	} {
		r := httptest.NewRequest("GET", "/api/inbox"+tc.query, nil)
		since, cursorSync := inboxCursorFromQuery(r)
		if since != tc.wantSince || cursorSync != tc.wantCursor {
			t.Errorf("%q: got since=%d cursorSync=%v, want since=%d cursorSync=%v",
				tc.query, since, cursorSync, tc.wantSince, tc.wantCursor)
		}
	}
}
