package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	imapadapter "github.com/Busnes-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busnes-app/kypost-server/backend/internal/config"
)

type deltaWire struct {
	ByTab      map[string][]inboxEmail `json:"byTab"`
	Delta      bool                    `json:"delta"`
	Cursor     int64                   `json:"cursor"`
	Removed    []string                `json:"removed"`
	AgedOut    []string                `json:"agedOut"`
	HasMore    bool                    `json:"hasMore"`
	NextBefore string                  `json:"nextBefore"`
}

func overviewsFor(ids ...int) []imapadapter.Overview {
	out := []imapadapter.Overview{}
	for _, id := range ids {
		out = append(out, imapadapter.Overview{UID: id, MessageID: strconv.Itoa(id), Subject: "s", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"})
	}
	return out
}

func TestServeInboxDeltaWindows(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID
	cache := testInboxCache(t)
	fake := &fakeMailClient{bodies: map[int]string{}}
	poll := func(limit int, since int64, ids ...int) deltaWire {
		t.Helper()
		fake.overviews = overviewsFor(ids...)
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, cache, config.Default(), "", limit, since, true, false, false)
		var out deltaWire
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
		}
		return out
	}
	count := func(w deltaWire) int {
		n := 0
		for _, rows := range w.ByTab {
			n += len(rows)
		}
		return n
	}

	// The web (500) and the app (50) polling the same mailbox used to reset
	// each other's window, re-sending every message as new on every switch.
	web := poll(maxInboxLimit, 0, 1, 2, 3)
	poll(50, 0, 1, 2, 3)
	again := poll(maxInboxLimit, web.Cursor, 1, 2, 3)
	if !again.Delta || count(again) != 0 {
		t.Fatalf("web delta after an app poll: delta=%v rows=%d, want an empty delta", again.Delta, count(again))
	}

	// Aged out is not removed.
	first := poll(2, 0, 1, 2)
	aged := poll(2, first.Cursor, 2, 3)
	if len(aged.Removed) != 0 || len(aged.AgedOut) != 1 || aged.AgedOut[0] != "1" {
		t.Fatalf("removed=%v agedOut=%v, want message 1 aged out only", aged.Removed, aged.AgedOut)
	}

	// Overflow: three new messages into a window of two.
	over := poll(2, aged.Cursor, 5, 6)
	if !over.HasMore || over.NextBefore != "5" {
		t.Fatalf("hasMore=%v nextBefore=%q, want continuation before 5", over.HasMore, over.NextBefore)
	}

	// A cursor this window never issued gets a full window, flagged as such.
	reset := poll(2, over.Cursor+1000, 5, 6)
	if reset.Delta || count(reset) != 2 {
		t.Fatalf("foreign cursor: delta=%v rows=%d, want a full window", reset.Delta, count(reset))
	}
}
