package mailcache

import (
	"os"
	"strings"
	"testing"
)

func uids(rs []Removal) []int {
	out := []int{}
	for _, r := range rs {
		out = append(out, r.UID)
	}
	return out
}

// A message pushed below a full window by newer mail still exists. Reporting
// it as removed made the Android app delete it locally on every new arrival.
func TestSync_AgedOutIsNotReportedAsRemoved(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 3, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread"), ov(3, "c", "unread")}, 0)

	// 4 and 5 arrive and push 1 and 2 below the window.
	res, err := s.Sync("INBOX", 3, []Overview{ov(3, "c", "unread"), ov(4, "d", "unread"), ov(5, "e", "unread")}, first.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := uids(res.AgedOut); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("agedOut = %v, want [1 2] (both below the oldest live UID 3)", got)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("removed = %v, want none", uids(res.Removed))
	}

	// A message missing from INSIDE the live range was deleted.
	res, err = s.Sync("INBOX", 3, []Overview{ov(3, "c", "unread"), ov(5, "e", "unread"), ov(6, "f", "unread")}, res.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := uids(res.Removed); len(got) != 1 || got[0] != 4 || len(res.AgedOut) != 0 {
		t.Fatalf("removed = %v agedOut = %v, want removed [4]", got, uids(res.AgedOut))
	}

	// A window that is not full holds the whole mailbox: anything missing is gone.
	res, err = s.Sync("INBOX", 3, []Overview{ov(6, "f", "unread")}, res.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got := uids(res.Removed); len(got) != 2 || len(res.AgedOut) != 0 {
		t.Fatalf("removed = %v agedOut = %v, want 3 and 5 removed", got, uids(res.AgedOut))
	}
}

// More new mail than the window holds used to be silently skipped: the cursor
// moved past messages the client never received.
func TestSync_HasMoreWhenNewMailOverflowsTheWindow(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 2, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)
	if first.HasMore {
		t.Fatal("a since=0 snapshot has nothing to continue")
	}

	// One new message: the oldest live (2) is known, nothing was skipped.
	one, _ := s.Sync("INBOX", 2, []Overview{ov(2, "b", "unread"), ov(3, "c", "unread")}, first.Cursor)
	if one.HasMore {
		t.Fatal("hasMore with the oldest live message already known to the caller")
	}

	// Three new messages (4,5,6) into a window of 2: 4 is below the window.
	over, _ := s.Sync("INBOX", 2, []Overview{ov(5, "e", "unread"), ov(6, "f", "unread")}, one.Cursor)
	if !over.HasMore {
		t.Fatal("hasMore = false although new mail overflowed the window")
	}
}

// A cursor the window never issued must not be trusted as a delta base.
func TestSync_ForeignCursorResetsToFullWindow(t *testing.T) {
	s := newTestStore(t)
	res, err := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 999)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !res.Reset || len(res.New) != 1 {
		t.Fatalf("future cursor: reset=%v new=%d, want a full window", res.Reset, len(res.New))
	}

	// A new window starts above every cursor the store has issued, so a cursor
	// from the shared window is below all of its revisions.
	old, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "read"), ov(2, "b", "unread")}, 0)
	small, err := s.Sync(WindowKey("INBOX", 2), 2, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, old.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(small.New) != 2 {
		t.Fatalf("new window reported %d new to an older foreign cursor, want 2", len(small.New))
	}
}

// Each limit has its own window: a 50-message poll between two 500-message
// polls no longer resets the larger window and re-sends everything as new.
func TestSync_LimitWindowsDoNotResetEachOther(t *testing.T) {
	s := newTestStore(t)
	live := []Overview{ov(1, "a", "unread"), ov(2, "b", "unread"), ov(3, "c", "unread")}
	big, _ := s.Sync("INBOX", 3, live, 0)
	if _, err := s.Sync(WindowKey("INBOX", 1), 1, live[2:], 0); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	again, err := s.Sync("INBOX", 3, live, big.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(again.New)+len(again.Updated)+len(again.Removed)+len(again.AgedOut) != 0 || again.Reset {
		t.Fatalf("unchanged mailbox reported changes after another limit polled: %+v", again)
	}
}

func TestRemove_AppliesToEveryLimitWindow(t *testing.T) {
	s := newTestStore(t)
	live := []Overview{ov(1, "a", "unread")}
	s.Sync("INBOX", 10, live, 0)
	small, _ := s.Sync(WindowKey("INBOX", 5), 5, live, 0)
	if err := s.Remove("INBOX", 1); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	res, _ := s.Sync(WindowKey("INBOX", 5), 5, []Overview{}, small.Cursor)
	if got := uids(res.Removed); len(got) != 1 || got[0] != 1 {
		t.Fatalf("removed in limit window = %v, want [1]", got)
	}
}

func TestWarmBody_SentLimitWindowStaysUncached(t *testing.T) {
	if warmBody(WindowKey("Sent", 50), Entry{Body: "secret"}) != "" {
		t.Fatal("a Sent body was cached under a limit window key")
	}
}

// A limit window reuses what the base window already warmed, so a phone at
// limit 50 does not re-fetch bodies the poller cached; a different message
// under the same UID inherits nothing.
func TestSync_LimitWindowInheritsBaseWarmth(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("INBOX", []Entry{entry(1, "a", "unread", "warm body")}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	res, err := s.Sync(WindowKey("INBOX", 5), 5, []Overview{ov(1, "a", "read")}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.New) != 1 || res.New[0].Body != "warm body" || !res.New[0].PGPClassified || res.New[0].Status != "read" {
		t.Fatalf("limit window entry = %+v, want the base body with live flags", res.New)
	}

	other := ov(1, "a", "unread")
	other.Sender = "someone-else@example.com"
	res, _ = s.Sync(WindowKey("INBOX", 6), 6, []Overview{other}, 0)
	if len(res.New) != 1 || res.New[0].Body != "" {
		t.Fatalf("a different message under a reused UID inherited %+v", res.New)
	}
}

// Limit windows are bounded: at most maxLimitWindows per mailbox survive, and
// they hold no bodies of their own (the base window holds each body once), so
// a client cycling through limits cannot grow the cache without bound.
func TestSync_LimitWindowsAreBounded(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("b", 4096)
	live := []Overview{}
	base := []Entry{}
	for uid := 1; uid <= 20; uid++ {
		live = append(live, ov(uid, "s", "unread"))
		base = append(base, entry(uid, "s", "unread", body))
	}
	if err := s.Upsert("INBOX", base); err != nil {
		t.Fatal(err)
	}
	for limit := 1; limit <= 20; limit++ {
		if _, err := s.Sync(WindowKey("INBOX", limit), limit, live[20-limit:], 0); err != nil {
			t.Fatal(err)
		}
		if err := s.Upsert(WindowKey("INBOX", limit), base[20-limit:]); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	windows, bodyBytes := 0, 0
	for key, win := range reopened.mailboxes {
		if key != "INBOX" {
			windows++
		}
		for _, e := range win.Entries {
			bodyBytes += len(e.Body)
		}
	}
	if windows > maxLimitWindows {
		t.Fatalf("%d limit windows retained, cap %d", windows, maxLimitWindows)
	}
	if want := 20 * len(body); bodyBytes > want {
		t.Fatalf("%d body bytes stored, want at most %d (each body once)", bodyBytes, want)
	}
	// The newest limits survived; the evicted ones are gone.
	if reopened.mailboxes[WindowKey("INBOX", 20)] == nil || reopened.mailboxes[WindowKey("INBOX", 1)] != nil {
		t.Fatal("eviction kept the wrong windows")
	}
}

// A cursor from an evicted window must not be trusted by the window that
// replaces it: the client gets a full window (Reset), never a partial delta.
func TestSync_EvictedWindowCursorResets(t *testing.T) {
	s := newTestStore(t)
	live := []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}
	first, _ := s.Sync(WindowKey("INBOX", 2), 2, live, 0)
	for limit := 3; limit < 3+maxLimitWindows; limit++ {
		s.Sync(WindowKey("INBOX", limit), limit, live, 0)
	}
	if s.mailboxes[WindowKey("INBOX", 2)] != nil {
		t.Fatal("window 2 should have been evicted")
	}
	again, err := s.Sync(WindowKey("INBOX", 2), 2, live, first.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Reset || len(again.New) != 2 {
		t.Fatalf("evicted cursor: reset=%v new=%d, want a full window", again.Reset, len(again.New))
	}
}

// A cursor issued before the cache was lost must not become valid again when
// a rebuilt window's sequence reaches the same number.
func TestSync_CursorFromLostCacheResets(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)
	if err := os.Remove(s.path()); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	live := []Overview{ov(2, "b", "unread"), ov(3, "c", "unread")}
	rebuilt.Sync("INBOX", 10, live, 0)
	res, err := rebuilt.Sync("INBOX", 10, live, old.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Reset || len(res.New) != 2 {
		t.Fatalf("old cursor %d after cache loss: reset=%v new=%d, want a full window of both rows", old.Cursor, res.Reset, len(res.New))
	}
}
