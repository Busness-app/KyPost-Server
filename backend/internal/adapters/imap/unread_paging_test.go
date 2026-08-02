package imap

import (
	"context"
	"strconv"
	"testing"
)

// One poll tick used to fetch every unread message past the checkpoint in a
// single GetEmails call, which fully buffers and MIME-decodes each one. With a
// 25 MiB per-message cap and no cap on the count, the peak memory of a tick was
// a function of how much unread mail happened to be waiting — a backlog after
// downtime is enough to take the container out, and the poller's rate limit
// cannot help because it applies during processing, after the fetch.
//
// These drive collectUnreadPages with a scripted fetcher: the paging and its
// budget are the whole behaviour, and this package has no fake dialer to reach
// them through ListUnreadInbox.

// scriptedPages records the pages it is asked for and answers with a fixed
// number of bytes per UID, so a test can put the budget wherever it needs it.
type scriptedPages struct {
	bytesPerUID int64
	pages       [][]int
}

func (s *scriptedPages) fetch(page []int) ([]Message, int64, int, error) {
	s.pages = append(s.pages, append([]int(nil), page...))
	msgs := make([]Message, 0, len(page))
	maxUID := 0
	for _, uid := range page {
		msgs = append(msgs, Message{ID: strconv.Itoa(uid)})
		if uid > maxUID {
			maxUID = uid
		}
	}
	return msgs, s.bytesPerUID * int64(len(page)), maxUID, nil
}

func uidRange(first, count int) []int {
	uids := make([]int, count)
	for i := range uids {
		uids[i] = first + i
	}
	return uids
}

func TestCollectUnreadPagesBoundsEachPage(t *testing.T) {
	s := &scriptedPages{bytesPerUID: 1}
	uids := uidRange(100, unreadFetchPageSize*3)

	out, maxUID, err := collectUnreadPages(context.Background(), uids, 99, s.fetch)
	if err != nil {
		t.Fatalf("collectUnreadPages: %v", err)
	}

	if len(out) != len(uids) {
		t.Fatalf("fetched %d messages, want all %d", len(out), len(uids))
	}
	if maxUID != uids[len(uids)-1] {
		t.Fatalf("maxUID = %d, want %d", maxUID, uids[len(uids)-1])
	}
	for i, page := range s.pages {
		if len(page) > unreadFetchPageSize {
			t.Fatalf("page %d held %d UIDs, over the %d cap: go-imap buffers a whole page at once",
				i, len(page), unreadFetchPageSize)
		}
	}
}

// The count cap exists for the case the byte budget cannot see: a backlog of
// many small messages, which would never reach the budget but would still hand
// the caller a slice with no ceiling on it.
func TestCollectUnreadPagesStopsAtTheMessageCap(t *testing.T) {
	s := &scriptedPages{bytesPerUID: 1}
	uids := uidRange(1, maxUnreadMessagesPerCall*2)

	out, maxUID, err := collectUnreadPages(context.Background(), uids, 0, s.fetch)
	if err != nil {
		t.Fatalf("collectUnreadPages: %v", err)
	}

	if len(out) > maxUnreadMessagesPerCall+unreadFetchPageSize {
		t.Fatalf("fetched %d messages, past the %d cap", len(out), maxUnreadMessagesPerCall)
	}
	if len(out) == len(uids) {
		t.Fatal("the whole backlog was fetched in one call")
	}
	// The unfetched remainder must stay above the checkpoint, or the next tick
	// skips it. This is the property that makes stopping early safe rather than
	// merely cheap.
	assertRemainderIsAboveCheckpoint(t, uids, out, maxUID)
}

func TestCollectUnreadPagesStopsAtTheByteBudget(t *testing.T) {
	// Each page alone spends half the budget, so the third page must not run.
	s := &scriptedPages{bytesPerUID: unreadFetchByteBudget / 2 / unreadFetchPageSize}
	uids := uidRange(500, unreadFetchPageSize*8)

	out, maxUID, err := collectUnreadPages(context.Background(), uids, 499, s.fetch)
	if err != nil {
		t.Fatalf("collectUnreadPages: %v", err)
	}

	if len(s.pages) != 2 {
		t.Fatalf("fetched %d pages, want 2 before the byte budget stopped it", len(s.pages))
	}
	if len(out) != unreadFetchPageSize*2 {
		t.Fatalf("fetched %d messages, want %d", len(out), unreadFetchPageSize*2)
	}
	assertRemainderIsAboveCheckpoint(t, uids, out, maxUID)
}

// A mailbox that fits inside one page must behave exactly as it did before
// paging existed: one fetch, everything returned.
func TestCollectUnreadPagesLeavesASmallMailboxAlone(t *testing.T) {
	s := &scriptedPages{bytesPerUID: 1}
	uids := []int{7, 8, 9}

	out, maxUID, err := collectUnreadPages(context.Background(), uids, 6, s.fetch)
	if err != nil {
		t.Fatalf("collectUnreadPages: %v", err)
	}
	if len(s.pages) != 1 {
		t.Fatalf("a 3-message mailbox took %d fetches", len(s.pages))
	}
	if len(out) != 3 || maxUID != 9 {
		t.Fatalf("out=%d maxUID=%d, want 3 and 9", len(out), maxUID)
	}
}

func TestCollectUnreadPagesStopsOnCancellation(t *testing.T) {
	s := &scriptedPages{bytesPerUID: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := collectUnreadPages(ctx, uidRange(1, 100), 0, s.fetch); err == nil {
		t.Fatal("a cancelled context still fetched")
	}
	if len(s.pages) != 0 {
		t.Fatalf("fetched %d pages after cancellation", len(s.pages))
	}
}

// assertRemainderIsAboveCheckpoint proves the checkpoint this call produces
// cannot skip mail: every UID that was not returned must be strictly greater
// than maxUID, so the next tick re-fetches it.
func assertRemainderIsAboveCheckpoint(t *testing.T, uids []int, out []Message, maxUID int) {
	t.Helper()
	fetched := make(map[string]bool, len(out))
	for _, m := range out {
		fetched[m.ID] = true
	}
	for _, uid := range uids {
		if fetched[strconv.Itoa(uid)] {
			continue
		}
		if uid <= maxUID {
			t.Fatalf("UID %d was not fetched but the checkpoint advanced to %d; that message is skipped forever", uid, maxUID)
		}
	}
}
