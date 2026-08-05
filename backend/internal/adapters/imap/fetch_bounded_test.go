package imap

import "testing"

// TestFetchEmailsBoundedStopsAtTheByteBudget pins the bound that
// GetMessageBodies and ListUnreadMessages did not have.
//
// ListUnreadInbox has applied unreadFetchPageSize / unreadFetchByteBudget /
// maxUnreadMessagesPerCall since it was written, with a comment explaining that
// go-imap buffers and MIME-decodes every message in a GetEmails call before
// returning any of it. Neither sibling inherited any of them, so a single
// request could materialise a whole mailbox at roughly 3.3x the wire bytes —
// measured at 4848 MiB of heap for 1500 MiB of mailbox, against an 8 GiB
// container limit.
//
// The budget must be a RUNNING TOTAL across pages: comparing only one page at a
// time leaves the caller's accumulated map unbounded, which is the accumulation
// that matters.
func TestFetchEmailsBoundedStopsAtTheByteBudget(t *testing.T) {
	// One "message" whose accounted size is a quarter of the budget, so the
	// fetch must stop well before the whole list is retrieved.
	const per = unreadFetchByteBudget / 4
	uids := make([]int, 0, unreadFetchPageSize*8)
	for i := 0; i < cap(uids); i++ {
		uids = append(uids, i+1)
	}

	fetched := 0
	emails, truncated, err := fetchEmailsBoundedWith(uids, func(page []int) (map[int]int64, error) {
		out := make(map[int]int64, len(page))
		for _, uid := range page {
			out[uid] = per
			fetched++
		}
		return out, nil
	})
	if err != nil {
		t.Fatalf("fetchEmailsBoundedWith: %v", err)
	}
	if !truncated {
		t.Fatal("fetch reported complete despite passing the byte budget")
	}
	if len(emails) >= len(uids) {
		t.Fatalf("fetched %d of %d UIDs; the byte budget did not bound the batch",
			len(emails), len(uids))
	}
	if fetched > unreadFetchPageSize*2 {
		t.Fatalf("fetched %d messages before stopping; the budget is checked per "+
			"page, not as a running total", fetched)
	}
}
