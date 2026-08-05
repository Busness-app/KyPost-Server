package imap

import (
	goimap "github.com/BrianLeishman/go-imap"
)

// fetchEmailsBounded fetches uids in bounded pages, stopping once the decoded
// content passes unreadFetchByteBudget.
//
// go-imap's GetEmails buffers and MIME-decodes EVERY message in a call before
// returning any of it, at roughly 3.3x the wire bytes. ListUnreadInbox has
// applied a page size, a byte budget and a message count for exactly that reason
// since it was written; its two siblings — GetMessageBodies and
// ListUnreadMessages — called GetEmails with the whole UID list and inherited
// none of them. The per-message SEARCH LARGER filter on GetMessageBodies bounds
// one message, not a batch, and ListUnreadMessages has no size filter at all.
//
// The budget is a RUNNING TOTAL across pages, not a per-page comparison: with a
// per-page check a caller's accumulated map still grows without limit, which is
// the accumulation that matters.
//
// truncated reports that the budget stopped the fetch before every UID was
// retrieved, so callers can tell "no more messages" from "not all of them".
func fetchEmailsBounded(d *goimap.Dialer, uids []int) (emails map[int]*goimap.Email, truncated bool, err error) {
	emails = make(map[int]*goimap.Email, len(uids))
	_, truncated, err = fetchEmailsBoundedWith(uids, func(page []int) (map[int]int64, error) {
		got, perr := d.GetEmails(page...)
		if perr != nil {
			return nil, perr
		}
		out := make(map[int]int64, len(got))
		for uid, e := range got {
			emails[uid] = e
			out[uid] = emailContentSize(e)
		}
		return out, nil
	})
	if err != nil {
		return nil, false, err
	}
	return emails, truncated, nil
}

// fetchEmailsBoundedWith is fetchEmailsBounded's paging and budget logic with
// the actual FETCH injected, so the bound can be tested without an IMAP server.
func fetchEmailsBoundedWith(uids []int, fetchPage func([]int) (map[int]int64, error)) (map[int]int64, bool, error) {
	seen := make(map[int]int64, len(uids))
	var fetchedBytes int64

	for start := 0; start < len(uids); start += unreadFetchPageSize {
		end := min(start+unreadFetchPageSize, len(uids))
		page, perr := fetchPage(uids[start:end])
		if perr != nil {
			return nil, false, perr
		}
		for uid, size := range page {
			seen[uid] = size
			fetchedBytes += size
		}
		// Checked AFTER the page, so a batch that fits in one page behaves
		// exactly as it did before.
		if fetchedBytes >= unreadFetchByteBudget && end < len(uids) {
			return seen, true, nil
		}
	}
	return seen, false, nil
}
