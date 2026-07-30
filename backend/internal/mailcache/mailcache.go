// Package mailcache caches per-mailbox IMAP overview metadata (UIDs, flags,
// envelope headers, and opportunistically a message's body) so a polling
// client doesn't force a full live IMAP fetch on every call to GET
// /api/inbox, and so only genuinely-new messages need an expensive body
// fetch. IMAP remains the source of truth for message content; a cache miss
// always falls back to a live fetch (see api.handleInbox).
//
// Unlike backend/internal/contacts, a Store here is not a permanent record:
// it represents "the current top-N window" for a given mailbox, which
// churns by nature — a message falling out of the window isn't a deletion,
// just a loss of visibility (it aged out, moved, or really was deleted; from
// a polling client's view those are indistinguishable and equally
// unimportant). There is deliberately no tombstone list and no GC pass.
package mailcache

import (
	"slices"
	"strconv"
)

// Entry is one cached message's metadata (and, opportunistically, body) for
// a mailbox window.
type Entry struct {
	UID int `json:"uid"`

	// MessageID mirrors the existing (pre-existing) wire convention used by
	// GET /api/inbox and POST /api/inbox/actions: strconv.Itoa(UID), not the
	// RFC822 Message-ID header. Kept here so callers can round-trip the
	// wire identity without recomputing it.
	MessageID string   `json:"messageId"`
	Subject   string   `json:"subject"`
	Sender    string   `json:"sender"`
	SentTo    string   `json:"sentTo,omitempty"`
	CC        string   `json:"cc,omitempty"`
	BCC       string   `json:"bcc,omitempty"`
	Keywords  []string `json:"keywords,omitempty"`
	Status    string   `json:"status"`
	AtUTC     string   `json:"atUtc"`

	// Rev is the window's monotonic sequence value as of this entry's most
	// recent metadata change (creation or a flag/label/subject change).
	Rev int64 `json:"rev"`

	// FirstRev is the Rev this UID was first added to the window with, and
	// never changes afterward. It is what distinguishes "New" from
	// "Updated" in a SyncResult: an entry is new *to a caller whose cursor
	// was `since`* only if FirstRev > since, regardless of whether Rev has
	// also advanced past since (which happens on every field change, since
	// Rev is bumped again).
	FirstRev int64 `json:"firstRev"`

	// Body is populated only via the daemon's opportunistic warm path
	// (Store.Upsert, called from the poller) — the live overview-sync path
	// (Store.Sync, fed by imapadapter.ListOverviews) never sets or clears
	// it, since overviews deliberately skip body content. Empty means "not
	// warmed yet, fetch live if needed," never "empty message."
	Body string `json:"body,omitempty"`

	// BodyMode says which MIME part Body came from ("html" or "plain"), and
	// follows the same warm-path-only rule as Body itself. Empty means not
	// warmed yet, or written before this field existed; the client falls back to
	// a conservative sniff there rather than mis-rendering an entry inherited
	// from an older cache file.
	BodyMode string `json:"bodyMode,omitempty"`

	// HasAttachments follows the same warm-path-only rule as Body: the poller
	// sets it from the full GetEmails parse it already performs, while the
	// overview-sync path leaves it false (overviews carry no attachment
	// info). False therefore means "no attachments, or not warmed yet" — a
	// client that needs certainty calls GET /api/mail/attachments.
	HasAttachments bool `json:"hasAttachments,omitempty"`

	// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint follow the
	// same warm-path-only rule as Body/HasAttachments: set by
	// internal/api's decrypt step when it warms the cache, absent
	// otherwise.
	PGPEncrypted         bool   `json:"pgpEncrypted,omitempty"`
	PGPSigned            bool   `json:"pgpSigned,omitempty"`
	PGPVerified          bool   `json:"pgpVerified,omitempty"`
	PGPSignerFingerprint string `json:"pgpSignerFingerprint,omitempty"`

	// PGPProtectedSubject is the real subject recovered from a decrypted
	// message's protected headers, warm-path-only like the other PGP fields.
	// Deliberately NOT part of entryMeta: Subject stays the plaintext
	// envelope/overview subject so Sync's overview diffing doesn't churn Rev
	// on every poll; internal/api substitutes this value into the response
	// subject instead.
	PGPProtectedSubject string `json:"pgpProtectedSubject,omitempty"`
}

// Overview is the caller-supplied live snapshot for one message, sourced
// from imapadapter.ListOverviews. mailcache deliberately does not import
// adapters/imap, mirroring contacts staying free of HTTP/IMAP concerns.
type Overview struct {
	UID      int
	Subject  string
	Sender   string
	SentTo   string
	CC       string
	BCC      string
	Keywords []string
	Status   string
	AtUTC    string
}

// SyncResult is what changed for a caller whose last known cursor was
// `since`, computed by reconciling a mailbox window against a freshly
// fetched live snapshot.
type SyncResult struct {
	// New is messages whose UID is new to a caller at `since` — the caller
	// must body-fetch these (no cached Body can be assumed authoritative
	// for a client that has never seen the UID, even if the daemon
	// happened to warm it).
	New []Entry
	// Updated is messages the caller already knows about (FirstRev <=
	// since) whose metadata changed since — flag/label-only, no body
	// needed.
	Updated []Entry
	// Removed is messages present in the window before this call, absent
	// from the freshly fetched live snapshot. Not retained across calls —
	// see the package doc and Store.Sync for the accepted multi-poller
	// staleness gap this implies.
	Removed []Entry
	// Cursor is the window's new high-water Rev.
	Cursor int64
}

// entryMeta is the subset of fields Entry and Overview share, used to
// compare "did this message's metadata change" without going through
// entryFromOverview (which allocates a full Entry, more than a comparison
// needs).
type entryMeta struct {
	Subject  string
	Sender   string
	SentTo   string
	CC       string
	BCC      string
	Status   string
	AtUTC    string
	Keywords []string
}

func (m entryMeta) equal(o entryMeta) bool {
	return m.Subject == o.Subject &&
		m.Sender == o.Sender &&
		m.SentTo == o.SentTo &&
		m.CC == o.CC &&
		m.BCC == o.BCC &&
		m.Status == o.Status &&
		m.AtUTC == o.AtUTC &&
		slices.Equal(m.Keywords, o.Keywords)
}

func (e Entry) meta() entryMeta {
	return entryMeta{
		Subject:  e.Subject,
		Sender:   e.Sender,
		SentTo:   e.SentTo,
		CC:       e.CC,
		BCC:      e.BCC,
		Status:   e.Status,
		AtUTC:    e.AtUTC,
		Keywords: e.Keywords,
	}
}

func (o Overview) meta() entryMeta {
	return entryMeta{
		Subject:  o.Subject,
		Sender:   o.Sender,
		SentTo:   o.SentTo,
		CC:       o.CC,
		BCC:      o.BCC,
		Status:   o.Status,
		AtUTC:    o.AtUTC,
		Keywords: o.Keywords,
	}
}

func overviewMetaEqual(a Entry, b Overview) bool {
	return a.meta().equal(b.meta())
}

func entryMetaEqual(a, b Entry) bool {
	return a.meta().equal(b.meta())
}

func entryFromOverview(ov Overview) Entry {
	return Entry{
		UID:       ov.UID,
		MessageID: strconv.Itoa(ov.UID),
		Subject:   ov.Subject,
		Sender:    ov.Sender,
		SentTo:    ov.SentTo,
		CC:        ov.CC,
		BCC:       ov.BCC,
		Keywords:  append([]string{}, ov.Keywords...),
		Status:    ov.Status,
		AtUTC:     ov.AtUTC,
	}
}
