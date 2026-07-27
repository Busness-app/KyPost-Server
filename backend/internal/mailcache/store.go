package mailcache

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"kypost-server/backend/internal/fsutil"
)

// maxWindowEntries bounds how many entries a single mailbox window retains,
// mirroring GET /api/inbox's own max `limit` (server.go's `v <= 5000`
// check) — an old, actively-polled mailbox's cache can't grow unbounded
// across months of daemon ticks.
const maxWindowEntries = 5000

// mailboxWindow is one mailbox's cached "current top-N" view.
type mailboxWindow struct {
	// Limit is the `limit` last used by Store.Sync to populate this window.
	// Store.Upsert never sets it — the daemon has no notion of a window
	// size, it just merges in whatever unread mail it found. A Sync call
	// whose limit differs from the stored value discards prior comparison
	// state (see Store.Sync).
	Limit   int     `json:"limit,omitempty"`
	Seq     int64   `json:"seq"`
	Entries []Entry `json:"entries"`
}

// Store is one user's mail metadata cache, persisted as mailcache.json
// alongside contacts.json/state.json/decisions.json in the user's state
// directory. The api and daemon processes share no memory, so every read
// and mutation re-reads the file from disk first, mirroring
// contacts.Store's convention.
type Store struct {
	mu        sync.Mutex
	baseDir   string
	mailboxes map[string]*mailboxWindow
}

type mailCacheFile struct {
	Mailboxes map[string]*mailboxWindow `json:"mailboxes"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, mailboxes: map[string]*mailboxWindow{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "mailcache.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(cf mailCacheFile) {
	if cf.Mailboxes == nil {
		cf.Mailboxes = map[string]*mailboxWindow{}
	}
	s.mailboxes = cf.Mailboxes
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	return fsutil.PersistJSONFile(s.path(), mailCacheFile{Mailboxes: s.mailboxes})
}

// Snapshot returns up to limit cached entries for mailboxKey (the limit
// most recent by UID) and whether it's safe to serve a request from this
// snapshot alone with zero IMAP calls: the window must hold at least limit
// entries and every one of the returned entries must have a non-empty Body.
// Read-only; never mutates the store.
func (s *Store) Snapshot(mailboxKey string, limit int) ([]Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()

	if limit <= 0 {
		return nil, false
	}
	win := s.mailboxes[mailboxKey]
	if win == nil || len(win.Entries) < limit {
		if win == nil {
			return nil, false
		}
		return append([]Entry{}, win.Entries...), false
	}

	start := len(win.Entries) - limit
	out := append([]Entry{}, win.Entries[start:]...)
	for _, e := range out {
		if e.Body == "" {
			return out, false
		}
	}
	return out, true
}

// Sync reconciles mailboxKey's cached window against a freshly fetched live
// overview snapshot (the current top-`limit` from IMAP, source of truth),
// replacing the stored window, and returns the delta relevant to a caller
// whose last known cursor was `since` (0 = everything).
//
// New/Updated are computed from the current, post-sync window filtered by
// FirstRev/Rev against since — not from "what changed in this specific
// call" — so a second poller with an older cursor still correctly receives
// entries that were bumped by a different caller's earlier Sync call (this
// is contacts.Store.ChangedSince's trick, applied here too).
//
// Removed is the one piece not retained across calls: it is only
// "previously-in-window, now absent from live", computed relative to this
// call's own prior window. See the package doc for the accepted
// multi-poller staleness gap this implies.
//
// If limit differs from the window's stored Limit, the prior window is
// discarded without computing Removed (a limit change invalidates window
// comparability) — every live entry is reported as New.
func (s *Store) Sync(mailboxKey string, limit int, live []Overview, since int64) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return SyncResult{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return SyncResult{}, err
	}

	win := s.mailboxes[mailboxKey]
	if win == nil {
		win = &mailboxWindow{}
		s.mailboxes[mailboxKey] = win
	}

	resetWindow := win.Limit != 0 && win.Limit != limit

	prevByUID := make(map[int]Entry, len(win.Entries))
	if !resetWindow {
		for _, e := range win.Entries {
			prevByUID[e.UID] = e
		}
	}
	prevEntries := win.Entries

	next := make([]Entry, 0, len(live))
	liveUIDs := make(map[int]bool, len(live))

	for _, ov := range live {
		liveUIDs[ov.UID] = true
		prev, existed := prevByUID[ov.UID]
		switch {
		case !existed:
			win.Seq++
			e := entryFromOverview(ov)
			e.Rev = win.Seq
			e.FirstRev = win.Seq
			next = append(next, e)
		case !overviewMetaEqual(prev, ov):
			win.Seq++
			e := entryFromOverview(ov)
			e.Rev = win.Seq
			e.FirstRev = prev.FirstRev
			e.Body = prev.Body
			// Overviews carry no attachment info, so preserve the warmed
			// flag across a metadata-only change (same rule as Body) — else
			// the paperclip badge would flicker off on every flag change.
			e.HasAttachments = prev.HasAttachments
			// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint follow
			// the same warm-path-only rule as Body/HasAttachments (see
			// Entry's doc comment) — overviews carry no PGP info either, so
			// preserve them across a metadata-only change or the PGP badge
			// would reset to zero-values on every read/label flip.
			e.PGPEncrypted = prev.PGPEncrypted
			e.PGPSigned = prev.PGPSigned
			e.PGPVerified = prev.PGPVerified
			e.PGPSignerFingerprint = prev.PGPSignerFingerprint
			e.PGPProtectedSubject = prev.PGPProtectedSubject
			next = append(next, e)
		default:
			next = append(next, prev)
		}
	}

	sort.Slice(next, func(i, j int) bool { return next[i].UID < next[j].UID })

	var removed []Entry
	if !resetWindow {
		for _, e := range prevEntries {
			if !liveUIDs[e.UID] {
				removed = append(removed, e)
			}
		}
	}

	win.Entries = next
	win.Limit = limit
	if err := s.persistLocked(); err != nil {
		return SyncResult{}, err
	}

	result := SyncResult{Cursor: win.Seq, Removed: removed}
	for _, e := range next {
		if e.Rev <= since {
			continue
		}
		if e.FirstRev > since {
			result.New = append(result.New, e)
		} else {
			result.Updated = append(result.Updated, e)
		}
	}
	return result, nil
}

// warmBody is the Body to persist for in. A decrypted OpenPGP body is never
// written: this cache is plain JSON on disk (see Store.path), so storing the
// plaintext of a message someone took the trouble to encrypt would recreate
// at rest exactly the exposure the encryption was for — and it would do so
// for every encrypted message the owner has ever received, which is a larger
// disclosure than the sealed private key beside it.
//
// The PGP flags are still stored: clients need them to render the badge, and
// correctness is unaffected, because callers already read an empty Body as
// "not warmed yet, fetch live if needed" rather than "empty message" (see
// Entry.Body).
//
// The performance cost is real and larger than one fetch: Snapshot reports a
// window as warmed only when every entry has a body, so one encrypted message
// makes the whole mailbox read as cold and handleInbox's cache-first branch is
// skipped. That is the right trade as it stands — serving that branch from a
// window with empty PGP bodies would emit pgpEncrypted with no body and no
// pgpDecryptError, which is exactly the wire signature of a CLIENT-protected
// message, so clients would tell a server-mode user their own mail is
// unreadable. See docs/E2E_PGP.md for the fix if the fast path is wanted back.
//
// A Sent body is never written either. That folder holds every message the
// owner has ever sent, in plaintext, on the disk of a server whose claim for
// client-custody mail is that it cannot read that mail — and under client
// custody the pickup-link notice lands there carrying the key to a message the
// server is otherwise storing as ciphertext it cannot open. Sent is opened far
// less often than the inbox, so the cost is one live fetch on a rare path.
//
// This is enforced here rather than at the two internal/api call sites so a
// future third caller cannot bypass it, and so the caller's own response
// entry keeps the body it just fetched.
func warmBody(mailboxKey string, in Entry) string {
	if in.PGPEncrypted || isSentMailbox(mailboxKey) {
		return ""
	}
	return redactPickupLinkFragments(in.Body)
}

// sentMailboxLeaf matches the last path component of a Sent folder across the
// naming conventions in the wild: "Sent", "Sent Items", "Sent Messages",
// "[Gmail]/Sent Mail", "INBOX.Sent". Deliberately a prefix match on the leaf
// rather than a substring match on the whole name, so a user folder called
// "Consent forms" or a parent named "Sent/Archive-2019" is not caught by
// accident.
func isSentMailbox(mailboxKey string) bool {
	leaf := mailboxKey
	if i := strings.LastIndexAny(leaf, "/."); i >= 0 {
		leaf = leaf[i+1:]
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(leaf)), "sent")
}

// pickupLinkFragment matches the URL-fragment key of a pickup link this server
// itself emitted. The character class stops at quotes and angle brackets so an
// HTML href is redacted without swallowing its closing quote and turning the
// cached body into broken markup.
var pickupLinkFragment = regexp.MustCompile(`(/pickup/[^\s"'<>]*#)[^\s"'<>]+`)

// redactPickupLinkFragments removes the AES key from any client-sealed pickup
// link in a body about to be persisted.
//
// The pickup link's whole security claim is that the key lives only in the URL
// fragment, which browsers never transmit, so the server storing the ciphertext
// cannot read it — see pickup_client_sealed.go, which states the key "is never
// written to disk". The notice carrying that link is ordinary unencrypted mail,
// so without this it was cached verbatim onto the same volume as the ciphertext,
// and the claim was simply false.
//
// Not caching Sent bodies (above) covers the sender. This covers the case that
// does not: when the recipient is another user on this same instance, the notice
// arrives in their INBOX and the poller warms it there.
//
// Content matching is unavoidable here — every cache write originates from an
// IMAP read, so the server has no memory that a message was a pickup notice by
// the time it caches it. What makes that acceptable is that the pattern is this
// server's own URL shape rather than arbitrary content, and a miss is no worse
// than the status quo it replaces.
func redactPickupLinkFragments(body string) string {
	// Cheap guard: the overwhelming majority of mail has no pickup link, and
	// this runs on every cached body.
	if !strings.Contains(body, "/pickup/") {
		return body
	}
	return pickupLinkFragment.ReplaceAllString(body, "${1}[redacted]")
}

// Upsert merges freshly-known entries into mailboxKey's window without
// inferring removals — unlike Sync, the caller (the background poller,
// which only ever sees UNSEEN-since-checkpoint INBOX mail) never has the
// full window in view, so absence from entries must never be treated as
// "message gone". New UID -> append, stamp Rev/FirstRev. Existing UID with
// changed metadata -> update fields, stamp Rev (FirstRev untouched).
// Existing UID with a newly-available Body -> attach it without bumping Rev
// (a cached body becoming available isn't a change a polling client needs
// to be told about). Trims the window to maxWindowEntries by evicting the
// lowest-UID entries beyond the cap.
func (s *Store) Upsert(mailboxKey string, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return err
	}

	win := s.mailboxes[mailboxKey]
	if win == nil {
		win = &mailboxWindow{}
		s.mailboxes[mailboxKey] = win
	}

	byUID := make(map[int]int, len(win.Entries))
	for i, e := range win.Entries {
		byUID[e.UID] = i
	}

	for _, in := range entries {
		idx, ok := byUID[in.UID]
		if !ok {
			win.Seq++
			e := in
			e.Body = warmBody(mailboxKey, in)
			e.Rev = win.Seq
			e.FirstRev = win.Seq
			win.Entries = append(win.Entries, e)
			byUID[e.UID] = len(win.Entries) - 1
			continue
		}

		// Start from the stored entry (keeps Rev/FirstRev/Body unless
		// overwritten below) so an Upsert call that only refreshes body
		// content, or only some fields, never regresses the rest.
		updated := win.Entries[idx]
		changed := !entryMetaEqual(updated, in)
		updated.Subject, updated.Sender, updated.SentTo = in.Subject, in.Sender, in.SentTo
		updated.CC, updated.BCC = in.CC, in.BCC
		updated.Keywords, updated.Status, updated.AtUTC = in.Keywords, in.Status, in.AtUTC
		if in.Body != "" {
			// warmBody, not in.Body: a decrypted OpenPGP body is never
			// persisted. Assigning it here also clears any plaintext an
			// older build already wrote for this UID.
			updated.Body = warmBody(mailboxKey, in)
			// PGP fields are only ever known alongside a freshly fetched
			// body (see decryptPGPMessageContent/decryptPGPUnreadMessage in
			// internal/api — a failed decrypt leaves Body empty and is
			// deliberately never warmed into the cache), so gate them on
			// the same sentinel as Body. Note the sentinel is the *incoming*
			// body, so the flags still land even though warmBody drops the
			// body itself.
			updated.PGPEncrypted = in.PGPEncrypted
			updated.PGPSigned = in.PGPSigned
			updated.PGPVerified = in.PGPVerified
			updated.PGPSignerFingerprint = in.PGPSignerFingerprint
			updated.PGPProtectedSubject = in.PGPProtectedSubject
		}
		// Only the warm path (poller) calls Upsert, and it always carries an
		// authoritative attachment flag from the same GetEmails parse — so
		// adopt it unconditionally, unlike Body which uses "" as its sentinel.
		updated.HasAttachments = in.HasAttachments
		if changed {
			win.Seq++
			updated.Rev = win.Seq
		}
		win.Entries[idx] = updated
	}

	sort.Slice(win.Entries, func(i, j int) bool { return win.Entries[i].UID < win.Entries[j].UID })
	if len(win.Entries) > maxWindowEntries {
		win.Entries = win.Entries[len(win.Entries)-maxWindowEntries:]
	}

	return s.persistLocked()
}
