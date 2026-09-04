package mailcache

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
)

// maxWindowEntries bounds how many entries a single mailbox window retains,
// mirroring GET /api/inbox's own max `limit` (server.go's `v <= 5000`
// check) — an old, actively-polled mailbox's cache can't grow unbounded
// across months of daemon ticks.
const maxWindowEntries = 5000

// maxRemovals bounds how many departed UIDs a window remembers, so the retained
// list stays a delivery buffer for clients that are briefly behind rather than a
// permanent tombstone log of everything a mailbox ever deleted. A client whose
// cursor falls off the back of it is far enough behind that its own periodic
// since=0 full resync is the honest repair, not an ever-growing list here.
const maxRemovals = 1000

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
	// Removals are UIDs that have left the window, newest-Rev last, capped at
	// maxRemovals. Retained so a removal can be reported to every caller whose
	// cursor predates it — see Store.Sync.
	Removals []Removal `json:"removals,omitempty"`
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
	dropStaleVerdicts(cf.Mailboxes)
	s.mailboxes = cf.Mailboxes
}

// dropStaleVerdicts clears every cached signature verdict that was computed
// under an older version of the binding rules.
//
// Here, at the single point where the file becomes in-memory state, so both
// Snapshot and Sync see the cleaned window and no caller has to remember.
//
// The warm Body goes with the verdict, deliberately. Body is what makes a read
// serve from cache instead of re-fetching, so leaving it would mean the entry
// never re-verifies and the badge silently stays absent forever; dropping it
// costs one IMAP fetch and gets a verdict under the current rules.
func dropStaleVerdicts(mailboxes map[string]*mailboxWindow) {
	for _, w := range mailboxes {
		if w == nil {
			continue
		}
		for i := range w.Entries {
			if w.Entries[i].PGPVerdictSchemaVersion == PGPVerdictSchema {
				continue
			}
			if !w.Entries[i].PGPSigned && !w.Entries[i].PGPVerified && w.Entries[i].PGPSignerFingerprint == "" {
				continue
			}
			clearPGPVerdict(&w.Entries[i])
		}
	}
}

func clearPGPVerdict(e *Entry) {
	e.PGPSigned = false
	e.PGPVerified = false
	e.PGPSignerFingerprint = ""
	e.PGPVerdictSchemaVersion = 0
	e.Body = ""
	e.BodyMode = ""
}

// InvalidatePGPVerdicts drops every cached signature verdict for this user, in
// every mailbox.
//
// Called when the address book changes a PGP key, because the address book is
// what the verdict is anchored to: removing or replacing a contact's key — the
// obvious remediation after discovering a forged badge — otherwise left the
// old verdict standing for every message already in the 5,000-entry window,
// so remediating the contact did not remediate the mail.
//
// Coarse on purpose. A verdict does not record which contact produced it, and
// the alternative is a per-message re-verification pass over the window; the
// cost of being coarse is one body re-fetch per signed message, on an action a
// user takes rarely.
func (s *Store) InvalidatePGPVerdicts() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return err
	}
	changed := false
	for _, w := range s.mailboxes {
		if w == nil {
			continue
		}
		for i := range w.Entries {
			e := &w.Entries[i]
			if !e.PGPSigned && !e.PGPVerified && e.PGPSignerFingerprint == "" {
				continue
			}
			clearPGPVerdict(e)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.persistLocked()
}

// refreshFromDiskLocked re-reads mailcache.json into memory. Its error is
// never discarded: entries carry PGP signature verdicts and warm bodies, so an
// in-memory copy served after a failed re-read is a message body and a trust
// badge this process can no longer confirm.
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
//
// A failed disk re-read is an error, not an empty window. Entries carry warm
// bodies and cached signature verdicts, so serving whatever this process last
// managed to load would present a stale body — and a badge computed against an
// address book generation that can no longer be checked — as current.
func (s *Store) Snapshot(mailboxKey string, limit int) ([]Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, false, err
	}

	if limit <= 0 {
		return nil, false, nil
	}
	win := s.mailboxes[mailboxKey]
	if win == nil || len(win.Entries) < limit {
		if win == nil {
			return nil, false, nil
		}
		return append([]Entry{}, win.Entries...), false, nil
	}

	start := len(win.Entries) - limit
	out := append([]Entry{}, win.Entries[start:]...)
	for _, e := range out {
		if e.Body == "" {
			return out, false, nil
		}
		// A body is not enough. The daemon poller writes a body but never looks
		// for PGP content, so serving its entry as warm reported "not signed"
		// for a message nobody had examined — and since PGPSigned is the sole
		// trigger for the browser's signature verification, that silently
		// turned the check off rather than merely dropping a badge. Report the
		// window cold so the caller does a live fetch and classifies.
		if !e.PGPClassified {
			return out, false, nil
		}
	}
	return out, true, nil
}

// Sync reconciles mailboxKey's cached window against a freshly fetched live
// overview snapshot (the current top-`limit` from IMAP, source of truth),
// replacing the stored window, and returns the delta relevant to a caller whose
// last known cursor was `since` (0 = everything).
//
// New/Updated are computed from the current, post-sync window filtered by
// FirstRev/Rev against since — not from what changed in this specific call — so
// a second poller with an older cursor still correctly receives entries that
// were bumped by a different caller's earlier Sync.
//
// Removed is retained, for the same reason New/Updated are cursor-filtered
// rather than call-local: a removal observed against this call's own prior
// window is only ever observable ONCE, because this call then replaces that
// window. Reporting just that set handed the removal to whichever caller polled
// first and told every other one nothing — a second device, or a retry after a
// response that never reached the client, could not learn of it at any later
// point. Mail deleted on the web stayed in that client's inbox indefinitely.
//
// So each departure is stamped with its own Rev and kept (identity only, capped
// at maxRemovals), and Removed is every retained removal with Rev > since. A UID
// that returns to the window drops its retained removal.
//
// If limit differs from the window's stored Limit, the prior window is discarded
// without computing Removed (a limit change invalidates window comparability)
// and every live entry is reported as New.
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
			// This branch runs precisely BECAUSE the envelope differs, and it
			// cannot distinguish "same message, flag flipped" from "this UID now
			// names a DIFFERENT message". Nothing here tracks UIDVALIDITY — the
			// IMAP value whose entire purpose is to announce that UIDs were
			// renumbered — so after a mailbox is deleted and recreated, restored
			// from backup, or migrated between providers, carrying the warm
			// state forward grafted one message's body and signature verdict
			// onto another message's envelope.
			//
			// A flag flip changes neither the sender nor the timestamp, so
			// requiring both to match separates the two cases without plumbing
			// UIDVALIDITY through the adapter. When they differ, treat the UID
			// as a new message: no body, no verdict, re-fetched on next read.
			if prev.Sender != ov.Sender || prev.AtUTC != ov.AtUTC {
				next = append(next, e)
				continue
			}
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
			// Carry the schema stamp with the verdict it describes. Without
			// this, Sync launders an old verdict into an unstamped entry and
			// dropStaleVerdicts can no longer tell it apart from a current one.
			e.PGPVerdictSchemaVersion = prev.PGPVerdictSchemaVersion
			e.PGPProtectedSubject = prev.PGPProtectedSubject
			// Same rule; preserved alongside Body, or a flag flip strips the
			// render mode off a body that is still there.
			e.BodyMode = prev.BodyMode
			next = append(next, e)
		default:
			next = append(next, prev)
		}
	}

	sort.Slice(next, func(i, j int) bool { return next[i].UID < next[j].UID })

	// A UID that is back in the window is not removed, whatever an earlier call
	// concluded. Dropping its retained removal first is what stops us handing a
	// client the same message as New and as Removed in one response.
	retained := win.Removals[:0]
	for _, r := range win.Removals {
		if !liveUIDs[r.UID] {
			retained = append(retained, r)
		}
	}
	win.Removals = retained

	if !resetWindow {
		for _, e := range prevEntries {
			if liveUIDs[e.UID] {
				continue
			}
			// Stamped with its own Rev so it can be compared against a caller's
			// cursor. Identity only: see Removal.
			win.Seq++
			win.Removals = append(win.Removals, Removal{UID: e.UID, MessageID: e.MessageID, Rev: win.Seq})
		}
	}
	if len(win.Removals) > maxRemovals {
		win.Removals = slices.Clone(win.Removals[len(win.Removals)-maxRemovals:])
	}

	win.Entries = next
	win.Limit = limit
	if err := s.persistLocked(); err != nil {
		return SyncResult{}, err
	}

	var removed []Removal
	for _, r := range win.Removals {
		if r.Rev > since {
			removed = append(removed, r)
		}
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

// warmBody is the Body to persist for in.
//
// A decrypted OpenPGP body is never written: this cache is plain JSON on disk
// (see Store.path), so storing the plaintext of a message someone took the
// trouble to encrypt recreates at rest exactly the exposure the encryption was
// for — and does so for every encrypted message the owner has ever received,
// which is a larger disclosure than the sealed private key beside it.
//
// The PGP flags are still stored: clients need them to render the badge, and
// callers already read an empty Body as "not warmed yet, fetch live if needed"
// rather than "empty message" (see Entry.Body).
//
// The cost is real and larger than one fetch: Snapshot reports a window as
// warmed only when every entry has a body, so one encrypted message makes the
// whole mailbox read as cold and handleInbox's cache-first branch is skipped.
// Serving that branch from a window with empty PGP bodies would emit
// pgpEncrypted with no body and no pgpDecryptError, which is exactly the wire
// signature of a CLIENT-protected message, so clients would tell a server-mode
// user their own mail is unreadable. See docs/E2E_PGP.md.
//
// A Sent body is never written either: that folder holds every message the owner
// has ever sent, in plaintext, on the disk of a server whose claim for
// client-custody mail is that it cannot read that mail — and under client
// custody the pickup-link notice lands there carrying the key to a message the
// server is otherwise storing as ciphertext. Sent is opened far less often than
// the inbox, so the cost is one live fetch on a rare path.
//
// Enforced here rather than at the two internal/api call sites so a future third
// caller cannot bypass it, and so the caller's own response entry keeps the body
// it just fetched.
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
// so without this it was cached verbatim onto the same volume as the ciphertext
// and the claim was simply false.
//
// Not caching Sent bodies (above) covers the sender. This covers the case that
// does not: a recipient on this same instance, whose INBOX the poller warms.
//
// Content matching is unavoidable here — every cache write originates from an
// IMAP read, so the server has no memory that a message was a pickup notice by
// the time it caches it. The pattern is this server's own URL shape rather than
// arbitrary content, and a miss is no worse than the status quo it replaces.
func redactPickupLinkFragments(body string) string {
	// Cheap guard: the overwhelming majority of mail has no pickup link, and
	// this runs on every cached body.
	if !strings.Contains(body, "/pickup/") {
		return body
	}
	return pickupLinkFragment.ReplaceAllString(body, "${1}[redacted]")
}

// Upsert merges freshly-known entries into mailboxKey's window without inferring
// removals: unlike Sync, the caller (the background poller, which only ever sees
// UNSEEN-since-checkpoint INBOX mail) never has the full window in view, so
// absence from entries must never be treated as "message gone". New UID ->
// append, stamp Rev/FirstRev. Existing UID with changed metadata -> update
// fields, stamp Rev (FirstRev untouched). Existing UID with a newly-available
// Body -> attach it without bumping Rev, since a cached body becoming available
// is not a change a polling client needs to be told about. Trims the window to
// maxWindowEntries by evicting the lowest-UID entries beyond the cap.
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
		// Stamp the rules this verdict was produced under, so a later change
		// to the binding invalidates it rather than replaying it. Only where
		// there IS a verdict: an entry carrying none must not be stamped, or
		// dropStaleVerdicts would have nothing to recognize later.
		if in.PGPSigned || in.PGPVerified || in.PGPSignerFingerprint != "" {
			in.PGPVerdictSchemaVersion = PGPVerdictSchema
		}
		idx, ok := byUID[in.UID]
		if !ok {
			win.Seq++
			e := in
			e.Body = warmBody(mailboxKey, in)
			e.Rev = win.Seq
			e.FirstRev = win.Seq
			// PGPDecryptError is a transient signal for this Upsert call's
			// guard, not durable state (see its doc comment in mailcache.go).
			// The persistence guarantee is the json:"-" tag: persistLocked
			// strips it before it ever reaches disk, and every Store method
			// reloads from disk first, so no caller of Snapshot or Sync can
			// observe it regardless of this line. `e := in` above did copy
			// it into the in-memory window entry, though, so this clear is
			// belt-and-braces for that in-memory copy — it protects a
			// same-process reader of win.Entries that bypasses a fresh
			// disk round trip, not Snapshot itself.
			e.PGPDecryptError = ""
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
		// The body is the sentinel for a freshly fetched message, but it is NOT
		// the only evidence of a correct classification. A client-protected
		// message is encrypted AND bodyless by design — the server deliberately
		// does not decrypt it — so gating on the body alone filtered the flags
		// out of exactly the messages end-to-end custody exists for, and the
		// phone cached them as ordinary mail.
		//
		// A decrypt FAILURE also leaves an empty body, and that half of the
		// original reasoning still holds: it may be transient, so it stays
		// uncached and retryable. Hence the error must be empty too.
		classified := in.PGPEncrypted && in.PGPDecryptError == ""
		if in.Body != "" || classified {
			if in.Body != "" {
				// warmBody, not in.Body: a decrypted OpenPGP body is never
				// persisted. Assigning it here also clears any plaintext an
				// older build already wrote for this UID.
				updated.Body = warmBody(mailboxKey, in)
				updated.BodyMode = in.BodyMode
			}
			// Only a writer that actually classified may overwrite the PGP
			// fields. The poller has a body for every signed-only message but
			// never looks for a signature, so adopting its zeroes erased the
			// API's marker on every tick — and PGPSigned is the sole trigger
			// for the browser's verification, so that silently turned the
			// check off rather than merely dropping a badge.
			if in.PGPClassified || !updated.PGPClassified {
				updated.PGPEncrypted = in.PGPEncrypted
				updated.PGPSigned = in.PGPSigned
				updated.PGPVerified = in.PGPVerified
				updated.PGPSignerFingerprint = in.PGPSignerFingerprint
				updated.PGPProtectedSubject = in.PGPProtectedSubject
				updated.PGPClassified = in.PGPClassified
				// The stamp travels with the verdict it describes, INSIDE the
				// same guard. Without this the existing-UID branch kept a zero
				// version alongside a fresh verdict, and dropStaleVerdicts
				// discarded both on the very next load — which is the
				// production ordering, since the poller creates the entry
				// before the API warms the verdict into it. Leaving the stamp
				// outside the guard reintroduced exactly that: the poller wrote
				// version 0 over a preserved marker and the next load cleared
				// it anyway.
				updated.PGPVerdictSchemaVersion = in.PGPVerdictSchemaVersion
				updated.ContactKeyGen = in.ContactKeyGen
			}
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
