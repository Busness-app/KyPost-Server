package contacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
)

// defaultTombstoneRetention is how long a deleted contact's tombstone is kept
// before GC permanently removes it. A sync client whose cursor predates the
// retention window can no longer be given an accurate deleted[] list and must
// be told to discard its cursor and re-fetch a full snapshot (see
// ChangedSince's tooOld return value).
const defaultTombstoneRetention = 30 * 24 * time.Hour

// Store is one user's address book, persisted as contacts.json alongside
// state.json and decisions.json in the user's state directory. The API and
// daemon processes share no memory, so every read and mutation re-reads the
// file from disk first (matching state.Store's convention), even though only
// the API process touches contacts today.
type Store struct {
	mu             sync.Mutex
	baseDir        string
	contacts       []Contact
	seq            int64
	gcHighWaterRev int64
	// pgpKeyGen changes whenever any contact's PGP key material or address set
	// changes. See PGPKeyGeneration.
	pgpKeyGen int64
}

type contactsFile struct {
	Contacts       []Contact `json:"contacts"`
	Seq            int64     `json:"seq"`
	GCHighWaterRev int64     `json:"gcHighWaterRev,omitempty"`
	PGPKeyGen      int64     `json:"pgpKeyGen,omitempty"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, contacts: []Contact{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "contacts.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(cf contactsFile) {
	s.contacts = append([]Contact{}, cf.Contacts...)
	s.seq = cf.Seq
	s.gcHighWaterRev = cf.GCHighWaterRev
	s.pgpKeyGen = cf.PGPKeyGen
}

// refreshFromDiskLocked re-reads contacts.json into memory.
//
// Its error is never discarded. The in-memory copy is a cache of a file two
// processes write, so a failed re-read means "this process does not know what
// the address book says" — and the address book is what decides which key a
// message is encrypted to and whose signature counts as verified. Answering
// from the last copy that happened to load is how a key the user removed keeps
// authorizing. Every reader below propagates it and every caller fails closed.
func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	cf := contactsFile{
		Contacts:       s.contacts,
		Seq:            s.seq,
		GCHighWaterRev: s.gcHighWaterRev,
		PGPKeyGen:      s.pgpKeyGen,
	}
	if err := fsutil.PersistJSONFile(s.path(), cf); err != nil {
		return fmt.Errorf("write contacts: %w", err)
	}
	return nil
}

// List returns all non-deleted contacts.
func (s *Store) List() ([]Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, fmt.Errorf("read contacts: %w", err)
	}
	out := make([]Contact, 0, len(s.contacts))
	for _, c := range s.contacts {
		if !c.Deleted {
			out = append(out, c)
		}
	}
	return out, nil
}

// Get returns a contact by UID, including a tombstoned one (callers decide
// whether Deleted should be treated as not-found).
func (s *Store) Get(uid string) (Contact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, false, fmt.Errorf("read contacts: %w", err)
	}
	for _, c := range s.contacts {
		if c.UID == uid {
			return c, true, nil
		}
	}
	return Contact{}, false, nil
}

// Upsert creates (when c.UID is empty) or replaces a contact, stamping a new
// Rev/UpdatedAt. Conflict detection (e.g. CardDAV If-Match, mobile-sync
// last-write-wins bookkeeping) is the caller's responsibility, applied before
// calling Upsert; the store itself always accepts the write. Callers that
// need the precondition check to be atomic with the write (so a concurrent
// writer can't slip in between) must use UpsertIfMatch instead.
func (s *Store) Upsert(c Contact) (Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Contact{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, err
	}
	return s.upsertLocked(c)
}

// SetPhotoRef sets (or, with an empty ref, clears) the server-owned photo
// reference for uid. Separate from Upsert because upsertLocked deliberately
// carries PhotoRef forward from the stored record, so no ordinary contact write
// can change it; the photo upload and delete handlers are the only legitimate
// writers. Returns false if uid is unknown.
func (s *Store) SetPhotoRef(uid, ref string) (Contact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Contact{}, false, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, false, err
	}
	for i := range s.contacts {
		if s.contacts[i].UID != uid {
			continue
		}
		s.contacts[i].PhotoRef = ref
		s.contacts[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.contacts[i].Rev++
		if err := s.persistLocked(); err != nil {
			return Contact{}, false, err
		}
		return s.contacts[i], true, nil
	}
	return Contact{}, false, nil
}

// ErrPreconditionFailed is returned by UpsertWithPrecondition when the
// caller's precondition (If-Match / If-None-Match) doesn't hold.
var ErrPreconditionFailed = errors.New("contact precondition failed")

// ContactPrecondition expresses a CardDAV-style conditional-write check to be
// evaluated atomically with the write in UpsertWithPrecondition.
type ContactPrecondition struct {
	// RequireAbsent corresponds to If-None-Match: * — the write fails if a
	// non-deleted contact with this UID already exists.
	RequireAbsent bool
	// RequireETag corresponds to If-Match: <etag> — the write fails unless a
	// contact with this UID currently exists and its ETag equals this value.
	// Empty means no If-Match check.
	RequireETag string
}

// UpsertWithPrecondition evaluates precondition and performs the write in the
// same critical section, so two concurrent requests racing the same
// precondition (e.g. two clients both PUTting with If-Match set to an ETag
// they both read moments earlier) can't both pass the check and silently
// clobber each other — the second one gets ErrPreconditionFailed instead.
func (s *Store) UpsertWithPrecondition(c Contact, precondition ContactPrecondition) (Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Contact{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, err
	}
	existing, exists := s.getLocked(c.UID)
	if precondition.RequireAbsent && exists && !existing.Deleted {
		return Contact{}, ErrPreconditionFailed
	}
	if precondition.RequireETag != "" && (!exists || existing.ETag() != precondition.RequireETag) {
		return Contact{}, ErrPreconditionFailed
	}
	return s.upsertLocked(c)
}

// getLocked is Get's body without the disk refresh or locking, for callers
// that already hold s.mu and have already refreshed from disk this call.
func (s *Store) getLocked(uid string) (Contact, bool) {
	for _, c := range s.contacts {
		if c.UID == uid {
			return c, true
		}
	}
	return Contact{}, false
}

// carryPGPProvenance restores the TOFU pin (fingerprint, source, verified) from
// the stored record when a writer sends back the same key material without it.
//
// PGPKeyFingerprint is the first-seen pin that makes the resolver's
// tierKeyChanged refusal work at all — that check is gated on pinnedFP != "", so
// a contact whose pin is missing silently accepts and auto-trusts the next WKD
// result for that address, which is the key substitution the pin exists to
// prevent. Three of five write paths (sync, CardDAV PUT, vCard import) have no
// field for the provenance and so dropped it on every ordinary write.
//
// Carrying it here rather than at the call sites is the point: a sixth write
// path cannot forget, in the same way none can drop a PhotoRef.
//
// Only when the key material is byte-identical. A different key deserves a
// different pin, and stamping the old fingerprint onto new key material would be
// worse than dropping it — tierKeyChanged would compare against a fingerprint no
// key has. An emptied key takes its provenance with it, for the same reason.
//
// A writer that supplies provenance explicitly is authoritative and is left
// alone: that is how the resolver re-pins a verified key change and how
// backfillPGPKeyFingerprint fills in a manually pasted key.
func carryPGPProvenance(c *Contact, existing Contact) {
	if c.PGPKey == "" || c.PGPKey != existing.PGPKey {
		return
	}
	if c.PGPKeyFingerprint != "" || c.PGPKeySource != "" || c.PGPKeyVerified {
		return
	}
	c.PGPKeyFingerprint = existing.PGPKeyFingerprint
	c.PGPKeySource = existing.PGPKeySource
	c.PGPKeyVerified = existing.PGPKeyVerified
}

func (s *Store) upsertLocked(c Contact) (Contact, error) {
	out, err := s.applyUpsertLocked(c)
	if err != nil {
		return Contact{}, err
	}
	if err := s.persistLocked(); err != nil {
		return Contact{}, err
	}
	return out, nil
}

// applyUpsertLocked is upsertLocked without the write.
//
// Split out so ApplyBatch can apply many changes and persist once. The single-
// change path is unchanged: upsertLocked above is this plus a persist.
// MaxContactsPerUser bounds how many live contacts one account may hold.
//
// Every sibling per-user store has a total cap — groups 1000, rules 100,
// send-as 20, native devices 20, pickups 100, contact photos 200 MiB — and this
// one had none. maxContactsSyncChanges bounds a single REQUEST, not the store,
// so a device-credential sync loop (a wrapper with no write meter) grew
// contacts.json without limit, on the volume that also holds every other user's
// mail cache and sealed key material.
//
// Set well above any plausible address book so it is a backstop rather than a
// product limit.
const MaxContactsPerUser = 10_000

func (s *Store) applyUpsertLocked(c Contact) (Contact, error) {
	// Bound growth, not editing: an existing contact (and a tombstone being
	// revived) must stay writable at the cap, or a full address book becomes
	// read-only and the user cannot even delete their way out of it.
	if existing, exists := s.getLocked(c.UID); c.UID == "" || !exists || existing.Deleted {
		if s.liveContactCountLocked() >= MaxContactsPerUser {
			return Contact{}, fmt.Errorf("contact limit reached (maximum %d)", MaxContactsPerUser)
		}
	}

	// Pin the TOFU fingerprint here, where EVERY write path passes, rather than
	// at the two handlers that remembered to.
	//
	// carryPGPProvenance below covers the update case: a write that resends an
	// existing key without provenance keeps the pin it already had. It cannot
	// cover the CREATE case, because there is nothing yet to carry from — and
	// create is exactly what vCard import, CardDAV PUT, mobile sync and the
	// outbound CardDAV pull do. Those four never called backfillPGPKeyFingerprint,
	// so a key arriving by any of them was stored with an empty fingerprint, and
	// the resolver's key_changed refusal is gated on the pin being non-empty. A
	// contact populated by import or sync — i.e. most of them — therefore had no
	// protection against silent WKD key substitution once its stored key expired.
	c = pinPGPKeyFingerprint(c)

	// Advance the key generation here, where EVERY write path passes, for the
	// same reason the TOFU pin is set here rather than at the handlers that
	// remembered to: three of the eleven writers live in the daemon process and
	// can never call a handler-level helper.
	if before, ok := s.getLocked(c.UID); ok {
		s.bumpPGPKeyGenIfBindingChanged(before, c)
	} else if c.PGPKey != "" {
		s.pgpKeyGen++
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.seq++
	c.Rev = s.seq
	c.Deleted = false
	c.UpdatedAt = now

	if c.UID == "" {
		uid, err := fsutil.NewUUIDv4()
		if err != nil {
			return Contact{}, err
		}
		c.UID = uid
		c.CreatedAt = now
		s.contacts = append(s.contacts, c)
		return c, nil
	}

	for i, existing := range s.contacts {
		if existing.UID == c.UID {
			if c.CreatedAt == "" {
				c.CreatedAt = existing.CreatedAt
			}
			c.IsSelf = existing.IsSelf
			// PhotoRef names a file this server wrote; it is set by the photo
			// upload handler and cleared by the delete handler, never by a
			// contact write. Carrying it forward here — rather than letting
			// callers echo it back — means no write path can drop a photo by
			// omitting the field, and none can point it somewhere else.
			c.PhotoRef = existing.PhotoRef
			carryPGPProvenance(&c, existing)
			s.contacts[i] = c
			return c, nil
		}
	}

	// UID was supplied but not found (e.g. mobile client offline-created a
	// contact and assigned its own UID) — treat as a create under that UID.
	c.CreatedAt = now
	s.contacts = append(s.contacts, c)
	return c, nil
}

// applyDeleteLocked is Delete's tombstoning without the write. Returns false if
// no contact with that UID exists.
func (s *Store) applyDeleteLocked(uid string) bool {
	for i, c := range s.contacts {
		if c.UID != uid {
			continue
		}
		s.seq++
		before := c
		c.tombstone()
		// tombstone() clears the key, so a deleted contact stops being an anchor
		// for its addresses — the same class of change as replacing the key.
		s.bumpPGPKeyGenIfBindingChanged(before, c)
		c.Rev = s.seq
		c.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		s.contacts[i] = c
		return true
	}
	return false
}

// Delete tombstones a contact (clearing its PII fields, keeping only
// identity/bookkeeping) so sync consumers can observe the deletion. Returns
// false if no contact with that UID exists.
func (s *Store) Delete(uid string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return false, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return false, err
	}
	if !s.applyDeleteLocked(uid) {
		return false, nil
	}
	if err := s.persistLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// SetSelf marks (self=true) or unmarks (self=false) the contact at uid as the
// caller's own contact card — the one api.handlePGPQRKey includes in the PGP QR
// key-exchange response. Marking clears the flag from whichever contact
// previously held it, enforcing at most one self-contact per store. Every
// contact whose IsSelf value actually flips gets a fresh Rev/UpdatedAt so
// ChangedSince reports the change to sync clients; a call that changes nothing
// is a no-op. Returns found=false if uid does not exist.
func (s *Store) SetSelf(uid string, self bool) (Contact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Contact{}, false, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, false, err
	}

	idx := -1
	for i, c := range s.contacts {
		if c.UID == uid {
			idx = i
			break
		}
	}
	if idx == -1 {
		return Contact{}, false, nil
	}

	now := time.Now().UTC().Format(time.RFC3339)
	changed := false

	if self {
		for i := range s.contacts {
			if i != idx && s.contacts[i].IsSelf {
				s.contacts[i].IsSelf = false
				s.seq++
				s.contacts[i].Rev = s.seq
				s.contacts[i].UpdatedAt = now
				changed = true
			}
		}
	}

	if s.contacts[idx].IsSelf != self {
		s.contacts[idx].IsSelf = self
		s.seq++
		s.contacts[idx].Rev = s.seq
		s.contacts[idx].UpdatedAt = now
		changed = true
	}

	if changed {
		if err := s.persistLocked(); err != nil {
			return Contact{}, false, err
		}
	}
	return s.contacts[idx], true, nil
}

// GetSelf returns the caller's own contact card — the (at most one) live
// contact with IsSelf set — or ok=false if none is set. A read failure is
// returned as an error rather than as ok=false, which would report a storage
// fault as "you have no own card" and let the caller act on it.
func (s *Store) GetSelf() (Contact, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, false, fmt.Errorf("read contacts: %w", err)
	}
	for _, c := range s.contacts {
		if c.IsSelf && !c.Deleted {
			return c, true, nil
		}
	}
	return Contact{}, false, nil
}

// ChangedSince returns contacts created/updated/deleted after rev, plus the
// current cursor (the highest assigned Rev). tooOld is true when rev predates
// the tombstone GC watermark, meaning some deletions may no longer be
// representable as tombstones — the caller must discard its cursor and
// request a full snapshot (rev=0) instead of trusting a partial delta.
func (s *Store) ChangedSince(rev int64) (changed, deleted []Contact, cursor int64, tooOld bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, nil, 0, false, fmt.Errorf("read contacts: %w", err)
	}

	tooOld = rev > 0 && rev < s.gcHighWaterRev
	changed = make([]Contact, 0)
	deleted = make([]Contact, 0)
	if !tooOld {
		for _, c := range s.contacts {
			if c.Rev <= rev {
				continue
			}
			if c.Deleted {
				deleted = append(deleted, c)
			} else {
				changed = append(changed, c)
			}
		}
	}
	return changed, deleted, s.seq, tooOld, nil
}

// DedupeMerge records one applied merge: the survivor UID and the UIDs it
// absorbed (now tombstones pointing back at it).
type DedupeMerge struct {
	Survivor string   `json:"survivor"`
	Absorbed []string `json:"absorbed"`
}

// DedupeReport summarizes a Dedupe run. MergedCount is the total number of
// contacts tombstoned (losers); Groups is empty when nothing merged.
type DedupeReport struct {
	MergedCount int           `json:"mergedCount"`
	Groups      []DedupeMerge `json:"groups"`
}

// Dedupe finds duplicate live contacts (sharing a normalized email or phone, or
// a name when otherwise empty), merges each qualifying group into its oldest
// member, and tombstones the losers so all sync clients converge. Survivors get
// unioned multi-value fields, most-recent scalars, and a MergedUIDs provenance
// list; losers get MergedInto set. The whole pass is applied under the lock and
// persisted once. It is idempotent — a second run finds no live duplicates.
func (s *Store) Dedupe() (DedupeReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return DedupeReport{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return DedupeReport{}, err
	}

	// Live subset, remembering each member's index in s.contacts.
	var live []Contact
	var liveIdx []int
	for i, c := range s.contacts {
		if !c.Deleted {
			live = append(live, c)
			liveIdx = append(liveIdx, i)
		}
	}

	report := DedupeReport{Groups: []DedupeMerge{}}
	now := time.Now().UTC().Format(time.RFC3339)
	changed := false

	for _, group := range findDuplicateGroups(live) {
		members := make([]Contact, len(group))
		for i, gi := range group {
			members[i] = live[gi]
		}
		if !groupShouldMerge(members) {
			continue
		}

		survivor, absorbed := mergeGroup(members)
		byUID := func(uid string) int {
			for _, gi := range group {
				if live[gi].UID == uid {
					return liveIdx[gi]
				}
			}
			return -1
		}

		s.seq++
		survivor.Rev = s.seq
		survivor.UpdatedAt = now
		s.contacts[byUID(survivor.UID)] = survivor

		for _, uid := range absorbed {
			loser := s.contacts[byUID(uid)]
			loser.tombstone()
			loser.MergedInto = survivor.UID
			s.seq++
			loser.Rev = s.seq
			loser.UpdatedAt = now
			s.contacts[byUID(uid)] = loser
		}

		report.Groups = append(report.Groups, DedupeMerge{Survivor: survivor.UID, Absorbed: absorbed})
		report.MergedCount += len(absorbed)
		changed = true
	}

	if changed {
		if err := s.persistLocked(); err != nil {
			return DedupeReport{}, err
		}
	}
	return report, nil
}

// GC permanently removes tombstones older than retention (nil selects
// defaultTombstoneRetention), recording the highest purged Rev as the new GC
// watermark so ChangedSince can detect stale cursors.
func (s *Store) GC(retention time.Duration) error {
	if retention <= 0 {
		retention = defaultTombstoneRetention
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
	cutoff := time.Now().Add(-retention)
	kept := make([]Contact, 0, len(s.contacts))
	changed := false
	for _, c := range s.contacts {
		if !c.Deleted {
			kept = append(kept, c)
			continue
		}
		updatedAt, err := time.Parse(time.RFC3339, c.UpdatedAt)
		if err == nil && updatedAt.Before(cutoff) {
			if c.Rev > s.gcHighWaterRev {
				s.gcHighWaterRev = c.Rev
			}
			changed = true
			continue
		}
		kept = append(kept, c)
	}
	if !changed {
		return nil
	}
	s.contacts = kept
	return s.persistLocked()
}

// Search performs a case-insensitive substring search against FormattedName,
// GivenName, FamilyName, and email addresses. Results are ranked by match
// quality (prefix matches rank higher than substring matches, name matches
// rank higher than email matches), sorted stable by score ascending, and
// truncated to the specified limit. Deleted contacts are excluded.
// Empty query or non-positive limit returns an empty slice.
func (s *Store) Search(query string, limit int) ([]Contact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, fmt.Errorf("read contacts: %w", err)
	}

	if query = strings.TrimSpace(query); query == "" || limit <= 0 {
		return []Contact{}, nil
	}

	q := strings.ToLower(query)

	type contactScore struct {
		contact Contact
		score   int
	}

	var results []contactScore

	for _, c := range s.contacts {
		if c.Deleted {
			continue
		}

		score := -1 // -1 means no match

		// 0: FormattedName has prefix q
		if strings.HasPrefix(strings.ToLower(c.FormattedName), q) {
			score = 0
		} else {
			// 1: any Emails[].Value has prefix q
			if score < 0 {
				for _, email := range c.Emails {
					if strings.HasPrefix(strings.ToLower(email.Value), q) {
						score = 1
						break
					}
				}
			}

			// 2: FormattedName contains q
			if score < 0 && strings.Contains(strings.ToLower(c.FormattedName), q) {
				score = 2
			}

			// 3: GivenName or FamilyName contains q
			if score < 0 && (strings.Contains(strings.ToLower(c.GivenName), q) ||
				strings.Contains(strings.ToLower(c.FamilyName), q)) {
				score = 3
			}

			// 4: any Emails[].Value contains q
			if score < 0 {
				for _, email := range c.Emails {
					if strings.Contains(strings.ToLower(email.Value), q) {
						score = 4
						break
					}
				}
			}
		}

		if score >= 0 {
			results = append(results, contactScore{c, score})
		}
	}

	// Sort by score ascending using SliceStable to keep stable secondary order
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].score < results[j].score
	})

	// Truncate to limit
	if len(results) > limit {
		results = results[:limit]
	}

	// Extract Contact values
	out := make([]Contact, len(results))
	for i, cs := range results {
		out[i] = cs.contact
	}
	return out, nil
}

// BatchOp is one change in an ApplyBatch call. Delete tombstones UID;
// otherwise Contact is upserted (creating it when its UID is empty or unknown).
type BatchOp struct {
	Delete  bool
	UID     string
	Contact Contact
}

// ApplyBatch applies every op under a single lock and a single write, or applies
// none of them.
//
// Per-op Upsert/Delete each takes the mutex, takes the inter-process file lock,
// re-reads contacts.json from disk, and rewrites the whole file with an fsync —
// so a 4,000-change push from a phone that had been offline was 4,000 full-file
// rewrites, holding the lock throughout and blocking every other reader.
//
// Atomicity is the more important half. Failing partway left the earlier changes
// committed, so the client's sync cursor no longer described the server's state:
// it would resync from its old base cursor and re-apply everything it had
// already applied. Either the whole batch lands and the returned cursor is
// meaningful, or nothing does. The in-memory state is restored on failure, not
// left ahead of the file.
func (s *Store) ApplyBatch(ops []BatchOp) error {
	if len(ops) == 0 {
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

	// Snapshot for rollback. The slice must be copied, not aliased: the apply
	// helpers assign into s.contacts[i] in place.
	prevContacts := append([]Contact{}, s.contacts...)
	prevSeq := s.seq
	rollback := func() {
		s.contacts = prevContacts
		s.seq = prevSeq
	}

	for _, op := range ops {
		if op.Delete {
			// A delete of an unknown UID is not an error: the client is telling
			// us about a contact that is already gone, which is the desired
			// end state.
			s.applyDeleteLocked(op.UID)
			continue
		}
		if _, err := s.applyUpsertLocked(op.Contact); err != nil {
			rollback()
			return err
		}
	}

	if err := s.persistLocked(); err != nil {
		rollback()
		return err
	}
	return nil
}

// pinPGPKeyFingerprint fills in a contact's TOFU fingerprint from its own key
// material when the caller supplied a key but no pin.
//
// Fingerprint only. PGPKeySource and PGPKeyVerified are the caller's to set:
// deriving a fingerprint from bytes that are already present asserts nothing
// about where they came from or whether anyone checked them.
//
// An unparseable key keeps an empty fingerprint rather than failing the write —
// the armored text is still stored verbatim, which is what every existing caller
// expects.
func pinPGPKeyFingerprint(c Contact) Contact {
	if c.PGPKey == "" || c.PGPKeyFingerprint != "" {
		return c
	}
	key, err := crypto.NewKeyFromArmored(c.PGPKey)
	if err != nil {
		return c
	}
	c.PGPKeyFingerprint = key.GetFingerprint()
	return c
}

// liveContactCountLocked counts contacts that are not tombstoned. Tombstones
// are excluded so a user who deletes contacts regains headroom immediately
// rather than having to wait for the tombstone sweeper.
func (s *Store) liveContactCountLocked() int {
	n := 0
	for _, c := range s.contacts {
		if !c.Deleted {
			n++
		}
	}
	return n
}

// PGPKeyGeneration is a counter that changes whenever any contact's PGP key
// material or address set changes.
//
// It exists so cached signature verdicts can be invalidated by EVERY writer
// rather than by the three handlers that remembered to call an invalidation
// helper. The other eight write paths — suppress-contact, mobile sync, CardDAV
// PUT, CardDAV pull, vCard import, the resolver's pin, dedupe, and the daemon's
// Autocrypt harvest — cannot all share a handler-level helper: three of them run
// in the daemon process, which has no *http.Request and no access to the API's
// objects.
//
// A number persisted alongside the contacts is what both processes can see. A
// reader compares the generation a verdict was computed under with the current
// one and discards the verdict when they differ, which is correct regardless of
// which process or which code path made the change.
//
// It also covers the case the handler helper explicitly skipped: it returned
// early when the key bytes were unchanged, so REMOVING AN ADDRESS — which
// narrows exactly what the key is an anchor for — invalidated nothing.
//
// The refresh error is returned, not swallowed. This is the value that decides
// whether a cached "signature verified" badge survives, so answering from a
// stale in-memory copy while contacts.json is unreadable keeps exactly the
// verdicts a user's key removal was meant to retire.
func (s *Store) PGPKeyGeneration() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return 0, fmt.Errorf("read contacts: %w", err)
	}
	return s.pgpKeyGen, nil
}

// pgpBindingOf is the part of a contact that determines which addresses its key
// is a trust anchor for. Two contacts with equal bindings produce identical
// signature verdicts.
func pgpBindingOf(c Contact) string {
	addrs := make([]string, 0, len(c.Emails))
	for _, e := range c.Emails {
		if v := strings.ToLower(strings.TrimSpace(e.Value)); v != "" {
			addrs = append(addrs, v)
		}
	}
	sort.Strings(addrs)
	return c.PGPKey + "\x00" + c.PGPKeyFingerprint + "\x00" + strings.Join(addrs, ",")
}

// bumpPGPKeyGenIfBindingChanged advances the generation when before and after
// disagree about the key or the addresses it binds to. Unrelated edits (a
// rename, a phone number) deliberately do not bump it: over-invalidating would
// force a body re-fetch for every signed message on every contact edit.
func (s *Store) bumpPGPKeyGenIfBindingChanged(before, after Contact) {
	if pgpBindingOf(before) != pgpBindingOf(after) {
		s.pgpKeyGen++
	}
}
