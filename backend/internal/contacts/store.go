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

	"kypost-server/backend/internal/fsutil"
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
}

type contactsFile struct {
	Contacts       []Contact `json:"contacts"`
	Seq            int64     `json:"seq"`
	GCHighWaterRev int64     `json:"gcHighWaterRev,omitempty"`
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
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	cf := contactsFile{
		Contacts:       s.contacts,
		Seq:            s.seq,
		GCHighWaterRev: s.gcHighWaterRev,
	}
	if err := fsutil.PersistJSONFile(s.path(), cf); err != nil {
		return fmt.Errorf("write contacts: %w", err)
	}
	return nil
}

// List returns all non-deleted contacts.
func (s *Store) List() []Contact {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := make([]Contact, 0, len(s.contacts))
	for _, c := range s.contacts {
		if !c.Deleted {
			out = append(out, c)
		}
	}
	return out
}

// Get returns a contact by UID, including a tombstoned one (callers decide
// whether Deleted should be treated as not-found).
func (s *Store) Get(uid string) (Contact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	for _, c := range s.contacts {
		if c.UID == uid {
			return c, true
		}
	}
	return Contact{}, false
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
func (s *Store) applyUpsertLocked(c Contact) (Contact, error) {
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
		c.tombstone()
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
// contact with IsSelf set — or ok=false if none is set.
func (s *Store) GetSelf() (Contact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Contact{}, false
	}
	for _, c := range s.contacts {
		if c.IsSelf && !c.Deleted {
			return c, true
		}
	}
	return Contact{}, false
}

// ChangedSince returns contacts created/updated/deleted after rev, plus the
// current cursor (the highest assigned Rev). tooOld is true when rev predates
// the tombstone GC watermark, meaning some deletions may no longer be
// representable as tombstones — the caller must discard its cursor and
// request a full snapshot (rev=0) instead of trusting a partial delta.
func (s *Store) ChangedSince(rev int64) (changed, deleted []Contact, cursor int64, tooOld bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()

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
	return changed, deleted, s.seq, tooOld
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
func (s *Store) Search(query string, limit int) []Contact {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()

	if query = strings.TrimSpace(query); query == "" || limit <= 0 {
		return []Contact{}
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
	return out
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
