package pgpmail

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/fsutil"
)

// PickupRecord is one queued message a recipient without a known PGP key
// can retrieve once via an authenticated link, in place of receiving PGP-
// encrypted content they have no key to read.
type PickupRecord struct {
	ID             string `json:"id"`
	SenderUserID   string `json:"senderUserId"`
	RecipientEmail string `json:"recipientEmail"`
	// SubjectEnc and BodyEnc are the SERVER-sealed form: the server holds the
	// key, so it can read both. Used only by legacy server-protected
	// accounts, for which the server can already read the mailbox anyway.
	//
	// The subject is sealed rather than stored plainly because for most mail it
	// gives away the substance of the message. The send path already treats it
	// that way — sendPickupNotification mails OuterPlaceholderSubject instead
	// of the real subject specifically so the cleartext notification does not
	// leak it — and writing it unsealed here put it on the same volume as the
	// ciphertext it was protecting. The client-sealed mode reaches the same
	// conclusion differently, by putting the subject inside the blob.
	//
	// Subject is the legacy cleartext field, still read (never written) so
	// records created before SubjectEnc existed keep their subject for the
	// remainder of their TTL. A pointer so "absent" is distinguishable from
	// "empty envelope" without inspecting the envelope's fields.
	Subject    string                      `json:"subject,omitempty"`
	SubjectEnc *cryptutil.EncryptedPayload `json:"subjectEnc,omitempty"`
	BodyEnc    cryptutil.EncryptedPayload  `json:"bodyEnc"`
	// Mode is the composed body's format — "html" or "plain" — carried from
	// the send request so the pickup page can present the body the way it was
	// written. Without it every body was treated as plain text, which showed
	// the recipient of an HTML message its tags. Empty on records written
	// before this field existed; those predate it by at most one TTL and are
	// read as plain, which is exactly how they were rendered when stored.
	Mode string `json:"mode,omitempty"`
	// ClientSealed is the browser-sealed form: an opaque blob encrypted
	// under a random key that never reaches this server (it travels in the
	// URL fragment of the pickup link, which browsers do not transmit). The
	// subject lives inside it, which is why Subject is empty in this mode —
	// storing it alongside would hand back exactly what the encryption was
	// meant to withhold. The server can delete this but never read it.
	ClientSealed string `json:"clientSealed,omitempty"`
	CreatedAt    string `json:"createdAt"`
	ExpiresAt    string `json:"expiresAt"`
	Viewed       bool   `json:"viewed"`
}

// PickupStore is the global (not per-user — the recipient has no account)
// store of pending pickup-link messages, one file per record under baseDir.
type PickupStore struct {
	mu      sync.Mutex
	baseDir string
	keyPath string
}

// NewPickupStore opens the pickup store rooted at baseDir (typically
// $STATE_DIR/pickup), sealing bodies with the master key at keyPath.
func NewPickupStore(baseDir, keyPath string) *PickupStore {
	return &PickupStore{baseDir: baseDir, keyPath: keyPath}
}

// recordPath is the file backing one pickup record.
//
// The lexical guard is defence in depth, and deliberately so. Every one of the
// five call sites HMAC-authenticates the id before reaching here, so a
// traversing id cannot currently arrive — but that safety is a property of a
// different package, held by five separate callers, and this is the only path
// sink in the codebase with nothing of its own. An empty string is returned for
// a rejected id so callers fail on the open rather than touching a path outside
// baseDir.
func (s *PickupStore) recordPath(id string) string {
	if !fsutil.SafePathComponent(id) {
		return ""
	}
	return filepath.Join(s.baseDir, id+".json")
}

// maxOutstandingPickupsPerUser bounds how many live pickup records one account
// may hold at once.
//
// Each record carries a whole message body — the send path admits roughly
// 34 MiB of decoded attachments — and sits on the shared state volume for its
// full TTL. Creating one is an ordinary authenticated send, so without a cap a
// single account (or a stolen session) can fill the volume that every other
// user's mail cache, contacts and sealed private keys are written to, at which
// point fsutil.AtomicWriteFile starts failing for everyone.
//
// 100 is set well above any plausible real use: the flow exists for the
// occasional correspondent who has no PGP key, not for bulk sending.
const maxOutstandingPickupsPerUser = 100

// maxPickupBytesTotal bounds the whole pickup directory.
//
// The record COUNT above does not bound bytes: each record may carry ~34 MiB,
// and a viewed record stops counting toward the quota the moment its sender
// follows their own link while its file stays on disk until the retention
// sweep. So the count cap could be recycled indefinitely inside one retention
// window, which is exactly the shared-volume exhaustion it was written to
// prevent. This ceiling is measured from directory metadata — no file is read
// to enforce it — and it also bounds the cost of the per-sender scan below,
// since that scan can only ever walk what fits under this.
const maxPickupBytesTotal = 2 << 30

// maxPickupBytesPerUser apportions the shared ceiling above.
//
// maxOutstandingPickupsPerUser is denominated in RECORDS, and the shared
// ceiling in BYTES, so the per-user cap never bound the shared resource: 100
// records of ~34 MiB is ~3.4 GiB against a 2 GiB total, letting one account
// exhaust the whole directory from entirely inside its own quota and deny
// pickup sending to every other user for the full retention window.
//
// A cap must be in the same unit as the thing it apportions. 128 MiB leaves
// room for sixteen accounts at their maximum before the shared ceiling is
// reachable at all, while still allowing several full-size messages outstanding.
//
// A var, not a const, solely so in-package tests can lower it and exercise the
// refusal without writing gigabytes; production never reassigns it.
var maxPickupBytesPerUser int64 = 128 << 20

// ErrPickupStorageFull reports that the pickup directory is at its byte
// ceiling. Distinct from the per-account quota: the sender may be well under
// their own limit and still be refused because the shared volume is not.
var ErrPickupStorageFull = errors.New("pgpmail: pickup storage is full, try again once pending messages have been read")

// pickupBytesTotalLocked sums the pickup directory from ReadDir metadata.
// Deliberately does not open anything: this runs on every create.
func (s *PickupStore) pickupBytesTotalLocked() int64 {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return 0
	}
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

// ErrPickupQuotaExceeded reports that senderUserID already holds the maximum
// number of live pickup records. Surfaced to the sender, so the text names the
// feature and nothing else.
var ErrPickupQuotaExceeded = errors.New("pgpmail: too many unread pickup messages are already waiting for this account")

// outstandingForLocked counts senderUserID's records that are still live —
// neither consumed nor past their expiry.
//
// Tombstones and expired records are deliberately not counted. The sweeper
// collects them on its own schedule, and letting them hold a slot would mean
// someone who legitimately sent a week's worth of pickup links gets refused
// over messages that have already been read.
// It also returns the BYTES those records occupy, because the per-user cap has
// to be denominated in the same unit as the shared ceiling it apportions — and
// this scan already reads every record, so the byte total is free.
func (s *PickupStore) outstandingForLocked(senderUserID string) (int, int64) {
	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		// No directory yet means no records yet. A read failure is reported as
		// zero rather than as "full": refusing to send because the quota could
		// not be counted would turn an unrelated disk problem into an outage.
		return 0, 0
	}
	now := time.Now().UTC()
	count := 0
	var bytes int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(s.baseDir, entry.Name()))
		if rerr != nil {
			continue
		}
		var record PickupRecord
		if json.Unmarshal(b, &record) != nil {
			continue
		}
		if record.SenderUserID != senderUserID || record.Viewed {
			continue
		}
		if expiresAt, perr := time.Parse(time.RFC3339, record.ExpiresAt); perr == nil && now.After(expiresAt) {
			continue
		}
		count++
		bytes += int64(len(b))
	}
	return count, bytes
}

// Create seals body and persists a new pickup record, expiring after ttl.
// Returns the record's ID, used to build the pickup link. mode is the body's
// format ("html" or "plain"), stored so the pickup page renders what the
// sender actually composed.
func (s *PickupStore) Create(senderUserID, recipientEmail, subject, body, mode string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Byte ceiling first: it is metadata-only, and it bounds how much the
	// per-sender scan below can be made to walk.
	if s.pickupBytesTotalLocked() >= maxPickupBytesTotal {
		return "", ErrPickupStorageFull
	}
	outstanding, senderBytes := s.outstandingForLocked(senderUserID)
	if outstanding >= maxOutstandingPickupsPerUser || senderBytes >= maxPickupBytesPerUser {
		return "", ErrPickupQuotaExceeded
	}

	id, err := fsutil.NewUUIDv4()
	if err != nil {
		return "", err
	}
	key, err := cryptutil.LoadOrCreateKey(s.keyPath)
	if err != nil {
		return "", err
	}
	bodyEnc, err := cryptutil.Seal([]byte(body), key)
	if err != nil {
		return "", err
	}
	subjectEnc, err := cryptutil.Seal([]byte(subject), key)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	record := PickupRecord{
		ID:             id,
		SenderUserID:   senderUserID,
		RecipientEmail: recipientEmail,
		SubjectEnc:     &subjectEnc,
		BodyEnc:        bodyEnc,
		Mode:           mode,
		CreatedAt:      now.Format(time.RFC3339),
		ExpiresAt:      now.Add(ttl).Format(time.RFC3339),
	}
	if err := s.save(record); err != nil {
		return "", err
	}
	return id, nil
}

// CreateClientSealed persists a browser-encrypted pickup record. sealed is
// opaque: this server stores and later returns it, and at no point holds the
// key that opens it.
//
// The subject is deliberately not a parameter — it belongs inside sealed. A
// subject stored alongside would be readable here, which for most mail gives
// away the substance of the message and would make the encryption largely
// decorative.
func (s *PickupStore) CreateClientSealed(senderUserID, recipientEmail, sealed string, ttl time.Duration) (string, error) {
	if strings.TrimSpace(sealed) == "" {
		return "", errors.New("pgpmail: sealed payload is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Byte ceiling first: it is metadata-only, and it bounds how much the
	// per-sender scan below can be made to walk.
	if s.pickupBytesTotalLocked() >= maxPickupBytesTotal {
		return "", ErrPickupStorageFull
	}
	outstanding, senderBytes := s.outstandingForLocked(senderUserID)
	if outstanding >= maxOutstandingPickupsPerUser || senderBytes >= maxPickupBytesPerUser {
		return "", ErrPickupQuotaExceeded
	}

	id, err := fsutil.NewUUIDv4()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	record := PickupRecord{
		ID:             id,
		SenderUserID:   senderUserID,
		RecipientEmail: recipientEmail,
		ClientSealed:   sealed,
		CreatedAt:      now.Format(time.RFC3339),
		ExpiresAt:      now.Add(ttl).Format(time.RFC3339),
	}
	if err := s.save(record); err != nil {
		return "", err
	}
	return id, nil
}

func (s *PickupStore) save(record PickupRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(s.recordPath(record.ID), b, 0o600)
}

var ErrPickupNotFound = errors.New("pgpmail: pickup record not found")
var ErrPickupExpired = errors.New("pgpmail: pickup record expired or already viewed")

// ErrPickupClientSealed / ErrPickupNotClientSealed report that a record was
// fetched through the wrong view path for how it was stored.
var ErrPickupClientSealed = errors.New("pgpmail: pickup record is client-sealed; the server cannot decrypt it")
var ErrPickupNotClientSealed = errors.New("pgpmail: pickup record is server-sealed")

// wantKind selects which of the two record shapes a consume call will accept,
// checked BEFORE the record is tombstoned.
type wantKind int

const (
	wantServerSealed wantKind = iota
	wantClientSealed
)

// consumeLocked loads a record of the requested kind and marks it viewed,
// enforcing "expire after N days or first view, whichever comes first". Shared
// by both view paths so the one-time semantics cannot drift between them.
//
// Marking viewed does not require reading the payload, which is what lets the
// server enforce single-use on a blob it cannot decrypt.
func (s *PickupStore) consumeLocked(id string, want wantKind) (PickupRecord, error) {
	b, err := os.ReadFile(s.recordPath(id))
	if os.IsNotExist(err) {
		return PickupRecord{}, ErrPickupNotFound
	}
	if err != nil {
		return PickupRecord{}, err
	}
	var record PickupRecord
	if err := json.Unmarshal(b, &record); err != nil {
		return PickupRecord{}, err
	}
	if record.Viewed {
		return PickupRecord{}, ErrPickupExpired
	}

	// Refuse the wrong-shaped request before tombstoning, not after. This used
	// to be checked by the callers on the returned record — by which point the
	// message had already been destroyed, so asking the client-sealed route for
	// a server-sealed record burned it and answered 409. Reaching either route
	// needs a valid token for that record, so this was never a disclosure, but
	// a store whose entire job is "readable exactly once" must not spend that
	// one read on a request it is going to refuse.
	isClientSealed := record.ClientSealed != ""
	switch {
	case want == wantClientSealed && !isClientSealed:
		return PickupRecord{}, ErrPickupNotClientSealed
	case want == wantServerSealed && isClientSealed:
		return PickupRecord{}, ErrPickupClientSealed
	}

	tombstone := func(r PickupRecord) PickupRecord {
		r.Viewed = true
		r.BodyEnc = cryptutil.EncryptedPayload{}
		r.SubjectEnc = nil
		r.ClientSealed = ""
		r.Subject = ""
		r.Mode = ""
		return r
	}
	if expiresAt, perr := time.Parse(time.RFC3339, record.ExpiresAt); perr == nil && time.Now().UTC().After(expiresAt) {
		_ = s.save(tombstone(record))
		return PickupRecord{}, ErrPickupExpired
	}

	// Tombstone before returning the payload: if the caller fails partway
	// through rendering, the link is still burned. A message that fails to
	// display is recoverable by asking the sender to resend; a link that
	// stays live after being fetched is not.
	//
	// This ordering gets re-reported as a bug — "the record is destroyed before
	// the key is loaded and before either encrypted field is authenticated, so a
	// transient read error loses the only ciphertext". That is an accurate
	// description of the code and the wrong conclusion. Working as designed.
	//
	// The proposed inversion (decrypt first, tombstone only on success) trades a
	// rare unrecoverable message for a routine one: any failure between handing
	// the plaintext out and committing the tombstone leaves a one-time link that
	// has been read and is still live. For a store whose entire contract is
	// "readable exactly once" that is the worse direction to fail in, and it is
	// the direction that fails silently — nobody notices a link that keeps
	// working, whereas a message that will not open gets reported immediately
	// and the sender can resend.
	//
	// Note also what already moved above this point for the same reason: the
	// wrong-kind check. It used to run in the callers on the returned record, so
	// asking the client-sealed route for a server-sealed record burned it and
	// then answered 409. Failures that can be detected WITHOUT spending the read
	// belong before the tombstone; the ones that cannot are what this ordering
	// deliberately accepts.
	if err := s.save(tombstone(record)); err != nil {
		return PickupRecord{}, err
	}
	return record, nil
}

// View opens a SERVER-sealed pickup record's body exactly once, returning it
// with the mode it was composed in. Returns ErrPickupClientSealed for a
// client-sealed record, which this server has no key for — the caller must
// serve it to the browser instead.
func (s *PickupStore) View(id string) (subject, body, mode string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.consumeLocked(id, wantServerSealed)
	if err != nil {
		return "", "", "", err
	}

	key, err := cryptutil.LoadKey(s.keyPath)
	if err != nil {
		return "", "", "", err
	}
	plain, err := cryptutil.Open(record.BodyEnc, key)
	if err != nil {
		return "", "", "", err
	}
	// Records written before the subject was sealed carry it in the legacy
	// cleartext field. They predate this by at most one TTL, and losing their
	// subject would be a worse outcome for the recipient than the leak was.
	subject = record.Subject
	if record.SubjectEnc != nil {
		plainSubject, serr := cryptutil.Open(*record.SubjectEnc, key)
		if serr != nil {
			return "", "", "", serr
		}
		subject = string(plainSubject)
	}
	return subject, string(plain), record.Mode, nil
}

// ViewClientSealed returns a client-sealed blob exactly once, for the browser
// to decrypt with the key from the link fragment. The server never sees that
// key and cannot read what it is handing over.
func (s *PickupStore) ViewClientSealed(id string) (sealed string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.consumeLocked(id, wantClientSealed)
	if err != nil {
		return "", err
	}
	return record.ClientSealed, nil
}

// Kind reports whether a record is client-sealed, without consuming it, so
// the page handler can choose what to render before burning the link.
func (s *PickupStore) Kind(id string) (clientSealed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, rerr := os.ReadFile(s.recordPath(id))
	if os.IsNotExist(rerr) {
		return false, ErrPickupNotFound
	}
	if rerr != nil {
		return false, rerr
	}
	var record PickupRecord
	if uerr := json.Unmarshal(b, &record); uerr != nil {
		return false, uerr
	}
	if record.Viewed {
		return record.ClientSealed != "", ErrPickupExpired
	}
	return record.ClientSealed != "", nil
}

// Discard deletes a record whose pickup link was never delivered, freeing the
// quota slot it would otherwise hold for the full TTL.
//
// The send path creates the record, then mints the link token, then mails the
// link. A failure in either later step leaves a live record for a link that
// reached nobody: it cannot be opened, it cannot be resent, and it counts
// against maxOutstandingPickupsPerUser until it expires a week later. Retrying
// during an SMTP outage therefore used to consume the sender's entire cap with
// records that were pure garbage, after which their real pickup sends were
// refused.
//
// Deleting outright (rather than tombstoning, as consumption does) is right
// here precisely because nothing was handed out: there is no recipient who
// might revisit the link and deserve an "already opened" answer, so there is
// nothing for a tombstone to say. A record that HAS been viewed is left exactly
// as it is — its slot is already free, and its tombstone is still doing that
// job.
//
// senderUserID must match the record's owner. Every present caller passes an id
// it created moments earlier, so the check never fires; it is here so that a
// later caller cannot turn "my send failed" into a way to delete somebody
// else's outstanding message.
func (s *PickupStore) Discard(senderUserID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := os.ReadFile(s.recordPath(id))
	if os.IsNotExist(err) {
		// Already gone. The caller is on a failure path and may be reacting to
		// the record never having landed, so this is the expected shape of
		// success, not an error.
		return nil
	}
	if err != nil {
		return err
	}
	var record PickupRecord
	if err := json.Unmarshal(b, &record); err != nil {
		return err
	}
	if record.SenderUserID != senderUserID {
		return ErrPickupNotFound
	}
	if record.Viewed {
		return nil
	}
	if err := os.Remove(s.recordPath(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// viewedPickupRetention is how long a consumed record's file lingers after it
// stops counting toward the per-account quota.
//
// Tombstones are kept briefly so a recipient who reloads the page gets the
// "already opened" answer rather than a bare 404. They must not be kept for the
// full link TTL: a consumed record frees a quota slot immediately, so pairing a
// 7-day file lifetime with an instantly-reusable slot let one account park
// unbounded bytes on the shared volume inside one window.
const viewedPickupRetention = time.Hour

// Sweep deletes tombstones (already-viewed or expired-and-unviewed records)
// older than retention, keeping the pickup directory from growing forever.
// Consumed records are collected on the shorter viewedPickupRetention clock.
func (s *PickupStore) Sweep(retention time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.baseDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	cutoff := now.Add(-retention)
	viewedCutoff := now.Add(-viewedPickupRetention)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.baseDir, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var record PickupRecord
		if err := json.Unmarshal(b, &record); err != nil {
			continue
		}
		createdAt, err := time.Parse(time.RFC3339, record.CreatedAt)
		if err != nil || createdAt.Before(cutoff) {
			_ = os.Remove(path)
			continue
		}
		// A consumed record has already freed its quota slot, so its bytes must
		// not linger for the full retention window.
		if record.Viewed && createdAt.Before(viewedCutoff) {
			_ = os.Remove(path)
		}
	}
	return nil
}
