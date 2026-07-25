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
	// Subject and BodyEnc are the SERVER-sealed form: the server holds the
	// key, so it can read both. Used only by legacy server-protected
	// accounts, for which the server can already read the mailbox anyway.
	Subject string                     `json:"subject"`
	BodyEnc cryptutil.EncryptedPayload `json:"bodyEnc"`
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

func (s *PickupStore) recordPath(id string) string {
	return filepath.Join(s.baseDir, id+".json")
}

// Create seals body and persists a new pickup record, expiring after ttl.
// Returns the record's ID, used to build the pickup link.
func (s *PickupStore) Create(senderUserID, recipientEmail, subject, body string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	now := time.Now().UTC()
	record := PickupRecord{
		ID:             id,
		SenderUserID:   senderUserID,
		RecipientEmail: recipientEmail,
		Subject:        subject,
		BodyEnc:        bodyEnc,
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

// consumeLocked loads a record and marks it viewed, enforcing
// "expire after N days or first view, whichever comes first". Shared by both
// view paths so the one-time semantics cannot drift between them.
//
// Marking viewed does not require reading the payload, which is what lets the
// server enforce single-use on a blob it cannot decrypt.
func (s *PickupStore) consumeLocked(id string) (PickupRecord, error) {
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

	tombstone := func(r PickupRecord) PickupRecord {
		r.Viewed = true
		r.BodyEnc = cryptutil.EncryptedPayload{}
		r.ClientSealed = ""
		r.Subject = ""
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
	if err := s.save(tombstone(record)); err != nil {
		return PickupRecord{}, err
	}
	return record, nil
}

// View opens a SERVER-sealed pickup record's body exactly once. Returns
// ErrPickupClientSealed for a client-sealed record, which this server has no
// key for — the caller must serve it to the browser instead.
func (s *PickupStore) View(id string) (subject, body string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.consumeLocked(id)
	if err != nil {
		return "", "", err
	}
	if record.ClientSealed != "" {
		return "", "", ErrPickupClientSealed
	}

	key, err := cryptutil.LoadKey(s.keyPath)
	if err != nil {
		return "", "", err
	}
	plain, err := cryptutil.Open(record.BodyEnc, key)
	if err != nil {
		return "", "", err
	}
	return record.Subject, string(plain), nil
}

// ViewClientSealed returns a client-sealed blob exactly once, for the browser
// to decrypt with the key from the link fragment. The server never sees that
// key and cannot read what it is handing over.
func (s *PickupStore) ViewClientSealed(id string) (sealed string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record, err := s.consumeLocked(id)
	if err != nil {
		return "", err
	}
	if record.ClientSealed == "" {
		return "", ErrPickupNotClientSealed
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

// Sweep deletes tombstones (already-viewed or expired-and-unviewed records)
// older than retention, keeping the pickup directory from growing forever.
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
	cutoff := time.Now().UTC().Add(-retention)
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
		}
	}
	return nil
}
