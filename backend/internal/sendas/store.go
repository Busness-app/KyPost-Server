package sendas

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// pendingExpiry is how long a newly created alias stays "pending" before its
// ExpiresAt cutoff passes and PendingNotExpired stops returning it (the
// background poller task is responsible for then transitioning it to
// "failed" via MarkFailed).
const pendingExpiry = 5 * time.Minute

// Store is one user's set of send-as alias records, persisted as
// send_as_aliases.json in the user's state directory. The API and daemon
// processes share no memory, so every read re-reads the file from disk
// first and every mutation runs through update, which additionally holds an
// inter-process file lock for the whole read-modify-write cycle.
type Store struct {
	mu      sync.Mutex
	baseDir string
	aliases []Alias
}

type aliasesFile struct {
	Aliases []Alias `json:"aliases"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, aliases: []Alias{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "send_as_aliases.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(af aliasesFile) {
	s.aliases = append([]Alias{}, af.Aliases...)
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	af := aliasesFile{Aliases: s.aliases}
	if err := fsutil.PersistJSONFile(s.path(), af); err != nil {
		return fmt.Errorf("write send-as aliases: %w", err)
	}
	return nil
}

// update runs mutate as one read-modify-write cycle, holding the in-process
// mutex and the inter-process file lock across the whole cycle and
// refreshing from disk first. mutate is responsible for calling
// persistLocked when it actually changes something.
//
// This file is written by both processes: the api process creates and
// deletes aliases from the settings UI, and the daemon process verifies and
// expires them (processor/sendas_check.go). Without the file lock, a
// verification landing at the same moment as a user deleting a different
// alias loses one of the two writes. See fsutil.WithFileLock.
func (s *Store) update(mutate func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsutil.WithFileLock(s.path(), func() error {
		if err := s.refreshFromDiskLocked(); err != nil {
			return err
		}
		return mutate()
	})
}

// List returns all alias records regardless of status (pending, verified,
// and failed), for the settings-UI listing.
func (s *Store) List() []Alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := make([]Alias, len(s.aliases))
	copy(out, s.aliases)
	return out
}

// ListVerified returns only records with Status == "verified".
func (s *Store) ListVerified() []Alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := make([]Alias, 0, len(s.aliases))
	for _, a := range s.aliases {
		if a.Status == "verified" {
			out = append(out, a)
		}
	}
	return out
}

// FindVerifiedByEmail returns the verified alias whose Email matches email
// case-insensitively. It always refreshes from disk first and never caches
// its result, since this is the method the mail-send path calls on every
// send to authorize a From address — the API and daemon are separate
// processes, so a verification recorded by one must be visible to the other
// on the very next call.
//
// The refresh error is returned rather than swallowed, unlike the listing
// readers above: this one is an authorization decision. Ignoring it answered
// from whatever this process last managed to read, so an alias deleted from a
// file that has since become unreadable or corrupt kept authorizing sends from
// an address the account no longer owns. The caller must fail the send, not
// fall through to the "not a verified alias" branch — that would report a
// storage fault as a permissions answer.
func (s *Store) FindVerifiedByEmail(email string) (Alias, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Alias{}, false, fmt.Errorf("read send-as aliases: %w", err)
	}
	needle := strings.ToLower(email)
	for _, a := range s.aliases {
		if a.Status == "verified" && strings.ToLower(a.Email) == needle {
			return a, true, nil
		}
	}
	return Alias{}, false, nil
}

// Get returns an alias record by ID regardless of status.
func (s *Store) Get(id string) (Alias, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	for _, a := range s.aliases {
		if a.ID == id {
			return a, true
		}
	}
	return Alias{}, false
}

// PendingNotExpired returns records with Status == "pending" whose ExpiresAt
// is still in the future. Pending records whose ExpiresAt has already passed
// are excluded — the background poller task is responsible for expiring
// those via MarkFailed, not this method silently including them.
func (s *Store) PendingNotExpired() []Alias {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	now := time.Now()
	out := make([]Alias, 0, len(s.aliases))
	for _, a := range s.aliases {
		if a.Status != "pending" {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err != nil || expiresAt.Before(now) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// newVerificationCode returns a random "kp-XXXXXXXX" code (8 hex chars) via
// crypto/rand. This is a uniqueness/collision-resistance property, not a
// secrecy one — the code travels in plaintext in the probe email — but
// crypto/rand is used for consistency with the rest of this codebase's token
// generation.
func newVerificationCode() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "kp-" + hex.EncodeToString(b), nil
}

// Create records a new pending alias for userID claiming email (normalized
// to lowercase before storing) with the given displayName, generating a
// random VerificationCode and setting ExpiresAt to 5 minutes from now.
func (s *Store) Create(userID, email, displayName string) (Alias, error) {
	return s.create(userID, email, displayName, false)
}

// CreateAuto is Create for a record the server initiated on the user's behalf
// (see Alias.Auto). Identical in every respect except the Auto flag, which
// changes how SweepTerminal treats the record once it fails.
func (s *Store) CreateAuto(userID, email string) (Alias, error) {
	return s.create(userID, email, "", true)
}

func (s *Store) create(userID, email, displayName string, auto bool) (Alias, error) {
	var created Alias
	err := s.update(func() error {
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		code, err := newVerificationCode()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		created = Alias{
			ID:               id,
			UserID:           userID,
			Email:            strings.ToLower(email),
			DisplayName:      displayName,
			VerificationCode: code,
			Status:           "pending",
			CreatedAt:        now.Format(time.RFC3339),
			ExpiresAt:        now.Add(pendingExpiry).Format(time.RFC3339),
			Auto:             auto,
		}
		s.aliases = append(s.aliases, created)
		return s.persistLocked()
	})
	if err != nil {
		return Alias{}, err
	}
	return created, nil
}

// MarkVerified sets Status to "verified" and stamps VerifiedAt. Calling it
// again on an already-verified record is a no-op success, not an error (a
// verification poller running on a ticker could plausibly race a duplicate
// match in the same tick window in future extensions — idempotency here
// costs nothing). Returns an error if no record with that ID exists.
func (s *Store) MarkVerified(id string) error {
	return s.update(func() error {
		for i, a := range s.aliases {
			if a.ID != id {
				continue
			}
			if a.Status == "verified" {
				return nil
			}
			s.aliases[i].Status = "verified"
			s.aliases[i].VerifiedAt = time.Now().UTC().Format(time.RFC3339)
			return s.persistLocked()
		}
		return fmt.Errorf("sendas: no alias with id %q", id)
	})
}

// MarkFailed sets Status to "failed" and stamps FailedAt. Only meaningful on
// a "pending" record; if the record is already "verified" or "failed", this
// returns an error rather than silently succeeding, since transitioning an
// already-verified alias to failed would be a real bug, not a race. Returns
// an error if no record with that ID exists.
func (s *Store) MarkFailed(id string) error {
	return s.update(func() error {
		for i, a := range s.aliases {
			if a.ID != id {
				continue
			}
			if a.Status != "pending" {
				return fmt.Errorf("sendas: alias %q is %q, not pending", id, a.Status)
			}
			s.aliases[i].Status = "failed"
			s.aliases[i].FailedAt = time.Now().UTC().Format(time.RFC3339)
			return s.persistLocked()
		}
		return fmt.Errorf("sendas: no alias with id %q", id)
	})
}

// Delete removes the record entirely. Unlike contacts.Store.Delete, which
// tombstones for sync consumers, there is no sync-consumer concept for
// aliases, so a real delete is correct and simpler.
func (s *Store) Delete(id string) error {
	return s.update(func() error {
		for i, a := range s.aliases {
			if a.ID != id {
				continue
			}
			s.aliases = append(s.aliases[:i], s.aliases[i+1:]...)
			return s.persistLocked()
		}
		return fmt.Errorf("sendas: no alias with id %q", id)
	})
}

// SweepTerminal removes records with Status == "failed" whose FailedAt is
// older than retention. "verified" and "pending" records are left untouched
// regardless of age, as are failed Auto records: a user-initiated alias that
// failed is just clutter (the user knows they tried), but a failed Auto record
// is the only report that the server could not prove the account's own address
// and that the key is therefore not being published. Dropping it would make a
// permanently unpublishable key look like one that was never set up, and would
// also erase the FailedAt the prober backs off against.
func (s *Store) SweepTerminal(retention time.Duration) error {
	return s.update(func() error {
		cutoff := time.Now().Add(-retention)
		kept := make([]Alias, 0, len(s.aliases))
		changed := false
		for _, a := range s.aliases {
			if a.Status == "failed" && !a.Auto {
				failedAt, err := time.Parse(time.RFC3339, a.FailedAt)
				if err == nil && failedAt.Before(cutoff) {
					changed = true
					continue
				}
			}
			kept = append(kept, a)
		}
		if !changed {
			return nil
		}
		s.aliases = kept
		return s.persistLocked()
	})
}
