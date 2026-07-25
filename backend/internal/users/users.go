// Package users provides the multi-user identity/role store, replacing the
// legacy single-admin admin.env file.
package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"

	"golang.org/x/crypto/scrypt"
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User is a single account record. Files/directories owned by a user are
// always keyed by ID, never Username, so a rename never requires moving data.
type User struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	PasswordHash       string `json:"passwordHash"`
	Role               Role   `json:"role"`
	Active             bool   `json:"active"`
	MustChangePassword bool   `json:"mustChangePassword"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	DeactivatedAt      string `json:"deactivatedAt,omitempty"`

	// Two-factor auth (Milestone 1: TOTP). TOTPSecretEnc is a cryptutil
	// envelope JSON string sealed with the dedicated TOTP key; it is set at
	// enrollment ("pending") and only becomes active once TOTPEnabled flips
	// true on confirmation. These fields are never exposed via Public().
	TOTPEnabled       bool     `json:"totpEnabled,omitempty"`
	TOTPSecretEnc     string   `json:"totpSecretEnc,omitempty"`
	TOTPConfirmedAt   string   `json:"totpConfirmedAt,omitempty"`
	RecoveryCodesHash []string `json:"recoveryCodesHash,omitempty"`
	// LastUsedTOTPStep is the RFC 6238 time-step (Unix seconds / 30) of the
	// most recently accepted TOTP code for this account, tracked across every
	// login challenge (not just the ephemeral, per-challenge replay guard in
	// mfa.Store.ConsumeTOTPStep). TOTP steps strictly increase over time, so
	// rejecting any code whose step is <= this value blocks replay of a
	// captured valid code against a freshly minted challenge, without
	// affecting legitimate retry-after-typo attempts at the current step (a
	// rejected code never advances this field — see handleMFATOTP). The zero
	// value (no code ever accepted yet) never rejects anything, since real
	// TOTP steps are large positive integers (currently around 1.7e9).
	LastUsedTOTPStep int64 `json:"lastUsedTotpStep,omitempty"`
	// PushMFAEnabled is reserved for a later push-2FA milestone; nothing in
	// Milestone 1 sets or reads it.
	PushMFAEnabled bool `json:"pushMfaEnabled,omitempty"`

	// PGP identity (backend-only encryption/signing — see internal/pgpmail).
	// PGPPrivateKeyEnc is a cryptutil envelope JSON string sealed with the
	// dedicated PGP private key master key; it is never exposed via Public().
	PGPFingerprint   string `json:"pgpFingerprint,omitempty"`
	PGPKeyID         string `json:"pgpKeyId,omitempty"`
	PGPPublicKey     string `json:"pgpPublicKey,omitempty"`
	PGPPrivateKeyEnc string `json:"pgpPrivateKeyEnc,omitempty"`
	PGPKeySource     string `json:"pgpKeySource,omitempty"`
	PGPKeyCreatedAt  string `json:"pgpKeyCreatedAt,omitempty"`
}

// Public is the JSON-safe view returned to API clients (no password hash).
type Public struct {
	ID                 string `json:"id"`
	Username           string `json:"username"`
	Role               Role   `json:"role"`
	Active             bool   `json:"active"`
	MustChangePassword bool   `json:"mustChangePassword"`
	CreatedAt          string `json:"createdAt"`
	UpdatedAt          string `json:"updatedAt"`
	DeactivatedAt      string `json:"deactivatedAt,omitempty"`
	TOTPEnabled        bool   `json:"totpEnabled,omitempty"`
	PGPFingerprint     string `json:"pgpFingerprint,omitempty"`
	PGPKeyID           string `json:"pgpKeyId,omitempty"`
	PGPKeySource       string `json:"pgpKeySource,omitempty"`
	PGPKeyCreatedAt    string `json:"pgpKeyCreatedAt,omitempty"`
}

func (u User) Public() Public {
	return Public{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		Active:             u.Active,
		MustChangePassword: u.MustChangePassword,
		CreatedAt:          u.CreatedAt,
		UpdatedAt:          u.UpdatedAt,
		DeactivatedAt:      u.DeactivatedAt,
		TOTPEnabled:        u.TOTPEnabled,
		PGPFingerprint:     u.PGPFingerprint,
		PGPKeyID:           u.PGPKeyID,
		PGPKeySource:       u.PGPKeySource,
		PGPKeyCreatedAt:    u.PGPKeyCreatedAt,
	}
}

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already in use")
	ErrPasswordWeak  = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
)

// MinPasswordLen is the minimum length of any password this store will
// accept. Length is the only rule enforced: character-class requirements
// push users toward predictable substitutions without adding real entropy,
// while a length floor is what actually defeats the online guessing this
// server's lockout only slows down.
const MinPasswordLen = 14

// ValidatePassword enforces MinPasswordLen. It is called by every store
// method that sets a password (Create, SetPassword) rather than by each API
// handler, so a new call site cannot forget it. Length is counted in runes,
// not bytes, so a passphrase in a non-Latin script is not penalized.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLen {
		return ErrPasswordWeak
	}
	return nil
}

// normalizeUsername folds a username to its comparison form. Usernames are
// stored as the user typed them (minus surrounding whitespace) but compared
// case-insensitively, so "admin", "Admin", and "ADMIN" can never coexist as
// separate accounts on a system where the admin role can reach every other
// user's configuration. Comparing rather than rewriting means accounts
// created before this rule existed keep working without a migration.
func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

type usersFile struct {
	Version int    `json:"version"`
	Users   []User `json:"users"`
}

// Store is the on-disk users.json store.
//
// Every mutation is a read-modify-write of the whole file, and this file is
// written by BOTH processes supervisord starts: the api process (password
// changes, TOTP enrollment, recovery-code consumption) and the daemon
// process (processor/sendas_check.go's SetPGPIdentity, when a verified
// send-as alias is added to a user's key). mu only serializes goroutines
// within one process, so every mutator additionally takes an inter-process
// file lock for the whole read-modify-write cycle — see
// fsutil.WithFileLock. Without it, two overlapping mutations each read the
// same starting state and the second write silently discards the first: a
// lost password change, or a recovery code that stays usable after being
// consumed.
type Store struct {
	mu   sync.RWMutex
	path string
}

func newStore(path string) *Store {
	return &Store{path: path}
}

// LoadOrMigrate opens CONFIG_DIR/users.json, creating it on first run by
// best-effort importing the legacy single-admin admin.env, or minting a
// fresh default admin if neither exists. This is intentionally simple:
// there is no production data to preserve, so a clean reset is an
// acceptable fallback if the legacy file is missing or unparseable.
func LoadOrMigrate(configDir, legacyAdminEnvPath string) (*Store, error) {
	path := filepath.Join(configDir, "users.json")
	store := newStore(path)

	if _, err := os.Stat(path); err == nil {
		if _, err := store.readLocked(); err != nil {
			return nil, err
		}
		return store, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if admin, ok := readLegacyAdminEnv(legacyAdminEnvPath); ok {
		now := time.Now().UTC().Format(time.RFC3339)
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return nil, err
		}
		u := User{
			ID:                 id,
			Username:           admin["ADMIN_USER"],
			PasswordHash:       admin["ADMIN_PASS_HASH"],
			Role:               RoleAdmin,
			Active:             true,
			MustChangePassword: strings.EqualFold(admin["MUST_CHANGE_PASSWORD"], "true"),
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		if u.PasswordHash == "" && admin["ADMIN_PASS"] != "" {
			hash, err := HashPassword(admin["ADMIN_PASS"])
			if err != nil {
				return nil, err
			}
			u.PasswordHash = hash
		}
		if u.Username == "" {
			u.Username = "admin"
		}
		if _, err := store.createInitial(usersFile{Version: 1, Users: []User{u}}); err != nil {
			return nil, err
		}
		return store, nil
	}

	// Fresh install with no legacy admin.env: mint a default admin. In the
	// normal container flow scripts/bootstrap.sh runs first and admin.env
	// will already exist, so this path is mainly a defensive fallback for
	// running the server standalone (e.g. local dev).
	randomPassword, err := randomPassword()
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(randomPassword)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	id, err := fsutil.NewUUIDv4()
	if err != nil {
		return nil, err
	}
	u := User{
		ID:                 id,
		Username:           "admin",
		PasswordHash:       hash,
		Role:               RoleAdmin,
		Active:             true,
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	won, err := store.createInitial(usersFile{Version: 1, Users: []User{u}})
	if err != nil {
		return nil, err
	}
	if won {
		fmt.Fprintf(os.Stderr, "Generated first-run admin credentials\nUsername: %s\nPassword: %s\nPassword change is required on first login\n", u.Username, randomPassword)
	}
	return store, nil
}

// createInitial writes the very first users.json atomically and exclusively.
// The api and daemon processes start at the same time on first boot; if the
// other process creates the file first, the loser silently adopts the
// winner's copy so both agree on the admin's user ID.
func (s *Store) createInitial(f usersFile) (won bool, err error) {
	if f.Version == 0 {
		f.Version = 1
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".users.json.tmp.*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Link(tmpName, s.path); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func readLegacyAdminEnv(path string) (map[string]string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(parts) != 2 {
			continue
		}
		out[parts[0]] = parts[1]
	}
	if out["ADMIN_USER"] == "" {
		return nil, false
	}
	return out, true
}

func (s *Store) readLocked() (usersFile, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return usersFile{}, err
	}
	var f usersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return usersFile{}, err
	}
	return f, nil
}

func (s *Store) writeLocked(f usersFile) error {
	if f.Version == 0 {
		f.Version = 1
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(s.path, b, 0o600)
}

// FirstAdmin returns the earliest-created active admin. Used by the legacy
// single-user migration to decide which user inherits the global data, and
// by the pre-login setup hint.
func (s *Store) FirstAdmin() (User, error) {
	all, err := s.List()
	if err != nil {
		return User{}, err
	}
	admin := FirstAdminFrom(all)
	if admin.ID == "" {
		return User{}, ErrNotFound
	}
	return admin, nil
}

// FirstAdminFrom returns the earliest-created active admin in all, or a
// zero-value User if there is none.
func FirstAdminFrom(all []User) User {
	var best User
	for _, u := range all {
		if u.Role != RoleAdmin || !u.Active {
			continue
		}
		if best.ID == "" || u.CreatedAt < best.CreatedAt {
			best = u
		}
	}
	return best
}

// List returns every user (including deactivated ones), sorted by username.
func (s *Store) List() ([]User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	sort.Slice(f.Users, func(i, j int) bool {
		return normalizeUsername(f.Users[i].Username) < normalizeUsername(f.Users[j].Username)
	})
	return f.Users, nil
}

// Get returns a user by ID.
func (s *Store) Get(id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := s.readLocked()
	if err != nil {
		return User{}, err
	}
	for _, u := range f.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// GetByUsername returns a user by username, compared case-insensitively —
// see normalizeUsername.
func (s *Store) GetByUsername(username string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := s.readLocked()
	if err != nil {
		return User{}, err
	}
	want := normalizeUsername(username)
	for _, u := range f.Users {
		if normalizeUsername(u.Username) == want {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// Create adds a new user with the given username/password/role.
func (s *Store) Create(username, password string, role Role) (User, error) {
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var created User
	err := fsutil.WithFileLock(s.path, func() error {
		f, err := s.readLocked()
		if err != nil {
			return err
		}
		username = strings.TrimSpace(username)
		want := normalizeUsername(username)
		for _, u := range f.Users {
			if normalizeUsername(u.Username) == want {
				return ErrUsernameTaken
			}
		}
		hash, err := HashPassword(password)
		if err != nil {
			return err
		}
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339)
		created = User{
			ID:                 id,
			Username:           username,
			PasswordHash:       hash,
			Role:               role,
			Active:             true,
			MustChangePassword: true,
			CreatedAt:          now,
			UpdatedAt:          now,
		}
		f.Users = append(f.Users, created)
		return s.writeLocked(f)
	})
	if err != nil {
		return User{}, err
	}
	return created, nil
}

// mutate re-reads the store, applies fn to the matching user, and persists
// the result. fn returns an error to abort without writing.
func (s *Store) mutate(id string, fn func(*User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var updated User
	err := fsutil.WithFileLock(s.path, func() error {
		f, err := s.readLocked()
		if err != nil {
			return err
		}
		for i := range f.Users {
			if f.Users[i].ID != id {
				continue
			}
			if err := fn(&f.Users[i]); err != nil {
				return err
			}
			f.Users[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if err := s.writeLocked(f); err != nil {
				return err
			}
			updated = f.Users[i]
			return nil
		}
		return ErrNotFound
	})
	if err != nil {
		return User{}, err
	}
	return updated, nil
}

// SetRole updates a user's role.
func (s *Store) SetRole(id string, role Role) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.Role = role
		return nil
	})
}

// SetPassword sets a new password. If requireChange is true the user must
// change it again on next login (used for admin-initiated resets).
func (s *Store) SetPassword(id, newPassword string, requireChange bool) (User, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return User{}, err
	}
	return s.mutate(id, func(u *User) error {
		u.PasswordHash = hash
		u.MustChangePassword = requireChange
		return nil
	})
}

// ClearMustChangePassword clears the first-login password-change requirement
// without touching the password hash. Used by the password-change flow's
// callers and available for administrative bookkeeping.
func (s *Store) ClearMustChangePassword(id string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.MustChangePassword = false
		return nil
	})
}

// Deactivate soft-deletes a user: their sessions stop being accepted and
// they can no longer log in, but their data is retained.
func (s *Store) Deactivate(id string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.Active = false
		u.DeactivatedAt = time.Now().UTC().Format(time.RFC3339)
		return nil
	})
}

// Reactivate restores a previously deactivated user.
func (s *Store) Reactivate(id string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.Active = true
		u.DeactivatedAt = ""
		return nil
	})
}

// SetPendingTOTPSecret stores a sealed TOTP secret during enrollment without
// enabling TOTP. It clears any previously confirmed state so a re-enrollment
// always starts clean.
func (s *Store) SetPendingTOTPSecret(id, secretEnc string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.TOTPSecretEnc = secretEnc
		u.TOTPEnabled = false
		u.TOTPConfirmedAt = ""
		u.RecoveryCodesHash = nil
		return nil
	})
}

// EnableTOTP marks TOTP confirmed and stores the scrypt-hashed recovery codes.
// It errors if no pending secret has been staged.
func (s *Store) EnableTOTP(id, confirmedAt string, recoveryHashes []string) (User, error) {
	return s.mutate(id, func(u *User) error {
		if u.TOTPSecretEnc == "" {
			return errors.New("no pending totp secret to confirm")
		}
		u.TOTPEnabled = true
		u.TOTPConfirmedAt = confirmedAt
		u.RecoveryCodesHash = recoveryHashes
		return nil
	})
}

// DisableTOTP clears all TOTP and recovery-code state.
func (s *Store) DisableTOTP(id string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.TOTPEnabled = false
		u.TOTPSecretEnc = ""
		u.TOTPConfirmedAt = ""
		u.RecoveryCodesHash = nil
		u.PushMFAEnabled = false
		return nil
	})
}

// SetPushMFAEnabled flips the push-2FA flag. Preconditions (TOTP enabled, a
// paired approver device present) are enforced by the API handler; this store
// method only persists the bit.
func (s *Store) SetPushMFAEnabled(id string, enabled bool) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.PushMFAEnabled = enabled
		return nil
	})
}

// ErrTOTPStepNotNewer is returned by SetLastUsedTOTPStep when step is not
// strictly greater than the account's currently recorded LastUsedTOTPStep —
// i.e. the caller is attempting to record a replayed or out-of-order code.
var ErrTOTPStepNotNewer = errors.New("totp step is not newer than last recorded step")

// SetLastUsedTOTPStep atomically checks-and-records the RFC 6238 time-step of
// an accepted TOTP code for replay protection scoped to the account (rather
// than a single ephemeral challenge — see mfa.Store.ConsumeTOTPStep for that
// narrower guard). It only writes, and only reports success, when step is
// strictly greater than the currently stored value; otherwise it returns
// ErrTOTPStepNotNewer without writing (mirroring ConsumeRecoveryCode's
// no-match-means-no-write behavior). Doing the check and the write inside the
// same mutate lock (rather than a separate Get + later write) closes a TOCTOU
// window where two concurrent requests bearing the same captured valid code —
// each against its own freshly minted challenge — could otherwise both pass a
// stale "not yet recorded" check before either request recorded it.
func (s *Store) SetLastUsedTOTPStep(id string, step int64) (User, error) {
	return s.mutate(id, func(u *User) error {
		if step <= u.LastUsedTOTPStep {
			return ErrTOTPStepNotNewer
		}
		u.LastUsedTOTPStep = step
		return nil
	})
}

// SetPGPIdentity stores a user's own PGP identity: the armored public key
// (not sensitive) and the sealed private key envelope (from
// pgpmail.Identity.SealPrivateKey), replacing any existing identity.
func (s *Store) SetPGPIdentity(id, fingerprint, keyID, armoredPublicKey, privateKeyEnc, source, createdAt string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.PGPFingerprint = fingerprint
		u.PGPKeyID = keyID
		u.PGPPublicKey = armoredPublicKey
		u.PGPPrivateKeyEnc = privateKeyEnc
		u.PGPKeySource = source
		u.PGPKeyCreatedAt = createdAt
		return nil
	})
}

// ClearPGPIdentity removes a user's PGP identity entirely.
func (s *Store) ClearPGPIdentity(id string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.PGPFingerprint = ""
		u.PGPKeyID = ""
		u.PGPPublicKey = ""
		u.PGPPrivateKeyEnc = ""
		u.PGPKeySource = ""
		u.PGPKeyCreatedAt = ""
		return nil
	})
}

// ReplaceRecoveryCodes overwrites the stored recovery-code hashes (used when a
// user regenerates their codes).
func (s *Store) ReplaceRecoveryCodes(id string, recoveryHashes []string) (User, error) {
	return s.mutate(id, func(u *User) error {
		u.RecoveryCodesHash = recoveryHashes
		return nil
	})
}

// errRecoveryCodeNoMatch aborts the mutate without a write when a recovery
// code fails to match, so a wrong attempt never bumps UpdatedAt.
var errRecoveryCodeNoMatch = errors.New("recovery code no match")

// ConsumeRecoveryCode verifies candidate against the user's stored recovery
// hashes; on the first match it removes that hash (one-time use) and persists.
// It returns matched=false with a nil error and no write when nothing matches.
func (s *Store) ConsumeRecoveryCode(id, candidate string) (User, bool, error) {
	u, err := s.mutate(id, func(u *User) error {
		for i, h := range u.RecoveryCodesHash {
			if verifyScryptHash(h, candidate) {
				u.RecoveryCodesHash = append(u.RecoveryCodesHash[:i], u.RecoveryCodesHash[i+1:]...)
				return nil
			}
		}
		return errRecoveryCodeNoMatch
	})
	if errors.Is(err, errRecoveryCodeNoMatch) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// VerifyPassword checks a candidate password against a user's stored hash.
func VerifyPassword(u User, candidate string) bool {
	return verifyScryptHash(u.PasswordHash, candidate)
}

// VerifySecretHash checks a candidate secret against a scrypt-encoded hash
// produced by HashPassword. It is a generic counterpart to VerifyPassword for
// callers hashing something other than a User's login password (e.g. an
// app-specific CardDAV password).
func VerifySecretHash(encoded, candidate string) bool {
	return verifyScryptHash(encoded, candidate)
}

// HashPassword produces a scrypt-encoded hash string in the same format
// used historically by admin.env's ADMIN_PASS_HASH field.
func HashPassword(password string) (string, error) {
	const (
		n      = 16384
		r      = 8
		p      = 1
		keyLen = 32
	)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := scrypt.Key([]byte(password), salt, n, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"scrypt$%d$%d$%d$%s$%s",
		n, r, p,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash),
	), nil
}

func verifyScryptHash(encoded, candidate string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	r, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(parts[3])
	if err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	if len(expected) == 0 {
		return false
	}
	derived, err := scrypt.Key([]byte(candidate), salt, n, r, p, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, expected) == 1
}
