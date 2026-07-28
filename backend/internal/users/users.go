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
	"regexp"
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

	// PGP identity. The public key is not sensitive. The private key is
	// stored one of two ways, distinguished by PGPKeyProtection:
	//
	//   "client" — PGPPrivateKeyWrapped holds an envelope the BROWSER
	//     produced, sealed under a key derived from the user's password
	//     (see frontend/src/lib/keyVault.ts). The server cannot open it and
	//     has no code that tries. This is the end-to-end mode: possession of
	//     the disk, a backup, or this process's memory does not yield the
	//     private key or anything encrypted to it.
	//
	//   "server" — LEGACY. PGPPrivateKeyEnc holds a cryptutil envelope
	//     sealed with a master key sitting on the same volume, which means
	//     the server (and anyone who can read that volume) can decrypt every
	//     message. Retained only so existing installs keep working until the
	//     owner logs in and migrates; see MigratePGPKeyToClientProtection.
	//
	// Neither private field is ever exposed via Public().
	PGPFingerprint string `json:"pgpFingerprint,omitempty"`
	PGPKeyID       string `json:"pgpKeyId,omitempty"`
	PGPPublicKey   string `json:"pgpPublicKey,omitempty"`
	// PGPPrivateKeyEnc is the legacy server-sealed private key. Empty for
	// any identity created or migrated since client-side protection landed.
	PGPPrivateKeyEnc string `json:"pgpPrivateKeyEnc,omitempty"`
	// PGPPrivateKeyWrapped is the client-wrapped private key envelope,
	// opaque to the server: it is stored, returned to the owning user, and
	// never interpreted here.
	PGPPrivateKeyWrapped string `json:"pgpPrivateKeyWrapped,omitempty"`
	PGPKeyProtection     string `json:"pgpKeyProtection,omitempty"`
	PGPKeySource         string `json:"pgpKeySource,omitempty"`
	PGPKeyCreatedAt      string `json:"pgpKeyCreatedAt,omitempty"`
}

// PGP key protection modes. See User's PGP block.
const (
	PGPProtectionClient = "client"
	PGPProtectionServer = "server"
)

// PGPProtection returns the effective protection mode for u's identity.
// An identity with no explicit mode but a legacy sealed key is "server";
// this keeps pre-existing users.json files readable without a migration
// pass.
func (u User) PGPProtection() string {
	if u.PGPKeyProtection == PGPProtectionClient || u.PGPPrivateKeyWrapped != "" {
		return PGPProtectionClient
	}
	if u.PGPPrivateKeyEnc != "" {
		return PGPProtectionServer
	}
	return ""
}

// HasServerReadableKey reports whether the server can still decrypt this
// user's mail on their behalf. Every server-side PGP operation must check
// this and refuse rather than assume — under client protection there is no
// key here to use.
func (u User) HasServerReadableKey() bool {
	return u.PGPProtection() == PGPProtectionServer
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
	// PGPKeyProtection tells the client whether it must unwrap the private
	// key itself ("client") or whether this is a legacy server-held key
	// ("server") the UI should prompt the user to migrate.
	PGPKeyProtection string `json:"pgpKeyProtection,omitempty"`
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
		PGPKeyProtection:   u.PGPProtection(),
	}
}

var (
	ErrNotFound      = errors.New("user not found")
	ErrUsernameTaken = errors.New("username already in use")
	// ErrLastActiveAdmin is returned when a write would leave the instance
	// with no active administrator. Enforced inside the store's write lock
	// rather than by the caller — see guardNotLastActiveAdmin.
	ErrLastActiveAdmin = errors.New("cannot remove the last active admin")
	// ErrNotClientProtected is returned when an operation that only makes
	// sense for a browser-held key is attempted against a server-custody
	// account.
	ErrNotClientProtected = errors.New("account is not client-protected")
	// ErrWouldDowngradeCustody is returned when storing a server-readable
	// identity would silently discard a browser-wrapped private key. There is
	// deliberately no downgrade path (docs/E2E_PGP.md); this enforces it.
	ErrWouldDowngradeCustody = errors.New("account uses a client-held key: delete the existing identity first")
	// ErrPGPFingerprintChanged is returned when a caller that read one key
	// tries to write its result back after a different key has replaced it.
	// The caller's copy is stale, not wrong; retrying against the current key
	// is the correct response.
	ErrPGPFingerprintChanged = errors.New("the account's pgp key changed while this update was in flight")
	ErrPasswordWeak          = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	ErrUsernameInvalid       = errors.New("username must start with a letter or digit and may otherwise contain only letters, digits, dot, underscore and hyphen (max 64 characters)")
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

// usernamePattern is the set of usernames this store will create.
//
// A username is not just a label here: the CardDAV surface builds every
// principal and address-book URL out of it (dav_server.go's
// CurrentUserPrincipal/AddressBookHomeSetPath) and then guards access by
// comparing the first path segment back against it. Nothing enforced that it
// WAS one path segment, so an admin could create "alice/bob" — whose owner is
// then served a principal URL of "/dav/alice/bob/" and refused it with
// "address book belongs to a different user" — or ".." , whose principal path
// ("//") escapes the /dav mount entirely.
//
// No cross-user access was reachable either way (the backend resolves the store
// from the authenticated UserID, never from the path), so this is a validity
// rule, not a patched hole: it keeps the one place that treats a username as a
// path segment honest.
//
// The leading character must be alphanumeric, which is what rules out "." and
// ".." — both of which match the body character class (dot is legitimately
// wanted in "first.last") and both of which are path traversal, not names. It
// also rules out a leading hyphen, which is an argument-injection hazard
// anywhere a username reaches a command line.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateUsername enforces usernamePattern. Called by Create rather than by
// the handler, for the same reason ValidatePassword is: a future call site
// cannot forget it.
//
// Deliberately NOT applied to existing accounts on read. An install that
// already has a "first last" username keeps working; only new accounts are
// held to the rule, exactly as NormalizeUsername's case-collision rule is.
func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(strings.TrimSpace(username)) {
		return ErrUsernameInvalid
	}
	return nil
}

// NormalizeUsername folds a username to its comparison form. Usernames are
// stored as the user typed them (minus surrounding whitespace) but compared
// case-insensitively, so "admin", "Admin", and "ADMIN" can never coexist as
// separate accounts on a system where the admin role can reach every other
// user's configuration. Comparing rather than rewriting means accounts
// created before this rule existed keep working without a migration.
//
// Exported because this fold is not an internal detail of the store: anything
// that keys per-account state off a client-supplied username must key it off
// the SAME string GetByUsername would resolve, or the two disagree about which
// account is which. The login lockout learned that the hard way — it keyed on
// the raw submitted username, so " Admin " and "admin" were one account to the
// lookup and two independent strike budgets to the lockout, which made the
// three-strikes limit unbounded. See api.handleLogin.
func NormalizeUsername(username string) string {
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
		return NormalizeUsername(f.Users[i].Username) < NormalizeUsername(f.Users[j].Username)
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
// see NormalizeUsername.
func (s *Store) GetByUsername(username string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := s.readLocked()
	if err != nil {
		return User{}, err
	}
	want := NormalizeUsername(username)
	for _, u := range f.Users {
		if NormalizeUsername(u.Username) == want {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

// Create adds a new user with the given username/password/role.
func (s *Store) Create(username, password string, role Role) (User, error) {
	if err := ValidateUsername(username); err != nil {
		return User{}, err
	}
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
		want := NormalizeUsername(username)
		for _, u := range f.Users {
			if NormalizeUsername(u.Username) == want {
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
	return s.mutateGuarded(id, nil, fn)
}

// mutateGuarded is mutate with a whole-file precondition evaluated inside the
// same lock as the write. guard receives every user as freshly read from disk
// plus the target; returning an error aborts without writing.
//
// This exists because a precondition checked in the handler and enforced by a
// separate write is not a precondition at all. isLastActiveAdmin used to be
// evaluated before calling Deactivate/SetRole, so two concurrent requests each
// saw one other active admin and both proceeded — leaving an instance with
// zero admins, no delete-user endpoint, and LoadOrMigrate only minting an
// admin when users.json is absent. Recovery meant hand-editing the volume.
func (s *Store) mutateGuarded(id string, guard func(all []User, target User) error, fn func(*User) error) (User, error) {
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
			if guard != nil {
				if err := guard(f.Users, f.Users[i]); err != nil {
					return err
				}
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
	guard := guardNotLastActiveAdmin
	if role == RoleAdmin {
		// Promoting to admin can never remove the last one.
		guard = nil
	}
	return s.mutateGuarded(id, guard, func(u *User) error {
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
	return s.mutateGuarded(id, guardNotLastActiveAdmin, func(u *User) error {
		u.Active = false
		u.DeactivatedAt = time.Now().UTC().Format(time.RFC3339)
		return nil
	})
}

// guardNotLastActiveAdmin refuses a write that would leave the instance with
// no active admin. Evaluated inside mutateGuarded's lock against the file as
// just read, so concurrent callers cannot each observe the other's admin as
// still active and both proceed.
func guardNotLastActiveAdmin(all []User, target User) error {
	if target.Role != RoleAdmin || !target.Active {
		return nil
	}
	for _, u := range all {
		if u.ID != target.ID && u.Role == RoleAdmin && u.Active {
			return nil
		}
	}
	return ErrLastActiveAdmin
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

// SetPGPIdentity stores a legacy, SERVER-READABLE PGP identity: the armored
// public key plus a private key sealed with the server's own master key.
//
// New identities must not use this. It exists for the send-as User ID
// reconcile, which can only run against a key the server can already open,
// and which skips client-protected identities entirely.
func (s *Store) SetPGPIdentity(id, fingerprint, keyID, armoredPublicKey, privateKeyEnc, source, createdAt string) (User, error) {
	return s.mutate(id, func(u *User) error {
		// Refuse to overwrite a client-held identity with a server-readable
		// one. This used to clear PGPPrivateKeyWrapped unconditionally, so
		// generate/import silently downgraded custody and destroyed the
		// browser envelope — the opposite of what docs/E2E_PGP.md promises.
		if u.PGPProtection() == PGPProtectionClient {
			return ErrWouldDowngradeCustody
		}
		u.PGPFingerprint = fingerprint
		u.PGPKeyID = keyID
		u.PGPPublicKey = armoredPublicKey
		u.PGPPrivateKeyEnc = privateKeyEnc
		u.PGPPrivateKeyWrapped = ""
		u.PGPKeyProtection = PGPProtectionServer
		u.PGPKeySource = source
		u.PGPKeyCreatedAt = createdAt
		return nil
	})
}

// UpdatePGPKeyMaterial replaces only the public key and its sealed private half
// for an identity whose fingerprint is still expectFingerprint, leaving key ID,
// source, creation time and protection untouched.
//
// This is the narrow write the daemon's send-as reconcile needs: it adds User
// IDs to an existing key, which changes the key's bytes but not its identity.
// It used to reach for SetPGPIdentity, which rewrites everything — and because
// it snapshots the user, spends hundreds of microseconds re-signing, and only
// then writes, a key replaced during that window was silently reverted to the
// stale copy.
//
// Making the expectation a required argument is what closes that window: the
// caller states which key it read, and the write is refused under the lock if
// that is no longer the current one. An empty expectation is rejected rather
// than treated as "any", because a vacuous precondition is worst exactly when
// the account has no key and a stale write would install one.
func (s *Store) UpdatePGPKeyMaterial(id, expectFingerprint, armoredPublicKey, privateKeyEnc string) (User, error) {
	if strings.TrimSpace(expectFingerprint) == "" {
		return User{}, errors.New("expected fingerprint is required to update key material")
	}
	return s.mutate(id, func(u *User) error {
		// Same refusal as SetPGPIdentity, restated rather than inherited so the
		// two preconditions cannot drift apart: writing privateKeyEnc onto a
		// client-held identity would hand the server back a readable copy of a
		// key it is not supposed to have, and destroy the browser envelope.
		if u.PGPProtection() == PGPProtectionClient {
			return ErrWouldDowngradeCustody
		}
		if u.PGPFingerprint != expectFingerprint {
			return ErrPGPFingerprintChanged
		}
		u.PGPPublicKey = armoredPublicKey
		u.PGPPrivateKeyEnc = privateKeyEnc
		return nil
	})
}

// SetPGPIdentityClientProtected stores an end-to-end PGP identity. wrapped
// is an opaque envelope the browser produced under a key derived from the
// user's password; this store never interprets it, and clearing
// PGPPrivateKeyEnc is the point — after this call there is no copy of the
// private key on this server that this server can open.
func (s *Store) SetPGPIdentityClientProtected(id, fingerprint, keyID, armoredPublicKey, wrapped, source, createdAt string) (User, error) {
	if strings.TrimSpace(wrapped) == "" {
		return User{}, errors.New("wrapped private key is required for client-protected identities")
	}
	return s.mutate(id, func(u *User) error {
		u.PGPFingerprint = fingerprint
		u.PGPKeyID = keyID
		u.PGPPublicKey = armoredPublicKey
		u.PGPPrivateKeyWrapped = wrapped
		u.PGPPrivateKeyEnc = ""
		u.PGPKeyProtection = PGPProtectionClient
		u.PGPKeySource = source
		u.PGPKeyCreatedAt = createdAt
		return nil
	})
}

// RewrapPGPPrivateKey replaces only the wrapped private key envelope,
// leaving the identity (fingerprint, public key, provenance) untouched.
// Used when the user changes their password: the wrapping key is derived
// from that password, so the browser unwraps with the old one and rewraps
// with the new one, and this stores the result.
func (s *Store) RewrapPGPPrivateKey(id, wrapped string) (User, error) {
	if strings.TrimSpace(wrapped) == "" {
		return User{}, errors.New("wrapped private key is required")
	}
	return s.mutate(id, func(u *User) error {
		if u.PGPFingerprint == "" {
			return errors.New("no pgp identity to rewrap")
		}
		// Rewrap exists for a password change on an account that is ALREADY
		// client-protected: unwrap with the old password, rewrap with the new,
		// store the result. Reaching it with a server-custody account instead
		// cleared PGPPrivateKeyEnc — the only copy of the private key anyone
		// could open — while leaving the identity advertised, so every message
		// ever encrypted to it became permanently unreadable and senders kept
		// encrypting to a key nobody held.
		if u.PGPProtection() != PGPProtectionClient {
			return ErrNotClientProtected
		}
		u.PGPPrivateKeyWrapped = wrapped
		u.PGPKeyProtection = PGPProtectionClient
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
		u.PGPPrivateKeyWrapped = ""
		u.PGPKeyProtection = ""
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
