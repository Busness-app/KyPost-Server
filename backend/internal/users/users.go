// Package users provides the multi-user identity/role store, replacing the
// legacy single-admin admin.env file.
package users

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

	// Login credential derivation.
	//
	// AuthDerivationPBKDF2 means PasswordHash is a hash of the AUTH SECRET the
	// browser derived, not of the password itself — the server never receives
	// the password for this account. LoginSalt is the salt the client must use
	// to reproduce that secret, and LoginIterations the work factor.
	//
	// This exists because the client-side PGP key vault derives its wrapping key
	// from the same password (frontend/src/lib/keyVault.ts), and that made the
	// "the server cannot open your key" claim false: the server was handed the
	// plaintext password on every single login and merely chose not to keep it.
	// Four lines in the login handler would have opened every client-protected
	// key on the instance. The browser now splits one password into two
	// domain-separated secrets and sends only the authentication half.
	//
	// AuthDerivationLegacy (the empty string) means PasswordHash is over the
	// plaintext password, as every account created before this existed. Those
	// upgrade in place on their next successful sign-in — see
	// UpgradeToDerivedAuth. Admin-set temporary passwords are deliberately
	// written legacy, because the admin's browser cannot derive a secret for
	// somebody else's account; the mandatory first-login password change
	// converts them.
	AuthDerivation  string `json:"authDerivation,omitempty"`
	LoginSalt       string `json:"loginSalt,omitempty"`
	LoginIterations int    `json:"loginIterations,omitempty"`

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

// clone returns a deep copy of u.
//
// Every read path that serves a User out of the Store's cache goes through
// this. A User is otherwise copied by value for free, but RecoveryCodesHash is
// a slice: handing it out shares the cache's backing array, so a caller that
// sorted or overwrote it would silently corrupt state every subsequent request
// reads. One small allocation per lookup is the cheaper half of that trade.
func (u User) clone() User {
	if u.RecoveryCodesHash != nil {
		u.RecoveryCodesHash = slices.Clone(u.RecoveryCodesHash)
	}
	return u
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
// Reads are served from a stat-guarded cache — see load.
type Store struct {
	mu   sync.RWMutex
	path string

	// cached is the last parsed file, valid only while the file's mtime and
	// size still match cachedMod/cachedSize. Guarded by mu.
	//
	// Without this, Get reparsed the whole of users.json on every authenticated
	// request: api.currentUser calls it per request (deliberately, so a
	// deactivation takes effect immediately), and a User carries PGPPublicKey,
	// PGPPrivateKeyWrapped and RecoveryCodesHash — so answering "is this
	// account still active?" meant reading and JSON-decoding every account's
	// armored key material, every time.
	//
	// mtime+size rather than a notify/invalidation protocol because the file is
	// written by two processes (api and daemon) and every writer goes through
	// fsutil.AtomicWriteFile, which renames a new inode into place. A rename
	// always moves mtime, so the other process's write is always observed. An
	// in-process invalidation hook could not see the daemon's writes at all.
	cached     usersFile
	cachedMod  time.Time
	cachedSize int64
	cacheValid bool
}

func newStore(path string) *Store {
	return &Store{path: path}
}

// load returns the current file contents, from cache when the file on disk is
// unchanged since it was last parsed.
//
// Callers must NOT hold mu: this takes it, for reading and then possibly for
// writing. Mutators hold the inter-process file lock and call readFileUnlocked
// directly instead — a cached copy is exactly what a read-modify-write cycle
// must not start from.
func (s *Store) load() (usersFile, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return usersFile{}, err
	}

	s.mu.RLock()
	if s.cacheValid && s.cachedSize == info.Size() && s.cachedMod.Equal(info.ModTime()) {
		f := s.cached
		s.mu.RUnlock()
		return f, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock: another goroutine may have refreshed while
	// this one waited.
	if s.cacheValid && s.cachedSize == info.Size() && s.cachedMod.Equal(info.ModTime()) {
		return s.cached, nil
	}
	f, err := s.readFileUnlocked()
	if err != nil {
		return usersFile{}, err
	}
	// Stat again AFTER the read. A write that landed between the first stat and
	// the read would otherwise be cached under the pre-write stamp and served
	// as current until the next change — stale for an unbounded time. Caching
	// only when the file did not move underneath us costs one stat and makes
	// that impossible.
	if after, err := os.Stat(s.path); err == nil &&
		after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
		s.cached = f
		s.cachedMod = info.ModTime()
		s.cachedSize = info.Size()
		s.cacheValid = true
	}
	return f, nil
}

// invalidateCacheLocked drops the cached copy. Callers must hold mu.
//
// Called after a mutation so the next read re-parses rather than waiting for a
// stat to disagree. Mostly belt-and-braces: AtomicWriteFile changes the mtime
// anyway. It matters on a filesystem with coarse mtime granularity, where a
// write landing in the same tick as the cached stamp would otherwise be
// invisible.
func (s *Store) invalidateCacheLocked() {
	s.cacheValid = false
	s.cached = usersFile{}
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
		if _, err := store.readFileUnlocked(); err != nil {
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

// readFileUnlocked reads and parses the file from disk, bypassing the read
// cache entirely.
//
// The name says "Unlocked" because it takes no lock of its own — it was called
// readLocked, which read as "this holds the lock" and meant the opposite.
//
// Every mutator uses this rather than load(): a read-modify-write cycle must
// start from what is actually on disk, inside the inter-process file lock, or
// it can serialize a cached copy back over another process's committed write.
func (s *Store) readFileUnlocked() (usersFile, error) {
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

// writeFileUnlocked persists f. Callers hold both mu and the file lock, and
// must invalidate the read cache — which this does, since every caller has to.
func (s *Store) writeFileUnlocked(f usersFile) error {
	if f.Version == 0 {
		f.Version = 1
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.path, b, 0o600); err != nil {
		return err
	}
	s.invalidateCacheLocked()
	return nil
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
//
// The returned slice is a deep copy. It used to sort f.Users in place and hand
// the slice straight back, which was harmless while every call re-read the file
// but corrupts a shared cache: the sort reorders the cached backing array while
// another goroutine is ranging over it.
func (s *Store) List() ([]User, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(f.Users))
	for _, u := range f.Users {
		out = append(out, u.clone())
	}
	sort.Slice(out, func(i, j int) bool {
		return NormalizeUsername(out[i].Username) < NormalizeUsername(out[j].Username)
	})
	return out, nil
}

// Get returns a user by ID.
//
// Served from the stat-guarded cache (see load): api.currentUser calls this on
// every authenticated request, and re-parsing every account's armored key
// material to answer "is this account still active?" was the single hottest
// avoidable cost in the request path.
func (s *Store) Get(id string) (User, error) {
	f, err := s.load()
	if err != nil {
		return User{}, err
	}
	for _, u := range f.Users {
		if u.ID == id {
			return u.clone(), nil
		}
	}
	return User{}, ErrNotFound
}

// GetByUsername returns a user by username, compared case-insensitively —
// see NormalizeUsername.
func (s *Store) GetByUsername(username string) (User, error) {
	f, err := s.load()
	if err != nil {
		return User{}, err
	}
	want := NormalizeUsername(username)
	for _, u := range f.Users {
		if NormalizeUsername(u.Username) == want {
			return u.clone(), nil
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
		f, err := s.readFileUnlocked()
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
		return s.writeFileUnlocked(f)
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
// A precondition checked in the handler and enforced by a separate write is
// not a precondition. Evaluating isLastActiveAdmin outside this lock lets two
// concurrent requests each see one other active admin and both proceed,
// leaving an instance with zero admins — unrecoverable short of hand-editing
// the volume, since there is no delete-user endpoint and LoadOrMigrate only
// mints an admin when users.json is absent.
func (s *Store) mutateGuarded(id string, guard func(all []User, target User) error, fn func(*User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var updated User
	err := fsutil.WithFileLock(s.path, func() error {
		f, err := s.readFileUnlocked()
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
			if err := s.writeFileUnlocked(f); err != nil {
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
		// Back to legacy derivation. This path stores a hash of a PLAINTEXT
		// password — it is how an admin sets a temporary one, and an admin's
		// browser cannot derive an auth secret for somebody else's account
		// (it would need to know the password it is about to hand over, which
		// is the thing derived auth exists to avoid transmitting).
		//
		// Clearing these three is load-bearing, not tidiness: leaving
		// AuthDerivation set while PasswordHash covers a plaintext password
		// would make VerifyAuthSecret the active check against a hash it can
		// never match, and lock the user out of the temporary password they were
		// just given. The mandatory first-login change converts the account back
		// to derived auth.
		u.AuthDerivation = AuthDerivationLegacy
		u.LoginSalt = ""
		u.LoginIterations = 0
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
		// one: clearing PGPPrivateKeyWrapped here would silently downgrade
		// custody and destroy the browser envelope, the opposite of what
		// docs/E2E_PGP.md promises.
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
// Do not substitute SetPGPIdentity: it rewrites everything, and since the
// caller snapshots the user, spends hundreds of microseconds re-signing, and
// only then writes, a key replaced during that window is silently reverted.
//
// expectFingerprint closes that window — the caller states which key it read,
// and the write is refused under the lock if that is no longer current. An
// empty expectation is rejected rather than treated as "any": a vacuous
// precondition is worst exactly when the account has no key and a stale write
// would install one.
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
// The scrypt comparisons run OUTSIDE the store lock, against a snapshot. Doing
// them inside mutate held both s.mu and the users.json file lock across up to
// ten 128 MiB derivations (~3s), and every authenticated request in the process
// takes s.mu.RLock via currentUser -> Get, so one wrong code stalled the whole
// API. Matching on the hash string rather than an index keeps the removal
// correct even if the list changed while we were deriving.
func (s *Store) ConsumeRecoveryCode(id, candidate string) (User, bool, error) {
	snapshot, err := s.Get(id)
	if err != nil {
		return User{}, false, err
	}
	matched := ""
	for _, h := range snapshot.RecoveryCodesHash {
		if verifyScryptHash(h, candidate) {
			matched = h
			break
		}
	}
	if matched == "" {
		return User{}, false, nil
	}

	u, err := s.mutate(id, func(u *User) error {
		for i, h := range u.RecoveryCodesHash {
			if h == matched {
				u.RecoveryCodesHash = append(u.RecoveryCodesHash[:i], u.RecoveryCodesHash[i+1:]...)
				return nil
			}
		}
		// Consumed concurrently between the snapshot and here.
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
// VerifyPassword checks a plaintext password against u's stored hash.
//
// Refuses outright for a derived-auth account. That is not a formality: after
// conversion PasswordHash covers the client-derived AUTH SECRET, so a bare
// comparison would happily accept that secret here as though it were the
// password. Nothing today passes one where the other is expected — but the two
// are different credentials for the same account, and the only way to keep them
// from being interchangeable by accident is to make each verifier refuse the
// other's accounts. See VerifyAuthSecret for the mirror image.
func VerifyPassword(u User, candidate string) bool {
	if u.UsesDerivedAuth() {
		return false
	}
	return verifyScryptHash(u.PasswordHash, candidate)
}

// VerifySecretHash checks a candidate secret against a scrypt-encoded hash
// produced by HashPassword. It is a generic counterpart to VerifyPassword for
// callers hashing something other than a User's login password (e.g. an
// app-specific CardDAV password).
func VerifySecretHash(encoded, candidate string) bool {
	return verifyScryptHash(encoded, candidate)
}

// deviceSecretPrefix tags the SHA-256 device-secret format so
// VerifyDeviceSecret can tell it apart from the scrypt hashes minted before
// this format existed.
const deviceSecretPrefix = "sha256:"

// HashDeviceSecret hashes a native device's pairing secret.
//
// Plain SHA-256 where the rest of this file uses scrypt. A password KDF exists
// to price guesses at a low-entropy human-chosen secret; a device secret is 24
// bytes from crypto/rand (api.randomToken), unguessable by construction. So
// scrypt bought nothing here and cost ~16 MB and ~50 ms on every request a
// paired device makes — App Pull polls, mail sync, contacts sync, push-MFA.
//
// Do NOT use this for anything a human types or chooses. Not full-entropy
// random means HashPassword.
func HashDeviceSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return deviceSecretPrefix + hex.EncodeToString(sum[:])
}

// VerifyDeviceSecret checks a candidate device secret against a stored hash in
// constant time.
//
// Untagged values fall through to scrypt: devices paired before
// HashDeviceSecret existed hold one, and rejecting them would silently unpair
// every phone on every existing install. New registrations write the tagged
// form, so that branch drains as devices re-pair.
func VerifyDeviceSecret(stored, candidate string) bool {
	encoded, ok := strings.CutPrefix(stored, deviceSecretPrefix)
	if !ok {
		return verifyScryptHash(stored, candidate)
	}
	want, err := hex.DecodeString(encoded)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// Current scrypt cost parameters for newly written password hashes.
//
// N was 16384 (16 MiB), which is scrypt's original 2009 "interactive" figure and
// the floor of current guidance rather than a target. 2^17 is 128 MiB and
// roughly 200 ms of a core — the standard recommendation for an interactive
// login, and about 8x the work per guess for anyone who steals users.json.
//
// The cost is paid on every login attempt, including attempts against usernames
// that do not exist (equalizeLoginTiming, so timing cannot enumerate accounts).
// That is only safe because the login endpoint is now throttled instance-wide
// AND per-IP AND per-account, and proof-of-work is on by default — see
// api.handleLogin. Do NOT raise this further without checking those bounds
// again: this constant and loginRateRefillPerSec multiply together into the CPU
// an anonymous caller can spend.
//
// Stored hashes carry their own parameters (see verifyScryptHash), so raising
// this does not invalidate anything. NeedsRehash reports which stored hashes are
// below the current cost, and the login path upgrades them on the next
// successful sign-in — the one moment the plaintext password is legitimately in
// hand.
const (
	scryptN      = 1 << 17
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
)

// HashPassword produces a scrypt-encoded hash string in the same format
// used historically by admin.env's ADMIN_PASS_HASH field.
func HashPassword(password string) (string, error) {
	const (
		n      = scryptN
		r      = scryptR
		p      = scryptP
		keyLen = scryptKeyLen
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
	// Bound the cost parameters: scrypt.Key allocates 128*r*N bytes of
	// whatever it is told, and these three come out of a file (users.json,
	// per-user state.json, an operator's ADMIN_PASS_HASH). One bad value asks
	// the allocator for terabytes on the next login, OOM-kills the process,
	// and supervisord restarts it straight back into the same crash.
	// x/crypto's own check only rejects values far above this.
	//
	// Floor is HashPassword's current cost — never accept a hash weaker than
	// we mint. Ceiling is ~1 GB, above any plausible tuning.
	if n < 1<<14 || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 32 || p < 1 || p > 16 {
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

// NeedsRehash reports whether a stored scrypt hash was written with cost
// parameters below the current ones, so a caller holding the verified plaintext
// can upgrade it.
//
// Raising scryptN protects new accounts and does nothing for existing ones,
// which is the majority of the accounts an attacker who steals users.json would
// be cracking. The only moment the plaintext is legitimately available to
// re-derive from is immediately after a successful verification, so that is
// where the upgrade has to happen.
//
// An unparseable or foreign-format hash returns false: rehashing something this
// package did not write is not an upgrade, it is a guess.
func NeedsRehash(encoded string) bool {
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
	// Only ever upgrade. A hash stored with a HIGHER cost than the current
	// default must be left alone — an operator may have deliberately raised it,
	// and "rehashing" it would silently weaken the account.
	return n < scryptN || r < scryptR || p < scryptP
}

// RehashPassword re-derives id's password hash at the current cost parameters,
// given the already-verified plaintext.
//
// Verifies the candidate again inside the write lock before replacing anything.
// The caller has necessarily already checked it, but this function's whole job
// is overwriting a credential, and re-checking under the lock is what makes a
// bug at the call site fail closed instead of setting the account's password to
// whatever string was passed in.
//
// MustChangePassword and every other field are left untouched: this is not a
// password change, and it must be invisible to the user.
func (s *Store) RehashPassword(id, verifiedCredential string) error {
	_, err := s.mutate(id, func(u *User) error {
		// Whichever credential form this account stores. VerifyPassword refuses
		// derived-auth accounts by design, so branching here is required, not
		// defensive — without it the rehash upgrade would silently never run for
		// a converted account and those hashes would stay at the old cost.
		ok := VerifyPassword(*u, verifiedCredential)
		if u.UsesDerivedAuth() {
			ok = VerifyAuthSecret(*u, verifiedCredential)
		}
		if !ok {
			return errors.New("refusing to rehash: candidate does not match the stored hash")
		}
		if !NeedsRehash(u.PasswordHash) {
			return nil
		}
		hash, err := HashPassword(verifiedCredential)
		if err != nil {
			return err
		}
		u.PasswordHash = hash
		return nil
	})
	return err
}

// Login credential derivation modes. See User's AuthDerivation field.
const (
	// AuthDerivationLegacy is the zero value: PasswordHash covers the plaintext
	// password, which the client therefore has to transmit.
	AuthDerivationLegacy = ""
	// AuthDerivationPBKDF2 means PasswordHash covers a client-derived auth
	// secret and the password never leaves the browser.
	AuthDerivationPBKDF2 = "pbkdf2-sha256-v1"
)

// MinAuthSecretHexLen is the shortest client-derived auth secret this store
// will accept, as hex.
//
// The server can no longer measure the password's length — that is the entire
// point — so it measures what it does receive. The browser derives 32 bytes (64
// hex chars); anything shorter is a client that is not doing the derivation, and
// accepting it would let a modified client register a trivially guessable
// credential. The password length floor (MinPasswordLen) is enforced in the
// browser before derivation, and by this store on every path where it still
// sees a plaintext password.
const MinAuthSecretHexLen = 64

// ErrAuthSecretMalformed is returned when a client-supplied auth secret is not
// the shape the browser produces.
var ErrAuthSecretMalformed = fmt.Errorf("auth secret must be at least %d hex characters", MinAuthSecretHexLen)

// ValidateAuthSecret checks a client-derived auth secret's shape.
func ValidateAuthSecret(secret string) error {
	if len(secret) < MinAuthSecretHexLen {
		return ErrAuthSecretMalformed
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return ErrAuthSecretMalformed
	}
	return nil
}

// UsesDerivedAuth reports whether u authenticates with a client-derived secret
// rather than a transmitted password.
func (u User) UsesDerivedAuth() bool {
	return u.AuthDerivation == AuthDerivationPBKDF2
}

// VerifyAuthSecret checks a client-derived auth secret against u's stored hash.
//
// Separate from VerifyPassword so no call site can accidentally accept a
// plaintext password for a derived-auth account, or the reverse. The two are
// different credentials for the same account and must never be interchangeable:
// treating a derived secret as a password would let anyone who read the salt
// off the public login-params endpoint authenticate with it.
func VerifyAuthSecret(u User, candidate string) bool {
	if !u.UsesDerivedAuth() {
		return false
	}
	return verifyScryptHash(u.PasswordHash, candidate)
}

// SetDerivedAuth replaces id's credential with a client-derived auth secret,
// recording the salt and iteration count the client used so a later login can
// reproduce it.
//
// requireChange mirrors SetPassword's flag. The PGP-key envelope is written in
// the same mutation when rewrapped is non-empty — see the note on
// SetDerivedAuthAndRewrapPGP.
func (s *Store) SetDerivedAuth(id, authSecret, loginSalt string, iterations int, requireChange bool) (User, error) {
	return s.SetDerivedAuthAndRewrapPGP(id, authSecret, loginSalt, iterations, requireChange, "")
}

// SetDerivedAuthAndRewrapPGP replaces id's credential AND, when rewrapped is
// non-empty, the client-wrapped PGP private key envelope — both inside one
// mutation, or neither.
//
// The two writes have to be atomic. The PGP envelope is sealed under a key
// derived from the account password, so a password change that lands without the
// matching rewrap leaves the envelope openable only with a password the user no
// longer has. That was two sequential HTTP requests, and a dropped connection
// between them permanently stranded the key: the documented recovery path
// ("unlock with your PREVIOUS password, then change your password again") could
// not work, because changing the password again re-derives from the CURRENT one
// and fails to unwrap. There is no way back from that except deleting the
// identity and losing every message ever encrypted to it.
func (s *Store) SetDerivedAuthAndRewrapPGP(id, authSecret, loginSalt string, iterations int, requireChange bool, rewrapped string) (User, error) {
	if err := ValidateAuthSecret(authSecret); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(loginSalt) == "" {
		return User{}, errors.New("login salt is required for derived auth")
	}
	if iterations < MinLoginIterations {
		return User{}, fmt.Errorf("login iterations must be at least %d", MinLoginIterations)
	}
	hash, err := HashPassword(authSecret)
	if err != nil {
		return User{}, err
	}
	return s.mutate(id, func(u *User) error {
		if rewrapped != "" {
			// Only a client-protected identity has an envelope to replace, and
			// silently ignoring a rewrap for an account that does not is how a
			// caller ends up believing the key was re-sealed when it was not.
			if u.PGPProtection() != PGPProtectionClient {
				return ErrNotClientProtected
			}
			u.PGPPrivateKeyWrapped = rewrapped
			u.PGPKeyProtection = PGPProtectionClient
		}
		u.PasswordHash = hash
		u.AuthDerivation = AuthDerivationPBKDF2
		u.LoginSalt = loginSalt
		u.LoginIterations = iterations
		u.MustChangePassword = requireChange
		return nil
	})
}

// MinLoginIterations is the floor on a client-declared PBKDF2 work factor.
//
// The client chooses it (it has to — it does the derivation), so the server
// bounds it. Without a floor a modified or downgraded client could declare 1
// iteration and register a credential derived at effectively no cost, which
// would be indistinguishable from a proper one to everything downstream.
const MinLoginIterations = 100_000

// UpgradeToDerivedAuth converts a legacy account to client-derived auth after a
// successful legacy login, given the auth secret the client derived alongside
// the password it just proved.
//
// Called on the legacy login path, which is the only moment both credentials are
// in hand at once. Verifies the plaintext password again inside the write lock:
// this replaces a credential, so a bug at the call site has to fail closed
// rather than pin the account to a caller-supplied secret.
//
// A no-op for an account that has already upgraded, so a racing second login
// cannot downgrade or re-pin it.
func (s *Store) UpgradeToDerivedAuth(id, verifiedPassword, authSecret, loginSalt string, iterations int) error {
	if err := ValidateAuthSecret(authSecret); err != nil {
		return err
	}
	if strings.TrimSpace(loginSalt) == "" {
		return errors.New("login salt is required for derived auth")
	}
	if iterations < MinLoginIterations {
		return fmt.Errorf("login iterations must be at least %d", MinLoginIterations)
	}
	hash, err := HashPassword(authSecret)
	if err != nil {
		return err
	}
	_, err = s.mutate(id, func(u *User) error {
		if u.UsesDerivedAuth() {
			return nil
		}
		if !VerifyPassword(*u, verifiedPassword) {
			return errors.New("refusing to upgrade auth derivation: password does not match")
		}
		u.PasswordHash = hash
		u.AuthDerivation = AuthDerivationPBKDF2
		u.LoginSalt = loginSalt
		u.LoginIterations = iterations
		return nil
	})
	return err
}
