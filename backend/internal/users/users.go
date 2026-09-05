// Package users provides the multi-user identity/role store, replacing the
// legacy single-admin admin.env file.
package users

import (
	"bytes"
	"context"
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

	// testing, in a non-test file, solely for testing.Testing() in
	// SetHashCostForTest. It reports whether this build is `go test` and pulls
	// no test framework into the binary.
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"

	"github.com/Busness-app/ky-primitives/password"
	"github.com/Busness-app/ky-primitives/recoverycode"
	"golang.org/x/crypto/argon2"
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

	// TOTPSecretEnc is a cryptutil envelope sealed with the dedicated TOTP key,
	// set at enrollment; TOTPEnabled flips true on confirmation. Never exposed
	// via Public().
	TOTPEnabled       bool     `json:"totpEnabled,omitempty"`
	TOTPSecretEnc     string   `json:"totpSecretEnc,omitempty"`
	TOTPConfirmedAt   string   `json:"totpConfirmedAt,omitempty"`
	RecoveryCodesHash []string `json:"recoveryCodesHash,omitempty"`
	// LastUsedTOTPStep is the RFC 6238 time-step (Unix seconds / 30) of the most
	// recently accepted TOTP code, tracked across every login challenge. Steps
	// strictly increase, so rejecting step <= this blocks replay of a captured
	// code against a fresh challenge; a rejected code never advances it, so
	// retry-after-typo at the current step still works. Zero rejects nothing.
	LastUsedTOTPStep int64 `json:"lastUsedTotpStep,omitempty"`
	// PushMFAEnabled is reserved for a later push-2FA milestone; nothing in
	// Milestone 1 sets or reads it.
	PushMFAEnabled bool `json:"pushMfaEnabled,omitempty"`

	// Single Sign-On (SSO) fields.
	SSOSub      string `json:"ssoSub,omitempty"`
	SSOUsername string `json:"ssoUsername,omitempty"`
	SSOEmail    string `json:"ssoEmail,omitempty"`
	SSOLinkedAt int64  `json:"ssoLinkedAt,omitempty"`
	// SSOLinkRevokedAt marks the link as no longer a credential without
	// forgetting which directory identity it names.
	//
	// SSOSub does two jobs at once: it is the proof handleSSOCallback signs a
	// caller in on, and it is the address the directory-sync webhook resolves
	// its events through. Erasing it to revoke the first destroys the second —
	// a later user.updated{active:true} for that same subject finds nothing and
	// the account can never be reactivated. So revocation sets this instead:
	// GetBySSOSub still resolves, and the login path refuses. Re-authorizing
	// the link clears it. See SSOLinkRevoked.
	SSOLinkRevokedAt int64 `json:"ssoLinkRevokedAt,omitempty"`

	// Login credential derivation.
	//
	// AuthDerivationPBKDF2: PasswordHash covers the AUTH SECRET the browser
	// derived, not the password — the server never receives the password.
	// LoginSalt and LoginIterations let the client reproduce that secret. This
	// exists because the client-side PGP key vault derives its wrapping key from
	// the same password (frontend/src/lib/keyVault.ts); sending the plaintext
	// password would have put every client-protected key within four lines of the
	// login handler.
	//
	// AuthDerivationLegacy (the empty string) means PasswordHash covers the
	// plaintext password. Those upgrade in place on the next successful sign-in —
	// see UpgradeToDerivedAuth. Admin-set temporary passwords are written legacy
	// (the admin's browser cannot derive a secret for somebody else's account);
	// the mandatory first-login change converts them.
	AuthDerivation  string `json:"authDerivation,omitempty"`
	LoginSalt       string `json:"loginSalt,omitempty"`
	LoginIterations int    `json:"loginIterations,omitempty"`

	// PGP identity. The public key is not sensitive; the private key is stored one
	// of two ways, per PGPKeyProtection:
	//
	//   "client" — PGPPrivateKeyWrapped holds an envelope the BROWSER sealed under
	//     a key derived from the user's password (frontend/src/lib/keyVault.ts).
	//     The server cannot open it and has no code that tries.
	//
	//   "server" — LEGACY. PGPPrivateKeyEnc holds a cryptutil envelope sealed with
	//     a master key on the same volume, so anyone who can read that volume can
	//     decrypt every message. Retained only until the owner logs in and
	//     migrates; see MigratePGPKeyToClientProtection.
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
	// PGPWrappedEnvelopes holds every sealing of the private key OTHER than the
	// password one, which stays in PGPPrivateKeyWrapped above. Splitting them
	// this way is what lets existing users.json files load unchanged: the legacy
	// field is still the password envelope, and WrappedEnvelopes() presents both
	// as one set. Each entry is opaque here, exactly like PGPPrivateKeyWrapped.
	PGPWrappedEnvelopes []WrappedEnvelope `json:"pgpWrappedEnvelopes,omitempty"`
	PGPKeyProtection    string            `json:"pgpKeyProtection,omitempty"`
	PGPKeySource        string            `json:"pgpKeySource,omitempty"`
	PGPKeyCreatedAt     string            `json:"pgpKeyCreatedAt,omitempty"`
}

// PGP key protection modes. See User's PGP block.
const (
	PGPProtectionClient = "client"
	PGPProtectionServer = "server"
)

// PGPProtection returns the effective protection mode for u's identity. No
// explicit mode plus a legacy sealed key means "server", so pre-existing
// users.json files stay readable without a migration pass.
func (u User) PGPProtection() string {
	if u.PGPKeyProtection == PGPProtectionClient || u.PGPPrivateKeyWrapped != "" {
		return PGPProtectionClient
	}
	if u.PGPPrivateKeyEnc != "" {
		return PGPProtectionServer
	}
	return ""
}

// WrappedEnvelope is one sealing of an account's PGP private key.
//
// Several may exist for one identity, each sealed under a different
// key-encryption key — the account password, a recovery code, an enrolled
// device — so that losing any single one is survivable. Envelope is opaque to
// this server in exactly the sense PGPPrivateKeyWrapped is: stored, returned to
// the owning user, never interpreted.
type WrappedEnvelope struct {
	Slot     string `json:"slot"`
	Envelope string `json:"envelope"`
	AddedAt  string `json:"addedAt,omitempty"`
	// ExpiresAt is set only on device: slots, which carry a payload in flight
	// rather than a durable sealing. The device that the envelope is for cannot
	// delete it — deletion needs a session and the ceremony's last step runs on
	// the device — so an expiry is how the server stops holding a copy whose
	// journey is over. Empty means "never", which is right for password and
	// recovery slots.
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Envelope slot names. "password" is not writable through the slot API: it
// lives in PGPPrivateKeyWrapped and is written only by RewrapPGPPrivateKey,
// which carries the ErrNotClientProtected guard that endpoint needs.
const (
	EnvelopeSlotPassword     = "password"
	EnvelopeSlotRecovery     = "recovery"
	EnvelopeSlotDevicePrefix = "device:"
)

// maxDeviceSlotIDLen bounds the caller-chosen half of a device slot name. The
// name is echoed back to clients and used as a map-ish key, so it is bounded
// and kept free of whitespace rather than trusted.
const maxDeviceSlotIDLen = 128

// maxWrappedEnvelopeSlots bounds how many non-password sealings one identity
// may accumulate. Real use is one recovery slot plus one sealing per enrolled
// device; 32 is generous for that (nobody enrolls 31 devices) and still small
// next to users.json, which Store.mutate rewrites whole under a global file
// lock on every write and which every authenticated request reads through —
// an unbounded slot count is an unbounded per-account share of that shared,
// instance-wide cost. This package only bounds the COUNT; the per-envelope
// byte bound (128 KiB, `maxWrappedKeyBytes`) that turns a slot count into an
// actual size budget is enforced by `io.LimitReader` in package `api`
// (pgp_client_keys.go), which this package cannot see or enforce itself —
// the two bounds are a dependency, not something this constant can reason
// about alone. Enforced only when ADDING a slot; replacing an existing
// one must keep working at the cap, or a user who reaches it can never
// rotate a sealing again.
const maxWrappedEnvelopeSlots = 32

// DeviceEnvelopeTTL bounds how long the server keeps a device: transport copy.
// Seven days matches the pickup-link retention window rather than introducing a
// third number; if one moves, both should. It is generous on purpose — enrolling
// at pairing completes in seconds, and this window only matters when the device
// is offline during a deferred enrollment. A device that misses it re-runs the
// ceremony; nothing is lost but the ceremony.
const DeviceEnvelopeTTL = 7 * 24 * time.Hour

// MaxWrappedEnvelopeBytes bounds a single client-wrapped envelope, whichever
// field it lands in.
//
// This used to live only in package api, as an io.LimitReader on the request
// body, and maxWrappedEnvelopeSlots' reasoning depended on it — "32 slots x 128
// KiB" is the budget that makes the slot count safe. That dependency did not
// hold: PGPPrivateKeyWrapped has a second writer, SetDerivedAuthAndRewrapPGP via
// POST /api/auth/password, whose reader allows 1 MiB and whose store path
// checked nothing. So the field the comment reasons about could be eight times
// the bound it reasons from.
//
// A byte bound that a package's own invariants depend on belongs in that
// package. api keeps its LimitReader — refusing an oversized body before
// buffering it is still worth doing — but the store no longer trusts it.
const MaxWrappedEnvelopeBytes = 128 << 10

// ErrWrappedEnvelopeTooLarge is returned for an envelope past
// MaxWrappedEnvelopeBytes.
var ErrWrappedEnvelopeTooLarge = fmt.Errorf("wrapped key envelope is too large: limit is %d bytes", MaxWrappedEnvelopeBytes)

// ValidateWrappedEnvelope bounds an opaque client-wrapped envelope. An empty
// envelope is allowed here: callers that require one check for it themselves.
func ValidateWrappedEnvelope(envelope string) error {
	if len(envelope) > MaxWrappedEnvelopeBytes {
		return ErrWrappedEnvelopeTooLarge
	}
	return nil
}

// ValidEnvelopeSlot reports whether slot may be written through the slot API.
func ValidEnvelopeSlot(slot string) bool {
	if slot == EnvelopeSlotRecovery {
		return true
	}
	id, ok := strings.CutPrefix(slot, EnvelopeSlotDevicePrefix)
	return ok && id != "" && len(id) <= maxDeviceSlotIDLen && !strings.ContainsAny(id, " \t\r\n")
}

// WrappedEnvelopes returns every sealing of this identity's private key, with
// PGPPrivateKeyWrapped synthesised as the password slot and listed first.
//
// A list entry claiming the password slot is ignored rather than merged: one
// slot has one writer, and honouring it here would let the slot API replace the
// password envelope without RewrapPGPPrivateKey's guard.
func (u User) WrappedEnvelopes() []WrappedEnvelope {
	out := make([]WrappedEnvelope, 0, len(u.PGPWrappedEnvelopes)+1)
	if strings.TrimSpace(u.PGPPrivateKeyWrapped) != "" {
		out = append(out, WrappedEnvelope{
			Slot:     EnvelopeSlotPassword,
			Envelope: u.PGPPrivateKeyWrapped,
		})
	}
	for _, e := range u.PGPWrappedEnvelopes {
		if e.Slot == EnvelopeSlotPassword || e.expired() {
			continue
		}
		out = append(out, e)
	}
	return out
}

// expired reports whether this envelope's TTL has passed. An unparseable
// ExpiresAt counts as expired: a timestamp the server cannot read is not
// evidence that a payload is still wanted, and failing closed here costs a
// re-run of the ceremony rather than leaving a blob around indefinitely.
func (e WrappedEnvelope) expired() bool {
	if e.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil {
		return true
	}
	return time.Now().UTC().After(t)
}

// HasServerReadableKey reports whether the server can still decrypt this user's
// mail on their behalf. Every server-side PGP operation must check this and
// refuse rather than assume — under client protection there is no usable key.
func (u User) HasServerReadableKey() bool {
	return u.PGPProtection() == PGPProtectionServer
}

// clone returns a deep copy of u. Every read served out of the Store's cache
// goes through this, and it must deep-copy every field a plain struct copy
// would still share with the cache's backing array — currently
// RecoveryCodesHash and PGPWrappedEnvelopes, both slices, so a shallow copy
// would let a caller corrupt shared state. WrappedEnvelope is all
// value-typed strings, so a shallow slices.Clone is enough for it — there is
// nothing under it left to alias.
func (u User) clone() User {
	if u.RecoveryCodesHash != nil {
		u.RecoveryCodesHash = slices.Clone(u.RecoveryCodesHash)
	}
	if u.PGPWrappedEnvelopes != nil {
		u.PGPWrappedEnvelopes = slices.Clone(u.PGPWrappedEnvelopes)
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
	SSOSub             string `json:"ssoSub,omitempty"`
	SSOUsername        string `json:"ssoUsername,omitempty"`
	SSOEmail           string `json:"ssoEmail,omitempty"`
	SSOLinkedAt        int64  `json:"ssoLinkedAt,omitempty"`
	// SSOLinkRevoked ships alongside the subject rather than blanking it,
	// because "linked" and "can sign in with it" stopped being the same thing:
	// revocation keeps the subject so directory sync can still address the
	// account. A viewer shown the subject with no flag would read a revoked
	// link as live. See User.SSOLinkRevokedAt.
	SSOLinkRevoked  bool   `json:"ssoLinkRevoked,omitempty"`
	PGPFingerprint  string `json:"pgpFingerprint,omitempty"`
	PGPKeyID        string `json:"pgpKeyId,omitempty"`
	PGPKeySource    string `json:"pgpKeySource,omitempty"`
	PGPKeyCreatedAt string `json:"pgpKeyCreatedAt,omitempty"`
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
		SSOSub:             u.SSOSub,
		SSOUsername:        u.SSOUsername,
		SSOEmail:           u.SSOEmail,
		SSOLinkedAt:        u.SSOLinkedAt,
		SSOLinkRevoked:     u.SSOLinkRevoked(),
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
	// ErrPGPFingerprintChanged means the caller read one key and tried to write
	// back after a different key replaced it. The copy is stale, not wrong;
	// retrying against the current key is the correct response.
	ErrPGPFingerprintChanged = errors.New("the account's pgp key changed while this update was in flight")
	// ErrTOTPEnrollmentRestarted is the same shape for TOTP: the secret staged
	// when the caller validated a code is no longer the one stored, so the
	// enrolment it was proving is gone. Committing anyway would enable a secret
	// nobody proved possession of.
	ErrTOTPEnrollmentRestarted = errors.New("two-factor enrolment was restarted; begin again")
	ErrPasswordWeak            = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	ErrUsernameInvalid         = errors.New("username must start with a letter or digit and may otherwise contain only letters, digits, dot, underscore and hyphen (max 64 characters)")
	// ErrInvalidEnvelopeSlot is returned for a slot name the slot API does not
	// write — an unknown name, or "password", which is owned by
	// RewrapPGPPrivateKey so that its ErrNotClientProtected guard cannot be
	// bypassed by writing the same envelope through a different door.
	ErrInvalidEnvelopeSlot = errors.New("invalid wrapped-envelope slot")
	// ErrNoPGPIdentity is returned when a slot write targets an account that has
	// no PGP identity to seal. A client error, not a server one — it fell through
	// to a 500 "user store error" before, which told the caller nothing and looked
	// like a fault on this side.
	ErrNoPGPIdentity = errors.New("no pgp identity to wrap")
	// ErrTooManyEnvelopeSlots is returned when adding a new slot would exceed
	// maxWrappedEnvelopeSlots. Never returned for a replace of an existing
	// slot — see that constant's comment.
	ErrTooManyEnvelopeSlots = fmt.Errorf("cannot add another wrapped-envelope slot: limit is %d", maxWrappedEnvelopeSlots)
)

// MinPasswordLen is the minimum length of any password this store accepts.
// Length is the only rule enforced: character-class requirements buy
// predictable substitutions rather than real entropy.
const MinPasswordLen = 14

// ValidatePassword enforces MinPasswordLen. Called by every store method that
// sets a password (Create, SetPassword) rather than by each handler, so a new
// call site cannot forget it. Length is counted in runes, not bytes.
func ValidatePassword(password string) error {
	if len([]rune(password)) < MinPasswordLen {
		return ErrPasswordWeak
	}
	return nil
}

// usernamePattern is the set of usernames this store will create.
//
// A username is a path segment on the CardDAV surface: dav_server.go builds
// principal and address-book URLs out of it and guards access by comparing the
// first path segment back against it, so "alice/bob" or ".." break that
// comparison. No cross-user access is reachable either way — the backend
// resolves the store from the authenticated UserID, never from the path.
//
// The leading character must be alphanumeric, ruling out "." and ".." (dot is
// legitimate in "first.last") and a leading hyphen, an argument-injection hazard
// wherever a username reaches a command line.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidateUsername enforces usernamePattern. Called by Create rather than by
// the handler, so a future call site cannot forget it. Deliberately NOT applied
// to existing accounts on read: an install that already has a "first last"
// username keeps working.
func ValidateUsername(username string) error {
	if !usernamePattern.MatchString(strings.TrimSpace(username)) {
		return ErrUsernameInvalid
	}
	return nil
}

// NormalizeUsername folds a username to its comparison form. Usernames are
// stored as typed (minus surrounding whitespace) but compared
// case-insensitively, so "admin" and "Admin" cannot coexist as separate accounts
// on a system where the admin role reaches every user's configuration.
//
// Exported because anything keying per-account state off a client-supplied
// username must key it off the SAME string GetByUsername resolves. Keyed on the
// raw string, " Admin " and "admin" are one account to the lookup and two strike
// budgets to the login lockout, which makes three-strikes unbounded.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

type usersFile struct {
	Version int    `json:"version"`
	Users   []User `json:"users"`
}

// Store is the on-disk users.json store.
//
// Every mutation is a read-modify-write of the whole file, and the file is
// written by BOTH processes supervisord starts: api (password changes, TOTP
// enrollment, recovery-code consumption) and daemon
// (processor/sendas_check.go's SetPGPIdentity). mu only serializes goroutines
// within one process, so every mutator additionally takes an inter-process file
// lock for the whole cycle — see fsutil.WithFileLock. Without it two
// overlapping mutations each read the same starting state and the second write
// silently discards the first: a lost password change, or a recovery code that
// stays usable after being consumed.
//
// Reads are served from a stat-guarded cache — see load.
type Store struct {
	mu   sync.RWMutex
	path string

	// cached is the last parsed file, valid only while the file's mtime and size
	// still match cachedMod/cachedSize. Guarded by mu. Without it Get reparsed
	// every account's armored key material on every authenticated request —
	// api.currentUser calls it per request, deliberately, so a deactivation takes
	// effect immediately.
	//
	// mtime+size rather than an invalidation protocol because the file is written
	// by two processes and every writer goes through fsutil.AtomicWriteFile, which
	// renames a new inode into place; a rename always moves mtime. An in-process
	// hook could not see the daemon's writes at all.
	cached     usersFile
	cachedIdx  userIndex
	cachedMod  time.Time
	cachedSize int64
	cacheValid bool
}

// userIndex resolves a lookup key to a position in usersFile.Users, replacing
// linear scans on a path api.currentUser takes for every authenticated request.
//
// Positions rather than *User: the slice aliases the cache (see load), so
// pointers would let a caller mutate the shared copy. Every read still goes
// through User.clone. Rebuilt only when the file changes.
type userIndex struct {
	byID       map[string]int
	byUsername map[string]int
	bySSOSub   map[string]int
}

func buildUserIndex(f usersFile) userIndex {
	idx := userIndex{
		byID:       make(map[string]int, len(f.Users)),
		byUsername: make(map[string]int, len(f.Users)),
		bySSOSub:   make(map[string]int, len(f.Users)),
	}
	for i, u := range f.Users {
		idx.byID[u.ID] = i
		// Folded with the same function GetByUsername folds the query with, so the
		// index cannot disagree with the lookup about what "the same account" means.
		// First writer wins on a duplicate, matching the scan this replaces.
		if key := NormalizeUsername(u.Username); key != "" {
			if _, exists := idx.byUsername[key]; !exists {
				idx.byUsername[key] = i
			}
		}
		if sub := strings.TrimSpace(u.SSOSub); sub != "" {
			if _, exists := idx.bySSOSub[sub]; !exists {
				idx.bySSOSub[sub] = i
			}
		}
	}
	return idx
}

func newStore(path string) *Store {
	return &Store{path: path}
}

// load returns the current file contents, from cache when the file on disk is
// unchanged since it was last parsed.
//
// The returned usersFile's Users slice ALIASES the cache. Reach it through
// withCachedUsers, the only caller, so the alias cannot escape.
//
// Callers must NOT hold mu: this takes it, for reading and then possibly for
// writing. Mutators hold the file lock and call readFileUnlocked instead — a
// read-modify-write cycle must not start from a cached copy.
func (s *Store) load() (usersFile, userIndex, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return usersFile{}, userIndex{}, err
	}

	s.mu.RLock()
	if s.cacheValid && s.cachedSize == info.Size() && s.cachedMod.Equal(info.ModTime()) {
		f, idx := s.cached, s.cachedIdx
		s.mu.RUnlock()
		return f, idx, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock: another goroutine may have refreshed while
	// this one waited.
	if s.cacheValid && s.cachedSize == info.Size() && s.cachedMod.Equal(info.ModTime()) {
		return s.cached, s.cachedIdx, nil
	}
	f, err := s.readFileUnlocked()
	if err != nil {
		return usersFile{}, userIndex{}, err
	}
	// Built whether or not the caching below takes, so a read that raced a write
	// still gets an index consistent with the slice it is returned alongside.
	idx := buildUserIndex(f)
	// Stat again AFTER the read. A write that landed between the first stat and
	// the read would otherwise be cached under the pre-write stamp and served as
	// current for an unbounded time.
	if after, err := os.Stat(s.path); err == nil &&
		after.Size() == info.Size() && after.ModTime().Equal(info.ModTime()) {
		s.cached = f
		s.cachedIdx = idx
		s.cachedMod = info.ModTime()
		s.cachedSize = info.Size()
		s.cacheValid = true
	}
	return f, idx, nil
}

// invalidateCacheLocked drops the cached copy; callers must hold mu. Mostly
// belt-and-braces, since AtomicWriteFile moves the mtime anyway. It matters on
// a filesystem with coarse mtime granularity, where a write landing in the same
// tick as the cached stamp would otherwise be invisible.
func (s *Store) invalidateCacheLocked() {
	s.cacheValid = false
	s.cached = usersFile{}
}

// LoadOrMigrate opens CONFIG_DIR/users.json, creating it on first run by
// best-effort importing the legacy single-admin admin.env, or minting a fresh
// default admin if neither exists. There is no production data to preserve, so
// a clean reset is an acceptable fallback for a missing or unparseable legacy
// file.
func LoadOrMigrate(ctx context.Context, configDir, legacyAdminEnvPath string) (*Store, error) {
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
			hash, err := HashPassword(ctx, admin["ADMIN_PASS"])
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
	// container flow scripts/bootstrap.sh runs first and admin.env already exists,
	// so this path is mainly for running the server standalone.
	randomPassword, err := randomPassword()
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(ctx, randomPassword)
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
		// The password goes to a 0600 file, never to stderr. It used to be
		// printed here, which is the same mistake app.BootstrapAdmin's doc
		// comment exists to prevent, reached by the other door: run standalone
		// under systemd (or any process manager, or CI) and stderr is the
		// journal — centralized, retained, and readable by more people than
		// the config directory. MustChangePassword narrows the window; it does
		// not stop the password sitting in a log forever.
		pwPath, werr := WriteFirstRunPassword(configDir, u.Username, randomPassword)
		if werr != nil {
			// Fatal, and it has to be: users.json now exists, so the next
			// start will NOT re-bootstrap, and the only account on it has a
			// random password that was never handed to anyone.
			return nil, fmt.Errorf(
				"created %s but could not hand over the generated admin password (%w); "+
					"delete %s to bootstrap again, or set BOOTSTRAP_ADMIN_PASS",
				path, werr, path)
		}
		fmt.Fprintf(os.Stderr,
			"Generated first-run admin credentials\nUsername: %s\nPassword: written to %s (read it, then delete it)\n"+
				"Password change is required on first login\n",
			u.Username, pwPath)
	}
	return store, nil
}

// BootstrapPasswordFile is where a generated first-run admin password is left
// for the operator to read once, inside CONFIG_DIR.
const BootstrapPasswordFile = "first-run-password.txt"

// WriteFirstRunPassword hands a generated first-run admin password to the
// operator through a 0600 file in configDir, and returns its path.
//
// One implementation for both bootstrap paths — the container's
// `--mode bootstrap-admin` (app.BootstrapAdmin) and a standalone start that
// finds no users.json (LoadOrMigrate above) — because they used to disagree:
// the container wrote this file and the standalone path printed the password
// to stderr. An operator following SECURITY.md's "the password is never
// logged" had no way to tell which one they were running.
func WriteFirstRunPassword(configDir, username, password string) (string, error) {
	pwPath := filepath.Join(configDir, BootstrapPasswordFile)
	body := fmt.Sprintf("username: %s\npassword: %s\n\n"+
		"This password must be changed at first login. Delete this file once you have it.\n",
		username, password)
	if err := fsutil.AtomicWriteFile(pwPath, []byte(body), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", pwPath, err)
	}
	return pwPath, nil
}

// createInitial writes the very first users.json atomically, exclusively, and
// durably. The api and daemon processes start at the same time on first boot;
// if the other creates the file first, the loser adopts the winner's copy so
// both agree on the admin's user ID.
//
// The two fsyncs are the same pair fsutil.AtomicWriteFile documents, and they
// matter here for a reason that file cannot state: this is the ONLY copy of
// the account whose ID everything else on the volume is about to be keyed to.
// Exclusive creation was handled and durable creation was not, so a crash
// between the link and the writeback lost users.json while the state written
// alongside it survived — and the next boot would mint a DIFFERENT admin ID,
// orphaning all of it. Link rather than Rename is what makes the creation
// exclusive (Rename would clobber a file the other process just won), so
// AtomicWriteFile cannot be reused wholesale; only its durability can.
func (s *Store) createInitial(f usersFile) (won bool, err error) {
	if f.Version == 0 {
		f.Version = 1
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return false, err
	}
	// 0o700, matching fsutil.AtomicWriteFile's 0o700 for this same class of
	// data. This directory holds users.json — every account record, the sealed
	// TOTP secrets, the scrypt password hashes and the wrapped PGP envelopes —
	// and was created world-readable while the file written into it was not.
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
	// Before the link, or the link can reach the disk while the bytes behind it
	// have not — leaving a users.json that exists and is empty, which is worse
	// than one that is missing: the missing one re-bootstraps, the empty one
	// fails to parse and the server will not start.
	if err := tmp.Sync(); err != nil {
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
	// After the link, or the link itself can be lost.
	if err := fsutil.SyncDir(dir); err != nil {
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
// cache. It takes no lock of its own; the caller must already hold both mu and
// the file lock. Every mutator uses this rather than load(): a read-modify-write
// cycle must start from what is actually on disk, or it can serialize a cached
// copy back over another process's committed write.
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
	// Encoder with HTML escaping OFF, not json.MarshalIndent.
	//
	// MarshalIndent escapes <, > and & to <, > and & — six bytes
	// on disk for one byte of input. Every size bound on the way in
	// (maxWrappedKeyBytes, the password handler's io.LimitReader) is applied to
	// the REQUEST body, i.e. the wrong side of this encoder, so a field of
	// literal '<' inflated 6x once it landed here. users.json is rewritten whole
	// under a global lock on every mutation, so that inflation is a direct
	// multiplier on how long every other request waits.
	//
	// The escaping bought nothing: this file is never interpolated into HTML.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return err
	}
	if err := fsutil.AtomicWriteFile(s.path, buf.Bytes(), 0o600); err != nil {
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

// List returns every user (including deactivated ones), sorted by username. The
// returned slice is a deep copy: sorting f.Users in place would reorder the
// cached backing array while another goroutine ranges over it.
func (s *Store) List() ([]User, error) {
	var out []User
	err := s.withCachedUsers(func(all []User) {
		out = make([]User, 0, len(all))
		for _, u := range all {
			out = append(out, u.clone())
		}
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return NormalizeUsername(out[i].Username) < NormalizeUsername(out[j].Username)
	})
	return out, nil
}

// withCachedUsers calls fn with the cached user records.
//
// The slice fn receives IS the cache's own backing array. It is passed to a
// callback rather than returned so it cannot escape: a reader that keeps, sorts,
// or writes through it corrupts what every subsequent request reads. fn must
// clone anything it keeps (see User.clone, which deep-copies every field a
// plain struct copy would still share with the cache — currently
// RecoveryCodesHash and PGPWrappedEnvelopes).
//
// Mutators do NOT use this; see readFileUnlocked.
func (s *Store) withCachedUsers(fn func(all []User)) error {
	f, _, err := s.load()
	if err != nil {
		return err
	}
	fn(f.Users)
	return nil
}

// withIndexedUsers is withCachedUsers for the two lookups that have a key, so
// they resolve by index instead of scanning. pos is -1 when the key is absent.
func (s *Store) withIndexedUsers(index func(userIndex) (int, bool), fn func(u User)) error {
	f, idx, err := s.load()
	if err != nil {
		return err
	}
	pos, ok := index(idx)
	if !ok || pos < 0 || pos >= len(f.Users) {
		return nil
	}
	fn(f.Users[pos])
	return nil
}

// Get returns a user by ID, served from the stat-guarded cache (see load).
// api.currentUser calls this on every authenticated request, so re-parsing
// every account's armored key material to answer "is this account still
// active?" was the hottest avoidable cost in the request path.
func (s *Store) Get(id string) (User, error) {
	found := false
	var out User
	err := s.withIndexedUsers(
		func(idx userIndex) (int, bool) { pos, ok := idx.byID[id]; return pos, ok },
		func(u User) { out, found = u.clone(), true },
	)
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrNotFound
	}
	return out, nil
}

// GetByUsername returns a user by username, compared case-insensitively —
// see NormalizeUsername.
func (s *Store) GetByUsername(username string) (User, error) {
	want := NormalizeUsername(username)
	found := false
	var out User
	err := s.withIndexedUsers(
		func(idx userIndex) (int, bool) { pos, ok := idx.byUsername[want]; return pos, ok },
		func(u User) { out, found = u.clone(), true },
	)
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrNotFound
	}
	return out, nil
}

// GetBySSOSub returns a user by their linked SSO subject identifier.
func (s *Store) GetBySSOSub(ssoSub string) (User, error) {
	sub := strings.TrimSpace(ssoSub)
	if sub == "" {
		return User{}, ErrNotFound
	}
	found := false
	var out User
	err := s.withIndexedUsers(
		func(idx userIndex) (int, bool) { pos, ok := idx.bySSOSub[sub]; return pos, ok },
		func(u User) { out, found = u.clone(), true },
	)
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrNotFound
	}
	return out, nil
}

// LinkSSO connects a user's account to an SSO identity.
func (s *Store) LinkSSO(userID, ssoSub, ssoUsername, ssoEmail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return fsutil.WithFileLock(s.path, func() error {
		f, err := s.readFileUnlocked()
		if err != nil {
			return err
		}
		found := false
		for i := range f.Users {
			if f.Users[i].ID == userID {
				f.Users[i].SSOSub = strings.TrimSpace(ssoSub)
				f.Users[i].SSOUsername = strings.TrimSpace(ssoUsername)
				f.Users[i].SSOEmail = strings.TrimSpace(ssoEmail)
				f.Users[i].SSOLinkedAt = time.Now().UTC().Unix()
				// Authorizing a link is what un-revokes one. The write reaches
				// here only from linkSSOIdentity, which the callback runs only
				// after spending a step-up grant, so this is the user proving
				// the account credential and asking for the link back.
				f.Users[i].SSOLinkRevokedAt = 0
				f.Users[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		return s.writeFileUnlocked(f)
	})
}

// RevokeSSOLink stops a linked identity being a credential, keeping the subject
// so the directory-sync webhook can still address the account. Revoking an
// unlinked or already-revoked account is a no-op. See User.SSOLinkRevokedAt.
func (s *Store) RevokeSSOLink(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return fsutil.WithFileLock(s.path, func() error {
		f, err := s.readFileUnlocked()
		if err != nil {
			return err
		}
		for i := range f.Users {
			if f.Users[i].ID != userID {
				continue
			}
			if f.Users[i].SSOSub == "" || f.Users[i].SSOLinkRevokedAt != 0 {
				return nil // nothing linked, or already revoked
			}
			f.Users[i].SSOLinkRevokedAt = time.Now().UTC().Unix()
			f.Users[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			return s.writeFileUnlocked(f)
		}
		return ErrNotFound
	})
}

// UnlinkSSO removes any linked SSO identity from a user's account.
func (s *Store) UnlinkSSO(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return fsutil.WithFileLock(s.path, func() error {
		f, err := s.readFileUnlocked()
		if err != nil {
			return err
		}
		found := false
		for i := range f.Users {
			if f.Users[i].ID == userID {
				f.Users[i].SSOSub = ""
				f.Users[i].SSOUsername = ""
				f.Users[i].SSOEmail = ""
				f.Users[i].SSOLinkedAt = 0
				f.Users[i].SSOLinkRevokedAt = 0
				f.Users[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		return s.writeFileUnlocked(f)
	})
}

// CreateSSOUser adds a new user provisioned via SSO.
func (s *Store) CreateSSOUser(username string, role Role, ssoSub, ssoUsername, ssoEmail string) (User, error) {
	if err := ValidateUsername(username); err != nil {
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
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339)
		created = User{
			ID:                 id,
			Username:           username,
			Role:               role,
			Active:             true,
			MustChangePassword: false,
			SSOSub:             strings.TrimSpace(ssoSub),
			SSOUsername:        strings.TrimSpace(ssoUsername),
			SSOEmail:           strings.TrimSpace(ssoEmail),
			SSOLinkedAt:        time.Now().UTC().Unix(),
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

// Create adds a new user with the given username/password/role.
func (s *Store) Create(ctx context.Context, username, password string, role Role) (User, error) {
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
		hash, err := HashPassword(ctx, password)
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

// errNoChangeNeeded is returned by a mutate fn that found the stored value
// already correct. mutateGuarded then skips the write and returns the user
// unchanged, with no error — the caller cannot tell the difference, which is the
// point: it turns "set this bit" into a no-op when the bit is already set.
//
// Deliberately unexported and never surfaced: it is a control-flow signal, not a
// failure. ConsumeRecoveryCode's errRecoveryCodeNoMatch does the same job for
// the same reason.
var errNoChangeNeeded = errors.New("users: no change needed")

// compactExpiredEnvelopes drops the wrapped-envelope slots whose transport TTL
// has passed, reporting whether it removed any.
//
// Called from mutateGuarded so every write path compacts, rather than from the
// two envelope endpoints — the leak's whole character was that the expired rows
// were invisible to every reader, so the fix must not depend on someone
// remembering to look.
func compactExpiredEnvelopes(u *User) bool {
	kept := u.PGPWrappedEnvelopes[:0]
	for _, e := range u.PGPWrappedEnvelopes {
		if !e.expired() {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(u.PGPWrappedEnvelopes) {
		return false
	}
	u.PGPWrappedEnvelopes = kept
	return true
}

// SweepExpiredEnvelopes drops every user's expired wrapped-envelope rows in a
// single pass, returning how many it removed.
//
// mutateGuarded already compacts on any write, which handles every account that
// is being used. This is for the account that is not: a device envelope expires,
// nothing else about that account ever changes, and the row sits in users.json
// forever — invisible to WrappedEnvelopes(), invisible to the slot cap, and
// inside the file every authenticated request on the instance reads through.
// Compaction-on-write is opportunistic; this is the guarantee.
//
// ONE read-modify-write for every user, not one per user. The whole cost being
// reclaimed here is whole-file rewrites under a global cross-process lock, so a
// sweep that took that lock once per account would be a smaller version of the
// problem it exists to fix.
//
// It deliberately does NOT stamp UpdatedAt. The rows removed were already
// invisible to every reader and to the cap, so from any observer's point of
// view the account did not change; bumping the timestamp would report a
// modification that no one made and nothing can see.
func (s *Store) SweepExpiredEnvelopes() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	err := fsutil.WithFileLock(s.path, func() error {
		f, err := s.readFileUnlocked()
		if err != nil {
			return err
		}
		for i := range f.Users {
			before := len(f.Users[i].PGPWrappedEnvelopes)
			if compactExpiredEnvelopes(&f.Users[i]) {
				removed += before - len(f.Users[i].PGPWrappedEnvelopes)
			}
		}
		if removed == 0 {
			return nil
		}
		return s.writeFileUnlocked(f)
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
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
// A precondition checked in the handler and enforced by a separate write is not
// a precondition: evaluating isLastActiveAdmin outside this lock lets two
// concurrent requests each see one other active admin and both proceed, leaving
// an instance with zero admins and no way back but hand-editing the volume.
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
			// Drop envelope slots whose transport TTL has passed, on whatever
			// write happens to come next.
			//
			// WrappedEnvelopes() filters them on READ and the slot cap counts
			// only live ones, so an expired row was invisible to every reader
			// and to the bound that exists to cap an account's share of this
			// file — but nothing removed it. Measured: 4 MiB per account per
			// week, permanently, with the visible slot count pinned at 33 and
			// no operator surface that could even see it. This is the one place
			// every write passes.
			compacted := compactExpiredEnvelopes(&f.Users[i])
			if err := fn(&f.Users[i]); err != nil {
				// A mutation that changes nothing must not cost a write. Every
				// write here is a whole-file marshal + fsync under this lock,
				// which every authenticated request contends with, so an
				// unthrottled endpoint that re-sets a field to the value it
				// already holds is a free instance-wide stall. See
				// ErrNoChangeNeeded.
				//
				// ...unless the compaction above actually removed something, in
				// which case there IS a change to persist and eliding the write
				// would leave the expired rows on disk forever.
				if errors.Is(err, errNoChangeNeeded) && !compacted {
					updated = f.Users[i]
					return nil
				}
				if !errors.Is(err, errNoChangeNeeded) {
					return err
				}
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
func (s *Store) SetPassword(ctx context.Context, id, newPassword string, requireChange bool) (User, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(ctx, newPassword)
	if err != nil {
		return User{}, err
	}
	return s.mutate(id, func(u *User) error {
		u.PasswordHash = hash
		u.MustChangePassword = requireChange
		// Back to legacy derivation. This path stores a hash of a PLAINTEXT password,
		// which is how an admin sets a temporary one — an admin's browser cannot
		// derive an auth secret for somebody else's account.
		//
		// Clearing these three is load-bearing, not tidiness: leaving AuthDerivation
		// set while PasswordHash covers a plaintext password would make
		// VerifyAuthSecret the active check against a hash it can never match, and lock
		// the user out of the temporary password they were just given. The mandatory
		// first-login change converts the account back to derived auth.
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

// guardNotLastActiveAdmin refuses a write that would leave the instance with no
// active admin. Evaluated inside mutateGuarded's lock against the file as just
// read, so concurrent callers cannot each observe the other's admin as still
// active and both proceed.
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

// EnableTOTP marks TOTP confirmed and stores the recovery codes' digests.
// It errors if no pending secret has been staged.
// expectSecretEnc is the secret the caller actually VALIDATED a code against,
// compared here inside mutate — the same compare-and-swap shape
// UpdatePGPKeyMaterial uses for a fingerprint.
//
// Without it this was a TOCTOU with a window measured in seconds, not
// instructions: handleMFAConfirm validates against a snapshot and then spends
// eleven scrypt derivations (one re-auth plus ten recovery-code hashes) before
// committing, while POST /api/mfa/totp/setup is session-only and re-stages the
// secret with no lockout. A stolen session that fires setup inside that window
// gets its own secret committed by the victim's confirm — the victim is told
// enrolment succeeded and handed ten working recovery codes, while the live
// second factor belongs to the attacker. Nothing clears TOTP state on a
// password change, so it survives the owner's own remediation.
func (s *Store) EnableTOTP(id, expectSecretEnc, confirmedAt string, recoveryHashes []string) (User, error) {
	if expectSecretEnc == "" {
		return User{}, errors.New("no validated totp secret to confirm")
	}
	return s.mutate(id, func(u *User) error {
		if u.TOTPSecretEnc == "" {
			return errors.New("no pending totp secret to confirm")
		}
		if u.TOTPSecretEnc != expectSecretEnc {
			return ErrTOTPEnrollmentRestarted
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
		if u.PushMFAEnabled == enabled {
			return errNoChangeNeeded
		}
		u.PushMFAEnabled = enabled
		return nil
	})
}

// ErrTOTPStepNotNewer is returned by SetLastUsedTOTPStep when step is not
// strictly greater than the account's currently recorded LastUsedTOTPStep —
// i.e. the caller is attempting to record a replayed or out-of-order code.
var ErrTOTPStepNotNewer = errors.New("totp step is not newer than last recorded step")

// SetLastUsedTOTPStep atomically checks-and-records the RFC 6238 time-step of an
// accepted TOTP code, for replay protection scoped to the account rather than to
// a single challenge (see mfa.Store.ConsumeTOTPStep for that narrower guard). It
// writes, and reports success, only when step is strictly greater than the
// stored value; otherwise it returns ErrTOTPStepNotNewer without writing. Check
// and write share one mutate lock, closing the TOCTOU window where two
// concurrent requests bearing the same captured code — each against its own
// fresh challenge — could both pass a stale check before either recorded it.
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
// New identities must not use this. It exists for the send-as User ID reconcile,
// which can only run against a key the server can already open, and which skips
// client-protected identities entirely.
func (s *Store) SetPGPIdentity(id, fingerprint, keyID, armoredPublicKey, privateKeyEnc, source, createdAt string) (User, error) {
	return s.mutate(id, func(u *User) error {
		// Refuse to overwrite a client-held identity with a server-readable one:
		// clearing PGPPrivateKeyWrapped here would silently downgrade custody and
		// destroy the browser envelope, the opposite of what docs/E2E_PGP.md promises.
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
		// Same reasoning as SetPGPIdentityClientProtected's clear below, restated
		// rather than inherited so the two preconditions cannot drift apart. This
		// path is only reachable for an account with no slots to begin with (the
		// guard above refuses a client-protected account, and only a
		// client-protected account can ever hold one), but clearing here means a
		// future writer of this method cannot reintroduce the gap by relying on
		// that invariant instead of restating it.
		u.PGPWrappedEnvelopes = nil
		return nil
	})
}

// UpdatePGPKeyMaterial replaces only the public key and its sealed private half
// for an identity whose fingerprint is still expectFingerprint, leaving key ID,
// source, creation time and protection untouched.
//
// This is the narrow write the daemon's send-as reconcile needs: adding User IDs
// changes the key's bytes but not its identity. Do not substitute
// SetPGPIdentity, which rewrites everything — the caller snapshots the user,
// spends hundreds of microseconds re-signing, and only then writes, so a key
// replaced during that window is silently reverted.
//
// expectFingerprint closes that window. An empty expectation is rejected rather
// than treated as "any": a vacuous precondition is worst exactly when the
// account has no key and a stale write would install one.
func (s *Store) UpdatePGPKeyMaterial(id, expectFingerprint, armoredPublicKey, privateKeyEnc string) (User, error) {
	if strings.TrimSpace(expectFingerprint) == "" {
		return User{}, errors.New("expected fingerprint is required to update key material")
	}
	return s.mutate(id, func(u *User) error {
		// Same refusal as SetPGPIdentity, restated rather than inherited so the two
		// preconditions cannot drift apart: writing privateKeyEnc onto a client-held
		// identity would hand the server back a readable copy of a key it is not
		// supposed to have, and destroy the browser envelope.
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

// SetPGPIdentityClientProtected stores an end-to-end PGP identity. wrapped is an
// opaque envelope the browser produced under a key derived from the user's
// password; this store never interprets it. Clearing PGPPrivateKeyEnc is the
// point — after this call no copy of the private key on this server is one this
// server can open.
func (s *Store) SetPGPIdentityClientProtected(id, fingerprint, keyID, armoredPublicKey, wrapped, source, createdAt string) (User, error) {
	if err := ValidateWrappedEnvelope(wrapped); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(wrapped) == "" {
		return User{}, errors.New("wrapped private key is required for client-protected identities")
	}
	return s.mutate(id, func(u *User) error {
		previousFingerprint := u.PGPFingerprint
		u.PGPFingerprint = fingerprint
		u.PGPKeyID = keyID
		u.PGPPublicKey = armoredPublicKey
		u.PGPPrivateKeyWrapped = wrapped
		u.PGPPrivateKeyEnc = ""
		u.PGPKeyProtection = PGPProtectionClient
		u.PGPKeySource = source
		u.PGPKeyCreatedAt = createdAt
		// Every non-password slot seals the OLD key. Keeping them across an
		// identity replacement would leave a recovery code that opens a key this
		// account no longer advertises — the user is told their mail is
		// recoverable, and it is not.
		//
		// Only when the identity actually CHANGED, though. This used to drop them
		// unconditionally, so re-posting the same fingerprint — a retried request,
		// a client that re-runs setup, a rewrap that routes through here —
		// destroyed a live recovery sealing that was still perfectly valid, with a
		// 200 and no log line. The fingerprint needed to tell the two apart is the
		// argument right here, and UpdatePGPKeyMaterial already shows the pattern.
		if !strings.EqualFold(strings.TrimSpace(previousFingerprint), strings.TrimSpace(fingerprint)) {
			u.PGPWrappedEnvelopes = nil
		}
		return nil
	})
}

// RewrapPGPPrivateKey replaces only the wrapped private key envelope, leaving
// the identity (fingerprint, public key, provenance) untouched. Used when the
// user changes their password: the wrapping key is derived from that password,
// so the browser unwraps with the old one and rewraps with the new one.
func (s *Store) RewrapPGPPrivateKey(id, wrapped string) (User, error) {
	if err := ValidateWrappedEnvelope(wrapped); err != nil {
		return User{}, err
	}
	if strings.TrimSpace(wrapped) == "" {
		return User{}, errors.New("wrapped private key is required")
	}
	return s.mutate(id, func(u *User) error {
		if u.PGPFingerprint == "" {
			return errors.New("no pgp identity to rewrap")
		}
		// Rewrap exists for a password change on an account that is ALREADY
		// client-protected. Reaching it with a server-custody account instead cleared
		// PGPPrivateKeyEnc — the only copy of the private key anyone could open — while
		// leaving the identity advertised, so every message ever encrypted to it became
		// permanently unreadable and senders kept encrypting to a key nobody held.
		if u.PGPProtection() != PGPProtectionClient {
			return ErrNotClientProtected
		}
		u.PGPPrivateKeyWrapped = wrapped
		u.PGPKeyProtection = PGPProtectionClient
		return nil
	})
}

// SetPGPWrappedEnvelope adds or replaces one non-password sealing of the
// private key. envelope is opaque here, exactly as in RewrapPGPPrivateKey.
//
// Replacing writes in place rather than appending: two entries for one slot
// would leave the unlock path with no deterministic answer about which sealing
// a given secret opens.
func (s *Store) SetPGPWrappedEnvelope(id, slot, envelope, addedAt string) (User, error) {
	if err := ValidateWrappedEnvelope(envelope); err != nil {
		return User{}, err
	}
	if !ValidEnvelopeSlot(slot) {
		return User{}, ErrInvalidEnvelopeSlot
	}
	if strings.TrimSpace(envelope) == "" {
		return User{}, errors.New("wrapped envelope is required")
	}
	expiresAt := ""
	if strings.HasPrefix(slot, EnvelopeSlotDevicePrefix) {
		expiresAt = time.Now().UTC().Add(DeviceEnvelopeTTL).Format(time.RFC3339)
	}
	return s.mutate(id, func(u *User) error {
		if u.PGPFingerprint == "" {
			return ErrNoPGPIdentity
		}
		// Same guard, and same reason, as RewrapPGPPrivateKey: a server-custody
		// account has no browser-held envelope, so an additional "sealing of the
		// key" would seal nothing the user can open, while making the account look
		// recoverable.
		if u.PGPProtection() != PGPProtectionClient {
			return ErrNotClientProtected
		}
		for i := range u.PGPWrappedEnvelopes {
			if u.PGPWrappedEnvelopes[i].Slot == slot {
				u.PGPWrappedEnvelopes[i].Envelope = envelope
				u.PGPWrappedEnvelopes[i].AddedAt = addedAt
				u.PGPWrappedEnvelopes[i].ExpiresAt = expiresAt
				return nil
			}
		}
		// Past this point the slot is new, not a replace — the cap applies.
		// Only live entries count, so an expired slot frees headroom: a device
		// that enrolled once and went quiet must not cost the user a slot forever.
		live := 0
		for _, e := range u.PGPWrappedEnvelopes {
			if !e.expired() {
				live++
			}
		}
		if live >= maxWrappedEnvelopeSlots {
			return ErrTooManyEnvelopeSlots
		}
		u.PGPWrappedEnvelopes = append(u.PGPWrappedEnvelopes, WrappedEnvelope{
			Slot: slot, Envelope: envelope, AddedAt: addedAt, ExpiresAt: expiresAt,
		})
		return nil
	})
}

// DeletePGPWrappedEnvelope removes one non-password sealing — a revoked device,
// or a recovery code the user is replacing.
//
// Deleting an absent slot succeeds: the caller's goal is that the slot is gone,
// and it already is. Refusing the password slot is what keeps this from being a
// way to make an account permanently unopenable.
func (s *Store) DeletePGPWrappedEnvelope(id, slot string) (User, error) {
	if !ValidEnvelopeSlot(slot) {
		return User{}, ErrInvalidEnvelopeSlot
	}
	return s.mutate(id, func(u *User) error {
		kept := u.PGPWrappedEnvelopes[:0]
		for _, e := range u.PGPWrappedEnvelopes {
			if e.Slot != slot {
				kept = append(kept, e)
			}
		}
		// Deleting a slot that is not there is a no-op, so it must not cost a
		// whole-file marshal + fsync under the global lock every authenticated
		// request contends with. It did: this returned nil unconditionally and
		// so always wrote, measured at 393 rewrites/s from one looping caller.
		if len(kept) == len(u.PGPWrappedEnvelopes) {
			return errNoChangeNeeded
		}
		u.PGPWrappedEnvelopes = kept
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
		// No identity survives this call, so no slot can seal a key this account
		// still advertises. Same rationale as SetPGPIdentityClientProtected.
		u.PGPWrappedEnvelopes = nil
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
//
// digest is the caller's keyed digest function (mfa.NewRecoveryCodeDigester,
// held by api.Server). It is a parameter rather than something this package
// calls, because it is keyed on a file in SECRET_DIR and this store owns
// CONFIG_DIR: reading that key here would put the pepper and the peppered
// value on one volume, which is the whole thing the key is for.
//
// Digest matching is a hash compare; the legacy scrypt comparisons run OUTSIDE
// the store lock, against a snapshot: holding s.mu and the file lock across up
// to ten 128 MiB derivations (~3s) stalls every authenticated request, which
// takes s.mu.RLock via currentUser -> Get. Matching on the hash string rather
// than an index keeps the removal correct if the list changed while we were
// deriving.
//
// Each comparison takes and releases a derivation slot INDIVIDUALLY, which is
// why ctx is passed straight through to verifyScryptHash rather than the whole
// loop running inside one WithKDFSlot. A check is up to ten derivations; one
// slot held across all ten owns it for seconds, and with MaxConcurrentKDF
// slots process-wide, that many such checks stall every login. Per-comparison
// admission lets other work interleave while never exceeding one derivation's
// memory per caller. Do NOT wrap a call to this in WithKDFSlot: it would
// collapse the ten acquisitions back into one and reintroduce exactly that.
//
// A slot error abandons the remaining comparisons and surfaces unchanged, so an
// overloaded server sheds rather than queues.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, id, candidate string, digest func(string) string) (User, bool, error) {
	snapshot, err := s.Get(id)
	if err != nil {
		return User{}, false, err
	}
	matched := ""
	if i, ok := recoverycode.MatchCode(candidate, snapshot.RecoveryCodesHash, digest); ok {
		matched = snapshot.RecoveryCodesHash[i]
	}
	// Codes stored before digests existed are scrypt hashes; they drain as
	// users regenerate. Each comparison takes its own derivation slot (see the
	// comment above) and a busy slot is "not checked", never "wrong".
	for _, h := range snapshot.RecoveryCodesHash {
		if matched != "" || !strings.HasPrefix(h, "scrypt$") {
			continue
		}
		hit, err := verifyScryptHash(ctx, h, candidate)
		if err != nil {
			return User{}, false, err
		}
		if hit {
			matched = h
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

// VerifyPassword checks a plaintext password against u's stored hash.
//
// Refuses outright for a derived-auth account. After conversion PasswordHash
// covers the client-derived AUTH SECRET, so a bare comparison would happily
// accept that secret here as though it were the password. The two are different
// credentials for the same account, and each verifier refusing the other's
// accounts is what keeps them from becoming interchangeable by accident. See
// VerifyAuthSecret for the mirror image.
// A non-nil error means the credential was NOT examined (ErrKDFBusy, or ctx
// cancelled); it never means "wrong". Callers must not spend a lockout strike
// on it — see ErrKDFBusy.
func VerifyPassword(ctx context.Context, u User, candidate string) (bool, error) {
	if u.UsesDerivedAuth() {
		return false, nil
	}
	return verifyHash(ctx, u.PasswordHash, candidate)
}

// VerifySecretHash checks a candidate secret against a hash produced by
// HashPassword — the generic counterpart to VerifyPassword, for secrets other
// than a User's login password (e.g. an app-specific CardDAV password).
func VerifySecretHash(ctx context.Context, encoded, candidate string) (bool, error) {
	return verifyHash(ctx, encoded, candidate)
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
// scrypt bought nothing and cost ~16 MB and ~50 ms on every request a paired
// device makes — App Pull polls, mail sync, contacts sync, push-MFA.
//
// Do NOT use this for anything a human types or chooses; that needs
// HashPassword.
func HashDeviceSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return deviceSecretPrefix + hex.EncodeToString(sum[:])
}

// VerifyDeviceSecret checks a candidate device secret against a stored hash in
// constant time. Untagged values fall through to scrypt: devices paired before
// HashDeviceSecret existed hold one, and rejecting them would silently unpair
// every phone on every existing install. New registrations write the tagged
// form, so that branch drains as devices re-pair.
// The legacy branch derives scrypt and so takes a slot; the tagged branch is a
// single SHA-256 and takes none. ctx is therefore only consulted on the legacy
// path, and a busy-slot error there means "not checked", exactly as elsewhere.
func VerifyDeviceSecret(ctx context.Context, stored, candidate string) (bool, error) {
	encoded, ok := strings.CutPrefix(stored, deviceSecretPrefix)
	if !ok {
		return verifyHash(ctx, stored, candidate)
	}
	want, err := hex.DecodeString(encoded)
	if err != nil || len(want) != sha256.Size {
		return false, nil
	}
	got := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(got[:], want) == 1, nil
}

// Current scrypt cost parameters for newly written password hashes.
//
// 2^17 is 128 MiB and roughly 200 ms of a core — the standard recommendation for
// an interactive login, and about 8x the work per guess of the previous 16 MiB
// setting for anyone who steals users.json.
//
// The cost is paid on every login attempt, including attempts against usernames
// that do not exist (equalizeLoginTiming, so timing cannot enumerate accounts).
// That is only safe because the login endpoint is throttled instance-wide AND
// per-IP AND per-account, and proof-of-work is on by default — see
// api.handleLogin. Do NOT raise this further without checking those bounds
// again: this constant and loginRateRefillPerSec multiply together into the CPU
// an anonymous caller can spend.
//
// Stored hashes carry their own parameters (see verifyScryptHash), so raising
// this does not invalidate anything. NeedsRehash reports which stored hashes are
// below the current cost, and the login path upgrades them on the next
// successful sign-in.
const (
	scryptN      = 1 << 17
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
)

// hashParams are the Argon2id cost parameters for every new hash. RFC 9106's
// second option (64 MiB, t=3, p=4); the library's budget bounds how many run
// at once and kdfSlots bounds it again inside this process.
var hashParams = password.DefaultParams()

// HashParams reports the Argon2id cost parameters new hashes are currently
// written with. Callers that cache a derived value whose cost has to match a
// real account's — see api.timingDummyHash — key that cache on this, not on
// HashCostN: that reports the unrelated legacy-scrypt fixture cost.
func HashParams() password.Params { return hashParams }

// SetHashParamsForTest lowers the Argon2id cost so a test suite that mints
// hundreds of hashes finishes. Refuses outside a test binary and refuses
// parameters the library would not verify.
func SetHashParamsForTest(p password.Params) (restore func()) {
	if !testing.Testing() { // same guard SetHashCostForTest uses
		panic("users.SetHashParamsForTest called outside a test binary")
	}
	if err := p.Validate(); err != nil {
		panic(fmt.Sprintf("users.SetHashParamsForTest: %v", err))
	}
	previous := hashParams
	hashParams = p
	return func() { hashParams = previous }
}

// mapBusy turns the library's admission error into this package's, so every
// caller keeps one error to check.
func mapBusy(err error) error {
	if errors.Is(err, password.ErrBusy) {
		return fmt.Errorf("%w: %v", ErrKDFBusy, err)
	}
	return err
}

// verifyHash checks candidate against whichever format encoded is in. Argon2id
// is what this package writes now; scrypt$ is what it wrote before and stays
// verifiable until the account rehashes on its next login. Anything else is
// false, never an error: an unreadable stored hash is a wrong credential, not
// an unchecked one.
func verifyHash(ctx context.Context, encoded, candidate string) (bool, error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		var (
			ok  bool
			err error
		)
		if slotErr := withKDFSlot(ctx, func() {
			ok, err = password.Verify(candidate, encoded)
		}); slotErr != nil {
			return false, slotErr
		}
		if errors.Is(err, password.ErrMalformed) {
			return false, nil
		}
		return ok, mapBusy(err)
	case strings.HasPrefix(encoded, "scrypt$"):
		return verifyScryptHash(ctx, encoded, candidate)
	}
	return false, nil
}

// hashCostN is the N that LegacyScryptHashForTest mints scrypt fixtures at
// (via hashScrypt). It is scryptN everywhere except under SetHashCostForTest.
// New hashes are written by HashPassword, which uses hashParams (Argon2id),
// not this, and NeedsRehash no longer reads it either: every scrypt hash now
// reports true unconditionally, since the format itself is retired rather
// than compared against a live cost floor.
var hashCostN = scryptN

// HashCostN reports the N LegacyScryptHashForTest currently mints scrypt
// fixtures at. It has nothing to do with the cost of a real account's hash —
// see HashParams for that.
func HashCostN() int { return hashCostN }

// MinVerifiableScryptN is the weakest N verifyScryptHash will accept. A hash
// written below it can never be verified again, so nothing may mint one,
// including tests. Exported so SetHashCostForTest can refuse such a cost.
const MinVerifiableScryptN = 1 << 14

// ProductionScryptN is the cost real password hashes are written at. Exported so
// tests whose subject is the cost can restore it by name: a hardcoded 1<<17 in a
// test helper stops meaning "production" the moment scryptN is raised.
const ProductionScryptN = scryptN

// SetHashCostForTest lowers the cost of the legacy scrypt hashes tests mint
// through LegacyScryptHashForTest, and returns a function that restores it:
// 128 MiB and ~200 ms per derivation is ruinous for a test suite that mints
// one to prove the old format still verifies.
//
// It panics outside a test binary. hashCostN only ever feeds hashScrypt, which
// only LegacyScryptHashForTest calls — HashPassword does not touch it, so this
// no longer weakens a real account's hash the way it once did. It is exported
// from a package production code imports regardless, so a stray call from
// non-test code cannot mint a legacy-format fixture weaker than
// MinVerifiableScryptN allows.
//
// It panics below MinVerifiableScryptN, which verifyScryptHash rejects — a lower
// setting mints hashes that can never verify.
//
// Call it from TestMain, before any test starts: it writes a package-level
// variable with no synchronization. Tests that assert production strength, or
// measure the CPU the login budget meters, must run in a package that does not
// apply the override.
func SetHashCostForTest(n int) (restore func()) {
	if !testing.Testing() {
		panic("users.SetHashCostForTest called outside a test binary: this weakens password hashing and must never run in production")
	}
	if n < MinVerifiableScryptN || n&(n-1) != 0 {
		panic(fmt.Sprintf(
			"users.SetHashCostForTest(%d): must be a power of two >= %d, or the hashes it writes can never verify",
			n, MinVerifiableScryptN,
		))
	}
	previous := hashCostN
	hashCostN = n
	return func() { hashCostN = previous }
}

// HashPassword derives an Argon2id PHC hash for a human-chosen secret. Holds
// one derivation slot for the duration (kdf.go) and returns ErrKDFBusy when
// none comes free.
func HashPassword(ctx context.Context, secret string) (string, error) {
	var (
		hash string
		err  error
	)
	if slotErr := withKDFSlot(ctx, func() {
		hash, err = password.HashWith(secret, hashParams)
	}); slotErr != nil {
		return "", slotErr
	}
	return hash, mapBusy(err)
}

// MeasureLegacyVerifyCost times ONE legacy scrypt verification at the cost
// this process mints legacy hashes at — ProductionScryptN in production, and
// whatever SetHashCostForTest lowered it to in a test binary.
//
// It exists so the api layer can floor every credential check at the most
// expensive stored format instead of trying to match its work: an account that
// has not signed in since the Argon2id migration still verifies through
// verifyScryptHash, which costs several times what an Argon2id dummy does, and
// that difference is an account-enumeration oracle on an unauthenticated
// endpoint. Measured rather than declared, because the figure is a property of
// the machine and a constant that reads low on a slow host closes nothing.
//
// The mint and the verify share ONE slot, so the returned duration is the
// derivation and not the queue in front of it. Callers memoize; this is a
// startup cost, not a per-request one.
func MeasureLegacyVerifyCost(ctx context.Context) (time.Duration, error) {
	const probe = "kypost-timing-floor-probe"
	var (
		measured time.Duration
		err      error
	)
	slotErr := WithKDFSlot(ctx, func(ctx context.Context) {
		var hash string
		if hash, err = hashScrypt(ctx, probe); err != nil {
			return
		}
		start := time.Now()
		_, err = verifyScryptHash(ctx, hash, probe)
		measured = time.Since(start)
	})
	if slotErr != nil {
		return 0, slotErr
	}
	return measured, err
}

// LegacyScryptHashForTest mints a scrypt hash so tests can prove the legacy
// verify path still redeems what older installs stored.
func LegacyScryptHashForTest(ctx context.Context, secret string) (string, error) {
	if !testing.Testing() {
		panic("users.LegacyScryptHashForTest called outside a test binary")
	}
	return hashScrypt(ctx, secret)
}

// hashScrypt produces a scrypt-encoded hash string in the same format used
// historically by admin.env's ADMIN_PASS_HASH field.
//
// Holds one of the process-wide derivation slots for the duration, and returns
// ErrKDFBusy if none comes free (see kdf.go). ctx is honoured while queueing,
// so a caller whose client has gone away stops occupying the queue.
func hashScrypt(ctx context.Context, password string) (string, error) {
	var (
		n      = hashCostN
		r      = scryptR
		p      = scryptP
		keyLen = scryptKeyLen
	)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	var (
		hash []byte
		err  error
	)
	if slotErr := withKDFSlot(ctx, func() {
		hash, err = scrypt.Key([]byte(password), salt, n, r, p, keyLen)
	}); slotErr != nil {
		return "", slotErr
	}
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

// verifyScryptHash reports whether candidate derives to encoded.
//
// The (bool, error) split is load-bearing: false means "wrong credential" and
// an error means "not checked". Collapsing the second into the first is what
// turns an overloaded server into a wrong-password answer, and then into a
// lockout for whoever was trying to sign in through the spike.
func verifyScryptHash(ctx context.Context, encoded, candidate string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false, nil
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, nil
	}
	r, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, nil
	}
	p, err := strconv.Atoi(parts[3])
	if err != nil {
		return false, nil
	}
	// Bound the cost parameters: scrypt.Key allocates 128*r*N bytes of whatever it
	// is told, and these come out of a file (users.json, per-user state.json, an
	// operator's ADMIN_PASS_HASH). One bad value asks for terabytes on the next
	// login and OOM-kills the process into a supervisord restart loop; x/crypto's
	// own check only rejects values far above this. The floor is
	// MinVerifiableScryptN so hashes written before the cost was raised still
	// verify; the ceiling is ~1 GB.
	//
	// This bound and the slot below answer different questions and both are
	// needed: this one caps what ONE derivation may allocate, the slot caps how
	// many may allocate at once.
	if n < MinVerifiableScryptN || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 32 || p < 1 || p > 16 {
		return false, nil
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, nil
	}
	expected, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, nil
	}
	if len(expected) == 0 {
		return false, nil
	}
	var derived []byte
	if slotErr := withKDFSlot(ctx, func() {
		derived, err = scrypt.Key([]byte(candidate), salt, n, r, p, len(expected))
	}); slotErr != nil {
		return false, slotErr
	}
	if err != nil {
		return false, nil
	}
	return subtle.ConstantTimeCompare(derived, expected) == 1, nil
}

// argon2VersionSegment is the version segment a hash this package's Argon2id
// dependency actually produced must carry — built from the same
// golang.org/x/crypto/argon2 constant ky-primitives derives with, rather than
// a hardcoded "v=19", so this cannot drift from what the library accepts.
var argon2VersionSegment = fmt.Sprintf("v=%d", argon2.Version)

// NeedsRehash reports whether a stored hash should be re-derived from the
// verified plaintext: every scrypt hash (the format is retired), and an
// Argon2id hash WEAKER THAN hashParams ON ANY AXIS — memory, time, or threads.
// A hash stronger on EVERY axis is left alone. Read the two together: a hash at
// four times the configured memory but one pass instead of three is weaker on
// an axis and is re-derived at the current parameters, which is deliberate and
// is not the same statement as "stronger on any axis is left alone".
//
// There is no overall-strength comparison, because the axes do not trade off
// linearly and nothing in this deployment sets them independently anyway
// (hashParams is a package variable only SetHashParamsForTest writes).
// Malformed or foreign is false; rehashing something this package did not
// write is a guess.
//
// This compares the embedded cost against hashParams itself rather than
// delegating to password.NeedsRehash: that library call measures against its
// own baked-in default, not whatever this process is actually configured to
// write, so it disagrees with reality whenever hashParams differs from
// password.DefaultParams() — which in production it never does, but under
// SetHashParamsForTest it always does. Verified empirically against v0.5.0:
// a hash minted with HashWith at a lowered Params is reported stale by
// password.NeedsRehash even though it exactly matches the cost this process
// currently writes.
func NeedsRehash(encoded string) bool {
	if strings.HasPrefix(encoded, "scrypt$") {
		return true
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != argon2VersionSegment {
		return false
	}
	mem, t, threads, ok := parseArgon2Params(parts[3])
	if !ok {
		return false
	}
	// Out-of-band costs are refused by the library's own band, so a hash
	// carrying one is not a hash password.Verify would read — reporting
	// "upgrade me" about it would make an account that already fails to
	// authenticate look like a working one due for a rehash. Validate() rather
	// than a second copy of the bounds, so this cannot drift from what the
	// library accepts.
	if (password.Params{Memory: mem, Time: t, Threads: threads}).Validate() != nil {
		return false
	}
	return mem < hashParams.Memory || t < hashParams.Time || threads < hashParams.Threads
}

// parseArgon2Params reads "m=<n>,t=<n>,p=<n>" strictly, mirroring
// ky-primitives' unexported parseParams: every field is parsed with strconv,
// then re-rendered in canonical form and compared byte-for-byte against
// segment. A lenient fmt.Sscanf here would accept exactly what the library
// documents rejecting — trailing garbage, a fourth field, leading zeros, a
// leading sign — and NeedsRehash reporting true about a string
// password.Verify would call malformed makes a broken hash look like a
// working account due for an upgrade rather than one that already fails to
// authenticate.
//
// This is only the SHAPE. The library's parseParams also enforces the accepted
// band, and NeedsRehash calls Params.Validate for that; a well-formed
// "m=1024,t=3,p=4" parses here and is refused there.
func parseArgon2Params(segment string) (mem, t uint32, threads uint8, ok bool) {
	fields := strings.Split(segment, ",")
	if len(fields) != 3 {
		return 0, 0, 0, false
	}
	var values [3]uint64
	// Each field is parsed at the bit size of the type it lands in, so the
	// conversions below cannot truncate. p used to be parsed at 32 bits and
	// range-checked afterwards, which is the same behaviour and was flagged as
	// an unchecked narrowing — a bound the parser enforces is one no reader or
	// analyzer has to connect to a separate `if`.
	bits := [3]int{32, 32, 8}
	for i, prefix := range [3]string{"m=", "t=", "p="} {
		if !strings.HasPrefix(fields[i], prefix) {
			return 0, 0, 0, false
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(fields[i], prefix), 10, bits[i])
		if err != nil {
			return 0, 0, 0, false
		}
		values[i] = v
	}
	mem, t, threads = uint32(values[0]), uint32(values[1]), uint8(values[2])
	if canonical := fmt.Sprintf("m=%d,t=%d,p=%d", mem, t, threads); canonical != segment {
		return 0, 0, 0, false
	}
	return mem, t, threads, true
}

// RehashPassword re-derives id's password hash at the current cost parameters,
// given the already-verified plaintext. It verifies the candidate again inside
// the write lock: this function's whole job is overwriting a credential, and
// re-checking under the lock is what makes a bug at the call site fail closed
// instead of setting the account's password to whatever string was passed in.
//
// The NEW hash is derived first, outside mutate. s.mu is the same mutex the
// read cache takes, and mutateGuarded holds a cross-process flock on top of it,
// so everything in that closure stalls api.currentUser — i.e. every
// authenticated request in both processes. Two derivations in there was ~330 ms
// of whole-store stall per rehash, and this path now fires for every account on
// its first sign-in after the Argon2id migration, which is a herd. One
// derivation still runs under the lock, because the fail-closed re-verify has
// to read the hash it is about to replace.
//
// MustChangePassword and every other field are left untouched: this is not a
// password change, and it must be invisible to the user.
func (s *Store) RehashPassword(ctx context.Context, id, verifiedCredential string) error {
	hash, err := HashPassword(ctx, verifiedCredential)
	if err != nil {
		return err
	}
	_, err = s.mutate(id, func(u *User) error {
		// Whichever credential form this account stores, chosen explicitly.
		// VerifyPassword refuses derived-auth accounts by design, so the branch
		// is required rather than defensive — and written as if/else so the
		// correctness is local instead of resting on that refusal.
		var (
			ok  bool
			err error
		)
		if u.UsesDerivedAuth() {
			ok, err = VerifyAuthSecret(ctx, *u, verifiedCredential)
		} else {
			ok, err = VerifyPassword(ctx, *u, verifiedCredential)
		}
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("refusing to rehash: candidate does not match the stored hash")
		}
		if !NeedsRehash(u.PasswordHash) {
			return nil
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

// MinAuthSecretHexLen is the shortest client-derived auth secret this store will
// accept, as hex. The server can no longer measure the password's length — that
// is the point — so it measures what it does receive: the browser derives 32
// bytes (64 hex chars), and anything shorter is a client that is not doing the
// derivation. MinPasswordLen is enforced in the browser before derivation, and
// by this store on every path where it still sees a plaintext password.
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

// SSOLinkRevoked reports whether this account's linked identity has been cut off
// as a credential. The subject is still stored — it is how directory sync
// addresses the account — but no login may be resolved through it until the user
// re-authorizes the link.
func (u User) SSOLinkRevoked() bool {
	return u.SSOSub != "" && u.SSOLinkRevokedAt != 0
}

// HasLocalCredential reports whether this account stores a password or derived
// auth secret of its own. An auto-provisioned SSO account has neither: its link
// is not a bypass of some other credential, it is the only one. Nothing may
// revoke that link, because there is no way back in afterwards — a re-link needs
// a step-up, and a step-up needs the credential this account does not have.
func (u User) HasLocalCredential() bool {
	return u.PasswordHash != ""
}

// VerifyAuthSecret checks a client-derived auth secret against u's stored hash.
// Separate from VerifyPassword so no call site can accidentally accept a
// plaintext password for a derived-auth account, or the reverse: treating a
// derived secret as a password would let anyone who read the salt off the public
// login-params endpoint authenticate with it.
func VerifyAuthSecret(ctx context.Context, u User, candidate string) (bool, error) {
	if !u.UsesDerivedAuth() {
		return false, nil
	}
	return verifyHash(ctx, u.PasswordHash, candidate)
}

// SetDerivedAuth replaces id's credential with a client-derived auth secret,
// recording the salt and iteration count the client used so a later login can
// reproduce it. requireChange mirrors SetPassword's flag. The PGP-key envelope
// is written in the same mutation when rewrapped is non-empty — see
// SetDerivedAuthAndRewrapPGP.
func (s *Store) SetDerivedAuth(ctx context.Context, id, authSecret, loginSalt string, iterations int, requireChange bool) (User, error) {
	return s.SetDerivedAuthAndRewrapPGP(ctx, id, authSecret, loginSalt, iterations, requireChange, "")
}

// SetDerivedAuthAndRewrapPGP replaces id's credential AND, when rewrapped is
// non-empty, the client-wrapped PGP private key envelope — both inside one
// mutation, or neither.
//
// The two writes have to be atomic. The envelope is sealed under a key derived
// from the account password, so a password change that lands without the
// matching rewrap leaves it openable only with a password the user no longer
// has — permanently, since a later rewrap re-derives from the CURRENT password.
// The only way back is deleting the identity and losing every message encrypted
// to it.
func (s *Store) SetDerivedAuthAndRewrapPGP(ctx context.Context, id, authSecret, loginSalt string, iterations int, requireChange bool, rewrapped string) (User, error) {
	if err := ValidateAuthSecret(authSecret); err != nil {
		return User{}, err
	}
	if err := validateLoginSalt(loginSalt); err != nil {
		return User{}, err
	}
	if err := validateLoginIterations(iterations); err != nil {
		return User{}, err
	}
	if err := ValidateWrappedEnvelope(rewrapped); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(ctx, authSecret)
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

// MinLoginIterations is the floor on a client-declared PBKDF2 work factor. The
// client chooses it — it does the derivation — so the server bounds it. Without
// a floor a modified or downgraded client could declare 1 iteration and register
// a credential derived at effectively no cost, indistinguishable downstream from
// a proper one.
const MinLoginIterations = 100_000

// MaxLoginIterations is the ceiling, and it exists for the opposite reason to
// the floor.
//
// This value is not a cost the server pays; it is a cost the BROWSER pays, on
// every sign-in, forever, because the credential is pinned to whatever was
// stored here. A client that declares 10^12 does not attack the server — it
// bricks the account, and the account cannot be fixed from the client that can
// no longer sign in to it.
//
// It must equal MAX_ITERATIONS in frontend/src/lib/authSecret.ts, which refuses
// to derive above it. That was the whole bug: the server enforced only the
// floor, so it would happily store a work factor its own client then rejected
// as unsupported, and the two halves of one contract disagreed about which
// credentials were usable. TestLoginIterationCeilingMatchesFrontend pins them
// together.
const MaxLoginIterations = 12_000_000

// validateLoginIterations bounds a client-declared work factor at both ends.
// One function so the two write paths — SetDerivedAuthAndRewrapPGP and
// UpgradeToDerivedAuth — cannot drift, which is exactly how the ceiling came to
// be missing from both.
func validateLoginIterations(iterations int) error {
	if iterations < MinLoginIterations {
		return fmt.Errorf("login iterations must be at least %d", MinLoginIterations)
	}
	if iterations > MaxLoginIterations {
		return fmt.Errorf("login iterations must be at most %d", MaxLoginIterations)
	}
	return nil
}

// MinLoginSaltBytes and MaxLoginSaltBytes bound the DECODED salt.
//
// The frontend calls atob() on this value before deriving, so a salt that is
// not valid base64 does not produce a weaker credential — it produces a client
// that throws on sign-in for an account that has no other way in. Both salts
// this server ever issues (newLoginSalt in the browser, syntheticLoginSalt on
// the server) are 16 bytes, so the range is generous in both directions and
// exists to reject shapes, not to second-guess sizes.
const (
	MinLoginSaltBytes = 16
	MaxLoginSaltBytes = 64
)

// validateLoginSalt checks that salt is the base64 the client will try to
// decode, at a length that could plausibly be a salt.
func validateLoginSalt(salt string) error {
	salt = strings.TrimSpace(salt)
	if salt == "" {
		return errors.New("login salt is required for derived auth")
	}
	raw, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return errors.New("login salt must be standard base64")
	}
	if len(raw) < MinLoginSaltBytes || len(raw) > MaxLoginSaltBytes {
		return fmt.Errorf("login salt must decode to between %d and %d bytes", MinLoginSaltBytes, MaxLoginSaltBytes)
	}
	return nil
}

// UpgradeToDerivedAuth converts a legacy account to client-derived auth after a
// successful legacy login, given the auth secret the client derived alongside
// the password it just proved — the only moment both credentials are in hand at
// once. It verifies the plaintext again inside the write lock so a bug at the
// call site fails closed rather than pinning the account to a caller-supplied
// secret. A no-op for an account that has already upgraded, so a racing second
// login cannot downgrade it.
func (s *Store) UpgradeToDerivedAuth(ctx context.Context, id, verifiedPassword, authSecret, loginSalt string, iterations int) error {
	if err := ValidateAuthSecret(authSecret); err != nil {
		return err
	}
	if err := validateLoginSalt(loginSalt); err != nil {
		return err
	}
	if err := validateLoginIterations(iterations); err != nil {
		return err
	}
	hash, err := HashPassword(ctx, authSecret)
	if err != nil {
		return err
	}
	_, err = s.mutate(id, func(u *User) error {
		if u.UsesDerivedAuth() {
			return nil
		}
		ok, verr := VerifyPassword(ctx, *u, verifiedPassword)
		if verr != nil {
			return verr
		}
		if !ok {
			return errors.New("refusing to upgrade auth derivation: password does not match")
		}
		// And the secret must actually BE the derivation of that password.
		//
		// Re-verifying the plaintext proves the caller knows the password; it
		// says nothing about the value being pinned as the new credential. The
		// doc comment above promises this check ("fails closed rather than
		// pinning the account to a caller-supplied secret") and it was never
		// performed, so anyone holding the current password — an admin-issued
		// temporary one, say — could pin the account to a credential of their
		// choosing and lock the owner out, on a login request that returns
		// mfaRequired and never proves a second factor.
		//
		// The server holds the plaintext here, which is the whole reason this
		// is the moment the claim is checkable at all.
		if derr := authSecretMatchesPassword(verifiedPassword, authSecret, loginSalt, iterations); derr != nil {
			return derr
		}
		u.PasswordHash = hash
		u.AuthDerivation = AuthDerivationPBKDF2
		u.LoginSalt = loginSalt
		u.LoginIterations = iterations
		return nil
	})
	return err
}
