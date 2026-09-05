// Package mfa holds the multi-factor-auth business logic that is independent
// of net/http: the in-memory login-challenge store, recovery-code generation,
// and TOTP-secret sealing on top of cryptutil.
package mfa

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/recoverycode"
	"github.com/Busness-app/kypost-server/backend/internal/cryptutil"
)

// MaxTOTPAttempts is the number of failed second-factor attempts tolerated on
// a single login challenge before it is invalidated.
const MaxTOTPAttempts = 5

// challengeTTL is how long a login challenge stays valid after password
// verification while the user produces their second factor.
const challengeTTL = 5 * time.Minute

var (
	ErrChallengeNotFound = errors.New("mfa: challenge not found")
	ErrTooManyAttempts   = errors.New("mfa: too many attempts")

	// ErrChallengeAlreadyUsed indicates a TOTP code was already consumed
	// against this challenge — returned by ConsumeTOTPStep on a replay
	// attempt.
	ErrChallengeAlreadyUsed = errors.New("mfa: challenge already used")

	// ErrChallengeAlreadyResolved is returned by ResolvePush when a push
	// challenge already has an approve/deny decision (first response wins).
	ErrChallengeAlreadyResolved = errors.New("mfa: challenge already resolved")

	// ErrPushNotApproved is returned by ConsumePushApproval when the challenge
	// is still pending or was denied.
	ErrPushNotApproved = errors.New("mfa: challenge not approved")
)

// Push-challenge status values. An empty stored status is treated as pending.
//
// PushLocked is a terminal state distinct from PushDenied: the approving device
// answered with the wrong number, so the push channel for this challenge is shut
// and the sign-in must finish on TOTP. It is not "denied" because nobody refused
// the sign-in, and the browser must be able to tell the two apart — a denial
// means "that was not me", a lock means "that tap did not match, use your
// authenticator".
const (
	PushPending  = "pending"
	PushApproved = "approved"
	PushDenied   = "denied"
	PushLocked   = "locked"
)

// Challenge is an in-progress second-factor login. It exists between a
// successful password check and a successful (or exhausted) second factor.
// The same struct serves both TOTP and push: TOTP uses TOTPAttempts/
// UsedTOTPStep; push uses PushStatus/RespondedBy. A challenge may offer both.
type Challenge struct {
	ID           string
	UserID       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	TOTPAttempts int
	UsedTOTPStep int64
	// PushStatus is "", "pending", "approved", or "denied" ("" == pending).
	PushStatus string
	// RespondedBy is the deviceID that resolved the push challenge.
	RespondedBy string

	// MatchDigits is the two-digit number shown in the browser that started
	// this login, which the approving device must send back. DecoyDigits are
	// the other values that device offers alongside it.
	//
	// This is the anti-fatigue control. Approval was already cryptographically
	// sound — device credentials, user binding, a live PushMFAEnabled check —
	// but a challenge that carries only its own id asks the human to approve
	// with no way to tell their own sign-in from an attacker's, which is
	// exactly what an MFA-fatigue attack relies on. Requiring a number that
	// only someone looking at the real browser can read makes a blind "yes"
	// impossible.
	//
	// Generated and verified server-side. A client-side comparison would be
	// theatre: the endpoint is reachable by anyone holding device credentials.
	MatchDigits string
	DecoyDigits []string
	// MatchAttempts counts wrong digits submitted against this challenge. The
	// budget is one: the first wrong number locks push for this challenge (see
	// maxMatchAttempts).
	MatchAttempts int

	// FinishSecret is what proves a caller of ConsumePushApproval is the
	// browser that started this sign-in. It is handed to that browser in the
	// login response and to nobody else.
	//
	// The ID cannot serve: it travels in the push payload, so the relay
	// operator and FCM/APNs all read it, and an approved challenge redeemed on
	// the ID alone mints a full session. Whoever holds the notification only
	// has to poll until the real user taps Approve and then call /finish first.
	// Number matching does not cover this — the attacker never answers it, they
	// ride the genuine user's correct approval. The secret never enters the
	// payload, so no hop of the notification path can redeem the approval it
	// carries.
	FinishSecret string
}

// Store is a concurrency-safe in-memory challenge map.
//
// Entries are dropped on access when expired, but that alone was never enough:
// a challenge nobody ever comes back for is never accessed, so it was never
// swept. Every abandoned second-factor login — the user closes the tab, the
// push is never answered — pinned an entry for the process lifetime, and an
// attacker holding a stolen password but not the second factor (precisely the
// case MFA exists for) could mint them at will, since every correct password
// clears the login lockout and Create runs before any second factor. scrypt's
// cost on the login path bounds the rate, so it is a slow leak rather than a
// fast OOM, but nothing bounded the total.
//
// SweepExpired is the missing half. Every other bounded map in this codebase
// already had one (api's sessions, loginLockout, nativePairingNonces,
// qrTokenGuard, sendAsCooldown, pickupStore); this was the only holdout.
type Store struct {
	mu sync.Mutex
	m  map[string]Challenge
}

func NewStore() *Store {
	return &Store{m: map[string]Challenge{}}
}

// SweepExpired drops every challenge past its TTL and reports how many went.
// Driven by api.Server.StartMFAChallengeSweeper; separate from the ticker so
// tests can run one sweep without waiting out an interval.
func (s *Store) SweepExpired(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, ch := range s.m {
		if now.After(ch.ExpiresAt) {
			delete(s.m, id)
			removed++
		}
	}
	return removed
}

// Len reports how many challenges are currently held. Exists for the sweeper's
// tests, which otherwise cannot observe the map at all from outside.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Create mints a new challenge for userID with a fresh random ID and a fresh
// random FinishSecret.
func (s *Store) Create(userID string) (Challenge, error) {
	idBytes := make([]byte, 24)
	if _, err := rand.Read(idBytes); err != nil {
		return Challenge{}, err
	}
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		return Challenge{}, err
	}
	matchDigits, decoyDigits, err := newNumberMatch()
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now()
	ch := Challenge{
		ID:           hex.EncodeToString(idBytes),
		UserID:       userID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(challengeTTL),
		MatchDigits:  matchDigits,
		DecoyDigits:  decoyDigits,
		FinishSecret: hex.EncodeToString(secretBytes),
	}
	s.mu.Lock()
	s.m[ch.ID] = ch
	s.mu.Unlock()
	return ch, nil
}

// Get returns the live challenge for id, lazily deleting and reporting
// ok=false if it is missing or expired.
func (s *Store) Get(id string) (Challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok {
		return Challenge{}, false
	}
	if time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return Challenge{}, false
	}
	return ch, true
}

// RecordTOTPAttempt increments the failed-attempt counter. It returns
// ErrChallengeNotFound when the challenge is unknown or expired, and
// ErrTooManyAttempts (after deleting the challenge) once the count exceeds
// MaxTOTPAttempts.
func (s *Store) RecordTOTPAttempt(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return ErrChallengeNotFound
	}
	ch.TOTPAttempts++
	if ch.TOTPAttempts > MaxTOTPAttempts {
		delete(s.m, id)
		return ErrTooManyAttempts
	}
	s.m[id] = ch
	return nil
}

// ConsumeTOTPStep atomically checks whether this challenge has already had a
// TOTP step consumed and, if not, marks it consumed with step in the same
// locked critical section. Callers must call this only after totp.Validate
// has confirmed step is a currently-valid code — ConsumeTOTPStep itself does
// not validate the code, it only enforces single-use. Doing the check and the
// write under one lock (rather than a separate Get + later RecordTOTPStep)
// closes a TOCTOU window where two concurrent requests bearing the same valid
// code could otherwise both pass a stale "not yet used" check before either
// recorded its use.
func (s *Store) ConsumeTOTPStep(id string, step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return ErrChallengeNotFound
	}
	if ch.UsedTOTPStep != 0 {
		return ErrChallengeAlreadyUsed
	}
	ch.UsedTOTPStep = step
	s.m[id] = ch
	return nil
}

// Delete removes a challenge (called on success or lockout).
func (s *Store) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// DeleteByUser removes every live challenge belonging to userID. Used when
// an admin clears a user's MFA: without this, a challenge already approved
// (but not yet finished) before the clear would still be redeemable via
// ConsumePushApproval until it naturally expired, even though the account's
// PushMFAEnabled bit had already been turned off underneath it.
func (s *Store) DeleteByUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ch := range s.m {
		if ch.UserID == userID {
			delete(s.m, id)
		}
	}
}

// SupersedeUnansweredPush deletes userID's still-unanswered push challenges,
// skipping exceptID, and reports how many went.
//
// Called when a new push challenge is about to be dispatched for the same
// account, so that at most one challenge is ever both pushed and answerable.
// Without it, each login attempt minted another challenge while the cap on push
// dispatch meant only one of them had actually been delivered — so a browser
// could sit polling a challenge id that no device had ever been told about,
// which is what made push MFA appear to stop working after the first sign-in.
//
// Only *unanswered* ones. An approved-but-not-yet-consumed challenge belongs to
// a browser that is about to call ConsumePushApproval, a denied one is a
// decision the user already made, and a locked one is a browser that has just
// been handed the TOTP fallback and is still using this challenge id to redeem
// it; deleting any of the three would discard a real answer or strand the
// failover.
// Superseding an unanswered challenge does cancel whatever earlier attempt was
// still waiting on it, and that is the intended trade: that attempt had no
// reachable notification behind it anyway, and its poll now reports "expired"
// instead of hanging until the TTL runs out.
func (s *Store) SupersedeUnansweredPush(userID, exceptID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	superseded := 0
	for id, ch := range s.m {
		if ch.UserID != userID || id == exceptID {
			continue
		}
		if isPushResolved(ch.PushStatus) {
			continue
		}
		delete(s.m, id)
		superseded++
	}
	return superseded
}

// isPushResolved reports whether a stored status is terminal — a real answer
// that must not be overwritten, superseded, or retried.
//
// One definition, because the three call sites that ask this question have to
// agree. ResolvePushWithMatch refusing to overwrite a status that
// SupersedeUnansweredPush is willing to delete is how a resolved challenge
// becomes reopenable.
func isPushResolved(status string) bool {
	switch status {
	case PushApproved, PushDenied, PushLocked:
		return true
	}
	return false
}

// PushStatus returns the current push status for a live challenge: "pending",
// "approved", "denied", or "locked". ok=false means missing or expired (caller
// should treat as "expired"). It is in-memory only — cheap enough to poll
// frequently.
func (s *Store) PushStatus(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", false
	}
	if ch.PushStatus == "" {
		return PushPending, true
	}
	return ch.PushStatus, true
}

// ConsumePushApproval atomically verifies the challenge is approved and that
// the caller holds its FinishSecret and, if so, deletes it (single-use,
// mirroring the TOTP path) and returns its UserID. Returns ErrChallengeNotFound
// if missing/expired, ErrPushNotApproved if the challenge is still pending or
// was denied.
//
// A wrong secret reports ErrChallengeNotFound and leaves the challenge intact:
// it is not this caller's challenge to resolve, and the browser that owns it
// must still be able to redeem its own approval.
func (s *Store) ConsumePushApproval(id, secret string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", ErrChallengeNotFound
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(ch.FinishSecret)) != 1 {
		return "", ErrChallengeNotFound
	}
	if ch.PushStatus != PushApproved {
		return "", ErrPushNotApproved
	}
	delete(s.m, id)
	return ch.UserID, nil
}

// GenerateRecoveryCodes returns n one-time codes formatted xxxx-xxxx-xxxx.
func GenerateRecoveryCodes(n int) ([]string, error) {
	return recoverycode.Generate(n)
}

// recoveryCodeDigestInfo domain-separates the recovery-code MAC key from every
// other use of the master key it is derived from.
const recoveryCodeDigestInfo = "kypost:recovery-code:v1"

// NewRecoveryCodeDigester reads the master key at keyPath ONCE and returns what
// turns a recovery code into the entry the store keeps: HMAC-SHA256 of the
// normalised code under an HKDF-SHA256 subkey of that master key, hex.
// Normalising first means what the user types and what was stored cannot
// disagree on case or dashes.
//
// Keyed, not bare. A code is 60 bits (twelve symbols over recoverycode.Alphabet),
// which is out of reach ONLINE — mfaLockout caps that at ten attempts per
// account per fifteen minutes — and squarely within reach offline: an unsalted
// SHA-256 over that space is GPU-days against one account's ten digests, and a
// redeemed code is a full second-factor bypass. The key lives in SECRET_DIR,
// a different volume from users.json, so a copy of the config volume alone
// still contains no usable second factor. That is the property a password KDF
// was buying here, at none of its cost — the ten 128 MiB derivations per
// regeneration are still gone.
//
// The key is read once per process, not per call: this is the redeem path.
// Callers hold the returned function for the process's life.
func NewRecoveryCodeDigester(keyPath string) (func(string) string, error) {
	master, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, master, nil, recoveryCodeDigestInfo, sha256.Size)
	if err != nil {
		return nil, err
	}
	return func(code string) string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(recoverycode.Normalize(code)))
		return hex.EncodeToString(m.Sum(nil))
	}, nil
}

// SealTOTPSecret AES-GCM seals base32Secret with the key at keyPath (creating
// the key on first use) and returns the JSON envelope as a string, ready to
// store on User.TOTPSecretEnc.
func SealTOTPSecret(base32Secret, keyPath string) (string, error) {
	return cryptutil.SealString(base32Secret, keyPath)
}

// OpenTOTPSecret reverses SealTOTPSecret, returning the base32 secret.
func OpenTOTPSecret(enc, keyPath string) (string, error) {
	return cryptutil.OpenString(enc, keyPath, errors.New("mfa: totp secret is not a valid envelope"))
}
