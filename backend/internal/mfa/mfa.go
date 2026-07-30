// Package mfa holds the multi-factor-auth business logic that is independent
// of net/http: the in-memory login-challenge store, recovery-code generation,
// and TOTP-secret sealing on top of cryptutil.
package mfa

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"kypost-server/backend/internal/cryptutil"
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
const (
	PushPending  = "pending"
	PushApproved = "approved"
	PushDenied   = "denied"
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
	// MatchAttempts counts wrong digits submitted against this challenge, so a
	// two-digit space cannot be brute-forced within the TTL.
	MatchAttempts int
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

// Create mints a new challenge for userID with a fresh random ID.
func (s *Store) Create(userID string) (Challenge, error) {
	idBytes := make([]byte, 24)
	if _, err := rand.Read(idBytes); err != nil {
		return Challenge{}, err
	}
	matchDigits, decoyDigits, err := newNumberMatch()
	if err != nil {
		return Challenge{}, err
	}
	now := time.Now()
	ch := Challenge{
		ID:          hex.EncodeToString(idBytes),
		UserID:      userID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(challengeTTL),
		MatchDigits: matchDigits,
		DecoyDigits: decoyDigits,
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
// a browser that is about to call ConsumePushApproval, and a denied one is a
// decision the user already made; deleting either would discard a real answer.
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
		if ch.PushStatus == PushApproved || ch.PushStatus == PushDenied {
			continue
		}
		delete(s.m, id)
		superseded++
	}
	return superseded
}

// PushStatus returns the current push status for a live challenge: "pending",
// "approved", or "denied". ok=false means missing or expired (caller should
// treat as "expired"). It is in-memory only — cheap enough to poll frequently.
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

// ResolvePush records the first approve/deny decision for a push challenge and
// the device that made it. First response wins: once a decision exists, a
// later call returns that decision together with ErrChallengeAlreadyResolved
// rather than overwriting it.
func (s *Store) ResolvePush(id, deviceID string, approve bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", ErrChallengeNotFound
	}
	if ch.PushStatus == PushApproved || ch.PushStatus == PushDenied {
		return ch.PushStatus, ErrChallengeAlreadyResolved
	}
	if approve {
		ch.PushStatus = PushApproved
	} else {
		ch.PushStatus = PushDenied
	}
	ch.RespondedBy = deviceID
	s.m[id] = ch
	return ch.PushStatus, nil
}

// ConsumePushApproval atomically verifies the challenge is approved and, if so,
// deletes it (single-use, mirroring the TOTP path) and returns its UserID.
// Returns ErrChallengeNotFound if missing/expired, ErrPushNotApproved if the
// challenge is still pending or was denied.
func (s *Store) ConsumePushApproval(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.m[id]
	if !ok || time.Now().After(ch.ExpiresAt) {
		delete(s.m, id)
		return "", ErrChallengeNotFound
	}
	if ch.PushStatus != PushApproved {
		return "", ErrPushNotApproved
	}
	delete(s.m, id)
	return ch.UserID, nil
}

// recoveryAlphabet has exactly 32 characters so a random byte modulo 32 is
// unbiased. It does not avoid visually ambiguous characters (e.g. i/l/o vs
// 1/0) since codes are copy/pasted, not transcribed by hand.
const recoveryAlphabet = "0123456789abcdefghijklmnopqrstuv"

// GenerateRecoveryCodes returns n one-time recovery codes formatted
// xxxx-xxxx-xxxx using crypto/rand.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 12) // 3 groups of 4 chars
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		chars := make([]byte, 12)
		for j, b := range raw {
			chars[j] = recoveryAlphabet[int(b)%len(recoveryAlphabet)]
		}
		codes = append(codes, string(chars[0:4])+"-"+string(chars[4:8])+"-"+string(chars[8:12]))
	}
	return codes, nil
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
