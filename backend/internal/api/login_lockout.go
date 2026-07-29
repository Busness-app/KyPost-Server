package api

import (
	"sync"
	"time"

	"kypost-server/backend/internal/users"
)

// loginMaxFailures/loginLockoutFor implement a three-strikes, 15-minute
// cooldown on password login: after loginMaxFailures failed attempts for a
// given username+client IP pair, further attempts for that pair are rejected
// until loginLockoutFor has elapsed. This is independent of whether the
// username actually exists — see failureLockout.allowed — so it can't be
// used to distinguish valid from invalid usernames by lockout behavior; and
// it is scoped to the client IP so failures manufactured by an attacker
// can't lock the account's real owner out from their own machine.
const (
	loginMaxFailures = 3
	loginLockoutFor  = 15 * time.Minute

	// davMaxFailures/davLockoutFor guard the CardDAV Basic Auth surface,
	// keyed by client IP (usernames there are fixed account names, and the
	// password is server-generated — the realistic abuse is one host burning
	// CPU with scrypt verifications, not a credible guessing campaign). The
	// threshold is looser than login's because sync clients legitimately
	// retry a stale password several times before surfacing an error.
	davMaxFailures = 10
	davLockoutFor  = 15 * time.Minute

	// mfaMaxFailures/mfaLockoutFor throttle second-factor verification per
	// account across challenges. The per-challenge attempt cap (mfa.Store) is
	// not enough on its own: a password-holding attacker can mint an unlimited
	// number of fresh challenges (each valid-password login clears the login
	// lockout), so without an account-scoped counter the TOTP code is brute
	// forceable online. Keyed on the challenge's UserID.
	mfaMaxFailures = 10
	mfaLockoutFor  = 15 * time.Minute

	// deviceMaxFailures/deviceLockoutFor guard per-device secret auth
	// (deviceAuthFromRequest). Bounds guessing, not CPU; against a 192-bit
	// random secret the threshold is generous. Keyed on deviceID+clientIP —
	// see deviceLockoutKey, and do not change one without the other.
	deviceMaxFailures = 10
	deviceLockoutFor  = 15 * time.Minute

	// loginLockoutSweepThreshold bounds loginLockout.entries. A stream of
	// distinct nonexistent usernames each gets an entry that never reaches the
	// lockout threshold and is otherwise never removed. Past this size,
	// not-currently-locked entries are swept inline; locked ones — the only
	// ones worth remembering — are kept.
	loginLockoutSweepThreshold = 10_000
)

type loginLockoutEntry struct {
	failures    int
	lockedUntil time.Time
}

// failureLockout is small in-memory, keyed strike/cooldown state: after
// maxFailures failed attempts for a key, further attempts for that key are
// rejected until lockoutFor has elapsed. handleLogin keys it by
// username+client IP; withDAVBasicAuth keys it by client IP alone. It
// intentionally lives outside Server.sessions/mu — it's unrelated state with
// its own, much smaller lock scope.
type failureLockout struct {
	mu          sync.Mutex
	maxFailures int
	lockoutFor  time.Duration
	entries     map[string]*loginLockoutEntry
}

func newFailureLockout(maxFailures int, lockoutFor time.Duration) *failureLockout {
	return &failureLockout{
		maxFailures: maxFailures,
		lockoutFor:  lockoutFor,
		entries:     map[string]*loginLockoutEntry{},
	}
}

func newLoginLockout() *failureLockout {
	return newFailureLockout(loginMaxFailures, loginLockoutFor)
}

// tryAttempt reports whether username may attempt right now and, if so, spends
// one strike in the same critical section.
//
// Reserving at check time is the point: checking at the top of a handler and
// recording after the credential check lets a concurrent burst all observe
// "allowed" before any has recorded, and sail past the budget together
// (measured at ~7x the login budget). Do not split these two steps.
//
// The caller settles the reservation:
//
//   - recordSuccess on a correct credential, clearing the whole entry
//   - cancelAttempt on a path that never became a credential check (see its
//     doc), returning the strike
//   - nothing at all on a failure — the strike is already counted
func (l *failureLockout) tryAttempt(username string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepIfCrowdedLocked()

	e, exists := l.entries[username]
	if !exists {
		e = &loginLockoutEntry{}
		l.entries[username] = e
	} else if remaining := time.Until(e.lockedUntil); remaining > 0 {
		return false, remaining
	} else if !e.lockedUntil.IsZero() {
		// The lockout ran its course; start a fresh set of strikes rather than
		// leaving the old ones to trip the very next attempt.
		e.failures = 0
		e.lockedUntil = time.Time{}
	}

	e.failures++
	if e.failures >= l.maxFailures {
		e.lockedUntil = time.Now().Add(l.lockoutFor)
	}
	return true, 0
}

// cancelAttempt returns a strike reserved by tryAttempt, for a path that turned
// out not to be a credential attempt at all — e.g. a CAPTCHA provider outage,
// where the user never got as far as offering a password and counting it would
// lock out every user of the instance for the duration.
//
// A FAILED captcha is deliberately not cancelled; that is an attempt.
func (l *failureLockout) cancelAttempt(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, exists := l.entries[username]
	if !exists {
		return
	}
	if e.failures > 0 {
		e.failures--
	}
	if e.failures < l.maxFailures {
		e.lockedUntil = time.Time{}
	}
	// Never let cancels accumulate into credit for extra attempts: an entry
	// back at zero is simply gone.
	if e.failures == 0 {
		delete(l.entries, username)
	}
}

// allowed reports whether username may attempt right now WITHOUT spending a
// strike. Read-only; use tryAttempt on any path that is about to make an
// attempt.
func (l *failureLockout) allowed(username string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, exists := l.entries[username]
	if !exists {
		return true, 0
	}
	if remaining := time.Until(e.lockedUntil); remaining > 0 {
		return false, remaining
	}
	return true, 0
}

// sweepIfCrowdedLocked drops entries that are not currently locked out once the
// map grows past the threshold, bounding it without a background goroutine.
// Callers must hold l.mu.
func (l *failureLockout) sweepIfCrowdedLocked() {
	if len(l.entries) < loginLockoutSweepThreshold {
		return
	}
	now := time.Now()
	for k, e := range l.entries {
		if e.lockedUntil.IsZero() || !now.Before(e.lockedUntil) {
			delete(l.entries, k)
		}
	}
}

// recordSuccess clears any strike history for username, so a successful
// login always starts the next set of attempts with a clean slate.
func (l *failureLockout) recordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}

const (
	// timingDummyHash is a precomputed scrypt hash used to equalize login
	// timing regardless of whether the account exists. It's a valid
	// scrypt(n=16384,r=8,p=1) hash of "kypost-timing-equalization-dummy"
	// with a fixed salt, hardcoded to avoid any runtime cost/variance in
	// computing the dummy hash.
	timingDummyHash = "scrypt$16384$8$1$WKzJYfE9CiMdmMrc+JFGzA==$xF16zj/zU2Y8NeGHTbs/wNF8iRSncahxdDCzZw0q34U="
)

// equalizeLoginTiming verifies candidate against a throwaway scrypt hash so
// the unknown-username (and inactive-account) login path costs the same as a
// real wrong-password check. The dummy hash is precomputed; its plaintext is
// irrelevant because the verification is only ever expected to fail.
func equalizeLoginTiming(candidate string) {
	users.VerifySecretHash(timingDummyHash, candidate)
}
