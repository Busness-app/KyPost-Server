package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"kypost-server/backend/internal/users"
)

// loginMaxFailures/loginLockoutFor implement a three-strikes, 15-minute cooldown
// on password login: after loginMaxFailures failed attempts for a given
// username+client IP pair, further attempts for that pair are rejected until
// loginLockoutFor has elapsed. Independent of whether the username exists (see
// failureLockout.allowed) so lockout behavior cannot distinguish valid
// usernames, and scoped to the client IP so failures manufactured by an attacker
// cannot lock the account's real owner out from their own machine.
const (
	loginMaxFailures = 3
	loginLockoutFor  = 15 * time.Minute

	// davMaxFailures/davLockoutFor guard the CardDAV Basic Auth surface, keyed by
	// client IP: usernames there are fixed account names and the password is
	// server-generated, so the realistic abuse is one host burning CPU with scrypt
	// verifications. Looser than login's because sync clients legitimately retry a
	// stale password several times before surfacing an error.
	davMaxFailures = 10
	davLockoutFor  = 15 * time.Minute

	// mfaMaxFailures/mfaLockoutFor throttle second-factor verification per account
	// across challenges, keyed on the challenge's UserID. The per-challenge attempt
	// cap (mfa.Store) is not enough on its own: a password-holding attacker can mint
	// unlimited fresh challenges, so without an account-scoped counter the TOTP code
	// is brute forceable online.
	mfaMaxFailures = 10
	mfaLockoutFor  = 15 * time.Minute

	// passwordChangeMaxFailures/passwordChangeLockoutFor throttle the
	// current-credential check on POST /api/auth/password — see
	// handleChangePassword. A session is not proof of the password, so a stolen
	// cookie must not buy unlimited guesses at an endpoint that answers definitively
	// and pays a full scrypt per attempt. Looser than login's three strikes because
	// mistyping the current password while changing it is ordinary.
	//
	// Keyed on the acting account AND the client IP: on the user ID alone, a thief
	// holding the cookie burns the budget from their own machine and locks the real
	// owner out of changing their password — the control becomes the attack.
	passwordChangeMaxFailures = 10
	passwordChangeLockoutFor  = 15 * time.Minute

	// deviceMaxFailures/deviceLockoutFor guard per-device secret auth
	// (deviceAuthFromRequest). Bounds guessing, not CPU; against a 192-bit
	// random secret the threshold is generous. Keyed on deviceID+clientIP —
	// see deviceLockoutKey, and do not change one without the other.
	deviceMaxFailures = 10
	deviceLockoutFor  = 15 * time.Minute

	// loginLockoutSweepThreshold is the size at which sweepIfCrowdedLocked runs
	// inline. A stream of distinct nonexistent usernames each gets an entry that
	// never reaches the lockout threshold and is otherwise never removed. Past
	// this size, not-currently-locked entries are swept.
	loginLockoutSweepThreshold = 10_000
	// loginLockoutHardCap is the size past which NEW keys are shed rather than
	// admitted. Live lockouts are never evicted to make room.
	//
	// Evicting them is a lockout bypass, not a memory trade: with locked entries
	// swept first, an attacker wanting more guesses at one account only has to push
	// the table past this cap with rotating keys and their target's cooldown goes in
	// the first tranche.
	//
	// Shedding is fail-CLOSED. A saturated table refuses to track new keys — a 429
	// outage for new sign-ins — but every lockout already in force stays in force.
	// An outage is visible and ends when the flood does; silently unlocking accounts
	// under load is invisible and is what the flood is for.
	//
	// Reaching this takes an attack: the login path is metered instance-wide in
	// seconds of derivation work (loginKDFDutyCycle), roughly one attempt a second,
	// so lockoutFor buys an attacker on the order of a thousand keys.
	loginLockoutHardCap = 50_000
	// maxLockoutKeyComponentBytes bounds the caller-supplied half of a lockout
	// key.
	//
	// loginLockoutHardCap bounds how MANY entries the table holds; nothing
	// bounded how LARGE each one is. The username reaches the key through
	// users.NormalizeUsername, which folds case and trims but does not truncate,
	// against a 64 KiB request body — so an unauthenticated caller sized the key
	// space directly. At the hard cap that is the difference between ~6 MiB of
	// keys and ~3.1 GiB of them, inside an 8 GiB container shared with Ollama.
	//
	// 128 bytes is far longer than any username the store will accept, so real
	// keys are unaffected and distinct accounts cannot be collided into a shared
	// strike budget by padding — the property the normalisation comment at the
	// key's construction site is protecting.
	maxLockoutKeyComponentBytes = 128
)

// clampLockoutKeyComponent bounds one caller-supplied component of a lockout
// key. Applied at every site that keys a lockout on something a request
// controls, so the bound cannot be forgotten at the next one.
func clampLockoutKeyComponent(s string) string {
	if len(s) <= maxLockoutKeyComponentBytes {
		return s
	}
	return s[:maxLockoutKeyComponentBytes]
}

type loginLockoutEntry struct {
	failures    int
	lockedUntil time.Time
	// lastSeen is when this key last attempted, so the sweep can tell an entry whose
	// strikes have gone stale from one mid-accumulation. With only "is it locked
	// right now?" to go on, the sweep deleted every PARTIAL strike record whenever
	// the table was crowded — flood it past the threshold and no key ever reaches
	// the third strike, so the lockout never engages for anyone.
	lastSeen time.Time
}

// failureLockout is small in-memory, keyed strike/cooldown state: after
// maxFailures failed attempts for a key, further attempts for that key are
// rejected until lockoutFor has elapsed. handleLogin keys it by username+client
// IP; withDAVBasicAuth keys it by client IP alone.
type failureLockout struct {
	mu          sync.Mutex
	maxFailures int
	lockoutFor  time.Duration
	entries     map[string]*loginLockoutEntry
	// lastSweep throttles sweepIfCrowdedLocked. It is O(n) and is called from
	// tryAttempt, so once the table sat above the threshold every single attempt
	// paid a full scan — the attacker choosing how much work each of their requests
	// costs the server.
	lastSweep time.Time
	// saturated records that the table hit loginLockoutHardCap and shed a new
	// key. Cleared when a sweep gets it back under the cap. Read via Saturated.
	saturated bool
}

// sweepMinInterval is the shortest gap between two crowded-table sweeps, so a
// table parked above the threshold does not scan itself on every attempt. The
// hard cap is still enforced immediately regardless (see sweepIfCrowdedLocked)
// — that one is a memory bound and cannot wait.
const sweepMinInterval = time.Second

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
//   - cancelAttempt on a path that never became a credential check
//   - nothing at all on a failure — the strike is already counted
func (l *failureLockout) tryAttempt(username string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.sweepIfCrowdedLocked(now)

	e, exists := l.entries[username]
	if !exists {
		// Saturated: sweeping could not get the table under the cap, so every remaining
		// entry is either locked or mid-accumulation. Shed this new key rather than
		// making room by forgiving one of them — see loginLockoutHardCap. Keys already
		// known to the table proceed normally.
		if len(l.entries) >= loginLockoutHardCap {
			l.saturated = true
			return false, l.lockoutFor
		}
		e = &loginLockoutEntry{}
		l.entries[username] = e
	} else if remaining := e.lockedUntil.Sub(now); remaining > 0 {
		e.lastSeen = now
		return false, remaining
	} else if !e.lockedUntil.IsZero() {
		// The lockout ran its course; start a fresh set of strikes rather than
		// leaving the old ones to trip the very next attempt.
		e.failures = 0
		e.lockedUntil = time.Time{}
	} else if now.Sub(e.lastSeen) >= l.lockoutFor {
		// Partial strikes gone stale. Forgiving them here rather than only in
		// the sweep means the budget behaves the same whether or not the table
		// happened to be crowded enough to sweep.
		e.failures = 0
	}

	e.lastSeen = now
	e.failures++
	if e.failures >= l.maxFailures {
		e.lockedUntil = now.Add(l.lockoutFor)
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

// sweepIfCrowdedLocked bounds the map without a background goroutine. Callers
// must hold l.mu.
//
// It reclaims entries that are neither locked nor mid-accumulation, keying off
// lastSeen and NOT off "is this locked right now" — the latter deleted partial
// strike records, so flooding the table past the threshold erased every real
// key's 1-of-3 and 2-of-3 progress and the lockout stopped engaging at all. An
// entry idle for longer than lockoutFor is safe to drop because its strikes
// would be reset on the next attempt anyway.
//
// Nothing here evicts a LIVE entry. The hard cap is enforced in tryAttempt by
// refusing new keys, so a saturated table denies service instead of forgiving
// lockouts. See loginLockoutHardCap.
func (l *failureLockout) sweepIfCrowdedLocked(now time.Time) {
	if len(l.entries) < loginLockoutSweepThreshold {
		return
	}
	// Throttled unless we are at the hard cap, where the scan is what stands
	// between a transient flood and shedding every new key.
	if len(l.entries) < loginLockoutHardCap && now.Sub(l.lastSweep) < sweepMinInterval {
		return
	}
	l.lastSweep = now

	for k, e := range l.entries {
		locked := !e.lockedUntil.IsZero() && now.Before(e.lockedUntil)
		if locked {
			continue
		}
		if now.Sub(e.lastSeen) >= l.lockoutFor {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < loginLockoutHardCap {
		l.saturated = false
	}
}

// Saturated reports whether the table has had to shed a new key since the last
// time it drained below the hard cap. Surfaced rather than handled silently:
// shedding is a denial of service to every caller the table has not seen before,
// and an operator needs to know the difference between that and their login
// being broken. Read by logSaturatedLockouts.
func (l *failureLockout) Saturated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.saturated
}

// recordSuccess clears any strike history for username, so a successful
// login always starts the next set of attempts with a clean slate.
func (l *failureLockout) recordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}

// timingDummyHash is a scrypt hash used only to equalize login timing, whether
// or not the account exists. Its plaintext is irrelevant — the verification is
// only ever expected to fail, and only its COST matters.
//
// Derived at run time from the CURRENT cost parameters. As a hardcoded
// scrypt$16384$... literal it became cheaper than a real account's hash the
// instant N was raised to 2^17, returning in ~22 ms against ~224 ms and
// reopening the account-enumeration oracle it exists to close. Pinned by
// TestLoginTimingDoesNotRevealUnknownUsernames.
//
// Computed on demand rather than at package init, so the daemon process — the
// same binary — does not pay a 128 MiB / ~200 ms derivation for a value it never
// uses. warmLoginTimingHash forces it during server construction so no request
// pays the first-call penalty; a slower first response discloses "no such
// account" just as well as a faster one. Cached against the cost it was derived
// at, since a value memoized across a cost change equalizes against the wrong
// figure.
var (
	timingHashMu   sync.RWMutex
	timingHashVal  string
	timingHashCost int
)

func timingDummyHash() string {
	cost := users.HashCostN()
	timingHashMu.RLock()
	cached, cachedCost := timingHashVal, timingHashCost
	timingHashMu.RUnlock()
	if cached != "" && cachedCost == cost {
		return cached
	}

	// Derived outside the lock: holding it across a 128 MiB scrypt would
	// serialize every concurrent unknown-username login behind one derivation.
	// Two callers racing here both produce a valid hash at the same cost.
	// context.Background(), not a request's: this hash is process-wide state
	// derived once per cost setting, and abandoning it because one caller went
	// away would make the next caller pay for it again.
	h, err := users.HashPassword(context.Background(), "kypost-timing-equalization-dummy")
	if err != nil {
		// HashPassword only fails on a crypto/rand failure or invalid cost
		// parameters, neither of which is recoverable or reachable in practice.
		// An empty string would make VerifySecretHash return immediately and
		// silently restore the timing oracle, so refuse to start instead.
		panic("users.HashPassword failed while deriving the login timing hash: " + err.Error())
	}
	timingHashMu.Lock()
	timingHashVal, timingHashCost = h, cost
	timingHashMu.Unlock()
	return h
}

// warmLoginTimingHash forces the derivation during server construction, so the
// api process pays it before it can serve and the daemon process never does.
// Synchronous on purpose: a goroutine would leave a race in which a login
// arriving during the warm-up derives the hash itself and reintroduces the
// first-call skew this exists to prevent.
func warmLoginTimingHash() {
	_ = timingDummyHash()
}

// chargeLoginKDF runs a password-derivation step under a KDF slot and bills what
// it actually cost to the instance-wide login budget, reconciling against the
// reservation handleLogin took up front.
//
// Every derivation on the login path goes through here, including the
// equalization one on the unknown-username path — the cheap one to abuse (no
// account needed, never trips the per-account lockout) and so the one that must
// be paid for.
//
// The slot and the budget bound different things and both are required. The
// budget admits before the work runs, so it caps sustained CPU but not how many
// derivations are in flight at once: loginRateBurst is 15, and fifteen
// concurrent scrypts at N=1<<17 is ~1.9 GiB. withKDFSlot bounds that memory. The
// measurement is taken inside the slot, so queueing is not billed to this
// attempt.
//
// Returns errKDFBusy when the slots were saturated. handleLogin must refund both
// lockout strikes and answer 503: no credential was examined, so spending a
// strike would turn a load spike into an account lockout.
//
// held is the reservation handleLogin carries (see loginBudget). This settles it
// on BOTH paths and clears the flag either way, so the caller's deferred refund
// becomes a no-op — taking the flag as a parameter is what stops a future call
// site double-refunding and minting budget out of nothing.
func (s *Server) chargeLoginKDF(ctx context.Context, held *loginBudget, work func(context.Context) bool) (bool, error) {
	var ok bool
	// The slot is taken HERE rather than left to the derivation inside work, so
	// the stopwatch starts after the queue. users.WithKDFSlot hands back a
	// context that already holds the slot, and the derivation work performs
	// reuses it instead of queueing a second time.
	err := users.WithKDFSlot(ctx, func(ctx context.Context) {
		start := time.Now()
		ok = work(ctx)
		held.settle(loginKDFBilledSeconds(time.Since(start)) - loginKDFReserveSeconds)
	})
	if err != nil {
		// The reservation handleLogin took up front bought derivation work that
		// never happened. Give it back, or a shed burst drains the instance
		// budget for the sign-ins that follow.
		held.refund()
		return false, err
	}
	return ok, nil
}

// billMeasuredTime is what a derivation costs the instance-wide budget: the
// wall-clock time it actually took. Metering the work rather than counting the
// requests is the whole point of the budget — see loginKDFReserve — so this is
// the production answer and the only one that should ever ship.
func billMeasuredTime(d time.Duration) float64 { return d.Seconds() }

// loginKDFBilledSeconds is the cost oracle chargeLoginKDF settles against. A var
// for one reason: the internal/api TEST BINARY cannot use the real one and stay
// deterministic.
//
// The budget is denominated in measured seconds, and a measured second in that
// binary means nothing. TestMain drops scrypt from N=2^17 to 2^14 so the suite
// finishes at all, and -race then inflates what the cheap derivation costs on
// the wall — by a factor that belongs to the machine, not to the code. The two
// do not cancel: a sign-in billed ~0.17 s against the 3.0 s burst on a
// developer's laptop and enough more than that on a CI runner that three of them
// emptied it. Tests about MFA replay, lockout scoping and push approval sign in
// several times each and failed there, and only there, on a 429 about CPU
// capacity that no part of their subject concerns.
//
// So the test binary bills a FIXED loginKDFReserveSeconds per derivation, which
// makes the burst worth exactly loginRateBurst sign-ins on every machine —
// precisely what loginRateBurst already claims to be. The budget is otherwise
// completely live in tests: real sizing, real refill, real shedding, and a test
// that drains it gets the same 429 a caller would. Only the stopwatch is
// stubbed, because the stopwatch is the one part that cannot be honest there.
//
// Assigned in exactly one place, internal/api's TestMain. Nothing in production
// may reassign it; billMeasuredTime is pinned directly by
// TestProductionBillsTheMeasuredTime so weakening it cannot pass unnoticed.
var loginKDFBilledSeconds = billMeasuredTime

// loginBudget is one outstanding reservation against the instance-wide login
// bucket, held from the admitCost at the top of handleLogin until something
// settles it.
//
// handleLogin reserves BEFORE the per-IP lockout, the per-account lockout and
// the CAPTCHA check — deliberately, so an outbound CAPTCHA verification is
// inside the budget too — and any of those can return without reaching a
// derivation. Walking away still holding 200 ms of a bucket that refills at
// 0.2 s/s lets ten empty POSTs a second hold it at zero and answer every
// legitimate login with 429.
//
// A reservation is settled exactly once, by whichever comes first:
//
//   - chargeLoginKDF, billing the real cost or refunding a shed KDF slot
//   - the deferred refund in handleLogin, for paths that never got that far
//
// The zero value (no limiter configured, or no reservation taken) is inert.
type loginBudget struct {
	limiter *ipRateLimiter
}

// settle bills delta (actual cost minus the reservation) and releases the hold.
func (b *loginBudget) settle(delta float64) {
	if b.limiter == nil {
		return
	}
	b.limiter.settleCost(loginRateLimitKey, delta)
	b.limiter = nil
}

// refund returns the whole reservation and releases the hold. Idempotent: the
// second call is a no-op, so the deferred refund in handleLogin is safe to arm
// unconditionally on every return path.
func (b *loginBudget) refund() { b.settle(-loginKDFReserveSeconds) }

// equalizeLoginTiming verifies candidate against a throwaway scrypt hash so
// the unknown-username (and inactive-account) login path costs the same as a
// real wrong-password check. The result is discarded — it is the COST that
// matters — but a shed slot is not: returning without deriving is the one
// outcome the caller has to be able to tell apart, or the unknown-username
// path becomes measurably cheaper than the known one under load.
func equalizeLoginTiming(ctx context.Context, candidate string) error {
	_, err := users.VerifySecretHash(ctx, timingDummyHash(), candidate)
	return err
}

// Instance-wide login throttle and the per-IP lockout, both added because the
// username+IP lockout above bounds the wrong thing: the username comes from the
// request body, so a caller who never repeats one never trips it, while every
// attempt against an unknown account runs scrypt on purpose
// (equalizeLoginTiming, so timing does not reveal whether the account exists) —
// tens of milliseconds for a 200-byte request, on a host whose other job is
// running an LLM.
const (
	// The instance-wide login budget is denominated in SECONDS OF KEY-DERIVATION
	// WORK, not in requests.
	//
	// Counting requests requires assuming a cost per request, and that assumption
	// fails exactly when it matters: the same one-per-second that is a fifth of a
	// core here is two full cores where a derivation costs ten times as much — a
	// slower machine, contention with the LLM, or a raise to scryptN — while the
	// counter keeps admitting at the same rate. Metering the work needs no
	// assumption.
	//
	// Instance-wide rather than per-IP because the CPU being protected is shared,
	// and a per-IP limit is defeated by using more IPs.

	// loginKDFReserve is what one attempt is assumed to cost when it starts:
	// one scrypt at HashPassword's parameters, roughly 200 ms of a core at
	// N=2^17. It is only the opening reservation — what an attempt finally pays
	// is what it actually took, reconciled by settleCost.
	loginKDFReserve        = 200 * time.Millisecond
	loginKDFReserveSeconds = float64(loginKDFReserve) / float64(time.Second)

	// loginKDFDutyCycle is the share of one core the instance will spend on
	// login derivations in the steady state. At the reference cost that is the
	// same one attempt per second this allowed before, and unlike that figure it
	// stays true when an attempt costs more.
	loginKDFDutyCycle = 0.2

	// loginRateBurst stays expressed in attempts, because it is a statement
	// about sign-ins: fifty users arriving at 9am must not meet a 429.
	// loginKDFBurstSeconds is what the bucket actually holds.
	loginRateBurst       = 15
	loginKDFBurstSeconds = loginRateBurst * loginKDFReserveSeconds

	// loginIPMaxFailures/loginIPLockoutFor cut off one address that is cycling
	// through usernames. Deliberately much looser than the 3-strike per-account
	// budget: a shared NAT egress, a family, or an office all legitimately produce
	// several failures from one address, and this must not become an easier way to
	// lock out a building than an account.
	loginIPMaxFailures = 50
	loginIPLockoutFor  = 15 * time.Minute

	// loginParamsBurst/loginParamsRefillPerSec meter the pre-login handshake PER IP,
	// in requests. It does no derivation — one cached lookup and one HMAC — so
	// pricing it in derivation seconds against the instance bucket was a ~40,000x
	// overcharge that let one address deny sign-in globally. Generous, because a
	// browser calls this once per sign-in and the re-authentication flows call it
	// again.
	loginParamsBurst        = 30
	loginParamsRefillPerSec = 1
)

// deviceRescanInterval is the floor between full device-index rebuilds.
// Long enough that a flood of unknown device ids cannot drive them, short
// enough that a device paired on another process shows up promptly.
const deviceRescanInterval = 30 * time.Second

// The derivation slots themselves live in package users, next to the scrypt
// call they bound — see users.WithKDFSlot and the file comment on users/kdf.go.
// They used to live here as a Server field that every caller had to remember to
// wrap itself, and half of them did not. errKDFBusy and kdfMaxQueueWait remain
// as this package's names for the shed condition and the queue tolerance, so
// the handlers below read the same as before.
var errKDFBusy = users.ErrKDFBusy

func kdfMaxQueueWait() time.Duration { return users.KDFMaxQueueWait }

// writeKDFBusy answers a shed derivation. 503 rather than 429: the caller did
// nothing wrong and no per-caller budget was exceeded — this instance is out of
// derivation capacity.
func writeKDFBusy(w http.ResponseWriter) {
	// Derived from the queue tolerance rather than hardcoded: a caller told to
	// come back sooner than the queue takes to drain just rejoins the same
	// saturated queue.
	retrySeconds := int(kdfMaxQueueWait().Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":             "server is busy verifying credentials, try again shortly",
		"retryAfterSeconds": retrySeconds,
	})
}

// loginRateLimitKey is the single bucket key for the instance-wide login
// throttle. ipRateLimiter is keyed, so a constant key gives one shared bucket
// rather than one per caller — which is the whole point here.
const loginRateLimitKey = "instance"
