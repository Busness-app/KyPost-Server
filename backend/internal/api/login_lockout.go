package api

import (
	"sort"
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

	// loginLockoutSweepThreshold is the size at which sweepIfCrowdedLocked runs
	// inline. A stream of distinct nonexistent usernames each gets an entry that
	// never reaches the lockout threshold and is otherwise never removed. Past
	// this size, not-currently-locked entries are swept.
	loginLockoutSweepThreshold = 10_000
	// loginLockoutHardCap is the size past which even currently-locked entries
	// are evicted, oldest-expiry first.
	//
	// The sweep above keeps locked entries, which are precisely the ones an
	// attacker creates on purpose — maxFailures requests buys one that survives
	// every subsequent sweep for lockoutFor. So the threshold alone bounded only
	// the unlocked portion, and the real limit on the table was the scrypt cost
	// per login attempt in an entirely different file.
	//
	// Sized above the threshold so a normal instance never reaches it: crossing
	// this means tens of thousands of distinct keys are simultaneously locked
	// out, which is an attack, not a busy Monday morning.
	loginLockoutHardCap = 50_000
	// loginLockoutLowWater is how far stage 2 trims below the hard cap, so a
	// table parked at the cap does not re-scan on every subsequent attempt.
	loginLockoutLowWater = loginLockoutHardCap * 3 / 4
)

type loginLockoutEntry struct {
	failures    int
	lockedUntil time.Time
	// lastSeen is when this key last attempted, so the sweep can tell an entry
	// whose strikes have gone stale from one mid-accumulation.
	//
	// Without it the sweep had only "is it locked right now?" to go on, and so
	// deleted every PARTIAL strike record whenever the table was crowded. That
	// is a lockout bypass, not a memory optimization: flood the table past the
	// threshold and every subsequent attempt wipes the 1-of-3 and 2-of-3
	// progress of every real key, so no key ever reaches the third strike and
	// the lockout never engages for anyone.
	lastSeen time.Time
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
	// lastSweep throttles sweepIfCrowdedLocked. Both of its stages are O(n) (the
	// second O(n log n)), and it is called from tryAttempt — so once the table
	// sat above the threshold, every single attempt paid a full scan. Under the
	// flood that makes the table big, that is the attacker choosing how much
	// work each of their requests costs the server.
	lastSweep time.Time
}

// sweepMinInterval is the shortest gap between two crowded-table sweeps.
//
// Hysteresis, so a table parked above the threshold does not scan itself on
// every attempt. The hard cap is still enforced immediately regardless (see
// sweepIfCrowdedLocked) — that one is a memory bound and cannot wait.
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
//   - cancelAttempt on a path that never became a credential check (see its
//     doc), returning the strike
//   - nothing at all on a failure — the strike is already counted
func (l *failureLockout) tryAttempt(username string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	l.sweepIfCrowdedLocked(now)

	e, exists := l.entries[username]
	if !exists {
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

// sweepIfCrowdedLocked bounds the map without a background goroutine. Callers
// must hold l.mu.
//
// Two stages, because the original single stage was neither a bound nor safe.
//
// Stage 1 reclaims entries that are neither locked nor mid-accumulation. It
// keys off lastSeen, NOT off "is this locked right now" — the latter deleted
// partial strike records, so flooding the table past the threshold erased every
// real key's 1-of-3 and 2-of-3 progress and the lockout stopped engaging at all.
// An entry idle for longer than lockoutFor is safe to drop because its strikes
// would be reset on the next attempt anyway (see tryAttempt).
//
// Stage 2 evicts currently-locked entries, soonest-expiry first, once even they
// exceed the hard cap. The old sweep exempted locked entries — which are exactly
// what an attacker manufactures, maxFailures requests each — so the threshold
// bounded only the unlocked portion while its comment claimed it bounded the
// map. What actually limited the table was the scrypt cost per attempt in
// handleLogin: a load-bearing dependency on a different file that nothing wrote
// down. Evicting a locked entry forgives that key's cooldown early, which is the
// right thing to trade for a real memory bound.
func (l *failureLockout) sweepIfCrowdedLocked(now time.Time) {
	overHardCap := len(l.entries) > loginLockoutHardCap
	if len(l.entries) < loginLockoutSweepThreshold {
		return
	}
	// Throttled unless we are over the hard cap, in which case the scan is not
	// optional.
	if !overHardCap && now.Sub(l.lastSweep) < sweepMinInterval {
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

	if len(l.entries) <= loginLockoutHardCap {
		return
	}
	// Everything left is either locked or recently active. Evict down to a
	// low-water mark rather than exactly to the cap, so the next attempt does
	// not immediately trigger another full scan.
	type keyed struct {
		key   string
		until time.Time
	}
	remaining := make([]keyed, 0, len(l.entries))
	for k, e := range l.entries {
		remaining = append(remaining, keyed{key: k, until: e.lockedUntil})
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i].until.Before(remaining[j].until) })
	for i := 0; i < len(remaining)-loginLockoutLowWater; i++ {
		delete(l.entries, remaining[i].key)
	}
}

// recordSuccess clears any strike history for username, so a successful
// login always starts the next set of attempts with a clean slate.
func (l *failureLockout) recordSuccess(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, username)
}

// timingDummyHash is a scrypt hash used only to equalize login timing,
// regardless of whether the account exists. Its plaintext is irrelevant: the
// verification is only ever expected to fail, and only its COST matters.
//
// Derived at init from the CURRENT cost parameters rather than hardcoded. It was
// a hardcoded scrypt$16384$... literal, and the instant HashPassword's N was
// raised to 2^17 that literal became a cheaper hash than a real account's — so
// the unknown-username path returned in ~22 ms against ~224 ms for a real user,
// reopening the exact account-enumeration oracle this function exists to close.
// A constant that has to be kept in step with another constant by hand will not
// be. Pinned by TestLoginTimingDoesNotRevealUnknownUsernames.
//
// Computed once, on demand, and warmed eagerly by NewServer.
//
// It was a plain package-level var, which meant the 128 MiB / ~200 ms scrypt
// derivation ran at package init in EVERY binary importing this package. Both
// processes supervisord starts are the same binary, so the daemon paid for a
// value it can never use.
//
// sync.OnceValue rather than a lazy nil-check because the alternative is a
// first-call penalty on exactly the path whose job is to have no timing
// signal: the very first unknown-username login after a restart would pay
// derivation PLUS verification while a real account paid only verification,
// and a SLOWER response discloses "no such account" just as well as a faster
// one. warmLoginTimingHash closes that window by forcing it during
// construction, off any request path.
var timingDummyHash = sync.OnceValue(func() string {
	h, err := users.HashPassword("kypost-timing-equalization-dummy")
	if err != nil {
		// HashPassword only fails on a crypto/rand failure or invalid cost
		// parameters, neither of which is recoverable or reachable in practice.
		// An empty string would make VerifySecretHash return immediately and
		// silently restore the timing oracle, so refuse to start instead.
		panic("users.HashPassword failed while deriving the login timing hash: " + err.Error())
	}
	return h
})

// warmLoginTimingHash forces the derivation during server construction, so the
// api process pays it before it can serve and the daemon process never does.
//
// Synchronous on purpose. A goroutine would leave a race in which a login
// arriving during the warm-up blocks on the OnceValue and reintroduces the
// first-call skew this exists to prevent; 200 ms in NewServer costs nothing.
func warmLoginTimingHash() {
	_ = timingDummyHash()
}

// chargeLoginKDF runs a password-derivation step and bills what it actually
// cost to the instance-wide login budget, reconciling against the reservation
// handleLogin took up front.
//
// Every derivation on the login path goes through here, including the
// equalization one on the unknown-username path — that path is the cheap one to
// abuse (no account needed, never trips the per-account lockout) and the one
// that must therefore be paid for.
func (s *Server) chargeLoginKDF(work func() bool) bool {
	start := time.Now()
	ok := work()
	if s.loginRateLimiter != nil {
		s.loginRateLimiter.settleCost(loginRateLimitKey, time.Since(start).Seconds()-loginKDFReserveSeconds)
	}
	return ok
}

// equalizeLoginTiming verifies candidate against a throwaway scrypt hash so
// the unknown-username (and inactive-account) login path costs the same as a
// real wrong-password check.
func equalizeLoginTiming(candidate string) {
	users.VerifySecretHash(timingDummyHash(), candidate)
}

// Instance-wide login throttle and the per-IP lockout, both added because the
// username+IP lockout above bounds the wrong thing.
//
// loginMaxFailures is a budget per (username, IP) pair, and the username comes
// from the request body — so a caller who never repeats a username never trips
// it. Meanwhile every attempt against an unknown account runs scrypt on purpose
// (equalizeLoginTiming, so timing does not reveal whether the account exists):
// 16 MB and tens of milliseconds for a 200-byte request, on a host whose other
// job is running an LLM.
const (
	// The instance-wide login budget is denominated in SECONDS OF KEY-DERIVATION
	// WORK, not in requests.
	//
	// Counting requests requires assuming a cost per request, and that
	// assumption fails exactly when it matters. The same one-per-second that is
	// a fifth of a core here is two full cores on a box where a derivation costs
	// ten times as much — a slower machine, one contending with the LLM, or a
	// future raise to scryptN — and a request counter cannot tell the difference,
	// so it keeps admitting at the same rate while the CPU it exists to protect
	// disappears. Metering the work itself needs no assumption: a derivation that
	// costs twice as much draws twice as much budget, and the ceiling holds.
	//
	// Instance-wide rather than per-IP because the resource being protected is
	// this server's CPU, which is shared, and because a per-IP limit is defeated
	// by using more IPs.

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
	// budget: a shared NAT egress, a family, or an office all legitimately
	// produce several failures from one address, and this must not become an
	// easier way to lock out a building than to lock out an account.
	loginIPMaxFailures = 50
	loginIPLockoutFor  = 15 * time.Minute

	// loginParamsBurst/loginParamsRefillPerSec meter the pre-login handshake
	// PER IP, in requests. It does no derivation — one cached lookup and one
	// HMAC — so pricing it in derivation seconds against the instance bucket
	// was a ~40,000x overcharge that let one address deny sign-in globally.
	// Generous, because a browser legitimately calls this once per sign-in and
	// the re-authentication flows call it again.
	loginParamsBurst       = 30
	loginParamsRefillPerSec = 1
)

// maxConcurrentKDF bounds simultaneous memory-hard derivations process-wide.
// Each scrypt at N=1<<17 holds 128 MiB, so this caps peak KDF memory at roughly
// maxConcurrentKDF*128 MiB regardless of how many callers arrive at once. The
// per-IP lockouts bound how many attempts an address may make; nothing bounded
// how many could be in flight together, which is what turns an auth endpoint
// into an OOM primitive on a memory-limited container.
const maxConcurrentKDF = 4

// withKDFSlot runs fn holding one of the process-wide derivation slots. Callers
// that perform scrypt on an unauthenticated path must use it; a nil semaphore
// (zero-value Server in tests) degrades to running fn directly.
func (s *Server) withKDFSlot(fn func()) {
	if s.kdfSem == nil {
		fn()
		return
	}
	s.kdfSem <- struct{}{}
	defer func() { <-s.kdfSem }()
	fn()
}

// loginRateLimitKey is the single bucket key for the instance-wide login
// throttle. ipRateLimiter is keyed, so a constant key gives one shared bucket
// rather than one per caller — which is the whole point here.
const loginRateLimitKey = "instance"
