package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// instanceBudget reads the instance-wide login bucket's current balance.
func instanceBudget(t *testing.T, srv *Server) float64 {
	t.Helper()
	l := srv.loginRateLimiter
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[loginRateLimitKey]
	if !ok {
		return l.burst
	}
	return e.tokens
}

// loginFrom posts a login and reports the status code.
func loginFrom(t *testing.T, srv *Server, ip, username, password string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)
	return rec.Code
}

// TestRejectedLoginRefundsTheInstanceBudget is the regression test for an
// unauthenticated, permanent, instance-wide denial of sign-in.
//
// handleLogin reserves 200 ms of the instance-wide derivation budget BEFORE the
// per-IP lockout, the per-account lockout and the CAPTCHA check — deliberately,
// so an outbound CAPTCHA verification is inside the budget too. Every one of
// those can return without ever running a derivation, and each of those returns
// used to walk away still holding the reservation.
//
// That made a request the server does no work for MORE expensive to the budget
// than one it does: the bucket refills at 0.2 s/s, so a caller whose address is
// already locked out drained it faster than it could recover, for the cost of an
// empty POST. Ten a second held it permanently at zero and every legitimate
// login on the instance — including the admin's — was answered 429 at the very
// first check, indefinitely.
//
// The property: a request that never reaches a derivation must leave the budget
// exactly as it found it.
func TestRejectedLoginRefundsTheInstanceBudget(t *testing.T) {
	srv := newTestServer(t)

	const attacker = "203.0.113.99"
	lockOutAddress(t, srv, attacker)

	// Fewer requests than the burst holds (3.0 token-seconds at 0.2 each), so an
	// unrefunded reservation shows up as a balance drop rather than being
	// swallowed by the floor.
	const rejected = 10
	before := instanceBudget(t, srv)
	for range rejected {
		if code := loginFrom(t, srv, attacker, "nosuchuser", "wrong-password-here"); code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 from the locked-out address, got %d", code)
		}
	}
	after := instanceBudget(t, srv)

	// The bucket refills with wall-clock time, so `after` may be slightly
	// HIGHER than `before`. It must never be lower: that is the drain.
	if after < before-0.001 {
		t.Errorf("%d requests that ran no derivation drained the instance budget from %.3f to %.3f "+
			"(%.2f token-seconds). A locked-out caller must not be able to spend the budget that "+
			"gates everybody else's sign-in.", rejected, before, after, before-after)
	}
}

// resetInstanceBudget refills the instance-wide login bucket to full.
func resetInstanceBudget(t *testing.T, srv *Server) {
	t.Helper()
	l := srv.loginRateLimiter
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries[loginRateLimitKey] = &rateBucket{tokens: l.burst, last: l.now()}
}

// lockOutAddress leaves ip refused by the per-IP lockout — before any derivation
// — with the instance budget back at full, so what a caller measures afterwards
// is the rejected-request path and nothing else.
//
// Two adjustments, both about isolating that path rather than about the values.
//
// The threshold is shrunk first, for the reason
// TestLoginIPLockoutCatchesRotatingUsernames shrinks it: every attempt against an
// unknown username runs a full scrypt on purpose (equalizeLoginTiming, so timing
// cannot reveal whether an account exists), so burning the production 50 costs
// fifty derivations in a test that is not about the threshold's value.
//
// And the budget comes out for the burn, which is load bearing. The burst is
// worth loginRateBurst sign-ins and a shed attempt returns BEFORE tryAttempt, so
// with the budget in place a burn longer than the burst never reaches the
// lockout: the address ends up merely rate-limited, not locked, and the caller
// measures the budget a second time instead of the lockout. It is restored, and
// the bucket refilled, before the helper returns.
func lockOutAddress(t *testing.T, srv *Server, ip string) {
	t.Helper()
	const maxFailures = 4
	srv.loginIPLockout = newFailureLockout(maxFailures, loginIPLockoutFor)

	budget := srv.loginRateLimiter
	srv.loginRateLimiter = nil
	for range maxFailures {
		loginFrom(t, srv, ip, "nosuchuser", "wrong-password-here")
	}
	srv.loginRateLimiter = budget
	resetInstanceBudget(t, srv)

	if code := loginFrom(t, srv, ip, "nosuchuser", "wrong-password-here"); code != http.StatusTooManyRequests {
		t.Fatalf("%s is not locked out (got %d); every request the caller makes next would run "+
			"a derivation, so it would not be exercising the rejected-request path at all", ip, code)
	}
}

// TestLockedOutFloodDoesNotDenySignInToEveryoneElse is the same defect stated as
// the outage it caused, rather than as an accounting identity.
//
// It fails on the pre-fix code even with the debt floor in place, because the
// floor bounds how long the outage lasts, not whether one happens.
func TestLockedOutFloodDoesNotDenySignInToEveryoneElse(t *testing.T) {
	srv := newTestServer(t)

	const attacker = "203.0.113.99"
	lockOutAddress(t, srv, attacker)
	for range 500 {
		loginFrom(t, srv, attacker, "nosuchuser", "wrong-password-here")
	}

	// An unrelated address, an unrelated account. The credential is wrong, so
	// 401 is the correct answer — the point is that the attempt is CONSIDERED
	// rather than refused by an exhausted instance budget.
	code := loginFrom(t, srv, "198.51.100.4", "victim", "some-password-value")
	if code == http.StatusTooManyRequests {
		t.Fatal("an unrelated user was refused sign-in with 429 after a locked-out address " +
			"flooded the login endpoint: the instance-wide budget was drained by requests that " +
			"cost the server no derivation work at all")
	}
	if code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401 (wrong credential, budget intact)", code)
	}
}

// TestBudgetIsSettledExactlyOnce guards the other direction. chargeLoginKDF
// settles the reservation and handleLogin's deferred refund must then be inert:
// if both fired, every real login would MINT budget, and the throttle would
// stop being a throttle under exactly the load it exists for.
func TestBudgetIsSettledExactlyOnce(t *testing.T) {
	l := newIPRateLimiter(loginKDFBurstSeconds, loginKDFDutyCycle)
	b := loginBudget{limiter: l}

	l.admitCost(loginRateLimitKey, loginKDFReserveSeconds)
	start := instanceBudgetOf(l)

	b.refund()
	afterFirst := instanceBudgetOf(l)
	b.refund() // the deferred one, after chargeLoginKDF already settled
	b.settle(1.0)
	afterExtra := instanceBudgetOf(l)

	if afterFirst-start < loginKDFReserveSeconds*0.99 {
		t.Errorf("first refund returned %.3f, want the full %.3f reservation",
			afterFirst-start, loginKDFReserveSeconds)
	}
	if afterExtra != afterFirst {
		t.Errorf("a settled reservation was settled again: balance moved %.3f -> %.3f. "+
			"Double-settling mints budget out of nothing.", afterFirst, afterExtra)
	}
}

func instanceBudgetOf(l *ipRateLimiter) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries[loginRateLimitKey].tokens
}

// TestBucketDebtIsFloored pins the blast-radius bound.
//
// admitCost admits on any positive balance and subtracts the reservation, so the
// balance goes negative by design. Unbounded, a caller who reserves without
// settling drives it arbitrarily far down and the retryAfter handed to everybody
// else grows without limit — a few minutes of abuse becoming an hours-long
// outage that outlives it. Floored, recovery is capped at burst/refillPerSec no
// matter how long the abuse ran.
func TestBucketDebtIsFloored(t *testing.T) {
	l := newIPRateLimiter(3.0, 0.2)
	now := time.Now()
	l.now = func() time.Time { return now }

	// Drain it, then keep billing without ever settling.
	l.admitCost("k", 0.2)
	for range 10_000 {
		l.settleCost("k", 5.0)
	}

	l.mu.Lock()
	tokens := l.entries["k"].tokens
	l.mu.Unlock()

	if tokens < -l.burst {
		t.Errorf("bucket balance is %.1f, below the -%.1f floor: recovery would take %.0f seconds",
			tokens, l.burst, -tokens/l.refillPerSec)
	}

	_, retryAfter := l.admitCost("k", 0.2)
	if maxRecovery := time.Duration(l.burst / l.refillPerSec * float64(time.Second)); retryAfter > maxRecovery+time.Second {
		t.Errorf("retryAfter = %v, want at most %v", retryAfter, maxRecovery)
	}
}

// TestCrowdedTableEvictsLockedBeforePartialStrikes covers stage 2 of
// sweepIfCrowdedLocked, which reintroduced the bypass stage 1 exists to close.
//
// An unlocked entry has a zero lockedUntil, and time.Time's zero value sorts
// BEFORE every real timestamp. Ordering the eviction list on lockedUntil alone
// therefore put the mid-accumulation entries at the front and deleted every real
// user's 1-of-3 and 2-of-3 progress before touching a single attacker-made
// lockout — so past the hard cap, no key ever reached its third strike and the
// lockout stopped engaging for anybody.
//
// TestCrowdedTableDoesNotErasePartialStrikes covers the same property at the
// SWEEP THRESHOLD; this one drives the table past the HARD CAP, which is the
// only place stage 2 runs.
func TestCrowdedTableEvictsLockedBeforePartialStrikes(t *testing.T) {
	// Reduced bounds, same proof — see newFailureLockoutSized. At production
	// scale the loop below is 165,000 race-instrumented tryAttempt calls.
	l := newFailureLockoutSized(3, 15*time.Minute, 100, 500)

	// A real user, mid-accumulation at 2 of 3 strikes.
	const victim = "real-victim\x00198.51.100.7"
	for range 2 {
		l.tryAttempt(victim)
	}

	// Now flood past the hard cap with fully-locked entries, the way an attacker
	// manufactures them: three requests each buys one that survives stage 1.
	for i := range l.hardCap + l.hardCap/10 {
		key := fmt.Sprintf("filler-%d", i)
		for range 3 {
			l.tryAttempt(key)
		}
	}

	l.mu.Lock()
	size := len(l.entries)
	_, victimSurvived := l.entries[victim]
	l.mu.Unlock()

	if size > l.hardCap {
		t.Errorf("table holds %d entries, want at most %d: the hard cap did not engage",
			size, l.hardCap)
	}
	if !victimSurvived {
		t.Fatal("the victim's partial strike record was evicted while attacker-manufactured " +
			"lockouts were kept. Flooding past the hard cap therefore erases every real key's " +
			"progress and the three-strikes lockout never engages — a lockout bypass by flooding.")
	}

	// And the record is intact, not merely present: the third strike must lock.
	if ok, _ := l.tryAttempt(victim); !ok {
		t.Fatal("the victim's 3rd attempt was refused; it should be the one that locks")
	}
	if ok, _ := l.tryAttempt(victim); ok {
		t.Fatal("the victim's 4th attempt was allowed: the strike record survived eviction " +
			"but its accumulated failures did not")
	}
}
