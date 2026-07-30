package api

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// wkdRateBurst/wkdRateRefillPerSec throttle the public, unauthenticated Web
// Key Directory endpoint per client IP. Unlike failureLockout (which counts
// *failed* attempts and is right for auth surfaces), every WKD request looks
// legitimate — there is no failure to strike on — so this is a plain
// request-rate token bucket instead.
//
// The endpoint is cheap for an unknown domain (one instance-store read, then
// 404) but a match costs a per-user scan that decrypts the IMAP config to
// resolve publishable addresses. Nothing about the route is authenticated, so
// without a limit one host can drive that work in a loop.
//
// A burst of 30 with 1 token/sec sustained is far above real usage — a mail
// client looks a correspondent's key up once and caches it, and even a busy
// MTA batching lookups stays well under this — while capping a single abusive
// client at 60 requests/minute.
const (
	wkdRateBurst        = 30
	wkdRateRefillPerSec = 1.0

	// wkdRateSweepThreshold bounds how large the per-IP map may grow before
	// idle entries are reclaimed. Mirrors loginLockoutSweepThreshold: a
	// stream of distinct source IPs would otherwise each leave an entry
	// behind forever. Buckets that have refilled to full carry no state
	// worth keeping, so they are the ones dropped.
	wkdRateSweepThreshold = 10_000
)

type rateBucket struct {
	tokens float64
	last   time.Time
}

// ipRateLimiter is a small in-memory token bucket keyed by client IP. It
// lives outside Server.mu for the same reason failureLockout does: unrelated
// state with a much smaller lock scope.
type ipRateLimiter struct {
	mu             sync.Mutex
	burst          float64
	refillPerSec   float64
	sweepThreshold int
	entries        map[string]*rateBucket
	// now is overridable in tests so refill behavior can be exercised
	// without sleeping.
	now func() time.Time
}

func newIPRateLimiter(burst, refillPerSec float64) *ipRateLimiter {
	return &ipRateLimiter{
		burst:          burst,
		refillPerSec:   refillPerSec,
		sweepThreshold: wkdRateSweepThreshold,
		entries:        map[string]*rateBucket{},
		now:            time.Now,
	}
}

// allow consumes one token for key, reporting whether the request may
// proceed. When it may not, retryAfter is how long until a token is
// available.
func (l *ipRateLimiter) allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.refillLocked(key, l.now())

	if e.tokens >= 1 {
		e.tokens--
		return true, 0
	}
	if l.refillPerSec <= 0 {
		return false, time.Second
	}
	return false, time.Duration((1-e.tokens)/l.refillPerSec*float64(time.Second)) + time.Millisecond
}

// refillLocked brings key's bucket up to date, creating it at full burst if it
// is new, and returns it. Callers must hold l.mu.
func (l *ipRateLimiter) refillLocked(key string, now time.Time) *rateBucket {
	e, exists := l.entries[key]
	if !exists {
		if len(l.entries) >= l.sweepThreshold {
			l.sweepLocked(now)
		}
		e = &rateBucket{tokens: l.burst, last: now}
		l.entries[key] = e
		return e
	}
	// Refill for elapsed time, capped at burst so an idle client can't
	// accumulate an unbounded allowance.
	if elapsed := now.Sub(e.last).Seconds(); elapsed > 0 {
		e.tokens = math.Min(l.burst, e.tokens+elapsed*l.refillPerSec)
	}
	e.last = now
	return e
}

// admitCost is allow() for a bucket denominated in seconds of work rather than
// in requests, for callers that are about to do something whose true cost they
// cannot know until it is done.
//
// It takes reserve up front and admits on any positive balance, so a bucket may
// go into debt — that is deliberate. The alternative is to refuse work until a
// full attempt's worth of budget has accrued, which on a machine where an
// attempt costs far more than reserve would refuse everything forever. Debt lets
// the true cost land after the fact and simply delays the next admission until
// the deficit has refilled, which is the behaviour the budget describes.
//
// The debt is FLOORED at one full burst below zero. Without
// a floor, a caller who can make the reservation without paying it back drives
// the balance arbitrarily negative and the retryAfter handed to everybody else
// grows without bound — a few minutes of that is an hours-long outage that
// outlives the abuse by as long as it takes to refill. A floor caps the recovery
// time at burst/refillPerSec no matter how long the abuse ran. Every caller must
// still settle its own reservation; this only bounds the blast radius when one
// forgets.
func (l *ipRateLimiter) admitCost(key string, reserve float64) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.refillLocked(key, l.now())

	if e.tokens > 0 {
		e.tokens = math.Max(e.tokens-reserve, -l.burst)
		return true, 0
	}
	if l.refillPerSec <= 0 {
		return false, time.Second
	}
	// Time to climb back out of debt and be admissible again.
	return false, time.Duration(-e.tokens/l.refillPerSec*float64(time.Second)) + time.Millisecond
}

// settleCost reconciles the reservation admitCost took against what the work
// actually cost. delta is (actual - reserve): positive bills the difference,
// negative refunds it.
//
// Clamped at both ends, to the same bounds admitCost uses: a refund cannot
// mint tokens above burst, and a bill cannot drive the balance further than
// one burst into debt. The floor forgives some genuinely-incurred cost when a
// single derivation runs pathologically long, and that is the right trade —
// an unbounded deficit turns one slow attempt into an outage measured in
// hours for every other caller of the bucket.
func (l *ipRateLimiter) settleCost(key string, delta float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, exists := l.entries[key]
	if !exists {
		return
	}
	e.tokens = math.Max(math.Min(l.burst, e.tokens-delta), -l.burst)
}

// sweepLocked drops entries that have refilled to full — an idle bucket is
// indistinguishable from one that was never created, so it holds no state
// worth the memory. Callers must hold l.mu.
func (l *ipRateLimiter) sweepLocked(now time.Time) {
	for k, e := range l.entries {
		tokens := e.tokens
		if elapsed := now.Sub(e.last).Seconds(); elapsed > 0 {
			tokens = math.Min(l.burst, tokens+elapsed*l.refillPerSec)
		}
		if tokens >= l.burst {
			delete(l.entries, k)
		}
	}
}

// withWKDRateLimit throttles the public WKD endpoint per client IP, answering
// 429 with Retry-After once a client exceeds its budget.
func (s *Server) withWKDRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.wkdLimiter != nil {
			if ok, retryAfter := s.wkdLimiter.allow(lockoutKeyForIP(clientIP(r))); !ok {
				seconds := int(math.Ceil(retryAfter.Seconds()))
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
		}
		next(w, r)
	}
}

// intervalGate allows an action at most once per interval, process-wide.
// Used where a miss must still be able to trigger expensive repair work, but
// the miss itself is attacker-controlled and so cannot be allowed to drive it.
type intervalGate struct {
	mu       sync.Mutex
	interval time.Duration
	last     time.Time
	now      func() time.Time
}

func newIntervalGate(interval time.Duration) *intervalGate {
	return &intervalGate{interval: interval, now: time.Now}
}

func (g *intervalGate) allow() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !g.last.IsZero() && now.Sub(g.last) < g.interval {
		return false
	}
	g.last = now
	return true
}
