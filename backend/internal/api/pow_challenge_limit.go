package api

import (
	"sync"
	"time"
)

const (
	// powChallengeBurst/powChallengeWindowLen cap how many proof-of-work
	// challenges one client IP can mint. GET /api/auth/pow-challenge is
	// unauthenticated by necessity — it runs before anyone has typed a
	// password — so without a cap it is a free entropy-and-CPU faucet, and
	// every challenge it issues is a salt that can later occupy an entry in
	// the verifier's spent-salt cache.
	//
	// 30/minute is far above real use (a login page fetches one, plus one
	// per retry) and far below anything worth doing on purpose.
	powChallengeBurst     = 30
	powChallengeWindowLen = time.Minute

	// powChallengeSweepThreshold bounds how large the per-IP map may grow
	// between StartPoWSweeper ticks. Mirrors wkdRateSweepThreshold: the
	// endpoint this guards is unauthenticated and requires zero solve-work
	// to hit, so an attacker presenting many distinct source IPs (real
	// rotation, or an attacker-influenced X-Forwarded-For chain when
	// TRUST_PROXY_HEADERS=true) can mint one entry per cheap GET — fast
	// enough to outgrow a 10-minute ticker many times over before it next
	// fires. Crossing this bound triggers an inline sweep at insertion time
	// as a second, tighter backstop.
	powChallengeSweepThreshold = 10_000
)

type powChallengeWindow struct {
	count   int
	resetAt time.Time
}

// powChallengeLimiter is a fixed-window per-IP counter.
//
// ponytail: fixed window, not a token bucket. Ceiling: a client can spend a
// full budget at the very end of one window and another at the start of the
// next, so the true short-term burst is 2x. Upgrade path: a token bucket, if
// that ever matters — for an endpoint this cheap, it does not.
type powChallengeLimiter struct {
	mu             sync.Mutex
	windows        map[string]*powChallengeWindow
	sweepThreshold int
}

func newPowChallengeLimiter() *powChallengeLimiter {
	return &powChallengeLimiter{
		windows:        map[string]*powChallengeWindow{},
		sweepThreshold: powChallengeSweepThreshold,
	}
}

// allow reports whether ip may mint a challenge now, counting it if so.
func (l *powChallengeLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, exists := l.windows[ip]
	if !exists {
		if len(l.windows) >= l.sweepThreshold {
			l.sweepExpiredLocked(now)
		}
		l.windows[ip] = &powChallengeWindow{count: 1, resetAt: now.Add(powChallengeWindowLen)}
		return true
	}
	if !now.Before(w.resetAt) {
		l.windows[ip] = &powChallengeWindow{count: 1, resetAt: now.Add(powChallengeWindowLen)}
		return true
	}
	if w.count >= powChallengeBurst {
		return false
	}
	w.count++
	return true
}

// sweepExpired drops windows that have rolled over. Driven by
// StartPoWSweeper: an attacker rotating source IPs mints an entry per IP that
// is otherwise never revisited, so this map needs a real sweep rather than
// lazy eviction (see backend/AGENTS.md). This ticker sweep and allow's
// threshold-triggered sweep are two independent bounds, not alternatives to
// each other — the ticker guarantees eventual reclamation even at low
// traffic, the threshold caps worst-case memory between ticks.
func (l *powChallengeLimiter) sweepExpired(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepExpiredLocked(now)
}

// sweepExpiredLocked does the actual reclamation. Callers must hold l.mu.
// Factored out so allow() can trigger it without re-locking a mutex it
// already holds.
func (l *powChallengeLimiter) sweepExpiredLocked(now time.Time) {
	for ip, w := range l.windows {
		if !now.Before(w.resetAt) {
			delete(l.windows, ip)
		}
	}
}

// windowCount reports how many IPs are currently tracked. Test-only.
func (l *powChallengeLimiter) windowCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.windows)
}
