package api

import (
	"sync"
	"time"
)

const (
	// powEscalationFactor multiplies the proof-of-work search space per
	// recent failed login from a client IP, and powMaxNumberCeiling caps it.
	//
	// The cap is not decoration: uncapped, a persistent attacker drives the
	// difficulty to a value nobody can solve, which denies service to
	// everyone behind that address — turning the defence into the attack.
	//
	// What the ceiling actually costs, measured rather than guessed: a
	// maxnumber of 50,000 averages 238 ms under crypto.subtle on a desktop,
	// so this ceiling is roughly 4.8 s on average and 9.5 s worst case, and
	// a phone throttled 4x against that desktop is 20-40 s. That is a real
	// cost to automation and an unpleasant-but-survivable one to a human who
	// has genuinely mistyped their password several times.
	powEscalationFactor = 4
	powMaxNumberCeiling = 1_000_000

	// powEscalationDecay is how long a failure keeps counting. Client IPs
	// are shared (carrier-grade NAT, office egress, a household), so a
	// stranger's failures must stop costing an innocent neighbour reasonably
	// soon. It mirrors loginLockoutFor for the same reason.
	powEscalationDecay = 15 * time.Minute

	// powEscalationSweepThreshold bounds how large the per-IP map may grow
	// between StartPoWSweeper ticks. Mirrors powChallengeSweepThreshold and
	// wkdRateSweepThreshold: any failed login from any address inserts an
	// entry and none of that needs a credential, entries live 15 minutes, and
	// the ticker fires only every 10 — so an attacker presenting many source
	// IPs (real rotation, or an attacker-influenced X-Forwarded-For chain when
	// TRUST_PROXY_HEADERS=true) accumulates freely in between. Crossing this
	// bound triggers an inline sweep at insertion time as a second, tighter
	// backstop.
	powEscalationSweepThreshold = 10_000
)

type powEscalationEntry struct {
	failures  int
	expiresAt time.Time
}

// powEscalation raises the proof-of-work difficulty for a client IP that has
// recently failed logins, so the common case (a correct password, first try)
// stays nearly free while naive repeated guessing from one address gets
// expensive fast.
//
// Be honest about the reach of that: a challenge is NOT bound to the address
// that requested it — captcha.PoWVerifier.Verify deliberately ignores its
// remoteIP argument — so an attacker can fetch base-difficulty challenges from
// a clean address and submit the solutions from an escalated one, and pay the
// base price forever. What escalation reliably prices is the honest user who
// mistyped, and the unsophisticated script that hammers from one address.
// Binding the challenge to the requesting IP would close that, at the cost of
// breaking a mobile client whose address changes mid-solve; that tradeoff has
// not been made, so do not read more into this than it does.
//
// It deliberately does not reuse loginLockout. That is keyed username+IP, and
// the challenge is issued before the user has typed a username — there is
// nothing to key on at issue time but the address.
//
// ponytail: counts failures per IP with no notion of which account was
// targeted. Ceiling: an attacker rotating source addresses resets to the base
// difficulty on every new one, and everyone behind one shared address shares
// one budget. Upgrade path: none planned — narrowing it needs an identifier
// that exists before the login form is filled in, and there isn't one.
type powEscalation struct {
	mu             sync.Mutex
	entries        map[string]*powEscalationEntry
	sweepThreshold int
}

func newPowEscalation() *powEscalation {
	return &powEscalation{
		entries:        map[string]*powEscalationEntry{},
		sweepThreshold: powEscalationSweepThreshold,
	}
}

// recordFailure counts one failed login against ip and refreshes its decay
// window.
func (p *powEscalation) recordFailure(ip string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, exists := p.entries[ip]
	if !exists || now.After(e.expiresAt) {
		if !exists && len(p.entries) >= p.sweepThreshold {
			// Only the !exists branch grows the map, so only it needs the
			// bound. sweepExpiredLocked, not sweepExpired: p.mu is already
			// held here and sync.Mutex is not reentrant.
			p.sweepExpiredLocked(now)
		}
		e = &powEscalationEntry{}
		p.entries[ip] = e
	}
	e.failures++
	e.expiresAt = now.Add(powEscalationDecay)
}

// clear drops ip's history, called on a successful login: whoever is at that
// address has now proved they hold a real credential.
func (p *powEscalation) clear(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, ip)
}

// maxNumberFor returns the search space to issue to ip: base multiplied by
// powEscalationFactor once per recent failure, capped.
func (p *powEscalation) maxNumberFor(ip string, base int, now time.Time) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, exists := p.entries[ip]
	if !exists || now.After(e.expiresAt) {
		return base
	}
	maxNumber := base
	for i := 0; i < e.failures; i++ {
		// Check before multiplying: powMaxNumberCeiling is far below
		// math.MaxInt, but growing by 4x per failure reaches overflow in
		// well under a hundred iterations and an attacker chooses the count.
		if maxNumber >= powMaxNumberCeiling/powEscalationFactor {
			return powMaxNumberCeiling
		}
		maxNumber *= powEscalationFactor
	}
	if maxNumber > powMaxNumberCeiling {
		return powMaxNumberCeiling
	}
	return maxNumber
}

// sweepExpired drops decayed entries. Fed by unauthenticated callers (any
// failed login from any address makes one), so it needs a real sweep — see
// backend/AGENTS.md. Driven by StartPoWSweeper, unconditionally: handleLogin
// records failures whatever CAPTCHA_PROVIDER is set to. This ticker sweep and
// recordFailure's threshold-triggered sweep are two independent bounds, not
// alternatives — the ticker guarantees eventual reclamation even at low
// traffic, the threshold caps worst-case memory between ticks.
func (p *powEscalation) sweepExpired(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweepExpiredLocked(now)
}

// sweepExpiredLocked does the actual reclamation. Callers must hold p.mu.
// Factored out so recordFailure can trigger it without re-locking a mutex it
// already holds.
func (p *powEscalation) sweepExpiredLocked(now time.Time) {
	for ip, e := range p.entries {
		if now.After(e.expiresAt) {
			delete(p.entries, ip)
		}
	}
}

// entryCount reports how many IPs are tracked. Test-only.
func (p *powEscalation) entryCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}
