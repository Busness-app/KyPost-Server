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
	// At the ceiling a browser needs a few seconds, which is a real cost to
	// automation and a survivable one to a human who has genuinely mistyped
	// their password several times.
	powEscalationFactor = 4
	powMaxNumberCeiling = 1_000_000

	// powEscalationDecay is how long a failure keeps counting. Client IPs
	// are shared (carrier-grade NAT, office egress, a household), so a
	// stranger's failures must stop costing an innocent neighbour reasonably
	// soon. It mirrors loginLockoutFor for the same reason.
	powEscalationDecay = 15 * time.Minute
)

type powEscalationEntry struct {
	failures  int
	expiresAt time.Time
}

// powEscalation raises the proof-of-work difficulty for a client IP that has
// recently failed logins, so the common case (a correct password, first try)
// stays nearly free while scripted spraying gets expensive fast.
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
	mu      sync.Mutex
	entries map[string]*powEscalationEntry
}

func newPowEscalation() *powEscalation {
	return &powEscalation{entries: map[string]*powEscalationEntry{}}
}

// recordFailure counts one failed login against ip and refreshes its decay
// window.
func (p *powEscalation) recordFailure(ip string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	e, exists := p.entries[ip]
	if !exists || now.After(e.expiresAt) {
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
// backend/AGENTS.md. Driven by StartPoWSweeper.
func (p *powEscalation) sweepExpired(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
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
