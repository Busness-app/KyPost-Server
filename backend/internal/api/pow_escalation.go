package api

import (
	"sync"
	"time"
)

const (
	// powEscalationFactor multiplies the proof-of-work search space per recent
	// failed login from a client IP; powMaxNumberCeiling caps it.
	//
	// The cap is load-bearing: uncapped, a persistent attacker drives
	// difficulty to a value nobody can solve, denying service to everyone
	// behind that address. Measured cost at the ceiling: ~4.8 s average and
	// ~9.5 s worst case under crypto.subtle on a desktop, 20-40 s on a phone.
	powEscalationFactor = 4
	powMaxNumberCeiling = 1_000_000

	// powEscalationDecay is how long a failure keeps counting. Client IPs
	// are shared (carrier-grade NAT, office egress, a household), so a
	// stranger's failures must stop costing an innocent neighbour reasonably
	// soon. It mirrors loginLockoutFor for the same reason.
	powEscalationDecay = 15 * time.Minute

	// powEscalationSweepThreshold bounds the per-IP map between StartPoWSweeper
	// ticks. Any failed login from any address inserts an entry with no
	// credential required, so an attacker presenting many source IPs (rotation,
	// or an influenced X-Forwarded-For chain under TRUST_PROXY_HEADERS=true)
	// accumulates freely between ticks. Crossing this triggers an inline sweep.
	powEscalationSweepThreshold = 10_000
)

// powEscalationEntry counts an address's recent failures per targeted account
// rather than as one total. Difficulty is the sum, so the honest user mistyping
// their own password sees flat-counter behaviour; the split exists so
// clearAccount can forgive one account without forgiving the others.
type powEscalationEntry struct {
	byAccount map[string]int
	expiresAt time.Time
}

func (e *powEscalationEntry) total() int {
	sum := 0
	for _, n := range e.byAccount {
		sum += n
	}
	return sum
}

// powEscalation raises the proof-of-work difficulty for a client IP with
// recent failed logins, so a correct password on the first try stays nearly
// free while repeated guessing from one address gets expensive fast.
//
// It depends on challenges being bound to the address that requested them
// (captcha.PoWVerifier signs the client IP in and Verify checks it). Without
// that binding an attacker fetches base-difficulty challenges from a clean
// address and spends them from an escalated one, and escalation then prices
// nothing but the honest user who mistyped. A mobile client whose address
// changes mid-solve gets captcha.ErrChallengeWrongClient, which handleLogin
// refunds the lockout strike for.
//
// It does not reuse loginLockout: that is keyed username+IP, and the challenge
// is issued before the user has typed a username.
//
// ponytail: the outer key is still the client IP. Ceiling: an attacker
// rotating source addresses gets base difficulty at each, and everyone behind
// one shared address shares one budget. Upgrade path: none planned — narrowing
// it needs an identifier that exists before the login form is filled in, and
// there isn't one. (Failures ARE now split per targeted account within an
// address, so a success no longer forgives guesses at other accounts — see
// clearAccount.)
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

// recordFailure counts one failed login against ip for the account it targeted
// and refreshes its decay window. account must already be folded through
// users.NormalizeUsername by the caller, so the three spellings of one
// username share one budget (the lesson handleLogin's lockout key learned).
func (p *powEscalation) recordFailure(ip, account string, now time.Time) {
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
		e = &powEscalationEntry{byAccount: map[string]int{}}
		p.entries[ip] = e
	}
	e.byAccount[account]++
	e.expiresAt = now.Add(powEscalationDecay)
}

// clearAccount forgives ip's failures against one account, called when a login
// for that account succeeds.
//
// Deliberately not "delete the whole entry": that would let an attacker holding
// any ordinary account on the instance spray guesses at another username, log
// in as themselves to reset the price, and repeat. Forgiveness is scoped to the
// account actually proved.
func (p *powEscalation) clearAccount(ip, account string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, exists := p.entries[ip]
	if !exists {
		return
	}
	delete(e.byAccount, account)
	if len(e.byAccount) == 0 {
		delete(p.entries, ip)
	}
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
	for i := 0; i < e.total(); i++ {
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

// sweepExpired drops decayed entries. Fed by unauthenticated callers, so it
// needs a real sweep — see backend/AGENTS.md. Driven by StartPoWSweeper
// unconditionally, since handleLogin records failures whatever
// CAPTCHA_PROVIDER says. This and recordFailure's threshold sweep are two
// independent bounds: the ticker guarantees eventual reclamation at low
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
