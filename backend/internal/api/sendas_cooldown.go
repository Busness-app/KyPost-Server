package api

import (
	"sync"
	"time"
)

// sendAsVerificationCooldownFor bounds how often a send-as verification probe
// email may be dispatched for a given (user, candidate address) pair: without
// this, an authenticated user could repeatedly trigger probe emails at any
// third-party address, turning the endpoint into a spam/harassment vector
// against people who never asked to receive anything from this account. This
// does not block the underlying alias record's lifecycle — it only limits how
// often a *new* probe email goes out for the same pair.
const sendAsVerificationCooldownFor = 5 * time.Minute

// sendAsVerificationCooldown is small in-memory, per-(user, candidate
// address) state: after a probe is dispatched for a key, further probes for
// that same pair are suppressed until sendAsVerificationCooldownFor has
// elapsed. Keyed on userID+"|"+normalizedEmail (not bare userID like
// mfaPushCooldown) since the goal is to limit how often any single candidate
// address gets emailed, without penalizing a user who is concurrently
// verifying a different address of their own.
type sendAsVerificationCooldown struct {
	mu       sync.Mutex
	lastSent map[string]time.Time
}

func newSendAsVerificationCooldown() *sendAsVerificationCooldown {
	return &sendAsVerificationCooldown{lastSent: map[string]time.Time{}}
}

// tryConsume atomically reports whether a verification probe may be sent for
// key right now and, if so, starts the cooldown in the same critical section.
//
// One call, not allowed() followed by recordSent(): the two-call form let
// concurrent requests for the same address all observe "allowed" before any of
// them recorded, so a burst mailed the candidate address several times. That
// address belongs to a third party who did not ask to hear from this server —
// the cap is there for them, not for us. Mirrors mfaPushCooldown.tryConsume,
// which adopted this shape for the same reason.
func (c *sendAsVerificationCooldown) tryConsume(key string) (ok bool, retryAfter time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, exists := c.lastSent[key]; exists {
		if remaining := sendAsVerificationCooldownFor - time.Since(last); remaining > 0 {
			return false, remaining
		}
	}
	c.lastSent[key] = time.Now()
	return true, 0
}

// sendAsCooldownSweepMaxAge bounds how long a lastSent entry is kept before
// StartSendAsCooldownSweeper reclaims it. lastSent is keyed on
// userID+"|"+candidate-email — an attacker can mint an unbounded number of
// distinct keys just by attempting to verify arbitrary addresses, so without
// a sweep this map grows forever. An entry is only ever consulted to enforce
// sendAsVerificationCooldownFor (5 minutes), so anything older than that is
// already dead weight; this uses a 12x margin (1 hour, matching the sweep
// interval below) so entries are never reclaimed while still influencing an
// active cooldown decision.
const sendAsCooldownSweepMaxAge = 1 * time.Hour

// sweep removes lastSent entries recorded more than maxAge ago, bounding the
// map's growth under sustained abuse. Mirrors PickupStore.Sweep's
// lock-then-iterate-and-delete shape (backend/internal/pgpmail/pickup.go).
func (c *sendAsVerificationCooldown) sweep(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, last := range c.lastSent {
		if last.Before(cutoff) {
			delete(c.lastSent, key)
		}
	}
}
