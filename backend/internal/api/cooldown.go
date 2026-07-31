package api

import (
	"sync"
	"time"
)

// cooldown is per-key "not again for a while" state: after a key is consumed,
// further attempts on that key are refused until the cooldown has elapsed.
//
// One type for what were two byte-identical ones — sendAsVerificationCooldown
// and classifierTestCooldown had the same field names, the same map type, the
// same tryConsume body, and differed only in which constant they compared
// against. Only one of them had a sweep, which is the tell: a copy does not
// inherit the fix made to its original. classifierTestCooldown's map was keyed
// on admin user ID so it never grew dangerously, but that was luck about the key
// space rather than a decision, and nothing said so.
//
// The cooldown duration is a field rather than a package constant so the two
// call sites keep their own — they are five minutes and ten seconds, and they
// exist for unrelated reasons documented where they are constructed.
type cooldown struct {
	mu       sync.Mutex
	every    time.Duration
	lastSent map[string]time.Time
}

func newCooldown(every time.Duration) *cooldown {
	return &cooldown{every: every, lastSent: map[string]time.Time{}}
}

// tryConsume atomically reports whether key may proceed right now and, if so,
// starts the cooldown in the same critical section.
//
// One call, not allowed() followed by record(): the two-call form let concurrent
// requests for the same key all observe "allowed" before any of them recorded.
// On the send-as path that meant a burst mailed a third party's address several
// times over — the cap is there for them, not for us. Do not split these.
func (c *cooldown) tryConsume(key string) (ok bool, retryAfter time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, exists := c.lastSent[key]; exists {
		if remaining := c.every - time.Since(last); remaining > 0 {
			return false, remaining
		}
	}
	c.lastSent[key] = time.Now()
	return true, 0
}

// sweep removes entries recorded more than maxAge ago, bounding the map under
// sustained abuse. Both instances are swept by StartCooldownSweeper.
//
// maxAge must stay comfortably above the instance's own cooldown duration, or a
// sweep reclaims an entry that is still meant to be suppressing something.
func (c *cooldown) sweep(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, last := range c.lastSent {
		if last.Before(cutoff) {
			delete(c.lastSent, key)
		}
	}
}

// len reports the number of tracked keys. Test-facing, so a sweep can be
// asserted on.
func (c *cooldown) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.lastSent)
}

// sendAsVerificationCooldownFor bounds how often a send-as verification probe
// email may be dispatched for a given (user, candidate address) pair: without
// this, an authenticated user could repeatedly trigger probe emails at any
// third-party address, turning the endpoint into a spam/harassment vector
// against people who never asked to receive anything from this account. This
// does not block the underlying alias record's lifecycle — it only limits how
// often a *new* probe email goes out for the same pair.
//
// Keyed on userID+"|"+normalizedEmail (not bare userID) since the goal is to
// limit how often any single candidate address gets emailed, without penalizing
// a user who is concurrently verifying a different address of their own.
const sendAsVerificationCooldownFor = 5 * time.Minute

// classifierTestCooldownFor bounds how often one admin may fire a
// connectivity-test request against the shared classifier/Ollama instance:
// handleClassifierTest builds its own ad-hoc classifier client rather than
// reusing the server's shared instance (to always reflect the currently saved
// config), which means it bypasses that shared client's own
// serialization/pacing against live poller traffic. This cooldown is the narrow
// substitute — it can't prevent a test request from racing a real
// classification, but it does prevent an admin (or a compromised admin session)
// from firing unlimited concurrent test requests that pile up unpaced against
// the same backend. Keyed on the admin's user ID.
const classifierTestCooldownFor = 10 * time.Second

// cooldownSweepMaxAge bounds how long an entry is kept before StartCooldownSweeper
// reclaims it.
//
// Sized against the LONGER of the two cooldowns (send-as, 5 minutes), because
// one sweeper serves both and an entry must never be reclaimed while it is still
// meant to be suppressing something. A 12x margin at that.
//
// The send-as map is the one that needs this: it is keyed on
// userID+"|"+candidate-email, so an attacker mints unbounded distinct keys just
// by attempting to verify arbitrary addresses.
const cooldownSweepMaxAge = 1 * time.Hour
