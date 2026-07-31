package api

import (
	"sync"
	"time"
)

// mfaPushWindow and mfaPushBurst bound how often a login can fan an actual MFA
// push notification out to a given account's approver devices: without a cap, an
// attacker who already holds a valid password can mint an unlimited number of
// real MFA challenges by calling login repeatedly (each successful password
// check clears loginLockout), bombarding the user's devices with "Approve
// sign-in" pushes until one gets tapped out of habit or annoyance — the "MFA
// fatigue" pattern used in the 2022 Uber breach.
//
// This caps the number of pushes per window rather than allowing exactly one,
// which is what it used to do. A flat one-per-five-minutes was unshippable in
// practice: every login attempt mints a *fresh* challenge id and fresh
// MatchDigits (mfa.Store.Create), so the second attempt inside the window handed
// the browser a challenge that no device had ever been pushed. The browser then
// polled it until the TTL expired, the phone stayed dark, and push MFA looked
// broken after exactly one successful sign-in. Retrying is normal behaviour, not
// an attack.
//
// A burst of 3 is a deliberate posture, not a guess. Number matching
// (mfa.Challenge.MatchDigits) already means a prompt cannot be approved by a
// blind "yes" — the approver has to read digits off the browser that started the
// sign-in — so the fatigue risk a hard one-per-window was buying down is already
// carried by a stronger control. Three prompts is comfortably more than a real
// user needs and far short of the volume a fatigue attack relies on.
//
// This still does not block login or challenge creation itself (a user who
// mistyped a TOTP code must be able to retry), only how often the push fans out.
// When it does throttle, the login response stops advertising "push" as a usable
// method — see handleLogin. Advertising a method whose notification was
// suppressed is what produced the original silent hang.
const (
	mfaPushWindow = 5 * time.Minute
	mfaPushBurst  = 3
)

// mfaPushLimiter is small in-memory, per-account state: the timestamps of the
// most recent pushes dispatched for each userID. Keyed on the account's user ID
// (not username+IP like loginLockout) since the whole point is to limit delivery
// to that account's devices regardless of where login attempts against it
// originate from.
//
// Each account's slice is capped at mfaPushBurst entries, so the per-key cost is
// bounded by construction and only the map itself needs sweeping.
type mfaPushLimiter struct {
	mu   sync.Mutex
	sent map[string][]time.Time
}

func newMfaPushLimiter() *mfaPushLimiter {
	return &mfaPushLimiter{sent: map[string][]time.Time{}}
}

// tryConsume atomically checks whether a push notification may be sent to
// userID right now and, if so, records it in the same critical section.
// retryAfter is how long until the oldest recorded push falls out of the window,
// and is zero when the push is allowed.
//
// Doing the check and the record under one lock closes a TOCTOU window that
// separate allowed()+recordSent() calls left open: concurrent logins for the
// same account could otherwise all observe "allowed" before any had recorded its
// send, permitting a burst past the intended cap.
func (c *mfaPushLimiter) tryConsume(userID string) (ok bool, retryAfter time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-mfaPushWindow)
	live := make([]time.Time, 0, mfaPushBurst)
	for _, at := range c.sent[userID] {
		if at.After(cutoff) {
			live = append(live, at)
		}
	}

	if len(live) >= mfaPushBurst {
		// live is append-ordered, so the first element is the oldest push in the
		// window and the one whose expiry frees the next slot.
		c.sent[userID] = live
		return false, mfaPushWindow - now.Sub(live[0])
	}

	c.sent[userID] = append(live, now)
	return true, 0
}

// mfaPushLimiterSweepMaxAge bounds how long an idle entry is kept before
// StartMfaPushLimiterSweeper reclaims it.
//
// sent is keyed on the ID of a real account, so it cannot be grown past the user
// count by an outsider — but an entry is only ever consulted to enforce
// mfaPushWindow, so anything older than that is dead weight, and the rule in this
// codebase is that every bounded in-memory map in this package has an explicit
// sweep (see backend/AGENTS.md). This map was the one that did not. The 12x
// margin over the window matches cooldownSweepMaxAge, so entries are never
// reclaimed while still influencing a live decision.
const mfaPushLimiterSweepMaxAge = 1 * time.Hour

// mfaPushLimiterSweepInterval mirrors cooldownSweepInterval: the map is
// tiny and bounded by the account count, so there is nothing to gain from
// sweeping it more eagerly than the margin above.
const mfaPushLimiterSweepInterval = 1 * time.Hour

// sweep drops entries whose most recent push is older than maxAge. Mirrors
// sendAsVerificationCooldown.sweep's lock-then-iterate-and-delete shape.
func (c *mfaPushLimiter) sweep(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for userID, sent := range c.sent {
		if len(sent) == 0 || sent[len(sent)-1].Before(cutoff) {
			delete(c.sent, userID)
		}
	}
}
