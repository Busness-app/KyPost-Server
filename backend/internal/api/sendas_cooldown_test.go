package api

import (
	"context"
	"testing"
	"time"
)

func TestSendAsVerificationCooldownBlocksWithinWindow(t *testing.T) {
	c := newSendAsVerificationCooldown()
	const key = "user-1|alice@example.com"

	ok, retryAfter := c.tryConsume(key)
	if !ok {
		t.Fatal("expected first verification probe to be allowed")
	}
	if retryAfter != 0 {
		t.Fatalf("retryAfter = %v, want 0 when allowed", retryAfter)
	}

	ok, retryAfter = c.tryConsume(key)
	if ok {
		t.Fatal("expected a second probe within the cooldown window to be blocked")
	}
	if retryAfter <= 0 || retryAfter > sendAsVerificationCooldownFor {
		t.Fatalf("retryAfter = %v, want a positive duration <= %v", retryAfter, sendAsVerificationCooldownFor)
	}
}

// TestSendAsVerificationCooldownIsPerKey demonstrates the reason this type is
// keyed on userID+"|"+email rather than bare userID like mfaPushCooldown: the
// same user verifying a second alias must not be blocked by the cooldown
// already in effect for their first alias.
func TestSendAsVerificationCooldownIsPerKey(t *testing.T) {
	c := newSendAsVerificationCooldown()
	const aliceKey = "user-a|alice@example.com"
	const bobKey = "user-a|bob@example.com"

	_, _ = c.tryConsume(aliceKey)

	if ok, _ := c.tryConsume(aliceKey); ok {
		t.Fatal("user-a's probe to alice@example.com should be in cooldown")
	}
	if ok, _ := c.tryConsume(bobKey); !ok {
		t.Fatal("user-a's probe to a different candidate address (bob@example.com) must not be affected by the cooldown on alice@example.com")
	}
}

func TestSendAsVerificationCooldownExpiresAfterWindow(t *testing.T) {
	c := newSendAsVerificationCooldown()
	const key = "user-2|carol@example.com"
	_, _ = c.tryConsume(key)
	// Simulate the window having already elapsed.
	c.mu.Lock()
	c.lastSent[key] = time.Now().Add(-sendAsVerificationCooldownFor - time.Second)
	c.mu.Unlock()

	if ok, _ := c.tryConsume(key); !ok {
		t.Fatal("expected probe to be allowed again once the cooldown window has elapsed")
	}
}

// TestSendAsVerificationCooldownSweepRemovesStaleEntries proves sweep bounds
// lastSent's growth: entries older than maxAge are removed, entries newer
// than maxAge are kept. Without this, lastSent grows forever since it's keyed
// on attacker-influenced (userID, candidate-email) pairs that anyone can
// mint by attempting to verify an arbitrary address.
func TestSendAsVerificationCooldownSweepRemovesStaleEntries(t *testing.T) {
	c := newSendAsVerificationCooldown()
	const staleKey = "user-1|stale@example.com"
	const freshKey = "user-1|fresh@example.com"

	_, _ = c.tryConsume(staleKey)
	_, _ = c.tryConsume(freshKey)

	// Backdate staleKey's timestamp so it's older than maxAge; leave freshKey
	// as just recorded.
	c.mu.Lock()
	c.lastSent[staleKey] = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()

	c.sweep(1 * time.Hour)

	c.mu.Lock()
	_, staleStillPresent := c.lastSent[staleKey]
	_, freshStillPresent := c.lastSent[freshKey]
	c.mu.Unlock()

	if staleStillPresent {
		t.Fatal("expected sweep to remove an entry older than maxAge")
	}
	if !freshStillPresent {
		t.Fatal("expected sweep to keep an entry newer than maxAge")
	}
}

// TestStartSendAsCooldownSweeperRunsOnTickerAndStopsOnCancel proves the
// background sweeper actually fires sweep() on its ticker and returns
// promptly once its context is canceled, mirroring StartPickupSweeper's
// ticker/select shape (server.go).
func TestStartSendAsCooldownSweeperRunsOnTickerAndStopsOnCancel(t *testing.T) {
	srv := newTestServer(t)

	const staleKey = "user-1|stale@example.com"
	_, _ = srv.sendAsCooldown.tryConsume(staleKey)
	srv.sendAsCooldown.mu.Lock()
	srv.sendAsCooldown.lastSent[staleKey] = time.Now().Add(-2 * time.Hour)
	srv.sendAsCooldown.mu.Unlock()

	old := sendAsCooldownSweepInterval
	sendAsCooldownSweepInterval = 10 * time.Millisecond
	t.Cleanup(func() { sendAsCooldownSweepInterval = old })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.StartSendAsCooldownSweeper(ctx)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for {
		srv.sendAsCooldown.mu.Lock()
		_, present := srv.sendAsCooldown.lastSent[staleKey]
		srv.sendAsCooldown.mu.Unlock()
		if !present {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected StartSendAsCooldownSweeper to have swept the stale entry via its ticker")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected StartSendAsCooldownSweeper to return promptly after context cancellation")
	}
}
