package api

import (
	"testing"
	"time"
)

func TestConsumedNativePairingNoncesConsumeOnce(t *testing.T) {
	c := newConsumedNativePairingNonces()
	const nonce = "abc123"

	if ok := c.consume(nonce, time.Minute); !ok {
		t.Fatal("expected first consume to succeed")
	}
	if ok := c.consume(nonce, time.Minute); ok {
		t.Fatal("expected replayed consume of the same nonce to fail")
	}
}

func TestConsumedNativePairingNoncesIsPerNonce(t *testing.T) {
	c := newConsumedNativePairingNonces()
	c.consume("nonce-a", time.Minute)

	if ok := c.consume("nonce-a", time.Minute); ok {
		t.Fatal("nonce-a should already be consumed")
	}
	if ok := c.consume("nonce-b", time.Minute); !ok {
		t.Fatal("a distinct nonce must not be affected by nonce-a's consumption")
	}
}

func TestConsumedNativePairingNoncesExpiresAfterTTL(t *testing.T) {
	c := newConsumedNativePairingNonces()
	const nonce = "expiring-nonce"
	c.consume(nonce, time.Minute)

	// Simulate the TTL having already elapsed.
	c.mu.Lock()
	c.seen[nonce] = time.Now().Add(-time.Second)
	c.mu.Unlock()

	if ok := c.consume(nonce, time.Minute); !ok {
		t.Fatal("expected a nonce to be consumable again once its recorded expiry has passed")
	}
}
