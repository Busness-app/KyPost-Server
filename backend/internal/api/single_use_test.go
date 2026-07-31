package api

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// storedKey is how singleUseTokens keys its map. Tests that reach into `seen`
// must go through it — poking a raw token in writes an entry consume will never
// look at, so the assertion passes without exercising anything.
func storedKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestSingleUseTokenConsumesOnce(t *testing.T) {
	c := newSingleUseTokens()
	const nonce = "abc123"

	if ok := c.consume(nonce, time.Minute); !ok {
		t.Fatal("expected first consume to succeed")
	}
	if ok := c.consume(nonce, time.Minute); ok {
		t.Fatal("expected replayed consume of the same nonce to fail")
	}
}

func TestSingleUseTokenIsPerToken(t *testing.T) {
	c := newSingleUseTokens()
	c.consume("nonce-a", time.Minute)

	if ok := c.consume("nonce-a", time.Minute); ok {
		t.Fatal("nonce-a should already be consumed")
	}
	if ok := c.consume("nonce-b", time.Minute); !ok {
		t.Fatal("a distinct nonce must not be affected by nonce-a's consumption")
	}
}

func TestSingleUseTokenExpiresAfterTTL(t *testing.T) {
	c := newSingleUseTokens()
	const nonce = "expiring-nonce"
	c.consume(nonce, time.Minute)

	// Simulate the TTL having already elapsed.
	c.mu.Lock()
	c.seen[storedKey(nonce)] = time.Now().Add(-time.Second)
	c.mu.Unlock()

	if ok := c.consume(nonce, time.Minute); !ok {
		t.Fatal("expected a nonce to be consumable again once its recorded expiry has passed")
	}
}

// The tokens are bearer credentials and this map is the kind of structure that
// ends up in a heap dump or a debug endpoint. qrTokenGuard hashed for this
// reason; the pairing-nonce map, which did the same job, stored raw values.
func TestSingleUseTokenStoresOnlyHashes(t *testing.T) {
	c := newSingleUseTokens()
	const token = "a-bearer-token-nobody-should-read-back"
	c.consume(token, time.Minute)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, raw := c.seen[token]; raw {
		t.Fatal("the raw token is recoverable from the map")
	}
	if _, hashed := c.seen[storedKey(token)]; !hashed {
		t.Fatal("the token was not recorded under its hash")
	}
}

// One map now backs two token systems. Without namespacing, a value valid in one
// could mark the other's spent.
func TestSingleUseTokenNamespacesItsCallers(t *testing.T) {
	srv := newTestServer(t)
	const shared = "collide"

	if !srv.consumeQRToken(shared) {
		t.Fatal("first QR redeem should succeed")
	}
	if !srv.consumeNativePairingNonce(shared, time.Minute) {
		t.Fatal("the same string in the pairing namespace must be independent of the QR one")
	}
	if srv.consumeQRToken(shared) {
		t.Fatal("the QR token should still be spent")
	}
	if srv.consumeNativePairingNonce(shared, time.Minute) {
		t.Fatal("the pairing nonce should now be spent")
	}
}
