package api

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// qrTokenSingleUseTTL is how long a spent QR token is remembered.
//
// The tokens themselves live two minutes (handlePGPQRToken), so anything older
// than that is already refused by the HMAC's own expiry and there is nothing
// left to guard against. A small margin covers clock skew between the mint and
// the redeem.
const qrTokenSingleUseTTL = 5 * time.Minute

// qrTokenGuard remembers which PGP QR key-exchange tokens have been redeemed,
// so each works exactly once.
//
// In memory rather than on disk, deliberately: the window is two minutes, and a
// restart inside it simply returns to the previous behaviour for the handful of
// tokens outstanding at that moment. Persisting a set of short-lived
// single-use markers would cost a write on every scan to close a gap measured
// in seconds after a process death.
//
// Tokens are stored hashed. They are bearer credentials, and this map is the
// kind of structure that ends up in a heap dump or a debug endpoint one day.
type qrTokenGuard struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func newQRTokenGuard() *qrTokenGuard {
	return &qrTokenGuard{used: map[string]time.Time{}}
}

// consume marks a token spent, reporting false if it already was.
//
// Check and mark happen under one lock: two scans arriving together must not
// both succeed, which is the whole property being added.
func (g *qrTokenGuard) consume(token string) bool {
	key := sha256.Sum256([]byte(token))
	id := hex.EncodeToString(key[:])

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	// Sweep here rather than on a ticker: the map only grows when someone
	// scans, so the natural moment to bound it is a scan.
	for k, at := range g.used {
		if now.Sub(at) > qrTokenSingleUseTTL {
			delete(g.used, k)
		}
	}

	if _, spent := g.used[id]; spent {
		return false
	}
	g.used[id] = now
	return true
}

// consumeQRToken reports whether this QR token may be redeemed now, marking it
// spent if so.
func (s *Server) consumeQRToken(token string) bool {
	return s.qrTokens.consume(token)
}
