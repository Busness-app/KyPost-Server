package api

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// singleUseSweepThreshold is the size past which consume reclaims expired
// entries.
//
// Threshold rather than every-call: qrTokenGuard swept the whole map on every
// redeem, which is an O(n) scan paid by each caller to reclaim entries that a
// bounded TTL was going to drop anyway.
const singleUseSweepThreshold = 10_000

// singleUseTokens remembers which one-time tokens have been redeemed, so each
// works exactly once.
//
// One type for what were two: qrTokenGuard (PGP QR key exchange) and
// consumedNativePairingNonces (native device pairing). Same job, same
// map[string]time.Time, same check-and-mark-under-one-lock requirement — and
// they had drifted apart in both directions, each holding one half of the right
// answer:
//
//   - qrTokenGuard HASHED the token before storing it, with the reasoning that
//     these are bearer credentials and this map is the kind of structure that
//     ends up in a heap dump or a debug endpoint one day. The nonce map stored
//     raw values. That reasoning applies to both.
//   - the nonce map swept on a size threshold. qrTokenGuard swept on every
//     single call.
//
// Both now hash and both sweep on a threshold.
//
// In memory rather than on disk, deliberately: the tokens live 90 seconds
// (native pairing) to two minutes (QR), so a restart inside that window returns
// to the previous behaviour for the handful outstanding at that moment.
// Persisting a set of short-lived single-use markers would cost a write on every
// redeem to close a gap measured in seconds after a process death.
type singleUseTokens struct {
	mu   sync.Mutex
	seen map[string]time.Time // sha256(token) -> expiry
}

func newSingleUseTokens() *singleUseTokens {
	return &singleUseTokens{seen: map[string]time.Time{}}
}

// consume marks a token spent for ttl, reporting false if it already was.
//
// Check and mark happen under one lock: two redemptions arriving together must
// not both succeed, which is the whole property this type exists to provide.
//
// The token is hashed before it is stored — see the type comment. A caller
// passing an already-opaque id loses nothing by it.
func (t *singleUseTokens) consume(token string, ttl time.Duration) bool {
	sum := sha256.Sum256([]byte(token))
	id := hex.EncodeToString(sum[:])

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if len(t.seen) >= singleUseSweepThreshold {
		for k, exp := range t.seen {
			if now.After(exp) {
				delete(t.seen, k)
			}
		}
	}

	if exp, spent := t.seen[id]; spent && now.Before(exp) {
		return false
	}
	t.seen[id] = now.Add(ttl)
	return true
}

// qrTokenSingleUseTTL is how long a spent QR token is remembered.
//
// The tokens themselves live two minutes (handlePGPQRToken), so anything older
// than that is already refused by the HMAC's own expiry and there is nothing
// left to guard against. A small margin covers clock skew between the mint and
// the redeem.
const qrTokenSingleUseTTL = 5 * time.Minute

// consumeQRToken reports whether this QR token may be redeemed now, marking it
// spent if so.
func (s *Server) consumeQRToken(token string) bool {
	return s.singleUse.consume("qr:"+token, qrTokenSingleUseTTL)
}

// consumeNativePairingNonce reports whether this pairing nonce may be redeemed
// now, marking it spent if so.
//
// Namespaced, like consumeQRToken. One map now backs both, and an unprefixed key
// space shared between two token systems means a value that is valid in one
// could mark the other's spent. The prefixes make that impossible rather than
// merely unlikely.
func (s *Server) consumeNativePairingNonce(nonce string, ttl time.Duration) bool {
	return s.singleUse.consume("pair:"+nonce, ttl)
}
