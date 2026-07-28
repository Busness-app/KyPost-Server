package captcha

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This provider is the self-hosted alternative to the two third-party ones
// above it. The server picks a secret number, publishes SHA-256(salt+number)
// plus an HMAC over the whole challenge, and the browser finds the number by
// brute force. Verification costs one HMAC and one SHA-256 — microseconds —
// while the client pays maxNumber/2 hashes on average. That asymmetry is the
// entire mechanism.
//
// What it is worth being honest about: an attacker running native code solves
// these one to two orders of magnitude faster than a browser does, so this is
// not a substitute for the three-strikes lockout in the api package — it sits
// on top of it, exactly as the Turnstile and Friendly verifiers do. What it
// buys over those two is that no login attempt leaves this host: no callout,
// no user IP handed to a third party, no third-party origin in the CSP, and
// it works on an install with no internet access at all.
const (
	// powChallengeTTL bounds how long a challenge stays solvable. It is
	// signed into the challenge, so a client cannot extend it. Long enough
	// for a slow phone to finish the work and for the user to finish typing
	// a password; short enough to bound the spent-salt cache.
	powChallengeTTL = 5 * time.Minute

	// defaultPoWMaxNumber is the level-0 search space when POW_MAX_NUMBER is
	// unset: ~2500 hashes expected, which is imperceptible. It is this low
	// because api's powEscalation raises it per recent failed login from the
	// same client IP — a fixed difficulty had to be high enough to deter an
	// attacker and low enough not to punish an honest phone, and no single
	// value is both.
	defaultPoWMaxNumber = 5_000

	algorithmSHA256 = "SHA-256"
)

// ErrChallengeExpired reports a correctly signed, correctly solved challenge
// that arrived after its deadline. It is distinct from a plain false on
// purpose: handleLogin refunds the lockout strike for this (the user's tab sat
// open; that is a clock, not a credential) and spends it for a wrong solution.
var ErrChallengeExpired = errors.New("captcha: proof-of-work challenge expired")

// ErrChallengeWrongClient reports a correctly signed, unexpired solution that
// was presented from a different address than the one it was issued to. Like
// ErrChallengeExpired it is distinct from a plain false, and for the same
// reason: handleLogin refunds the lockout strike for it. A phone handing off
// from wifi to cellular mid-solve changes address through no fault of its
// own, and that is a network event, not a wrong credential.
var ErrChallengeWrongClient = errors.New("captcha: proof-of-work challenge was issued to a different client address")

// Challenge is what GET /api/auth/pow-challenge returns and what the client
// echoes back inside its solution. Every field is covered by Signature, so a
// client can edit none of them — notably not MaxNumber, which is the whole
// difficulty setting, nor ClientIP, which binds the challenge to one address.
type Challenge struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Expires   int64  `json:"expires"`
	// ClientIP is the address this challenge was issued to. It is echoed to
	// the client on purpose rather than kept server-side: Verify needs to
	// tell "this solution belongs to another address" apart from "this
	// signature is forged", and it can only do that if the issuing address
	// travels with the challenge. Handing it back leaks nothing — it is that
	// client's own address, and it is HMAC-covered so they cannot edit it.
	ClientIP  string `json:"clientip"`
	Signature string `json:"signature"`
}

// solution is a Challenge plus the client's answer.
type solution struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Expires   int64  `json:"expires"`
	ClientIP  string `json:"clientip"`
	Signature string `json:"signature"`
	Number    int    `json:"number"`
}

// PoWVerifier implements Verifier for the self-hosted proof-of-work provider.
type PoWVerifier struct {
	hmacKey   []byte
	maxNumber int

	// now is a field so tests can move the clock past an expiry without
	// sleeping; production always leaves it as time.Now.
	now func() time.Time

	mu    sync.Mutex
	spent map[string]time.Time // salt -> the challenge's own expiry
}

// NewPoWVerifier builds a proof-of-work verifier. hmacKey must be non-empty:
// an empty key makes every signature forgeable, which turns the difficulty
// setting and the expiry into client-supplied values. maxNumber <= 0 falls
// back to defaultPoWMaxNumber.
func NewPoWVerifier(hmacKey []byte, maxNumber int) (*PoWVerifier, error) {
	if len(hmacKey) == 0 {
		return nil, errors.New("captcha: an HMAC key is required for the pow provider")
	}
	if maxNumber <= 0 {
		maxNumber = defaultPoWMaxNumber
	}
	return &PoWVerifier{
		hmacKey:   hmacKey,
		maxNumber: maxNumber,
		now:       time.Now,
		spent:     map[string]time.Time{},
	}, nil
}

// sign covers every field a client could otherwise choose for itself,
// including the address the challenge was issued to — without that, a
// challenge minted cheaply at a clean address could be spent at an escalated
// one and api's per-IP difficulty escalation would price nobody but the
// honest user who mistyped.
//
// The fields are joined with "|" and none of them can contain one: salt and
// challenge are hex, maxnumber and expires are integers, and an IP address
// can contain ":" (IPv6) or "." but never "|". So the delimiter stays
// unambiguous and no two distinct field sets share a preimage. Anything added
// here later must satisfy the same property.
func (v *PoWVerifier) sign(salt, challenge string, maxNumber int, expires int64, clientIP string) string {
	mac := hmac.New(sha256.New, v.hmacKey)
	fmt.Fprintf(mac, "%s|%s|%d|%d|%s", salt, challenge, maxNumber, expires, clientIP)
	return hex.EncodeToString(mac.Sum(nil))
}

// IssueAt mints a challenge bound to clientIP at a caller-chosen difficulty,
// for api's per-IP escalation. maxNumber <= 0 falls back to the configured
// default.
//
// Verify does not consult v.maxNumber at all — it checks the number against
// the maxnumber signed into the challenge — so raising the difficulty for one
// client cannot invalidate another's in-flight challenge.
func (v *PoWVerifier) IssueAt(clientIP string, maxNumber int) (Challenge, error) {
	if maxNumber <= 0 {
		maxNumber = v.maxNumber
	}
	saltBytes := make([]byte, 16)
	// Go 1.24+ crypto/rand.Read never returns an error; it panics internally
	// if the OS source is unavailable, which is not a condition this process
	// could survive anyway.
	_, _ = rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxNumber)+1))
	if err != nil {
		return Challenge{}, err
	}
	sum := sha256.Sum256([]byte(salt + strconv.FormatInt(n.Int64(), 10)))

	ch := Challenge{
		Algorithm: algorithmSHA256,
		Salt:      salt,
		Challenge: hex.EncodeToString(sum[:]),
		MaxNumber: maxNumber,
		Expires:   v.now().Add(powChallengeTTL).Unix(),
		ClientIP:  clientIP,
	}
	ch.Signature = v.sign(ch.Salt, ch.Challenge, ch.MaxNumber, ch.Expires, ch.ClientIP)
	return ch, nil
}

// BaseMaxNumber is the configured level-0 difficulty, which api's per-IP
// escalation multiplies up from.
func (v *PoWVerifier) BaseMaxNumber() int { return v.maxNumber }

// Verify checks a base64 solution payload against remoteIP. ctx is unused —
// the Verifier interface carries it for the two providers that make a network
// call, and this one deliberately makes none.
//
// Check order is load-bearing.
//
// The signature comes first because every other field is attacker-controlled
// until it passes, including the salt this would otherwise record as spent
// and the ClientIP the address check below trusts.
//
// The address check sits above the range and hash checks and well above
// consume, so a foreign solution never burns its salt: a user whose address
// changed mid-solve gets ErrChallengeWrongClient, fetches a fresh challenge,
// and is not additionally told their old one was already spent. Moving it
// below consume would turn one network hiccup into two failures.
//
// The spent-salt burn comes last so only a fully valid solution consumes an
// entry, which keeps garbage out of the cache.
func (v *PoWVerifier) Verify(_ context.Context, token, remoteIP string) (bool, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false, nil
	}
	var sol solution
	if err := json.Unmarshal(raw, &sol); err != nil {
		return false, nil
	}
	if sol.Algorithm != algorithmSHA256 {
		return false, nil
	}

	want := v.sign(sol.Salt, sol.Challenge, sol.MaxNumber, sol.Expires, sol.ClientIP)
	if subtle.ConstantTimeCompare([]byte(sol.Signature), []byte(want)) != 1 {
		return false, nil
	}
	if v.now().After(time.Unix(sol.Expires, 0)) {
		return false, ErrChallengeExpired
	}
	// sol.ClientIP survived the signature check, so this server put it there:
	// a client that rewrites it fails above with a plain false (a forgery),
	// not here. Neither value is a secret, so a plain compare is right —
	// there is no timing signal in an address the caller already knows. Both
	// sides come from api.clientIP, so they are the same textual form.
	if sol.ClientIP != remoteIP {
		return false, ErrChallengeWrongClient
	}
	if sol.Number < 0 || sol.Number > sol.MaxNumber {
		return false, nil
	}
	sum := sha256.Sum256([]byte(sol.Salt + strconv.Itoa(sol.Number)))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(sol.Challenge)) != 1 {
		return false, nil
	}
	if !v.consume(sol.Salt, time.Unix(sol.Expires, 0)) {
		return false, nil
	}
	return true, nil
}

// consume records salt as spent, returning false if it already was. Doing the
// check and the insert under one lock closes the same TOCTOU window
// ConsumeTOTPStep (mfa.go) and consumedNativePairingNonces.consume
// (api/native_pairing_nonce.go) describe for their own equivalents.
func (v *PoWVerifier) consume(salt string, expiry time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.spent[salt]; exists {
		return false
	}
	v.spent[salt] = expiry
	return true
}

// SweepExpired drops spent salts whose challenges can no longer be replayed
// anyway. Driven by api.Server.StartPoWSweeper on a ticker, per the
// "every bounded in-memory map has an explicit sweep" rule in
// backend/AGENTS.md. The map is bounded meanwhile by the challenge endpoint's
// own per-IP rate limit: only a salt this server issued can ever be recorded.
func (v *PoWVerifier) SweepExpired(now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for salt, expiry := range v.spent {
		if now.After(expiry) {
			delete(v.spent, salt)
		}
	}
}

// spentCount reports how many salts are currently recorded. Test-only.
func (v *PoWVerifier) spentCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.spent)
}
