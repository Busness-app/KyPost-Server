package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/logging"
)

// powSweepInterval is a var rather than an inline literal (like
// sendAsCooldownSweepInterval) solely so tests can shrink it; production
// always runs the 10-minute default. Challenges live 5 minutes, so this
// reclaims an entry within two of its expiry at worst.
var powSweepInterval = 10 * time.Minute

// powSecretMinLen is the shortest POW_SECRET this will accept. The key is an
// HMAC key over a challenge whose every field the client already sees, so a
// guessable one (POW_SECRET=changeme) is recoverable offline from a single
// issued challenge. Whoever recovers it mints their own challenges —
// maxnumber 0, number 0, an expiry years out, a signature that verifies — and
// the proof-of-work becomes a silent no-op that still reports success. 16
// bytes is the floor; the documented `openssl rand -base64 32` gives 44.
const powSecretMinLen = 16

// resolvePoWSecret returns the HMAC key that signs proof-of-work challenges,
// mirroring resolvePairingSecret's precedence: an operator-supplied
// POW_SECRET wins, otherwise a generated-and-persisted key at keyPath.
//
// A POW_SECRET shorter than powSecretMinLen returns nil, which makes
// captcha.NewVerifier fail and NewServer install misconfiguredCaptchaVerifier:
// login rejects every attempt with a logged reason, and the server still
// starts. Falling back to a generated key instead would be worse than it
// looks — it would silently ignore the operator's configuration, so a
// multi-replica deployment would end up with a different key per replica and
// challenges that verify nowhere but where they were issued.
//
// Where it deliberately differs from resolvePairingSecret is the failure
// path. A pairing secret that cannot be written disables an optional feature,
// so returning "" and failing closed is right there. Here, failing closed
// means nobody can log into the mail server at all — a read-only secrets
// volume would brick the install. So a persistence failure falls back to a
// per-process random key: challenges issued before a restart stop verifying,
// which costs a stale tab one retry, and a multi-replica deployment has to
// set POW_SECRET so every replica agrees. Both are logged loudly. Neither is
// a weak key, which is the outcome that would actually matter.
func resolvePoWSecret(keyPath string, logger *logging.Logger) []byte {
	if fromEnv := strings.TrimSpace(os.Getenv("POW_SECRET")); fromEnv != "" {
		if len(fromEnv) < powSecretMinLen {
			if logger != nil {
				logger.Error("POW_SECRET is too short to be an HMAC key; the login CAPTCHA will "+
					"reject every attempt until it is fixed. A short key can be recovered offline "+
					"from one issued challenge, after which the proof-of-work verifies forged "+
					"challenges and protects nothing. Generate one with: openssl rand -base64 32",
					"length", strconv.Itoa(len(fromEnv)), "minimum", strconv.Itoa(powSecretMinLen))
			}
			return nil
		}
		return []byte(fromEnv)
	}
	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err == nil {
		return key
	}
	if logger != nil {
		logger.Error("could not persist the proof-of-work key; falling back to a per-process key. "+
			"Challenges issued before a restart will stop verifying, and a multi-replica deployment "+
			"must set POW_SECRET so every replica agrees on one key.",
			"path", keyPath, "error", err.Error())
	}
	ephemeral := make([]byte, 32)
	// Go 1.24+ crypto/rand.Read never returns an error.
	_, _ = rand.Read(ephemeral)
	return ephemeral
}

// handlePoWChallenge issues a proof-of-work challenge for the login form. It
// is public and pre-session by necessity — it runs before anyone has typed a
// password — which is why it is rate limited per client IP.
func (s *Server) handlePoWChallenge(w http.ResponseWriter, r *http.Request) {
	if s.powVerifier == nil {
		// Not the configured provider. 404 rather than a stub response so
		// the endpoint simply does not exist on a default install.
		http.Error(w, "proof-of-work is not enabled", http.StatusNotFound)
		return
	}
	ip := clientIP(r)
	if !s.powChallenges.allow(ip, time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many challenge requests, try again shortly", http.StatusTooManyRequests)
		return
	}
	// Difficulty rises with this address's recent failed logins, so an
	// honest first login stays nearly free. The challenge is bound to ip as
	// well as priced for it: otherwise an attacker whose address had been
	// escalated would just fetch base-difficulty challenges from a clean one
	// and submit them here, and escalation would price nobody but the honest
	// user who mistyped.
	maxNumber := s.powDifficulty.maxNumberFor(ip, s.powVerifier.BaseMaxNumber(), time.Now())
	ch, err := s.powVerifier.IssueAt(ip, maxNumber)
	if err != nil {
		s.logger.Error("could not issue a proof-of-work challenge", "error", err.Error())
		http.Error(w, "could not issue a challenge", http.StatusInternalServerError)
		return
	}
	// A cached challenge is a replayed challenge: every one must be unique
	// and single-use, so no shared cache or proxy may hand the same one to
	// a second client.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, ch)
}

// StartPoWSweeper reclaims spent salts, stale rate-limit windows, and decayed
// per-IP difficulty escalation on an interval for the process lifetime,
// mirroring StartSendAsCooldownSweeper's ticker/select pattern. All three maps
// are fed by unauthenticated callers, so all three need a real sweep rather
// than lazy eviction (backend/AGENTS.md). Call once after NewServer, in both
// app.go mode blocks.
//
// Two of the three maps only ever gain entries when pow is the configured
// provider, so they are skipped otherwise. powDifficulty is swept
// unconditionally, and that asymmetry is the point: handleLogin calls
// powDifficulty.recordFailure on every failed login regardless of
// CAPTCHA_PROVIDER, so a default install (provider unset) and a
// Turnstile/Friendly install both accumulate one entry per failing client IP.
// Returning early on powVerifier == nil, as this used to, left exactly those
// installs — the ones that never opted into proof-of-work — with an
// unbounded, remotely-triggerable map.
func (s *Server) StartPoWSweeper(ctx context.Context) {
	ticker := time.NewTicker(powSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.powDifficulty.sweepExpired(now)
			if s.powVerifier == nil {
				continue
			}
			s.powVerifier.SweepExpired(now)
			s.powChallenges.sweepExpired(now)
		}
	}
}
