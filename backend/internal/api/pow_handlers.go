package api

import (
	"context"
	"crypto/rand"
	"net/http"
	"os"
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

// resolvePoWSecret returns the HMAC key that signs proof-of-work challenges,
// mirroring resolvePairingSecret's precedence: an operator-supplied
// POW_SECRET wins, otherwise a generated-and-persisted key at keyPath.
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
	if !s.powChallenges.allow(clientIP(r), time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many challenge requests, try again shortly", http.StatusTooManyRequests)
		return
	}
	ch, err := s.powVerifier.Issue()
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

// StartPoWSweeper reclaims spent salts and stale rate-limit windows on an
// interval for the process lifetime, mirroring StartSendAsCooldownSweeper's
// ticker/select pattern. Both maps are fed by unauthenticated callers, so
// both need a real sweep rather than lazy eviction (backend/AGENTS.md). Call
// once after NewServer, in both app.go mode blocks. A no-op when pow is not
// the configured provider.
func (s *Server) StartPoWSweeper(ctx context.Context) {
	if s.powVerifier == nil {
		return
	}
	ticker := time.NewTicker(powSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.powVerifier.SweepExpired(now)
			s.powChallenges.sweepExpired(now)
		}
	}
}
