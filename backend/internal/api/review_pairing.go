package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// handleReviewPairing is an explicit Play-review escape hatch. A trailing * in the configured
// username admits that prefix; without it, only the exact configured account is admitted.
func (s *Server) handleReviewPairing(w http.ResponseWriter, r *http.Request) {
	reviewPattern := strings.TrimSpace(os.Getenv("REVIEW_PAIRING_USERNAME"))
	if reviewPattern == "" {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	requestedUsername := strings.TrimSpace(req.Username)
	lockKey := clampLockoutKeyComponent(users.NormalizeUsername(requestedUsername)) + "\x00" + lockoutKeyForIP(clientIP(r))
	if allowed, retryAfter := s.loginLockout.tryAttempt(lockKey); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	// This endpoint is unauthenticated and reaches the same two hash formats
	// handleLogin does, so it gets the same wall-clock floor: an account still
	// holding a scrypt$ hash costs several times the always-Argon2id
	// equalization dummy, and that gap says which name the operator configured.
	// The writeKDFBusy paths are the exception, as on handleLogin — both
	// branches shed identically, and delaying a 503 under load is the wrong
	// trade.
	credentialStart := time.Now()
	u, err := s.users.GetByUsername(requestedUsername)
	if err != nil || !u.Active || !reviewUsernameMatches(reviewPattern, requestedUsername) {
		// Keep the configured-account failure indistinguishable from a bad password.
		if err := s.equalizeLoginTiming(r.Context(), req.Password); err != nil {
			s.loginLockout.cancelAttempt(lockKey)
			writeKDFBusy(w)
			return
		}
		s.settleCredentialTiming(r.Context(), credentialStart)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	credential := req.Password
	if u.UsesDerivedAuth() {
		credential, err = users.DeriveAuthSecret(req.Password, u.LoginSalt, u.LoginIterations)
		if err != nil {
			s.loginLockout.cancelAttempt(lockKey)
			s.settleCredentialTiming(r.Context(), credentialStart)
			http.Error(w, "review account is not configured correctly", http.StatusServiceUnavailable)
			return
		}
	}
	verified, verifyErr := verifyAccountCredential(r.Context(), u, req.Password, credential)
	if verifyErr != nil {
		s.loginLockout.cancelAttempt(lockKey)
		writeKDFBusy(w)
		return
	}
	// Both hash formats and both verdicts leave here at the same moment as the
	// no-such-review-account branch above.
	s.settleCredentialTiming(r.Context(), credentialStart)
	if !verified {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if u.MustChangePassword || u.TOTPEnabled || u.PushMFAEnabled {
		s.loginLockout.cancelAttempt(lockKey)
		http.Error(w, "review account requires an interactive sign-in", http.StatusForbidden)
		return
	}
	s.loginLockout.recordSuccess(lockKey)
	s.writeNotificationPairing(w, u.ID)
}

func reviewUsernameMatches(pattern, username string) bool {
	want := users.NormalizeUsername(strings.TrimSpace(pattern))
	got := users.NormalizeUsername(username)
	if strings.HasSuffix(want, "*") {
		prefix := strings.TrimSuffix(want, "*")
		return prefix != "" && strings.HasPrefix(got, prefix)
	}
	return got == want
}
