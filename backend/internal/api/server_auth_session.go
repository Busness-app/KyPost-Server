// Sign-in and session identity: password login, the second-factor challenge
// completions (TOTP, recovery code), session mint/teardown, and the middleware
// every authenticated route goes through (withAuth, withMailAuth, csrfCheckOK,
// currentUser).
//
// Split out of server.go, which had grown to 4,499 lines holding this alongside
// mailbox reads, notifications, pairing and SPA file serving. That size is not a
// style complaint: the login lockout keyed itself on the raw submitted username
// forty lines from the case-folding lookup that resolved the account, and in a
// file where nothing is forty lines from anything, the two never got read
// together.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kypost-server/backend/internal/captcha"
	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/totp"
	"kypost-server/backend/internal/users"
)

// Sessions live in process memory only (Server.sessions) and are never
// persisted. That is a deliberate trade, and it has a user-visible cost worth
// stating rather than discovering:
//
//   - Every restart logs every user out, mid-compose. Restarts are not rare
//     here — scheduleContainerRestart exits the process on config changes that
//     need one, and supervisord brings it back.
//   - In Docker the `server` and `daemon` processes share no memory, so only
//     the API process has sessions at all; a future second API replica would
//     not share them either (no sticky routing, no shared store).
//
// What it buys: a stolen session token cannot outlive the process, there is no
// session file to leak or to keep encrypted at rest, and revocation is a map
// delete that cannot fail halfway. Persisting sessions would mean writing
// bearer-equivalent credentials to the same volume this project already works
// hard to keep free of plaintext secrets. For a self-hosted server with a
// handful of users, being logged out by a restart is the cheaper problem.
//
// Session tracks who a live session token belongs to. Role is deliberately
// not stored here: currentUser looks the user up live from the users store
// on every request so a role change or deactivation take effect on the very
// next request rather than only at next login. CSRFToken backs the
// double-submit CSRF check (see csrfCheckOK) — minted alongside the session
// and mirrored into the non-HttpOnly csrf_token cookie so the frontend can
// read and echo it back as a header.
type Session struct {
	UserID string
	// IssuedAt is when this session was minted. ExpiresAt slides forward on
	// every request so an active user is not logged out mid-work, but
	// IssuedAt never moves, and sessionMaxLifetime past it the session dies
	// regardless of activity. Without that cap a stolen cookie is valid
	// forever: the thief's own polling keeps renewing it, and the legitimate
	// user has no way to see it or end it short of changing their password.
	IssuedAt  time.Time
	ExpiresAt time.Time
	CSRFToken string
}

const (
	// sessionIdleTimeout is how long a session survives with no requests.
	sessionIdleTimeout = 24 * time.Hour
	// sessionMaxLifetime is the absolute ceiling from IssuedAt, renewals
	// notwithstanding.
	sessionMaxLifetime = 7 * 24 * time.Hour
	// sessionSweepInterval is how often StartSessionSweeper reclaims
	// sessions that expired without anyone presenting them again.
	sessionSweepInterval = time.Hour
)

// AuthContext identifies the caller of an authenticated request.
type AuthContext struct {
	UserID             string
	Username           string
	Role               users.Role
	MustChangePassword bool
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaToken string `json:"captchaToken,omitempty"`
	}
	// Bounded before it is buffered. This is the only unauthenticated decode in
	// the codebase, and it runs before the lockout and captcha checks below, so
	// an unbounded body let any anonymous caller choose the server's allocation:
	// json.Decode buffers the whole value and then allocates the string on top,
	// measured at ~5.6x the wire size. A login body is a username, a password
	// and a captcha token.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Three-strikes/15-minute lockout, keyed by the submitted username
	// regardless of whether it belongs to a real account (so lockout behavior
	// can't be used to enumerate valid usernames) plus the client IP (so an
	// attacker hammering a known username can't lock the real owner out from
	// their own machine).
	//
	// The username is folded through users.NormalizeUsername — the exact fold
	// GetByUsername below resolves the account with. Keying on the raw string
	// instead made the lockout worthless: "victim", "Victim" and " victim "
	// are one account to the lookup but three independent strike budgets here,
	// and whitespace padding makes that key space unbounded, so a single IP
	// could guess passwords forever with the lockout permanently "engaged" on
	// the canonical spelling.
	lockoutKey := users.NormalizeUsername(req.Username) + "\x00" + clientIP(r)
	if allowed, retryAfter := s.loginLockout.tryAttempt(lockoutKey); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return
	}

	// CAPTCHA, when an operator has configured a provider, is required on
	// every login attempt and checked before the password is verified so a
	// failed/missing solution never pays scrypt's cost.
	if s.captchaVerifier != nil {
		ok, err := s.captchaVerifier.Verify(r.Context(), req.CaptchaToken, clientIP(r))
		switch {
		case errors.Is(err, captcha.ErrChallengeExpired):
			// Self-hosted proof-of-work only: the solution was correct and
			// correctly signed, it just arrived after the challenge's
			// deadline — a tab left open, not a credential. Refund the
			// strike (three stale tabs must not lock anyone out) and answer
			// 401 rather than the 503 below, which means "the provider is
			// down" and would be a lie here: there is no provider. The
			// client fetches a fresh challenge and retries. No password is
			// checked on this path, so the refund cannot buy an attacker
			// guesses.
			s.loginLockout.cancelAttempt(lockoutKey)
			http.Error(w, "security check expired, please try again", http.StatusUnauthorized)
			return
		case err != nil:
			// The operator's CAPTCHA provider is down; the user never got as
			// far as offering a password. Give the strike back, or an outage
			// would lock out every user of the instance.
			s.loginLockout.cancelAttempt(lockoutKey)
			s.logger.Error("captcha verification failed", "error", err.Error())
			http.Error(w, "captcha verification unavailable", http.StatusServiceUnavailable)
			return
		case !ok:
			http.Error(w, "captcha verification failed", http.StatusUnauthorized)
			return
		}
	}

	u, err := s.users.GetByUsername(req.Username)
	if err != nil || !u.Active {
		// Pay the same scrypt cost a real password check would, so response
		// timing doesn't reveal whether the username exists (or is inactive).
		equalizeLoginTiming(req.Password)
		// No recordFailure: tryAttempt already spent the strike.
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !users.VerifyPassword(u, req.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.loginLockout.recordSuccess(lockoutKey)

	// Second-factor users must clear a challenge before a session exists. No
	// cookie is set here; the client receives a challenge id plus the methods it
	// may use. A push-enabled challenge additionally fans a notification out to
	// the user's approver devices (asynchronously — see dispatchPushChallenge).
	if u.TOTPEnabled || u.PushMFAEnabled {
		ch, err := s.mfaChallenges.Create(u.ID)
		if err != nil {
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}
		methods := make([]string, 0, 2)
		if u.TOTPEnabled {
			methods = append(methods, "totp")
		}
		if u.PushMFAEnabled {
			methods = append(methods, "push")
			// Rate-limit the push itself, not challenge creation or login: a user who
			// mistyped a TOTP code must still be able to retry, but repeated logins
			// within the cooldown window reuse the existing push rather than fanning
			// another one out — see mfaPushCooldown's doc for why.
			if allowed, _ := s.mfaPushCooldown.tryConsume(u.ID); allowed {
				// Snapshot the request context before the goroutine: r is not
				// safe to touch once this handler returns.
				go s.dispatchPushChallenge(u.ID, ch.ID, newLoginContext(r), ch.CreatedAt, ch.MatchDigits, ch.DecoyDigits)
			}
		}
		resp := map[string]any{
			"mfaRequired": true,
			"challengeId": ch.ID,
			"methods":     methods,
		}
		if u.PushMFAEnabled {
			// The number the approving device must send back. Safe to hand to
			// this caller: they are the one being asked to read it off this
			// screen, and knowing it proves nothing on its own — approving
			// still needs a paired device's credentials.
			resp["matchDigits"] = ch.MatchDigits
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

// handleCaptchaConfig is public (pre-login) and tells the frontend which
// CAPTCHA widget, if any, to render on the login form. provider=="" means
// CAPTCHA is disabled. siteKey is the provider's public site key — safe to
// expose, unlike the secret key used server-side for verification.
func (s *Server) handleCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": s.captchaProvider,
		"siteKey":  s.captchaSiteKey,
	})
}

// handleCSRFToken returns the CSRF token paired with the caller's session,
// for same-origin JS that cannot read the non-HttpOnly csrf_token cookie —
// specifically the service worker's pushsubscriptionchange handler, which
// must send X-CSRF-Token on its resubscription POST but has no access to
// document.cookie. The response carries no CORS headers, so a cross-origin
// page can trigger this GET but never read the token; possession of the
// session cookie remains the only way to obtain it, which is exactly the
// double-submit invariant csrfCheckOK enforces.
func (s *Server) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrfToken": sess.CSRFToken})
}

// startSession mints a session token for userID, records it, and sets the
// kypost_session cookie with exactly the flags the legacy password-only login
// used. Shared by handleLogin and the second-factor endpoints.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID string) error {
	token, err := randomToken(24)
	if err != nil {
		return err
	}
	csrfToken, err := randomToken(24)
	if err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	s.sessions[token] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(sessionIdleTimeout),
		CSRFToken: csrfToken,
	}
	s.mu.Unlock()
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{Name: "kypost_session", Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	// Deliberately NOT HttpOnly: the frontend must be able to read this and
	// echo it back as the X-CSRF-Token header (double-submit pattern) — see
	// csrfCheckOK. It carries no authority on its own without the paired
	// HttpOnly session cookie, so JS-readability doesn't weaken the session.
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode})
	return nil
}

// handleMFATOTP completes a login challenge with a TOTP code. It is
// authenticated solely by possession of a valid challengeId (no session
// cookie). On success it mints the real session.
func (s *Server) handleMFATOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ch, ok := s.mfaChallenges.Get(strings.TrimSpace(req.ChallengeID))
	if !ok {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Per-account throttle spanning challenges: the per-challenge attempt cap
	// alone can be reset by minting a new challenge, so a password-holding
	// attacker could otherwise brute force TOTP online.
	if allowed, _ := s.mfaLockout.tryAttempt(ch.UserID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	u, err := s.users.Get(ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled || u.TOTPSecretEnc == "" {
		// The account changed underneath the challenge; no code was offered,
		// so the strike tryAttempt reserved goes back.
		s.mfaLockout.cancelAttempt(ch.UserID)
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	secret, err := mfa.OpenTOTPSecret(u.TOTPSecretEnc, s.totpSecretKeyPath)
	if err != nil {
		s.mfaLockout.cancelAttempt(ch.UserID)
		http.Error(w, "failed to load second factor", http.StatusInternalServerError)
		return
	}

	step, valid := totp.Validate(secret, req.Code, time.Now())
	if !valid {
		// tryAttempt already spent the strike.
		if err := s.mfaChallenges.RecordTOTPAttempt(ch.ID); errors.Is(err, mfa.ErrTooManyAttempts) {
			http.Error(w, "too many attempts", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	// A challenge is single-use: ConsumeTOTPStep atomically checks-and-marks
	// consumption under a single lock, so two concurrent requests bearing the
	// same still-valid code cannot both win (closes the TOCTOU window a
	// separate Get + later RecordTOTPStep would leave open).
	if err := s.mfaChallenges.ConsumeTOTPStep(ch.ID, step); err != nil {
		if errors.Is(err, mfa.ErrChallengeAlreadyUsed) {
			http.Error(w, "challenge already used", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Per-account replay guard: a password-holding attacker can mint any
	// number of challenges, so single-use protection on the challenge alone
	// (above) is not enough — it would let one captured valid code be
	// replayed once per freshly minted challenge. SetLastUsedTOTPStep
	// atomically rejects any step that is not strictly newer than the last
	// one accepted for this account, persisted across challenges. It runs
	// only after every other check has passed (a wrong/rejected code never
	// reaches here, so it never advances the recorded step), and a rejection
	// here gets the exact same generic response as a wrong code so it cannot
	// be distinguished from one over the wire.
	//
	// recordSuccess (which clears the account's brute-force lockout throttle)
	// is deliberately deferred until after this guard passes: a replayed code
	// is a rejected attempt, exactly like a wrong code, and must count against
	// the lockout rather than clearing it — otherwise a captured valid code let
	// an attacker keep the lockout counter at zero indefinitely while brute
	// forcing the real, still-unknown current code. tryAttempt spent the strike
	// on the way in, so simply not clearing it is what counts it.
	if _, err := s.users.SetLastUsedTOTPStep(u.ID, step); err != nil {
		s.mfaChallenges.Delete(ch.ID)
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	s.mfaLockout.recordSuccess(ch.UserID)

	s.mfaChallenges.Delete(ch.ID)
	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

// handleMFARecoveryCode completes a login challenge with a one-time recovery
// code. The matched code is consumed (removed) on success.
func (s *Server) handleMFARecoveryCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ch, ok := s.mfaChallenges.Get(strings.TrimSpace(req.ChallengeID))
	if !ok {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	if allowed, _ := s.mfaLockout.tryAttempt(ch.UserID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	u, err := s.users.Get(ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled {
		s.mfaLockout.cancelAttempt(ch.UserID)
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	_, matched, err := s.users.ConsumeRecoveryCode(u.ID, strings.TrimSpace(req.Code))
	if err != nil {
		s.mfaLockout.cancelAttempt(ch.UserID)
		http.Error(w, "failed to verify recovery code", http.StatusInternalServerError)
		return
	}
	if !matched {
		if err := s.mfaChallenges.RecordTOTPAttempt(ch.ID); errors.Is(err, mfa.ErrTooManyAttempts) {
			http.Error(w, "too many attempts", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	s.mfaLockout.recordSuccess(ch.UserID)

	s.mfaChallenges.Delete(ch.ID)
	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("kypost_session")
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{Name: "kypost_session", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// currentSessionToken returns the kypost_session cookie value on r, or "" if
// absent — used alongside revokeUserSessions so a self-service credential
// change revokes every *other* session without also logging out the request
// that made the change.
func currentSessionToken(r *http.Request) string {
	if c, err := r.Cookie("kypost_session"); err == nil {
		return c.Value
	}
	return ""
}

// revokeUserSessions deletes every live session belonging to userID, except
// keepToken if non-empty (the caller's own session, when the caller and the
// affected account are the same — e.g. a user changing their own password).
// Called after a password change/reset or MFA disable/regeneration so a
// stolen session cookie for that account is cut off from continued access
// as soon as the legitimate user (or an admin, on their behalf) takes one of
// those recovery actions, rather than remaining valid for up to the
// remaining 24h sliding-expiry window.
func (s *Server) revokeUserSessions(userID, keepToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.UserID == userID && token != keepToken {
			delete(s.sessions, token)
		}
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.currentUser(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	// Read, never mint: this is a GET the frontend polls on every auth refresh,
	// and GetOrCreateSubscriberID made each one a file-locked write. The mint
	// belongs to handleNotificationPairing, which is where a subscriber ID is
	// actually about to be used.
	subscriberID := ""
	if store, err := s.userStore(ac.UserID); err == nil {
		subscriberID = store.SubscriberID()
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "subscriberId": subscriberID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":      true,
		"userId":             u.ID,
		"username":           u.Username,
		"role":               u.Role,
		"mustChangePassword": u.MustChangePassword,
		"subscriberId":       subscriberID,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := users.ValidatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if !u.MustChangePassword && !users.VerifyPassword(u, req.OldPassword) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if u.MustChangePassword && strings.TrimSpace(req.OldPassword) != "" && !users.VerifyPassword(u, req.OldPassword) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if _, err := s.users.SetPassword(u.ID, req.NewPassword, false); err != nil {
		http.Error(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	// A password change is the remediation a user reaches for when they think
	// they have been compromised, so it must cut off *every* credential the
	// account holds — not just sessions. A device secret minted from a stolen
	// session is independent of the password and survived this call, keeping
	// full mailbox access and (since every device registers MFAApprover=true)
	// a standing second factor. The three admin recovery paths already call
	// revokeAllUserCredentials for exactly this reason; the self-service path
	// was the gap.
	//
	// The session making this request is preserved so the legitimate user is
	// not logged out of the tab they are standing in.
	s.revokeAllUserCredentialsExcept(u, currentSessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, ok := s.currentUser(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !s.csrfCheckOK(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Enforce the first-login password change server-side: a user who still
		// owes a password change (e.g. the bootstrap admin) gets a full session
		// but may reach nothing except the change/logout endpoints until they
		// rotate it. Without this the flag is merely advisory and a default
		// credential grants full access.
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

// csrfCheckOK enforces a double-submit CSRF check on cookie-authenticated,
// state-changing (non-GET/HEAD/OPTIONS) requests: the X-CSRF-Token header
// must match the csrf_token minted alongside the caller's session (see
// startSession). It intentionally does nothing when no kypost_session cookie
// is present — mobile clients (X-Kypost-Device-Id/X-Kypost-Device-Secret
// headers, see resolveMailAuthContext) and CardDAV (HTTP Basic Auth) never send that
// cookie, so they carry no ambient, forgeable credential for CSRF to exploit
// in the first place and are structurally exempt rather than specially
// carved out here.
func (s *Server) csrfCheckOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		return true
	}
	s.mu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()
	if !ok {
		// No matching session for this cookie value: either it's stale (the
		// caller-visible auth check elsewhere will already reject the
		// request) or this request actually authenticated via a different,
		// cookie-free path (e.g. withMailAuth's mobile fallback) despite an
		// unrelated cookie being present. Either way there's no session CSRF
		// token to check against.
		return true
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(sess.CSRFToken)) == 1
}

// withMailAuth gates endpoints mobile clients need to reach without a web
// session — mail read/act-on (inbox, folders, actions, draft, send), contacts
// dedupe/groups/photo-get, and the PGP QR token mint — for either a web
// session cookie or a paired device's own X-Kypost-Device-Id/
// X-Kypost-Device-Secret credentials — see resolveMailAuthContext. Despite
// the name, it's no longer mail-exclusive; IMAP/SMTP account setup
// (/api/imap/config, /api/imap/test) and other web-UI-only writes
// intentionally stay on withAuth only.
func (s *Server) withMailAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, err := s.resolveMailAuthContext(r)
		if err != nil {
			var lockErr *mailLockedOutError
			if errors.As(err, &lockErr) {
				w.Header().Set("Retry-After", strconv.Itoa(int(lockErr.retryAfter.Seconds())+1))
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many failed attempts, try again later"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !s.csrfCheckOK(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Session users still owing a first-login password change are blocked
		// here too (device-auth contexts never set this flag).
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

type authContextKey struct{}

// authFromContext retrieves the AuthContext injected by withAuth or
// withDAVBasicAuth. It only returns ok=false if called on a request that
// never passed through either (a programming error), since both already
// reject the request before next() runs otherwise.
func authFromContext(r *http.Request) (AuthContext, bool) {
	return authContextFromContext(r.Context())
}

func authContextFromContext(ctx context.Context) (AuthContext, bool) {
	ac, ok := ctx.Value(authContextKey{}).(AuthContext)
	return ac, ok
}

// currentUser validates the session cookie and looks the owning user up
// live from the users store (not snapshotted into the session), so a role
// change or deactivation take effect on the request immediately following
// it rather than only at next login.
func (s *Server) currentUser(r *http.Request) (AuthContext, bool) {
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		return AuthContext{}, false
	}

	now := time.Now()
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	if !ok {
		s.mu.Unlock()
		return AuthContext{}, false
	}
	// Idle timeout, then the absolute cap. The cap is checked separately so
	// that renewing below can never push a session past sessionMaxLifetime.
	if now.After(sess.ExpiresAt) || now.Sub(sess.IssuedAt) >= sessionMaxLifetime {
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		return AuthContext{}, false
	}
	// Sliding idle window for active users; IssuedAt is deliberately carried
	// through unchanged so the absolute ceiling still applies.
	sess.ExpiresAt = now.Add(sessionIdleTimeout)
	s.sessions[cookie.Value] = sess
	s.mu.Unlock()

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		return AuthContext{}, false
	}
	return AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role, MustChangePassword: u.MustChangePassword}, true
}

// mustChangePasswordExemptPaths are the only authenticated routes a user with
// an unsatisfied first-login password-change requirement may reach: the
// change endpoint itself and logout. Everything else is refused until the
// password is rotated, so a known/default bootstrap credential cannot be used
// for anything but changing it.
var mustChangePasswordExemptPaths = map[string]bool{
	"/api/auth/password": true,
	"/api/auth/logout":   true,
}
