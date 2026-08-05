// Sign-in and session identity: password login, the second-factor challenge
// completions (TOTP, recovery code), session mint/teardown, and the middleware
// every authenticated route goes through (withAuth, withMailAuth, csrfCheckOK,
// currentUser). Keep the lockout key, the case-folding account lookup, and the
// credential check within reading distance: they have to agree on what "the
// same account" means, and that agreement is invisible from any one of them.
package api

import (
	"cmp"
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

// Session tracks who a live session token belongs to.
//
// Sessions are in-memory only (Server.sessions) and never persisted: persisting
// them would write bearer-equivalent credentials to the same volume this project
// keeps free of plaintext secrets. A stolen token cannot outlive the process,
// and revocation is a map delete that cannot fail halfway. The cost is that any
// restart logs everyone out, and the process does not decide when it restarts.
// Only the API process has sessions; a second replica would not share them.
//
// Role is deliberately not stored here: currentUser looks the user up live on
// every request, so a role change or deactivation takes effect on the next
// request rather than at next login. CSRFToken backs the double-submit check
// (see csrfCheckOK), mirrored into the non-HttpOnly csrf_token cookie.
type Session struct {
	UserID string
	// IssuedAt is when this session was minted and never moves; ExpiresAt slides
	// forward on every request so an active user is not logged out mid-work.
	// sessionMaxLifetime past IssuedAt the session dies regardless of activity,
	// without which a stolen cookie is valid forever — the thief's own polling
	// keeps renewing it.
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
	// sessionSlideGranularity is how much the idle window must have advanced
	// before currentUser rewrites a session's ExpiresAt — i.e. the resolution
	// sessionIdleTimeout is actually enforced at. Noise against a 24-hour horizon,
	// and it is what keeps the common request path on a read lock.
	sessionSlideGranularity = 5 * time.Minute
)

// AuthContext identifies the caller of an authenticated request.
type AuthContext struct {
	UserID             string
	Username           string
	Role               users.Role
	MustChangePassword bool

	// SessionCSRFToken is the CSRF token of the session this request authenticated
	// with, and is EMPTY for every other authentication path (paired-device
	// headers, CardDAV Basic).
	//
	// It is how csrfCheckOK knows whether the caller presented an ambient,
	// browser-attached credential, rather than inferring it from whether a cookie
	// happened to be on the request. The old inference answered "no session found
	// for this cookie" by allowing the request, survivable only because the session
	// cookie is SameSite=Lax and never reaches a cross-site POST.
	SessionCSRFToken string
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		// Password is the LEGACY credential, sent only while this account still
		// authenticates with one. A converted account's client leaves it empty
		// and the server never sees the password again.
		Password string `json:"password"`
		// AuthSecret is the client-derived authentication half of the stretched
		// password — see login_params.go and frontend/src/lib/authSecret.ts. The
		// key-wrapping half is derived from the same stretch under a different HKDF
		// label and never leaves the browser, which is what makes the PGP vault
		// genuinely end-to-end.
		AuthSecret string `json:"authSecret,omitempty"`
		// LoginSalt/LoginIterations are what the client actually used, echoed
		// back so a legacy upgrade can pin the credential to them.
		LoginSalt       string `json:"loginSalt,omitempty"`
		LoginIterations int    `json:"loginIterations,omitempty"`
		CaptchaToken    string `json:"captchaToken,omitempty"`
	}
	// Bounded before it is buffered. This is the only unauthenticated decode in the
	// codebase and it runs before the lockout and captcha checks below, so an
	// unbounded body let any anonymous caller choose the server's allocation:
	// json.Decode buffers the whole value and then allocates the string on top,
	// measured at ~5.6x the wire size.
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Instance-wide rate limit FIRST, before anything that costs real work.
	//
	// The per-account lockout below cannot bound total work: it is keyed on
	// username+IP and the username comes out of the request body, so a caller who
	// never repeats one never trips it — while every attempt against an unknown
	// account runs scrypt on purpose (see equalizeLoginTiming).
	//
	// The bucket holds seconds of derivation work: this reserves one attempt's worth
	// and chargeLoginKDF settles up with what the attempt really cost, so a slower
	// machine drains the budget faster instead of waving through the same number of
	// requests to burn more CPU each. The reservation is released exactly once — by
	// chargeLoginKDF, or by the deferred refund on any path that derived nothing.
	// See loginBudget.
	var budget loginBudget
	if s.loginRateLimiter != nil {
		if ok, retryAfter := s.loginRateLimiter.admitCost(loginRateLimitKey, loginKDFReserveSeconds); !ok {
			retrySeconds := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":             "too many sign-in attempts right now, try again shortly",
				"retryAfterSeconds": retrySeconds,
			})
			return
		}
		budget.limiter = s.loginRateLimiter
	}
	defer budget.refund()

	// Per-IP lockout, independent of the username. Closes the rotating-username
	// hole in the per-account budget below: 50 failures from one address in 15
	// minutes stops that address, whatever names it tried. Loose on purpose — a NAT
	// egress or an office must not be easier to lock out than an account. Login is
	// where a constant clientIP does the most damage, so it is where the proxy
	// misconfiguration announces itself.
	s.warnOnUnusedProxyHeaders(r)
	ipLockoutKey := lockoutKeyForIP(clientIP(r))
	if allowed, retryAfter := s.loginIPLockout.tryAttempt(ipLockoutKey); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts from this address, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return
	}

	// Three-strikes/15-minute lockout, keyed on username+client IP: on the username
	// whether or not it exists (so lockout behavior cannot enumerate accounts), and
	// on the IP (so hammering a known username cannot lock its real owner out from
	// their own machine).
	//
	// The username MUST be folded through users.NormalizeUsername — the same fold
	// GetByUsername resolves the account with. On the raw string, "victim",
	// "Victim" and " victim " are one account to the lookup but three strike
	// budgets here, and padding makes that key space unbounded.
	// Clamped: NormalizeUsername folds case and trims but does not truncate, and
	// the body allows 64 KiB, so without this the caller sizes the lockout
	// table's memory as well as populating it.
	lockoutKey := clampLockoutKeyComponent(users.NormalizeUsername(req.Username)) + "\x00" + lockoutKeyForIP(clientIP(r))
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
			// Self-hosted proof-of-work only: a correctly signed solution that arrived
			// after its deadline — a tab left open, not a credential. Refund the strike so
			// three stale tabs cannot lock anyone out. 401, not the 503 below, which means
			// "the provider is down" and there is no provider here. No password is checked
			// on this path, so the refund buys an attacker no guesses.
			s.loginLockout.cancelAttempt(lockoutKey)
			s.loginIPLockout.cancelAttempt(ipLockoutKey)
			http.Error(w, "security check expired, please try again", http.StatusUnauthorized)
			return
		case errors.Is(err, captcha.ErrChallengeWrongClient):
			// Self-hosted proof-of-work only: a valid solution presented from a different
			// address than it was issued to. The binding stops an attacker fetching cheap
			// challenges from a clean address and spending them from an escalated one, but
			// a phone handing off wifi to cellular mid-solve looks identical. A changed
			// address is a network event, not a wrong credential, so refund the strike.
			s.loginLockout.cancelAttempt(lockoutKey)
			s.loginIPLockout.cancelAttempt(ipLockoutKey)
			http.Error(w, "your network address changed during the security check, please try again", http.StatusUnauthorized)
			return
		case err != nil:
			// The operator's CAPTCHA provider is down; the user never got as
			// far as offering a password. Give the strike back, or an outage
			// would lock out every user of the instance.
			s.loginLockout.cancelAttempt(lockoutKey)
			s.loginIPLockout.cancelAttempt(ipLockoutKey)
			s.logger.Error("captcha verification failed", "error", err.Error())
			http.Error(w, "captcha verification unavailable", http.StatusServiceUnavailable)
			return
		case !ok:
			http.Error(w, "captcha verification failed", http.StatusUnauthorized)
			return
		}
	}

	// The account this attempt targeted, folded the same way GetByUsername
	// resolves it and the lockout key above is built — so escalation, lockout
	// and lookup all agree on what "the same account" means.
	powAccount := clampLockoutKeyComponent(users.NormalizeUsername(req.Username))

	u, err := s.users.GetByUsername(req.Username)
	if err != nil || !u.Active {
		// Pay the same scrypt cost a real check would, so response timing doesn't
		// reveal whether the username exists (or is inactive). Equalize against
		// whichever credential was offered: a converted client sends only AuthSecret,
		// so equalizing on the empty Password would make the unknown-account path cheap
		// again for exactly the callers that matter.
		if _, err := s.chargeLoginKDF(r.Context(), &budget, func(ctx context.Context) bool {
			// The error is discarded here because the enclosing chargeLoginKDF
			// already holds the slot, so this derivation cannot be shed — see
			// users.WithKDFSlot.
			_ = equalizeLoginTiming(ctx, cmp.Or(req.AuthSecret, req.Password))
			return false
		}); err != nil {
			// Shed before the equalization ran. The refund is not just
			// courtesy: answering 401 instantly on the unknown-username path
			// while a real account still waits for a slot is the timing
			// disclosure equalizeLoginTiming exists to erase.
			s.loginLockout.cancelAttempt(lockoutKey)
			s.loginIPLockout.cancelAttempt(ipLockoutKey)
			writeKDFBusy(w)
			return
		}
		// Make the next challenge from this address more expensive. Recorded
		// for the unknown-username case too: spraying a list of guessed
		// usernames is exactly the pattern this is here to price.
		s.powDifficulty.recordFailure(lockoutKeyForIP(clientIP(r)), powAccount, time.Now())
		// No recordFailure on the lockout: tryAttempt already spent the strike.
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	// Two credential shapes, chosen by what the ACCOUNT stores rather than by what
	// the client sent. Letting the request pick would mean a caller could present a
	// plaintext password against a derived-auth account (or the reverse) and have
	// the server try both — and since the derivation salt is public
	// (login_params.go), "try both" would let anyone authenticate with a value they
	// can compute from the salt alone.
	//
	// Both verifiers run inside chargeLoginKDF's slot, so their busy error is
	// unreachable here and a false really is a wrong credential.
	verify := func(ctx context.Context) bool {
		ok, _ := users.VerifyPassword(ctx, u, req.Password)
		return ok
	}
	if u.UsesDerivedAuth() {
		verify = func(ctx context.Context) bool {
			ok, _ := users.VerifyAuthSecret(ctx, u, req.AuthSecret)
			return ok
		}
	}
	verified, err := s.chargeLoginKDF(r.Context(), &budget, verify)
	if err != nil {
		// Saturated slots, not a wrong password. Refund both strikes: a 401 here would
		// spend a third of this account's budget on a credential nobody looked at, so
		// three unlucky arrivals during a burst would lock out a user who typed
		// everything correctly. recordFailure is skipped for the same reason.
		s.loginLockout.cancelAttempt(lockoutKey)
		s.loginIPLockout.cancelAttempt(ipLockoutKey)
		writeKDFBusy(w)
		return
	}
	if !verified {
		s.powDifficulty.recordFailure(lockoutKeyForIP(clientIP(r)), powAccount, time.Now())
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.loginLockout.recordSuccess(lockoutKey)
	// A correct credential clears this address's accumulated failures too. The
	// per-IP budget exists to stop a caller with no valid credential from
	// spending unbounded CPU; someone who just proved one is not that caller.
	s.loginIPLockout.recordSuccess(ipLockoutKey)

	// Transparently upgrade a password hash written at an older, cheaper scrypt
	// cost. This is the only moment the plaintext is legitimately in hand, so it is
	// the only place the upgrade can happen — otherwise raising the cost protects
	// new accounts and leaves every existing one at the old strength forever.
	//
	// Best-effort and non-blocking to the login: a failure here means the account
	// keeps its old hash and gets another chance next time, which is strictly
	// better than refusing a correct password.
	if users.NeedsRehash(u.PasswordHash) {
		credential := req.Password
		if u.UsesDerivedAuth() {
			credential = req.AuthSecret
		}
		if err := s.users.RehashPassword(r.Context(), u.ID, credential); err != nil {
			s.logger.Error("password hash upgrade failed", "user_id", u.ID, "error", err.Error())
		}
	}

	// Convert a legacy account to derived auth, now that the password has been
	// proven and the client has supplied the secret it derived from it — the only
	// moment both are in hand. After this the password stops being transmitted at
	// all.
	//
	// Pinned to the salt the CLIENT used, which for a legacy account is the
	// synthetic one loginParamsFor handed out, recomputed here rather than trusted
	// from the request so a caller cannot pin their credential to a salt of their
	// choosing.
	if !u.UsesDerivedAuth() && req.AuthSecret != "" {
		salt := s.syntheticLoginSalt(req.Username)
		// Checked against what this server ISSUED, not clamped into range.
		//
		// loginParamsFor hands a legacy account exactly one work factor —
		// clientLoginIterations — so that is the only value a client can
		// honestly echo. Clamping an out-of-range echo was worse than useless:
		// the stored count has to be the one the client actually derived with,
		// so silently substituting a different number pins the account to a
		// credential nobody can reproduce, and the next sign-in fails for good.
		// A mismatch means the client did not use the parameters it was given,
		// which is not something to paper over.
		//
		// Zero is the one exception: a client that never sent the field used
		// what it was handed, because there was nothing else to use.
		iterations := req.LoginIterations
		if iterations == 0 {
			iterations = clientLoginIterations
		}
		if iterations != clientLoginIterations {
			// Non-fatal, like every other failure in this block: the account
			// keeps authenticating the legacy way.
			s.logger.Error("refusing auth derivation upgrade: client used a work factor this server did not issue",
				"user_id", u.ID, "client_iterations", strconv.Itoa(req.LoginIterations))
		} else if err := s.users.UpgradeToDerivedAuth(r.Context(), u.ID, req.Password, req.AuthSecret, salt, iterations); err != nil {
			// Non-fatal: the account keeps authenticating the legacy way and
			// gets another chance next sign-in. Refusing a correct password
			// because an optimization failed would be worse.
			s.logger.Error("auth derivation upgrade failed", "user_id", u.ID, "error", err.Error())
		}
	}
	// A correct password proves whoever is at this address holds THIS
	// account's credential — and nothing about any other account they have
	// been guessing at from the same address. Forgive only this one; see
	// powEscalation.clearAccount.
	s.powDifficulty.clearAccount(lockoutKeyForIP(clientIP(r)), powAccount)

	// Second-factor users must clear a challenge before a session exists. No
	// cookie is set here; the client receives a challenge id plus the methods it
	// may use. A push-enabled challenge additionally fans a notification out to
	// the user's approver devices (asynchronously — see dispatchPushChallenge).
	if u.TOTPEnabled || u.PushMFAEnabled {
		if u.PushMFAEnabled {
			store, err := s.userStore(u.ID)
			if err != nil {
				http.Error(w, "failed to open user state", http.StatusServiceUnavailable)
				return
			}
			if _, err := mfaApproverDevices(store); err != nil {
				http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
				return
			}
		}
		ch, err := s.mfaChallenges.Create(u.ID)
		if err != nil {
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}
		methods := make([]string, 0, 2)
		if u.TOTPEnabled {
			methods = append(methods, "totp")
		}
		// Rate-limit the push itself, not challenge creation or login: a user who
		// mistyped a TOTP code must still be able to retry. See mfaPushLimiter for
		// why this is a burst cap rather than one-per-window.
		pushDispatched, pushRetryAfter := false, time.Duration(0)
		if u.PushMFAEnabled {
			if allowed, retryAfter := s.mfaPushLimiter.tryConsume(u.ID); allowed {
				// At most one challenge for this account is ever both pushed and answerable.
				// Earlier attempts that were never answered are dropped rather than left
				// polling an id no device was told about — which, with the old
				// one-push-per-window cap, is how push MFA came to look broken after the first
				// sign-in.
				s.mfaChallenges.SupersedeUnansweredPush(u.ID, ch.ID)
				pushDispatched = true
				// Snapshot the request context before the goroutine: r is not
				// safe to touch once this handler returns.
				go s.dispatchPushChallenge(u.ID, ch.ID, newLoginContext(r), ch.CreatedAt, ch.MatchDigits, ch.DecoyDigits)
			} else {
				pushRetryAfter = retryAfter
			}
		}
		// Offered only when a notification actually went out for THIS challenge.
		// Advertising "push" for a challenge whose push was suppressed left the
		// browser polling a challenge no device could answer, with nothing on the
		// phone and no explanation, until the TTL ran out.
		if pushDispatched {
			methods = append(methods, "push")
		}
		resp := map[string]any{
			"mfaRequired": true,
			"challengeId": ch.ID,
			"methods":     methods,
		}
		if pushDispatched {
			// The number the approving device must send back. Safe to hand to
			// this caller: they are the one being asked to read it off this
			// screen, and knowing it proves nothing on its own — approving
			// still needs a paired device's credentials.
			resp["matchDigits"] = ch.MatchDigits
		}
		if pushRetryAfter > 0 {
			// So the UI can say "you have requested too many approvals, try again
			// in N seconds" instead of silently falling back to TOTP with no
			// account of where the push option went.
			resp["pushRetryAfterSeconds"] = int(pushRetryAfter.Seconds()) + 1
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

// handleCSRFToken returns the CSRF token paired with the caller's session, for
// same-origin JS that cannot read the non-HttpOnly csrf_token cookie —
// specifically the service worker's pushsubscriptionchange handler, which must
// send X-CSRF-Token but has no access to document.cookie. The response carries
// no CORS headers, so a cross-origin page can trigger this GET but never read
// the token; possession of the session cookie remains the only way to obtain it.
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
	// Read lock: this is a lookup, and the whole reason cfgMu and sessMu were
	// split off the old single mu is that taking sessMu exclusively on a request
	// path serializes every other request behind it. csrfCheckOK does the
	// identical lookup under RLock thirty lines below.
	s.sessMu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.sessMu.RUnlock()
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
	s.sessMu.Lock()
	s.sessions[token] = Session{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(sessionIdleTimeout),
		CSRFToken: csrfToken,
	}
	s.sessMu.Unlock()
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

	// Per-account replay guard. Single-use protection on the challenge alone is not
	// enough: a password-holding attacker can mint unlimited challenges, so a
	// captured valid code would be replayable once per fresh one.
	// SetLastUsedTOTPStep rejects any step not strictly newer than the last accepted
	// for this account, across challenges.
	//
	// Ordering is load-bearing: this runs after every other check so a rejected code
	// never advances the recorded step and answers exactly like a wrong code, and
	// recordSuccess stays below it so a replay counts against the lockout instead of
	// clearing it.
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

	// A KDF slot per comparison, not one slot around the whole call.
	// ConsumeRecoveryCode compares the candidate against every stored hash until one
	// matches, so a wrong code is up to ten scrypt derivations at 128 MiB each — and
	// this endpoint takes no session, a challenge id is the whole credential. A
	// single slot held across all ten would park a quarter of the instance's
	// derivation capacity for ~2s per request. Per-comparison admission keeps peak
	// memory per caller at one derivation and lets logins interleave — which is why
	// the request context is passed straight through rather than wrapped in
	// users.WithKDFSlot, and why it must stay that way.
	var matched bool
	_, matched, err = s.users.ConsumeRecoveryCode(r.Context(), u.ID, strings.TrimSpace(req.Code))
	switch {
	case errors.Is(err, errKDFBusy), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Shed mid-check. No verdict was reached on this code, so refund the
		// strike: otherwise a load spike burns an MFA budget the user needs to
		// get back into their account.
		s.mfaLockout.cancelAttempt(ch.UserID)
		writeKDFBusy(w)
		return
	case err != nil:
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
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
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
// affected account are the same). Called after a password change/reset or MFA
// disable/regeneration so a stolen session cookie is cut off as soon as the
// legitimate user, or an admin on their behalf, takes one of those recovery
// actions, rather than staying valid for the remaining 24h sliding window.
func (s *Server) revokeUserSessions(userID, keepToken string) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
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
		// Legacy plaintext fields, for a client that has not converted and for
		// an account whose credential is still a password (an admin-set
		// temporary one, or a first sign-in).
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`

		// Derived-auth fields. NewAuthSecret plus NewLoginSalt/NewIterations
		// replace the credential without the server ever seeing the new
		// password; OldAuthSecret proves the current one for an account that has
		// already converted.
		OldAuthSecret string `json:"oldAuthSecret,omitempty"`
		NewAuthSecret string `json:"newAuthSecret,omitempty"`
		NewLoginSalt  string `json:"newLoginSalt,omitempty"`
		NewIterations int    `json:"newIterations,omitempty"`

		// RewrappedPGPKey is the client-wrapped private-key envelope re-sealed under
		// the NEW password, written in the SAME transaction as the credential.
		//
		// As a separate follow-up request, a dropped connection in between left the
		// password changed and the envelope still sealed under the old one —
		// permanently, because the only rewrap path re-derives from the CURRENT
		// password and could never open it again.
		RewrappedPGPKey string `json:"rewrappedPgpKey,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}

	// Verify the CURRENT credential in whichever form this account stores, for the
	// same reason handleLogin does: the account decides, not the request.
	//
	// Behind a lockout, and every derivation on this path is admitted by the
	// shared slots. This is three 128 MiB derivations per request on an endpoint
	// any authenticated account can call in a loop: the check here, plus the hash
	// and any rewrap below. The comment used to say all three were "under a KDF
	// slot" while only this one was — SetPassword and SetDerivedAuthAndRewrapPGP
	// reached scrypt on their own, which is two thirds of the cost of the most
	// expensive authenticated endpoint sitting outside the ceiling. They now take
	// the request context and are admitted like everything else.
	verifyCurrent := func() (bool, error) {
		if u.UsesDerivedAuth() {
			return users.VerifyAuthSecret(r.Context(), u, req.OldAuthSecret)
		}
		return users.VerifyPassword(r.Context(), u, req.OldPassword)
	}
	// This request always verifies the current credential. There is no
	// MustChangePassword exemption, and there was one.
	//
	// The exemption's stated reasoning — "a user handed a temporary password may
	// have nothing to prove" — is false as implemented. Every path to a session
	// on such an account runs through handleLogin, or through an MFA completion
	// whose challenge is minted only after a successful password login, so the
	// caller demonstrably HAS the temporary password. The shipped SPA proves it
	// too: LoginPage refuses to submit this form without a current password and
	// always sends credentialFields(oldCredential, "old").
	//
	// What the exemption actually bought was a password reset for anyone holding
	// a cookie. A request carrying only {newAuthSecret, newLoginSalt,
	// newIterations} verified nothing, returned 200, installed the attacker's
	// secret, killed the temporary password, cleared MustChangePassword, and
	// then revokeAllUserCredentialsExcept evicted the owner while preserving the
	// attacker — against every admin-created and admin-reset account, for the
	// whole forced-change window. csrf_token is deliberately non-HttpOnly, so
	// XSS reaches this. 2f0e9d9 gated the recoverable half (the PGP rewrap, an
	// irreversible write) and left the credential half open.
	//
	// The existing test's own comment named the risk: "Inverted, this branch
	// turns the endpoint into a password reset for anyone holding a cookie."
	//
	// Keyed on user AND client IP, like the login lockout and for the same reason:
	// on the user alone, an attacker holding a stolen cookie burns the whole budget
	// from their own machine and locks the real owner out of changing their
	// password — during the incident where changing it is the remedy. Keyed on the
	// pair, a thief locks out only themselves.
	lockKey := ac.UserID + "\x00" + lockoutKeyForIP(clientIP(r))
	if allowed, retryAfter := s.passwordChangeLockout.tryAttempt(lockKey); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts, try again later",
			"retryAfterSeconds": int(retryAfter.Seconds()) + 1,
		})
		return
	}
	okCurrent, err := verifyCurrent()
	if err != nil {
		// Shed before the derivation ran. Refund: no credential was
		// examined, so this attempt must not count against the budget.
		s.passwordChangeLockout.cancelAttempt(lockKey)
		writeKDFBusy(w)
		return
	}
	if !okCurrent {
		// tryAttempt already spent the strike.
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.passwordChangeLockout.recordSuccess(lockKey)

	// Prefer the derived form when the client supplied it. The plaintext branch
	// stays only for clients that have not converted; it is the one that still
	// lets the server see a password, so it must never be the path taken when
	// the better one is available.
	switch {
	case req.NewAuthSecret != "":
		if req.NewLoginSalt == "" {
			http.Error(w, "newLoginSalt is required with newAuthSecret", http.StatusBadRequest)
			return
		}
		iterations := req.NewIterations
		if iterations <= 0 {
			iterations = clientLoginIterations
		}
		// One mutation for the credential and the PGP envelope, or neither.
		if _, err := s.users.SetDerivedAuthAndRewrapPGP(
			r.Context(), u.ID, req.NewAuthSecret, req.NewLoginSalt, iterations, false, req.RewrappedPGPKey,
		); err != nil {
			if errors.Is(err, users.ErrKDFBusy) {
				writeKDFBusy(w)
				return
			}
			if errors.Is(err, users.ErrAuthSecretMalformed) || errors.Is(err, users.ErrNotClientProtected) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "failed to update password", http.StatusInternalServerError)
			return
		}
	default:
		// The server can still measure length here, so it does.
		if err := users.ValidatePassword(req.NewPassword); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.RewrappedPGPKey != "" {
			// A plaintext password change cannot carry a rewrap: SetPassword
			// resets the account to legacy derivation, and accepting an envelope
			// alongside it would store one sealed under a key nothing will ask
			// for. Refuse rather than write a mismatched pair.
			http.Error(w, "rewrappedPgpKey requires newAuthSecret", http.StatusBadRequest)
			return
		}
		if _, err := s.users.SetPassword(r.Context(), u.ID, req.NewPassword, false); err != nil {
			if errors.Is(err, users.ErrKDFBusy) {
				writeKDFBusy(w)
				return
			}
			http.Error(w, "failed to update password", http.StatusInternalServerError)
			return
		}
	}
	// A password change is what a user reaches for when they think they have been
	// compromised, so it must cut off EVERY credential, not just sessions: a device
	// secret minted from a stolen session is independent of the password and would
	// otherwise keep full mailbox access and — since every device registers
	// MFAApprover=true — a standing second factor. The caller's own session is
	// preserved.
	if err := s.revokeAllUserCredentialsExcept(u, currentSessionToken(r)); err != nil {
		http.Error(w, "password changed but credential revocation failed; retry immediately", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, ok := s.currentUser(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !csrfCheckOK(r, ac) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Enforce the first-login password change server-side: a user who still owes
		// one (e.g. the bootstrap admin) gets a full session but may reach nothing
		// except the change/logout endpoints. Without this the flag is merely advisory
		// and a default credential grants full access.
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		// Per-account meter on MUTATING requests. A session is not a licence to
		// drive whole-file users.json rewrites in a loop — every account
		// mutation marshals and fsyncs the entire file under a global
		// cross-process lock that every authenticated request also reads
		// through, so one looping session stalls the instance. Reads are
		// untouched. See accountWriteBurst.
		if !s.meterAccountWrite(w, r, ac.UserID) {
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

// csrfCheckOK enforces a double-submit CSRF check on cookie-authenticated,
// state-changing (non-GET/HEAD/OPTIONS) requests: the X-CSRF-Token header must
// match the csrf_token minted alongside the caller's session (see startSession).
//
// It takes the RESOLVED AuthContext rather than re-deriving one from the
// request. Looking the cookie up here means answering "I don't know" — no
// cookie, or a cookie matching no session — with "allow", which leaves
// SameSite=Lax as the only real control. TestSessionCookieStaysSameSiteLax pins
// that attribute; this function no longer depends on it.
//
// Callers that did not authenticate by cookie — paired mobile clients
// (X-Kypost-Device-Id/X-Kypost-Device-Secret, see resolveMailAuthContext) and
// CardDAV (HTTP Basic) — leave SessionCSRFToken empty and are structurally
// exempt: their credential is not attached by the browser.
func csrfCheckOK(r *http.Request, ac AuthContext) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if ac.SessionCSRFToken == "" {
		return true
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(ac.SessionCSRFToken)) == 1
}

// withMailAuth gates endpoints mobile clients need to reach without a web
// session — mail read/act-on (inbox, folders, actions, draft, send), contacts
// dedupe/groups/photo-get, and the PGP QR token mint — for either a web session
// cookie or a paired device's own X-Kypost-Device-Id/X-Kypost-Device-Secret
// credentials (see resolveMailAuthContext). Despite the name it is no longer
// mail-exclusive; IMAP/SMTP account setup (/api/imap/config, /api/imap/test)
// and other web-UI-only writes intentionally stay on withAuth only.
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
		if !csrfCheckOK(r, ac) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Session users still owing a first-login password change are blocked
		// here too (device-auth contexts never set this flag).
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		if !s.meterAccountWrite(w, r, ac.UserID) {
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

// meterAccountWrite applies the per-account write meter to a mutating request,
// writing the 429 and returning false when the caller is over budget.
//
// Extracted so every authentication wrapper can apply it. The meter was
// deliberately placed at the wrapper rather than at the endpoints so new routes
// would inherit the bound automatically — but only withAuth ever called it, so
// the ~26 withMailAuth routes, every device-credential route and every CardDAV
// route ran unmetered. Those wrappers carry rules/run, recipient resolution and
// pickup creation, which is what left the expensive paths with no rate bound at
// all.
//
// Reads are untouched, here as in withAuth: metering a mailbox listing would
// throttle ordinary use.
func (s *Server) meterAccountWrite(w http.ResponseWriter, r *http.Request, userID string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	ok, retryAfter := s.accountWriteLimiter.allow(userID)
	if ok {
		return true
	}
	seconds := int(retryAfter.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":             "too many requests, slow down",
		"retryAfterSeconds": seconds,
	})
	return false
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
	// Read under the read lock first. The common case is a live session that was
	// already touched moments ago and does not need its expiry rewritten, and
	// taking the write lock for that turned every authenticated request into an
	// exclusive critical section — see the sessMu note on Server.
	s.sessMu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.sessMu.RUnlock()
	if !ok {
		return AuthContext{}, false
	}

	// Idle timeout, then the absolute cap. The cap is checked separately so
	// that renewing below can never push a session past sessionMaxLifetime.
	if now.After(sess.ExpiresAt) || now.Sub(sess.IssuedAt) >= sessionMaxLifetime {
		s.sessMu.Lock()
		// Re-check identity before deleting: this token could have been logged
		// out and a new session minted under the same map key in between (not
		// possible today — tokens are 24 random bytes — but deleting a session
		// this goroutine never validated is wrong regardless).
		if cur, still := s.sessions[cookie.Value]; still && cur.IssuedAt.Equal(sess.IssuedAt) {
			delete(s.sessions, cookie.Value)
		}
		s.sessMu.Unlock()
		return AuthContext{}, false
	}

	// Sliding idle window for active users; IssuedAt is deliberately carried
	// through unchanged so the absolute ceiling still applies. Only written when
	// the window has moved by sessionSlideGranularity — rewriting a 24-hour horizon
	// because 40 milliseconds elapsed buys nothing and costs an exclusive lock on
	// the hot path.
	if now.Sub(sess.ExpiresAt.Add(-sessionIdleTimeout)) >= sessionSlideGranularity {
		s.sessMu.Lock()
		if cur, still := s.sessions[cookie.Value]; still {
			cur.ExpiresAt = now.Add(sessionIdleTimeout)
			s.sessions[cookie.Value] = cur
		}
		s.sessMu.Unlock()
	}

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		s.sessMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessMu.Unlock()
		return AuthContext{}, false
	}
	return AuthContext{
		UserID:             u.ID,
		Username:           u.Username,
		Role:               u.Role,
		MustChangePassword: u.MustChangePassword,
		// This request authenticated by cookie, so it carries an ambient
		// credential and csrfCheckOK must enforce the double submit.
		SessionCSRFToken: sess.CSRFToken,
	}, true
}

// mustChangePasswordExemptPaths are the only authenticated routes a user with
// an unsatisfied first-login password-change requirement may reach: the change
// endpoint itself and logout. Everything else is refused, so a known or default
// bootstrap credential cannot be used for anything but changing it.
var mustChangePasswordExemptPaths = map[string]bool{
	"/api/auth/password": true,
	"/api/auth/logout":   true,
}
