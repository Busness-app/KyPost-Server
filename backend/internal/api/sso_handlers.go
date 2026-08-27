package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/sso"
	"kypost-server/backend/internal/users"
)

const ssoCookieName = "kypost_sso_state"

// ssoModeLink marks a flow started from "link my account", as opposed to a
// plain login. It is only a mode marker: the account that gets linked is
// resolved from the caller's authenticated session at callback time, never
// from the cookie. See handleSSOCallback.
const ssoModeLink = "link"

// ssoLinkGrantTTL bounds how long a step-up authorizes one link. It matches the
// state cookie's own five-minute life: the round trip to the provider has to fit
// inside both, and a grant outliving the flow it was minted for would be a
// re-authentication that quietly keeps authorizing.
const ssoLinkGrantTTL = 5 * time.Minute

// ssoSessionTag fingerprints the caller's session token.
//
// It is stored in the state cookie for a link flow and re-derived at callback,
// so a link started in one session cannot be completed in another. The cookie
// is browser-supplied and this server does not sign it; without the tag, an
// attacker who can plant a cookie (a related-domain position, or an XSS) could
// drop their own in-flight link state into a victim's browser and have the
// victim's next navigation bind the attacker's identity to the victim's
// account. The tag makes that cookie useless anywhere but the session that
// minted it.
func ssoSessionTag(r *http.Request) string {
	c, err := r.Cookie("kypost_session")
	if err != nil || c.Value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(c.Value))
	return hex.EncodeToString(sum[:8])
}

// handleSSOConfig returns public SSO configuration (enabled, issuerUrl) for frontend UI login buttons.
func (s *Server) handleSSOConfig(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   settings.Enabled,
		"issuerUrl": settings.IssuerURL,
	})
}

// handleAdminSSOGet returns full SSO settings for administrators.
func (s *Server) handleAdminSSOGet(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	writeJSON(w, http.StatusOK, settings)
}

// handleAdminSSOPut updates SSO settings for administrators.
//
// Configuration is validated before it is stored, so an unusable issuer is
// refused in the admin panel with an explanation rather than at the next login
// attempt with a redirect into nowhere.
func (s *Server) handleAdminSSOPut(w http.ResponseWriter, r *http.Request) {
	var req sso.SSOSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Enabled {
		if err := sso.ValidateIssuerURL(req.IssuerURL, req.AllowInsecureIssuer); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.ClientID) == "" {
			http.Error(w, "client ID is required when SSO is enabled", http.StatusBadRequest)
			return
		}
	}

	if err := s.ssoStore.Save(req); err != nil {
		http.Error(w, "failed to save SSO settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": req})
}

// ssoRedirectURI builds the callback URL the provider must be told to return to.
//
// SERVER_BASE_URL only, never the request. Two reasons, and the first is plain
// correctness: behind a reverse proxy r.Host is the internal name, so a
// Host-derived redirect_uri does not match the one registered at the provider
// and every login is rejected anyway. The second is that OAuth pins
// redirect_uri across the authorize and token calls, so letting a request
// header choose it hands the caller influence over where an authorization code
// is sent — the provider's own allowlist is the only thing that would catch it.
func (s *Server) ssoRedirectURI() string {
	if s.serverBaseURL == "" {
		return ""
	}
	return strings.TrimRight(s.serverBaseURL, "/") + "/api/auth/oidc/callback"
}

// ssoProvider returns the discovered, policy-checked provider for these
// settings. sso.NewProvider caches the discovery behind the settings that
// produced it, so this is a network call only on a cold or expired entry.
func (s *Server) ssoProvider(r *http.Request, settings sso.SSOSettings) (*sso.Provider, string, error) {
	redirectURI := s.ssoRedirectURI()
	if redirectURI == "" {
		return nil, "", errors.New("cannot determine this server's external URL; set SERVER_BASE_URL")
	}
	p, err := sso.NewProvider(r.Context(), settings, redirectURI)
	return p, redirectURI, err
}

// ssoRateLimited meters a public SSO route per IP, on the same bucket the
// pre-login handshake uses, and answers 429 when the caller is over it.
//
// Both routes it guards are public, unauthenticated and reach an OUTBOUND
// request to the operator's identity provider — discovery at the login route,
// the token exchange at the callback — and there is no global rate-limiting
// middleware in front of either. sso.NewProvider caches discovery, so a flood
// no longer reflects one request per request received, but a cold cache, a
// settings change or an IdP that is down all put the fetch back on the request
// path. A real sign-in spends one token per leg.
func (s *Server) ssoRateLimited(w http.ResponseWriter, r *http.Request) bool {
	if s.loginParamsLimiter == nil {
		return false
	}
	if ok, _ := s.loginParamsLimiter.allow(lockoutKeyForIP(clientIP(r))); ok {
		return false
	}
	http.Error(w, "too many sign-in attempts right now, try again shortly", http.StatusTooManyRequests)
	return true
}

// handleSSOLogin initiates an OpenID Connect authorization code flow with PKCE.
func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "Single Sign-On is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	if s.ssoRateLimited(w, r) {
		return
	}

	// No link mode here. Starting a link requires a step-up this public GET
	// cannot perform, so it is minted by handleSSOLinkStart instead.
	s.startSSOFlow(w, r, settings, "")
}

// handleSSOLinkStart begins a link flow, and is the only thing that can.
//
// Linking creates a credential: handleSSOCallback signs a caller in from the
// stored sub and an Active check, nothing more. A session cookie is a bearer
// token, so gating the write on the session alone meant a hijacked session
// bound the attacker's directory identity to the victim's account with no
// password and no second factor — the durable-mutation standard every other
// self-service write is held to (see pgp_stepup.go and handleAuthStepUp).
//
// The redirect flow has no request body to carry a credential in, which is why
// the gate lives here: this POST proves the credential and the second factor,
// then records the grant on the session itself (Session.SSOLinkGrantedAt) for
// the callback to spend. Nothing about the authorization travels in the state
// cookie, deliberately — an attacker holding the session controls their own
// cookie jar and could write any self-consistent value into it, so a fact the
// caller cannot write at all is the only thing worth checking.
func (s *Server) handleSSOLinkStart(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "Single Sign-On is not configured or disabled", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Password   string `json:"password"`
		AuthSecret string `json:"authSecret,omitempty"`
		Code       string `json:"code,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	// An auto-provisioned account stores no password and no derived secret, so
	// there is no credential for the step-up below to check and it could only
	// ever answer "invalid credentials" — an account cannot re-link its way out
	// of a problem it never had a second credential to prove itself with. Say so
	// plainly. That such an account can never pass this gate is also why nothing
	// revokes its link: see users.User.HasLocalCredential.
	if !u.HasLocalCredential() {
		http.Error(w, "set an account password before linking or re-linking an SSO identity",
			http.StatusConflict)
		return
	}
	// Credential first, then the second factor, each on its own counter and the
	// success recorded only once both hold — handleAuthStepUp explains why
	// clearing between the two would leave the second factor unthrottled.
	if !s.confirmAccountCredentialNoRecord(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}
	if u.TOTPEnabled && !s.confirmSecondFactor(w, r, u, strings.TrimSpace(req.Code)) {
		return
	}
	s.passwordChangeLockout.recordSuccess(stepUpLockoutKey(ac.UserID, r))
	s.mfaLockout.recordSuccess(ac.UserID)

	if !s.grantSSOLink(r) {
		http.Error(w, "failed to authorize the link", http.StatusInternalServerError)
		return
	}
	s.startSSOFlow(w, r, settings, ssoModeLink+":"+ssoSessionTag(r))
}

// startSSOFlow generates the PKCE/state/nonce triple, stores it in the state
// cookie under mode, and sends the caller to the provider. handleSSOLogin
// redirects; handleSSOLinkStart is a POST from the Security page, so it answers
// with the URL for the page to navigate to.
func (s *Server) startSSOFlow(w http.ResponseWriter, r *http.Request, settings sso.SSOSettings, mode string) {
	verifier, challenge, err := sso.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}
	state, err := sso.RandomToken(16)
	if err != nil {
		http.Error(w, "failed to generate SSO state", http.StatusInternalServerError)
		return
	}
	// The nonce is echoed into the ID token and checked at callback, which is
	// what stops a token minted for some other session of this same client
	// from being replayed into this one.
	nonce, err := sso.RandomToken(16)
	if err != nil {
		http.Error(w, "failed to generate SSO nonce", http.StatusInternalServerError)
		return
	}

	provider, _, err := s.ssoProvider(r, settings)
	if err != nil {
		s.ssoFailure(w, "start", err)
		return
	}

	// Cookie value: state|verifier|nonce|mode.
	//
	// Deliberately no user id. The predecessor stored the target account here
	// and linked whatever it named, so anyone who knew a victim's user id
	// could set the cookie themselves, run the flow with their own IdP
	// account, and bind their identity to that victim's account.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    strings.Join([]string{state, verifier, nonce, mode}, "|"),
		Path:     "/",
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	authorizeURL := provider.AuthCodeURL(state, nonce, challenge)
	if r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, map[string]any{"authorizeUrl": authorizeURL})
		return
	}
	http.Redirect(w, r, authorizeURL, http.StatusFound)
}

// handleSSOCallback processes the authorization code callback from the OIDC IdP.
func (s *Server) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" {
		http.Error(w, "Single Sign-On is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	cookie, err := r.Cookie(ssoCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "missing or expired SSO session state cookie", http.StatusBadRequest)
		return
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		MaxAge:   -1,
	})

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 4 {
		http.Error(w, "corrupted SSO state cookie", http.StatusBadRequest)
		return
	}
	expectedState, codeVerifier, nonce, mode := parts[0], parts[1], parts[2], parts[3]

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or authorization code", http.StatusBadRequest)
		return
	}
	if !hmac.Equal([]byte(state), []byte(expectedState)) {
		http.Error(w, "invalid or mismatched SSO state parameter", http.StatusBadRequest)
		return
	}

	// Link mode targets the session making this request, and nothing else.
	linkUserID := ""
	if rest, isLink := strings.CutPrefix(mode, ssoModeLink+":"); isLink {
		auth, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "sign in before linking an SSO identity", http.StatusUnauthorized)
			return
		}
		if !hmac.Equal([]byte(rest), []byte(ssoSessionTag(r))) {
			http.Error(w, "this SSO link was started by a different session", http.StatusBadRequest)
			return
		}
		// The tag proves only that SOME request in this session wrote the
		// cookie, and an attacker holding the session can write it themselves —
		// so it is not the authorization. The grant is: handleSSOLinkStart
		// records it on the session only after the credential and the second
		// factor, the caller cannot write it, and consuming it here means one
		// step-up authorizes exactly one link.
		if !s.consumeSSOLinkGrant(r) {
			http.Error(w, "this SSO link was not authorized; start it from the Security page", http.StatusForbidden)
			return
		}
		linkUserID = auth.UserID
	}

	// Spent here only once the request is well-formed enough to be worth an
	// outbound call: the checks above cost nothing, and charging junk for them
	// would be a way to deny a NAT its own sign-ins.
	if s.ssoRateLimited(w, r) {
		return
	}

	provider, _, err := s.ssoProvider(r, settings)
	if err != nil {
		s.ssoFailure(w, "discovery", err)
		return
	}

	claims, err := provider.Exchange(r.Context(), code, codeVerifier, nonce)
	if err != nil {
		s.ssoFailure(w, "exchange", err)
		return
	}

	if linkUserID != "" {
		s.linkSSOIdentity(w, r, linkUserID, claims)
		return
	}

	user, err := s.resolveSSOUser(w, settings, claims)
	if err != nil {
		return // resolveSSOUser wrote the response
	}

	if !user.Active {
		http.Error(w, "Access denied: your KyPost account is deactivated.", http.StatusForbidden)
		return
	}

	if err := s.startSession(w, r, user.ID); err != nil {
		http.Error(w, "failed to initialize session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/read", http.StatusFound)
}

// linkSSOIdentity binds a verified identity to the caller's own account.
//
// Reaching here means the callback has already spent the single-use grant
// handleSSOLinkStart recorded on the session, so the caller proved the account
// credential and the second factor — a session alone does not authorize this
// write. revokeAllUserCredentials revokes the link too, so a victim's password
// change ends a link that should never have been made; LinkSSO clears that
// revocation, because this step-up is exactly the proof it was waiting for.
func (s *Server) linkSSOIdentity(w http.ResponseWriter, r *http.Request, userID string, claims *sso.SSOTokenClaims) {
	// One subject, one account. Without this an identity already linked
	// elsewhere could be attached a second time, and GetBySSOSub would then
	// resolve a login to whichever of the two happened to be indexed.
	if existing, err := s.users.GetBySSOSub(claims.Sub); err == nil && existing.ID != userID {
		http.Error(w, "that SSO identity is already linked to another KyPost account", http.StatusConflict)
		return
	} else if err != nil && !errors.Is(err, users.ErrNotFound) {
		http.Error(w, "failed to check existing SSO links", http.StatusInternalServerError)
		return
	}

	if err := s.users.LinkSSO(userID, claims.Sub, claims.PreferredUsername, claims.Email); err != nil {
		http.Error(w, "failed to link account: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?sso=linked", http.StatusFound)
}

// resolveSSOUser maps a verified identity to a local account.
//
// The only accepted proof of ownership is a stored subject. The predecessor
// also matched on preferred_username, which treats a name collision as
// authentication: any directory user who could set preferred_username=admin
// got silently linked to the local administrator and signed in with its role.
// A correctly signed token does not make that safe, because the IdP really did
// sign the name the attacker chose. Linking an existing account now requires
// an authenticated session on that account — see linkSSOIdentity.
func (s *Server) resolveSSOUser(w http.ResponseWriter, settings sso.SSOSettings, claims *sso.SSOTokenClaims) (users.User, error) {
	user, err := s.users.GetBySSOSub(claims.Sub)
	if err == nil {
		// The account still knows this subject — that is how directory sync
		// addresses it — but a revocation said it is no longer a credential.
		// Refuse here rather than falling through to auto-provision, which
		// would hand the same subject a second, empty account.
		if user.SSOLinkRevoked() {
			http.Error(w, "Access denied: this SSO link was revoked. "+
				"Sign in locally and link it again from Settings.", http.StatusForbidden)
			return users.User{}, errors.New("sso link revoked")
		}
		return user, nil
	}
	if !errors.Is(err, users.ErrNotFound) {
		http.Error(w, "failed to look up SSO identity", http.StatusInternalServerError)
		return users.User{}, err
	}

	if !settings.AutoProvision {
		http.Error(w, "Access denied: your SSO identity is not linked to an existing KyPost account. "+
			"Sign in locally and link it from Settings.", http.StatusForbidden)
		return users.User{}, errors.New("not provisioned")
	}

	role := users.RoleUser
	if claims.IsAdmin() {
		role = users.RoleAdmin
	}

	username := ssoUsername(claims.PreferredUsername, claims.Sub)
	created, errCreate := s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
	if errors.Is(errCreate, users.ErrUsernameTaken) {
		// A local account already owns that name and this identity is not it.
		// Provision under a distinct name rather than touching theirs.
		created, errCreate = s.users.CreateSSOUser(
			ssoUsernameWithSuffix(username, claims.Sub), role, claims.Sub, claims.PreferredUsername, claims.Email)
	}
	if errCreate != nil {
		http.Error(w, "failed to auto-provision user: "+errCreate.Error(), http.StatusInternalServerError)
		return users.User{}, errCreate
	}
	return created, nil
}

// subDigest derives a stable, bounded hex tag from an OIDC subject.
//
// The subject is whatever the provider chose — `42` is a legal one. The
// predecessor sliced it with claims.Sub[:8], so any provider issuing a short
// subject panicked the callback instead of logging the user in.
func subDigest(sub string, n int) string {
	h := sha256.Sum256([]byte(sub))
	return hex.EncodeToString(h[:n])
}

// ssoUsername returns the provider's preferred_username when this server can
// represent it, and a subject-derived name when it cannot.
func ssoUsername(preferred, sub string) string {
	if users.ValidateUsername(preferred) == nil {
		return strings.TrimSpace(preferred)
	}
	return "user_" + subDigest(sub, 4)
}

// ssoUsernameWithSuffix disambiguates a taken username, staying inside the
// 64-character limit users.ValidateUsername enforces.
func ssoUsernameWithSuffix(username, sub string) string {
	suffix := "_" + subDigest(sub, 3)
	if len(username)+len(suffix) > 64 {
		username = username[:64-len(suffix)]
	}
	return username + suffix
}

// ssoFailure logs why SSO failed and tells the caller only that it did.
//
// These handlers are unauthenticated, and the underlying error can carry the
// identity provider's own response body and dial-level detail. An operator
// needs that to debug a broken provider; an anonymous caller poking the
// callback does not, and `GET /api/logs` is already admin-only.
func (s *Server) ssoFailure(w http.ResponseWriter, stage string, err error) {
	s.logger.Error("SSO sign-in failed", "stage", stage, "error", err.Error())
	http.Error(w, "Single Sign-On is unavailable right now. Ask an administrator to check the server logs.",
		http.StatusBadGateway)
}

// handleSSOUnlink removes the linked SSO identity from the current user's profile.
func (s *Server) handleSSOUnlink(w http.ResponseWriter, r *http.Request) {
	auth, ok := s.currentUser(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := s.users.UnlinkSSO(auth.UserID); err != nil {
		http.Error(w, "failed to unlink SSO identity: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// grantSSOLink records on the caller's own session that they have just proved
// their credential and second factor, authorizing one link.
func (s *Server) grantSSOLink(r *http.Request) bool {
	c, err := r.Cookie("kypost_session")
	if err != nil || c.Value == "" {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return false
	}
	sess.SSOLinkGrantedAt = time.Now()
	s.sessions[c.Value] = sess
	return true
}

// consumeSSOLinkGrant reports whether this session may write a link now,
// clearing the grant so a second callback cannot reuse it.
func (s *Server) consumeSSOLinkGrant(r *http.Request) bool {
	c, err := r.Cookie("kypost_session")
	if err != nil || c.Value == "" {
		return false
	}
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok || sess.SSOLinkGrantedAt.IsZero() {
		return false
	}
	fresh := time.Since(sess.SSOLinkGrantedAt) < ssoLinkGrantTTL
	sess.SSOLinkGrantedAt = time.Time{}
	s.sessions[c.Value] = sess
	return fresh
}
