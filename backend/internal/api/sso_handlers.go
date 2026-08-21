package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"kypost-server/backend/internal/sso"
	"kypost-server/backend/internal/users"
)

const ssoCookieName = "kypost_sso_state"

// ssoModeLink marks a flow started from "link my account", as opposed to a
// plain login. It is only a mode marker: the account that gets linked is
// resolved from the caller's authenticated session at callback time, never
// from the cookie. See handleSSOCallback.
const ssoModeLink = "link"

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
// It goes through the configured base URL, falling back to externalBaseURL,
// rather than reading r.Host directly. Two reasons, and the first is plain
// correctness: behind a reverse proxy r.Host is the internal name, so a
// Host-derived redirect_uri does not match the one registered at the provider
// and every login is rejected. externalBaseURL is the helper that already
// honours X-Forwarded-Host, and only from a trusted proxy. The second is that
// OAuth pins redirect_uri across the authorize and token calls, so letting an
// arbitrary Host header choose it hands a request header influence over where
// an authorization code is sent.
func (s *Server) ssoRedirectURI(r *http.Request) string {
	base := s.serverBaseURL
	if base == "" {
		base = externalBaseURL(r)
	}
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + "/api/auth/oidc/callback"
}

// ssoProvider discovers and policy-checks the configured provider for one request.
func (s *Server) ssoProvider(r *http.Request, settings sso.SSOSettings) (*sso.Provider, string, error) {
	redirectURI := s.ssoRedirectURI(r)
	if redirectURI == "" {
		return nil, "", errors.New("cannot determine this server's external URL; set SERVER_BASE_URL")
	}
	p, err := sso.NewProvider(r.Context(), settings, redirectURI)
	return p, redirectURI, err
}

// handleSSOLogin initiates an OpenID Connect authorization code flow with PKCE.
func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "Single Sign-On is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	mode := ""
	if r.URL.Query().Get("link") == "true" {
		if _, ok := s.currentUser(r); !ok {
			http.Error(w, "sign in before linking an SSO identity", http.StatusUnauthorized)
			return
		}
		mode = ssoModeLink + ":" + ssoSessionTag(r)
	}

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

	http.Redirect(w, r, provider.AuthCodeURL(state, nonce, challenge), http.StatusFound)
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
	if tag, isLink := strings.CutPrefix(mode, ssoModeLink+":"); isLink {
		auth, ok := s.currentUser(r)
		if !ok {
			http.Error(w, "sign in before linking an SSO identity", http.StatusUnauthorized)
			return
		}
		if !hmac.Equal([]byte(tag), []byte(ssoSessionTag(r))) {
			http.Error(w, "this SSO link was started by a different session", http.StatusBadRequest)
			return
		}
		linkUserID = auth.UserID
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
