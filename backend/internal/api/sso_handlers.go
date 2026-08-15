package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"kypost-server/backend/internal/sso"
	"kypost-server/backend/internal/users"
)

const ssoCookieName = "kypost_sso_state"

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
func (s *Server) handleAdminSSOPut(w http.ResponseWriter, r *http.Request) {
	var req sso.SSOSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if err := s.ssoStore.Save(req); err != nil {
		http.Error(w, "failed to save SSO settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "settings": req})
}

// handleSSOLogin initiates an OpenID Connect authorization code flow with PKCE.
func (s *Server) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	settings := s.ssoStore.Load()
	if !settings.Enabled || settings.IssuerURL == "" || settings.ClientID == "" {
		http.Error(w, "Single Sign-On is not configured or disabled", http.StatusServiceUnavailable)
		return
	}

	linkUserID := ""
	if r.URL.Query().Get("link") == "true" {
		if auth, ok := s.currentUser(r); ok {
			linkUserID = auth.UserID
		}
	}

	verifier, challenge, err := sso.GeneratePKCE()
	if err != nil {
		http.Error(w, "failed to generate PKCE challenge", http.StatusInternalServerError)
		return
	}

	stateBytes := make([]byte, 16)
	_, _ = rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Cookie value: state|verifier|linkUserID
	cookieVal := fmt.Sprintf("%s|%s|%s", state, verifier, linkUserID)
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    cookieVal,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, r.Host)

	authURL, err := url.Parse(disc.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "invalid authorization endpoint", http.StatusInternalServerError)
		return
	}
	q := authURL.Query()
	q.Set("response_type", "code")
	q.Set("client_id", settings.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
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
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{
		Name:     ssoCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		MaxAge:   -1,
	})

	parts := strings.Split(cookie.Value, "|")
	if len(parts) < 2 {
		http.Error(w, "corrupted SSO state cookie", http.StatusBadRequest)
		return
	}
	expectedState := parts[0]
	codeVerifier := parts[1]
	linkUserID := ""
	if len(parts) >= 3 {
		linkUserID = parts[2]
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or authorization code", http.StatusBadRequest)
		return
	}

	if state != expectedState {
		http.Error(w, "invalid or mismatched SSO state parameter", http.StatusBadRequest)
		return
	}

	disc, err := sso.DiscoverEndpoints(r.Context(), settings.IssuerURL)
	if err != nil {
		http.Error(w, "failed to discover OIDC endpoints: "+err.Error(), http.StatusBadGateway)
		return
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}
	redirectURI := fmt.Sprintf("%s://%s/api/auth/oidc/callback", scheme, r.Host)

	tok, err := sso.ExchangeCode(r.Context(), disc.TokenEndpoint, settings.ClientID, settings.ClientSecret, code, redirectURI, codeVerifier)
	if err != nil {
		http.Error(w, "failed to exchange code for token: "+err.Error(), http.StatusBadGateway)
		return
	}

	claims, err := sso.ParseClaims(r.Context(), tok.IDToken, tok.AccessToken, disc.UserinfoEndpoint)
	if err != nil {
		http.Error(w, "failed to parse identity claims: "+err.Error(), http.StatusBadGateway)
		return
	}

	// 1. Account linking mode
	if linkUserID != "" {
		if err := s.users.LinkSSO(linkUserID, claims.Sub, claims.PreferredUsername, claims.Email); err != nil {
			http.Error(w, "failed to link account: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/settings?sso=linked", http.StatusFound)
		return
	}

	// 2. Login mode
	user, err := s.users.GetBySSOSub(claims.Sub)
	if err != nil && errors.Is(err, users.ErrNotFound) {
		// Attempt match by username
		if claims.PreferredUsername != "" {
			if u, errU := s.users.GetByUsername(claims.PreferredUsername); errU == nil {
				user = u
				_ = s.users.LinkSSO(u.ID, claims.Sub, claims.PreferredUsername, claims.Email)
			}
		}
	}

	// If still not found, check auto-provision
	if user.ID == "" {
		if !settings.AutoProvision {
			http.Error(w, "Access denied: your SSO identity is not linked to an existing KyPost account.", http.StatusForbidden)
			return
		}

		role := users.RoleUser
		if claims.IsAdmin() {
			role = users.RoleAdmin
		}

		username := claims.PreferredUsername
		if username == "" {
			username = "user_" + claims.Sub[:8]
		}

		createdUser, errCreate := s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
		if errCreate != nil {
			// If username taken, suffix with sub
			if errors.Is(errCreate, users.ErrUsernameTaken) {
				username = fmt.Sprintf("%s_%s", username, claims.Sub[:6])
				createdUser, errCreate = s.users.CreateSSOUser(username, role, claims.Sub, claims.PreferredUsername, claims.Email)
			}
			if errCreate != nil {
				http.Error(w, "failed to auto-provision user: "+errCreate.Error(), http.StatusInternalServerError)
				return
			}
		}
		user = createdUser
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
