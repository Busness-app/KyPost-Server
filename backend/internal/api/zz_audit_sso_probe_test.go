package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/sso/ssotest"
	"kypost-server/backend/internal/users"
)

// runSSOFlowMux drives the flow through routes() so every middleware applies.
func runSSOFlowMux(t *testing.T, srv *Server, idp *ssotest.IdP, sessionCookie *http.Cookie, link bool) *httptest.ResponseRecorder {
	t.Helper()
	mux := srv.routes()

	path := "/api/auth/oidc/login"
	if link {
		path += "?link=true"
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = ssoTestHost
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d (%s)", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no state cookie")
	}
	code, state := idp.Authorize(t, rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	req.Host = ssoTestHost
	req.AddCookie(stateCookie)
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	mux.ServeHTTP(rec, req)
	return rec
}

// PROBE 1: a session confined by MustChangePassword can still bind an external
// SSO identity to the account.
func TestProbe_MustChangePasswordDoesNotConfineSSOLink(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	idp.SetClaims(map[string]any{
		"sub":                "attacker-idp-subject",
		"email":              "attacker@evil.example",
		"preferred_username": "attacker",
	})

	u, err := srv.users.Create(context.Background(), "victim", "temp-pass-from-admin-1", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !u.MustChangePassword {
		t.Fatal("setup: expected MustChangePassword")
	}
	token, csrf := "confined-session", "confined-csrf"
	srv.sessMu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrf}
	srv.sessMu.Unlock()
	cookie := &http.Cookie{Name: "kypost_session", Value: token}

	// Baseline: the confinement works for a normal endpoint.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	srv.routes().ServeHTTP(rec, req)
	t.Logf("GET /api/status while confined -> %d", rec.Code)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("baseline confinement broken: %d", rec.Code)
	}

	// Attack: link an SSO identity from the confined session.
	rec = runSSOFlowMux(t, srv, idp, cookie, true)
	t.Logf("SSO link callback -> %d Location=%q body=%q", rec.Code, rec.Header().Get("Location"), strings.TrimSpace(rec.Body.String()))

	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	t.Logf("victim SSOSub after link = %q  SSOEmail = %q", after.SSOSub, after.SSOEmail)
	if after.SSOSub == "attacker-idp-subject" {
		t.Errorf("CONFIRMED: MustChangePassword-confined session linked an external identity")
	}
}

// PROBE 2: SSO sign-in skips the TOTP/push second factor the password path enforces.
func TestProbe_SSOLoginSkipsMFA(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	idp.SetClaims(map[string]any{
		"sub":                "mfa-user-subject",
		"email":              "mfa@example.com",
		"preferred_username": "mfauser",
	})

	u, err := srv.users.CreateSSOUser("mfauser", users.RoleUser, "mfa-user-subject", "mfauser", "mfa@example.com")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	if _, err := srv.users.SetPushMFAEnabled(u.ID, true); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}
	reloaded, _ := srv.users.Get(u.ID)
	t.Logf("user PushMFAEnabled=%v TOTPEnabled=%v", reloaded.PushMFAEnabled, reloaded.TOTPEnabled)

	rec := runSSOFlowMux(t, srv, idp, nil, false)
	sc := sessionCookieFrom(rec)
	t.Logf("SSO login callback -> %d Location=%q session=%v", rec.Code, rec.Header().Get("Location"), sc != nil)
	if sc != nil {
		srv.sessMu.RLock()
		sess, ok := srv.sessions[sc.Value]
		srv.sessMu.RUnlock()
		t.Logf("full session minted: ok=%v userID=%s", ok, sess.UserID)
		t.Errorf("CONFIRMED: full session minted for an MFA-enabled account with no second factor")
	}
}

// PROBE 3: does the credential-revocation sweep clear the SSO link?
func TestProbe_RevokeAllUserCredentialsLeavesSSOLink(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.CreateSSOUser("linked", users.RoleUser, "sub-abc", "linked", "l@e.com")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	if err := srv.revokeAllUserCredentials(u); err != nil {
		t.Logf("revokeAllUserCredentials err (non-fatal): %v", err)
	}
	after, _ := srv.users.Get(u.ID)
	t.Logf("SSOSub after full credential revocation = %q", after.SSOSub)
	if after.SSOSub != "" {
		t.Errorf("CONFIRMED: SSO link survives revokeAllUserCredentials")
	}
}
