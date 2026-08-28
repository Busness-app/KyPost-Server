package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// Full chain: temp credential -> confined session -> SSO link -> victim rotates
// password (full credential revocation) -> attacker still signs in as victim.
func TestProbe_ChainTempPasswordToPermanentTakeover(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	idp.SetClaims(map[string]any{
		"sub":                "attacker-idp-subject",
		"email":              "attacker@evil.example",
		"preferred_username": "attacker",
	})
	mux := srv.routes()

	// Victim account in the post-admin-reset state.
	v, err := srv.users.Create(context.Background(), "victim", "temp-pass-from-admin-1", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Give the victim a second factor, to show it does not help.
	if _, err := srv.users.SetPushMFAEnabled(v.ID, true); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}

	// STEP 1: attacker signs in with the intercepted temp password.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login",
		bytes.NewReader([]byte(`{"username":"victim","password":"temp-pass-from-admin-1"}`))))
	t.Logf("STEP1 login -> %d body=%s", rec.Code, strings.TrimSpace(rec.Body.String()))
	// PushMFA is on, so login returns a challenge, not a session. Model the
	// weaker (and realistic) case instead: no MFA yet on a freshly reset account.
	if _, err := srv.users.SetPushMFAEnabled(v.ID, false); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login",
		bytes.NewReader([]byte(`{"username":"victim","password":"temp-pass-from-admin-1"}`))))
	sc := sessionCookieFrom(rec)
	t.Logf("STEP1 login -> %d session=%v body=%s", rec.Code, sc != nil, strings.TrimSpace(rec.Body.String()))
	if sc == nil {
		t.Fatal("no session from temp password")
	}

	// STEP 2: confined session links the attacker's IdP identity.
	rec = runSSOFlowMux(t, srv, idp, sc, true)
	t.Logf("STEP2 sso link -> %d %s", rec.Code, rec.Header().Get("Location"))

	// STEP 3: victim rotates the password. This runs the full revocation sweep.
	after, _ := srv.users.Get(v.ID)
	t.Logf("STEP3 pre-rotate SSOSub=%q", after.SSOSub)
	if _, err := srv.users.SetPassword(context.Background(), v.ID, "brand-new-strong-pass-9"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	reloaded, _ := srv.users.Get(v.ID)
	if err := srv.revokeAllUserCredentials(reloaded); err != nil {
		t.Logf("revoke err: %v", err)
	}
	// Victim re-enables their second factor.
	if _, err := srv.users.SetPushMFAEnabled(v.ID, true); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}
	after, _ = srv.users.Get(v.ID)
	t.Logf("STEP3 post-rotate SSOSub=%q PushMFAEnabled=%v", after.SSOSub, after.PushMFAEnabled)

	// STEP 4: attacker signs in via SSO with their own IdP identity.
	rec = runSSOFlowMux(t, srv, idp, nil, false)
	sc2 := sessionCookieFrom(rec)
	t.Logf("STEP4 sso login -> %d %s session=%v", rec.Code, rec.Header().Get("Location"), sc2 != nil)
	if sc2 == nil {
		t.Fatal("no session")
	}
	srv.sessMu.RLock()
	sess := srv.sessions[sc2.Value]
	srv.sessMu.RUnlock()
	if sess.UserID != v.ID {
		t.Fatalf("session is for %s, want victim %s", sess.UserID, v.ID)
	}
	// Prove it is a usable, unconfined session.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(sc2)
	mux.ServeHTTP(rec, req)
	t.Logf("STEP4 GET /api/status as victim -> %d", rec.Code)
	if rec.Code == http.StatusOK {
		t.Errorf("CONFIRMED: full unconfined session as the victim after password rotation + full revocation + MFA")
	}
	_ = time.Now
}
