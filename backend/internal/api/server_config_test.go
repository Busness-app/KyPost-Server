package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestConfigPutRequiresAdmin is a regression test: PUT /api/config used to be
// reachable by any authenticated user, not just admins, letting a non-admin
// account overwrite install-wide settings (redaction patterns, rate limits,
// label allowlist) that only the Classifier sub-struct was ever meant to gate.
func TestConfigPutRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, regular := newTestUsers(t, srv)
	srv.configPath = t.TempDir() + "/config.yaml"

	srv.cfgMu.Lock()
	originalPatternCount := len(srv.cfg.Redaction.Patterns)
	srv.cfgMu.Unlock()
	if originalPatternCount == 0 {
		t.Fatal("expected the default config to seed at least one redaction pattern")
	}

	next := config.Default()
	next.Redaction.Patterns = nil // what a malicious/careless non-admin PUT would try to do
	body, _ := json.Marshal(next)

	// Non-admin PUT is rejected outright, before ever reaching handleConfig.
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, regular.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin PUT /api/config: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	srv.cfgMu.Lock()
	stillIntact := len(srv.cfg.Redaction.Patterns)
	srv.cfgMu.Unlock()
	if stillIntact != originalPatternCount {
		t.Fatalf("redaction patterns were modified by a rejected non-admin PUT: got %d, want %d", stillIntact, originalPatternCount)
	}

	// The same payload from an admin is accepted.
	req = httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT /api/config: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestChangePasswordRevokesOtherSessions is a regression test: changing a
// password used to leave every other live session for the account (e.g. a
// stolen cookie) valid for up to the remaining 24h sliding-expiry window.
// The session that performs the change itself must stay logged in.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "heidi", "old-password-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	changingToken := "changing-session-token"
	otherToken := "other-stolen-session-token"
	srv.sessMu.Lock()
	srv.sessions[changingToken] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-a"}
	srv.sessions[otherToken] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-b"}
	srv.sessMu.Unlock()

	body, _ := json.Marshal(map[string]string{"oldPassword": "old-password-testpassword", "newPassword": "new-password-testpassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: changingToken})
	req.Header.Set("X-CSRF-Token", "csrf-a")
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleChangePassword)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	srv.sessMu.Lock()
	_, changingStillLive := srv.sessions[changingToken]
	_, otherStillLive := srv.sessions[otherToken]
	srv.sessMu.Unlock()
	if !changingStillLive {
		t.Error("the session that performed the password change was itself revoked; it should stay logged in")
	}
	if otherStillLive {
		t.Error("a different live session for the same account survived a password change; it should have been revoked")
	}
}

// TestAdminResetPasswordRevokesTargetSessions mirrors
// TestChangePasswordRevokesOtherSessions for the admin-triggered path: none
// of the target account's sessions belong to the admin, so all of them (not
// "all but one") must be revoked.
func TestAdminResetPasswordRevokesTargetSessions(t *testing.T) {
	srv := newTestServer(t)
	admin, target := newTestUsers(t, srv)

	targetToken := "target-session-token"
	srv.sessMu.Lock()
	srv.sessions[targetToken] = Session{UserID: target.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-target"}
	srv.sessMu.Unlock()

	body, _ := json.Marshal(map[string]string{"password": "brand-new-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+target.ID+"/reset-password", bytes.NewReader(body))
	req.SetPathValue("id", target.ID)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersResetPassword)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin reset password: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	srv.sessMu.Lock()
	_, targetStillLive := srv.sessions[targetToken]
	srv.sessMu.Unlock()
	if targetStillLive {
		t.Error("target's session survived an admin password reset; it should have been revoked")
	}
}

// TestRoutesRegistersEveryArea guards the routes() split: each per-area
// function must actually be called from routes(). Dropping one would compile
// fine and silently 404 a whole feature, and the SPA fallback ("/") would
// serve index.html for those paths rather than erroring, so nothing else
// would notice.
func TestRoutesRegistersEveryArea(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.routes()

	// One representative path per routes* function, chosen so a match proves
	// that function ran. Each must resolve to something other than the SPA
	// fallback.
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/login"},           // routesAuth
		{http.MethodGet, "/api/health"},                // routesAdmin
		{http.MethodGet, "/api/inbox"},                 // routesMail
		{http.MethodGet, "/api/contacts"},              // routesContacts
		{http.MethodGet, "/api/pgp/identity"},          // routesPGP
		{http.MethodGet, "/api/notifications/pairing"}, // routesNotifications
		{http.MethodGet, "/api/rules"},                 // routesRules
	} {
		req := httptest.NewRequest(probe.method, probe.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		// Unauthenticated, so 401/403/400 are all fine — what must not happen
		// is falling through to the SPA fallback, which answers 200 with HTML
		// (or 404 "frontend assets not found" when no build is present).
		body := rec.Body.String()
		if strings.Contains(body, "frontend assets not found") {
			t.Errorf("%s %s fell through to the SPA fallback; its routes* function is not wired into routes()",
				probe.method, probe.path)
		}
	}
}
