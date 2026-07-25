package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// authRequestAs simulates an authenticated request the way a real browser
// client would: a session cookie plus the matching X-CSRF-Token header (see
// csrfCheckOK), since state-changing requests are rejected without both.
func authRequestAs(s *Server, req *http.Request, userID string) {
	token := "session-token-" + userID
	csrfToken := "csrf-token-" + userID
	s.mu.Lock()
	s.sessions[token] = Session{UserID: userID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrfToken}
	s.mu.Unlock()
	// Represent a fully-onboarded session: users are created with
	// MustChangePassword=true, which is now enforced server-side (see withAuth),
	// so clear it here to model a user past first login. Tests that specifically
	// exercise the must-change gate set the flag themselves.
	_, _ = s.users.ClearMustChangePassword(userID)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", csrfToken)
}

// findCookie returns the cookie named name from cookies, or nil. Login now
// always sets two cookies (kypost_session + the non-HttpOnly csrf_token used
// by csrfCheckOK), so tests that need the session cookie specifically must
// look it up by name rather than assume it's the only one.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func doJSON(srv *Server, handler http.HandlerFunc, method, path string, payload any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *bytes.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, body)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestLoginMeLogoutFlow(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	admin := all[0]

	// Wrong password is rejected.
	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
		"username": admin.Username,
		"password": "wrong-password",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with wrong password: status = %d, want 401", rec.Code)
	}

	// handleMe with no session says unauthenticated.
	rec = doJSON(srv, srv.handleMe, http.MethodGet, "/api/auth/me", nil)
	var meResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("unmarshal handleMe: %v", err)
	}
	if meResp["authenticated"] != false {
		t.Fatalf("expected unauthenticated, got %+v", meResp)
	}

	// The bootstrap admin's password is unknown to this test (it's randomly
	// generated), so create a fresh known-password user to exercise login.
	u, err := srv.users.Create("alice", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	rec = doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
		"username": u.Username,
		"password": "correct-horse-battery",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	sessionCookie := findCookie(cookies, "kypost_session")
	if sessionCookie == nil || findCookie(cookies, "csrf_token") == nil {
		t.Fatalf("expected both kypost_session and csrf_token cookies, got %+v", cookies)
	}

	rec = doJSON(srv, srv.handleMe, http.MethodGet, "/api/auth/me", nil, sessionCookie)
	if err := json.Unmarshal(rec.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("unmarshal handleMe: %v", err)
	}
	if meResp["authenticated"] != true || meResp["username"] != "alice" || meResp["role"] != string(users.RoleUser) {
		t.Fatalf("unexpected /api/auth/me payload: %+v", meResp)
	}

	// Deactivating the user must immediately invalidate their live session.
	if _, err := srv.users.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	rec = doJSON(srv, srv.handleMe, http.MethodGet, "/api/auth/me", nil, sessionCookie)
	if err := json.Unmarshal(rec.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("unmarshal handleMe: %v", err)
	}
	if meResp["authenticated"] != false {
		t.Fatalf("expected deactivated user's session to be rejected, got %+v", meResp)
	}
}

// TestSessionCookieSecureFlag guards against the session cookie being sent
// over plain HTTP with no Secure attribute: it must be absent for a plain
// HTTP request (so local/dev deployments without TLS still work) and set
// whenever the request arrived over HTTPS, including via a TLS-terminating
// reverse proxy that signals this with X-Forwarded-Proto.
func TestSessionCookieSecureFlag(t *testing.T) {
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	srv := newTestServer(t)
	u, err := srv.users.Create("carol", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	login := func(setHeaders func(*http.Request)) *http.Cookie {
		body, _ := json.Marshal(map[string]string{"username": u.Username, "password": "correct-horse-battery"})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		if setHeaders != nil {
			setHeaders(req)
		}
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("login: status = %d, body=%s", rec.Code, rec.Body.String())
		}
		cookies := rec.Result().Cookies()
		sessionCookie := findCookie(cookies, "kypost_session")
		csrfCookie := findCookie(cookies, "csrf_token")
		if sessionCookie == nil || csrfCookie == nil {
			t.Fatalf("expected kypost_session and csrf_token cookies, got %+v", cookies)
		}
		if sessionCookie.Secure != csrfCookie.Secure {
			t.Fatalf("kypost_session.Secure=%v but csrf_token.Secure=%v, want matching", sessionCookie.Secure, csrfCookie.Secure)
		}
		return sessionCookie
	}

	if c := login(nil); c.Secure {
		t.Fatalf("plain HTTP login must not set Secure, got Secure=%v", c.Secure)
	}
	if c := login(func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }); !c.Secure {
		t.Fatalf("HTTPS-via-proxy login must set Secure, got Secure=%v", c.Secure)
	}
}

// TestHandleLoginLocksOutAfterThreeFailures verifies the three-strikes
// lockout (login_lockout.go) is actually wired into handleLogin, not just
// unit-tested in isolation: three wrong passwords for the same username must
// make even the correct password fail with 429 until the lockout expires.
func TestHandleLoginLocksOutAfterThreeFailures(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("frank", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < loginMaxFailures; i++ {
		rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
			"username": u.Username,
			"password": "wrong-password",
		})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}

	// Even the correct password must now be rejected while locked out.
	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
		"username": u.Username,
		"password": "correct-horse-battery",
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on a locked-out login")
	}
}

// fakeCaptchaVerifier lets tests control CAPTCHA outcomes without hitting a
// real provider.
type fakeCaptchaVerifier struct {
	ok  bool
	err error
}

func (f fakeCaptchaVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	return f.ok, f.err
}

// TestHandleLoginRequiresCaptchaWhenConfigured verifies handleLogin actually
// consults s.captchaVerifier: a configured verifier that rejects the
// submitted token must block login even with the correct password, and one
// that accepts it must let the login through.
func TestHandleLoginRequiresCaptchaWhenConfigured(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("grace", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	srv.captchaVerifier = fakeCaptchaVerifier{ok: false}
	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
		"username": u.Username,
		"password": "correct-horse-battery",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("rejected captcha: status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}

	srv.captchaVerifier = fakeCaptchaVerifier{ok: true}
	rec = doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login", map[string]string{
		"username":     u.Username,
		"password":     "correct-horse-battery",
		"captchaToken": "whatever-the-widget-produced",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("accepted captcha: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleCaptchaConfigReportsDisabledByDefault(t *testing.T) {
	srv := newTestServer(t)
	rec := doJSON(srv, srv.handleCaptchaConfig, http.MethodGet, "/api/auth/captcha-config", nil)
	var resp struct {
		Provider string `json:"provider"`
		SiteKey  string `json:"siteKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Provider != "" {
		t.Fatalf("provider = %q, want empty (disabled) by default", resp.Provider)
	}
}

// TestCSRFProtectionOnCookieAuthedMutations verifies the double-submit CSRF
// check (csrfCheckOK, wired into withAuth/withMailAuth) actually blocks a
// forged cross-site-style request — one that carries the session cookie
// (as a browser would send automatically) but no X-CSRF-Token header (as an
// attacker's cross-site form/script couldn't produce, since it can't read
// the non-HttpOnly cookie cross-origin) — while a legitimate request with a
// matching header still succeeds.
func TestCSRFProtectionOnCookieAuthedMutations(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("heidi", "old-password-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	protected := srv.withAuth(srv.handleChangePassword)

	// Cookie present, no CSRF header: rejected, even with correct password.
	body, _ := json.Marshal(map[string]string{"oldPassword": "old-password-testpassword", "newPassword": "new-password-testpassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	token := "session-token-" + u.ID
	srv.mu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "the-real-csrf-token"}
	srv.mu.Unlock()
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	rec := httptest.NewRecorder()
	protected(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no csrf header: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	// Cookie present, wrong CSRF header: also rejected.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", "not-the-real-token")
	rec = httptest.NewRecorder()
	protected(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong csrf header: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	// Cookie present, matching CSRF header: allowed through.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", "the-real-csrf-token")
	rec = httptest.NewRecorder()
	protected(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("matching csrf header: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestCSRFProtectionSkipsRequestsWithoutSessionCookie guards the scoping
// that keeps CSRF protection from ever touching mobile: withMailAuth's
// device-credential path (no cookie at all) must not require a CSRF header,
// since a request with no session cookie carries no ambient, forgeable
// credential for CSRF to exploit.
func TestCSRFProtectionSkipsRequestsWithoutSessionCookie(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("ivan", "pw-ivan-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "csrf-device")

	req := httptest.NewRequest(http.MethodPost, "/api/inbox/actions", bytes.NewReader([]byte(`{"action":"read","messageIds":[]}`)))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handleInboxActions)(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("mobile (cookie-free) request must not be CSRF-blocked, got 403: %s", rec.Body.String())
	}
}

func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("bob", "old-password-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	protected := srv.withAuth(srv.handleChangePassword)

	// Wrong old password is rejected.
	body, _ := json.Marshal(map[string]string{"oldPassword": "not-it", "newPassword": "new-password-testpassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	protected(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body=%s", rec.Code, rec.Body.String())
	}

	// Correct old password succeeds and the new password takes effect.
	body, _ = json.Marshal(map[string]string{"oldPassword": "old-password-testpassword", "newPassword": "new-password-testpassword"})
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec = httptest.NewRecorder()
	protected(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	got, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !users.VerifyPassword(got, "new-password-testpassword") {
		t.Fatalf("expected new password to verify")
	}
}
