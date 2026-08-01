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
	s.sessMu.Lock()
	s.sessions[token] = Session{UserID: userID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrfToken}
	s.sessMu.Unlock()
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
	u, err := srv.users.Create(context.Background(), "alice", "correct-horse-battery", users.RoleUser)
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
	// httptest.NewRequest's default peer is 192.0.2.1; trust it as the
	// TLS-terminating proxy so X-Forwarded-Proto is honored below.
	trustProxyCIDRsForTest(t, "192.0.2.0/24")
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "carol", "correct-horse-battery", users.RoleUser)
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
	u, err := srv.users.Create(context.Background(), "frank", "correct-horse-battery", users.RoleUser)
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
	u, err := srv.users.Create(context.Background(), "grace", "correct-horse-battery", users.RoleUser)
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
	u, err := srv.users.Create(context.Background(), "heidi", "old-password-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	protected := srv.withAuth(srv.handleChangePassword)

	// Cookie present, no CSRF header: rejected, even with correct password.
	body, _ := json.Marshal(map[string]string{"oldPassword": "old-password-testpassword", "newPassword": "new-password-testpassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	token := "session-token-" + u.ID
	srv.sessMu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "the-real-csrf-token"}
	srv.sessMu.Unlock()
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
	u, err := srv.users.Create(context.Background(), "ivan", "pw-ivan-testpassword", users.RoleUser)
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
	u, err := srv.users.Create(context.Background(), "bob", "old-password-testpassword", users.RoleUser)
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
	if ok, _ := users.VerifyPassword(context.Background(), got, "new-password-testpassword"); !ok {
		t.Fatalf("expected new password to verify")
	}
}

// newTestServerWithUser returns a test server plus one non-admin user, for
// tests that only need "some authenticated identity".
func newTestServerWithUser(t *testing.T) (*Server, users.User) {
	t.Helper()
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "session-tester", "session-tester-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return srv, u
}

// TestSessionAbsoluteLifetimeCapsRenewal pins that the sliding idle window
// cannot extend a session past sessionMaxLifetime. Without the cap, a
// stolen cookie stays valid indefinitely: the thief's own traffic renews it
// forever and the legitimate user has no way to end it.
func TestSessionAbsoluteLifetimeCapsRenewal(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	token := "aged-session"
	srv.sessMu.Lock()
	srv.sessions[token] = Session{
		UserID: u.ID,
		// Issued just over the ceiling ago, but kept "fresh" by activity —
		// exactly the state continuous renewal produces.
		IssuedAt:  time.Now().Add(-sessionMaxLifetime - time.Minute),
		ExpiresAt: time.Now().Add(sessionIdleTimeout),
		CSRFToken: "csrf",
	}
	srv.sessMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	if _, ok := srv.currentUser(req); ok {
		t.Fatal("a session past sessionMaxLifetime authenticated; the absolute cap is not enforced")
	}

	srv.sessMu.Lock()
	_, still := srv.sessions[token]
	srv.sessMu.Unlock()
	if still {
		t.Fatal("expired-by-lifetime session was not dropped from the map")
	}
}

// TestSessionSweeperReclaimsAbandonedSessions pins that sessions belonging
// to users who never return are reclaimed. currentUser only ever drops a
// session when its own token is presented again, so without the sweeper
// every abandoned session is pinned for the process lifetime.
func TestSessionSweeperReclaimsAbandonedSessions(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	now := time.Now()

	srv.sessMu.Lock()
	srv.sessions["idle-expired"] = Session{
		UserID: u.ID, IssuedAt: now.Add(-48 * time.Hour),
		ExpiresAt: now.Add(-time.Minute), CSRFToken: "a",
	}
	srv.sessions["too-old"] = Session{
		UserID: u.ID, IssuedAt: now.Add(-sessionMaxLifetime - time.Hour),
		ExpiresAt: now.Add(sessionIdleTimeout), CSRFToken: "b",
	}
	srv.sessions["healthy"] = Session{
		UserID: u.ID, IssuedAt: now, ExpiresAt: now.Add(sessionIdleTimeout), CSRFToken: "c",
	}
	srv.sessMu.Unlock()

	if removed := srv.sweepSessions(now); removed != 2 {
		t.Fatalf("sweepSessions removed %d, want 2", removed)
	}
	srv.sessMu.Lock()
	defer srv.sessMu.Unlock()
	if _, ok := srv.sessions["healthy"]; !ok {
		t.Fatal("sweeper removed a live session")
	}
	if len(srv.sessions) != 1 {
		t.Fatalf("sessions left = %d, want 1", len(srv.sessions))
	}
}

// TestSessionSlideIsQuantized covers the change that took the session expiry
// rewrite off the exclusive-lock path.
//
// currentUser used to take sessMu (then mu) for WRITING on every authenticated
// request, to push a 24-hour horizon forward by however many milliseconds had
// passed. That made the RWMutex a plain Mutex for all request traffic. It now
// only writes once the window has actually advanced by sessionSlideGranularity.
//
// The behaviour that must survive: an active session still gets extended, and
// the extension still cannot breach the absolute lifetime cap.
func TestSessionSlideIsQuantized(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "slider", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.ClearMustChangePassword(u.ID); err != nil {
		t.Fatalf("ClearMustChangePassword: %v", err)
	}

	const token = "slide-token"
	issued := time.Now()
	srv.sessMu.Lock()
	srv.sessions[token] = Session{
		UserID:    u.ID,
		IssuedAt:  issued,
		ExpiresAt: issued.Add(sessionIdleTimeout),
		CSRFToken: "csrf",
	}
	srv.sessMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})

	// A request arriving immediately must NOT rewrite the expiry.
	if _, ok := srv.currentUser(req); !ok {
		t.Fatal("currentUser rejected a live session")
	}
	srv.sessMu.RLock()
	after := srv.sessions[token].ExpiresAt
	srv.sessMu.RUnlock()
	if !after.Equal(issued.Add(sessionIdleTimeout)) {
		t.Errorf("expiry moved on an immediate second request (%v -> %v); the slide should be quantized",
			issued.Add(sessionIdleTimeout), after)
	}

	// Backdate so the window has advanced past the granularity, and confirm the
	// session IS extended — the quantization must not become a session that
	// never renews.
	stale := time.Now().Add(-2 * sessionSlideGranularity)
	srv.sessMu.Lock()
	srv.sessions[token] = Session{
		UserID:    u.ID,
		IssuedAt:  issued,
		ExpiresAt: stale.Add(sessionIdleTimeout),
		CSRFToken: "csrf",
	}
	srv.sessMu.Unlock()

	if _, ok := srv.currentUser(req); !ok {
		t.Fatal("currentUser rejected a live session on the second pass")
	}
	srv.sessMu.RLock()
	extended := srv.sessions[token]
	srv.sessMu.RUnlock()
	if !extended.ExpiresAt.After(stale.Add(sessionIdleTimeout)) {
		t.Errorf("expiry did not advance (%v) after the granularity elapsed; an active user would "+
			"be logged out mid-work", extended.ExpiresAt)
	}
	if !extended.IssuedAt.Equal(issued) {
		t.Errorf("IssuedAt moved from %v to %v; the absolute lifetime cap is measured from it",
			issued, extended.IssuedAt)
	}

	// And a session past its absolute cap is still refused and reclaimed,
	// regardless of how recently it was touched.
	srv.sessMu.Lock()
	srv.sessions[token] = Session{
		UserID:    u.ID,
		IssuedAt:  time.Now().Add(-sessionMaxLifetime - time.Minute),
		ExpiresAt: time.Now().Add(sessionIdleTimeout),
		CSRFToken: "csrf",
	}
	srv.sessMu.Unlock()
	if _, ok := srv.currentUser(req); ok {
		t.Error("currentUser accepted a session past sessionMaxLifetime")
	}
	srv.sessMu.RLock()
	_, still := srv.sessions[token]
	srv.sessMu.RUnlock()
	if still {
		t.Error("a session past its absolute cap was not reclaimed")
	}
}
