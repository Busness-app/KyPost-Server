package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// The service worker's pushsubscriptionchange handler must send the
// double-submit X-CSRF-Token header on its resubscription POST, but a service
// worker cannot read document.cookie — so it fetches the token here with its
// session cookie instead.
func TestCSRFTokenEndpointReturnsSessionToken(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil)
	authRequestAs(srv, req, all[0].ID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := "csrf-token-" + all[0].ID; resp.CSRFToken != want {
		t.Fatalf("csrfToken = %q, want the token paired with the caller's session (%q)", resp.CSRFToken, want)
	}
}

func TestCSRFTokenEndpointRequiresSession(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/csrf", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestSessionCookieStaysSameSiteLax pins the attribute that used to be the real
// CSRF control.
//
// csrfCheckOK returned true on both "no cookie" and "cookie matches no session",
// so a state-changing request with an unrecognised cookie sailed through. That
// was only survivable because SameSite=Lax means the session cookie never
// reaches a cross-site POST in the first place. csrfCheckOK now keys off whether
// the request actually authenticated by cookie, so it no longer depends on this
// — but loosening SameSite is still a real weakening (it re-enables cross-site
// delivery of the session cookie), and it is the kind of one-line change made to
// fix an embedding problem without anyone connecting it to CSRF.
func TestSessionCookieStaysSameSiteLax(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "samesite-user", "pw-samesite-testpass", users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	if err := srv.startSession(rec, req, u.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}

	seen := map[string]http.SameSite{}
	for _, c := range rec.Result().Cookies() {
		seen[c.Name] = c.SameSite
	}
	for _, name := range []string{"kypost_session", "csrf_token"} {
		mode, ok := seen[name]
		if !ok {
			t.Fatalf("startSession did not set the %s cookie", name)
		}
		if mode != http.SameSiteLaxMode {
			t.Errorf("%s cookie SameSite = %v, want Lax.\n"+
				"SameSiteNone re-enables cross-site delivery of an ambient credential. "+
				"If a third-party context genuinely needs this, the CSRF story has to be "+
				"re-argued in the same change, not loosened here alone.", name, mode)
		}
	}
}

// A cookie-authenticated state change without the header must be refused. This
// is the case csrfCheckOK's old "no matching session, allow it" branch let
// through whenever the cookie did not resolve.
func TestCSRFRequiredWhenAuthenticatedBySession(t *testing.T) {
	ac := AuthContext{UserID: "u1", SessionCSRFToken: "the-real-token"}

	post := httptest.NewRequest(http.MethodPost, "/api/config", nil)
	if csrfCheckOK(post, ac) {
		t.Error("a cookie-authenticated POST with no X-CSRF-Token was allowed")
	}
	post.Header.Set("X-CSRF-Token", "not-the-token")
	if csrfCheckOK(post, ac) {
		t.Error("a cookie-authenticated POST with the wrong X-CSRF-Token was allowed")
	}
	post.Header.Set("X-CSRF-Token", "the-real-token")
	if !csrfCheckOK(post, ac) {
		t.Error("a cookie-authenticated POST with the right X-CSRF-Token was refused")
	}

	// Device- and DAV-authenticated callers carry no ambient credential, so they
	// stay exempt — that exemption is now structural (an empty token) rather
	// than inferred from the absence of a cookie.
	if !csrfCheckOK(httptest.NewRequest(http.MethodPost, "/api/inbox/actions", nil), AuthContext{UserID: "u1"}) {
		t.Error("a device-authenticated POST was refused a CSRF check it cannot satisfy")
	}
}
