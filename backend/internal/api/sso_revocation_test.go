package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// localAccount is a password-holding account, which is what makes the link a
// FOURTH credential rather than the only one.
// linkTestPassword is the password every local test account is created with.
const linkTestPassword = "victim-password-123"

func localAccount(t *testing.T, srv *Server, username string) users.User {
	t.Helper()
	u, err := srv.users.Create(context.Background(), username, linkTestPassword, users.RoleUser)
	if err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	// Past first-run: a MustChangePassword account is refused by withAuth, so it
	// could never reach the step-up these tests exercise.
	clearMustChangePassword(t, srv, u.ID)
	reloaded, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload %s: %v", username, err)
	}
	return reloaded
}

// The SSO link is a fourth way into an account, and every revocation path must
// cut it. Before this, an attacker who bound their own directory identity to a
// hijacked session kept full mailbox access through the victim's own
// remediation: handleSSOCallback resolves a sign-in from the stored sub alone.
func TestPasswordChangeRevokesTheSSOLink(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	victim := localAccount(t, srv, "victim")

	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), victim.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	sess := sessionCookieFrom(rec)
	if sess == nil {
		t.Fatal("no session cookie")
	}
	if got := runSSOFlow(t, srv, idp, sess, true); got.Code != http.StatusFound {
		t.Fatalf("link flow status = %d: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
	linked, err := srv.users.Get(victim.ID)
	if err != nil || linked.SSOSub != "sso-sub-12345" {
		t.Fatalf("precondition: expected the identity to be linked, got %+v err=%v", linked, err)
	}

	// The victim secures the account.
	if got := changePassword(t, srv, linked, "198.51.100.7",
		"victim-password-123", "a-brand-new-password-456"); got.Code != http.StatusOK {
		t.Fatalf("password change status = %d: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}

	after, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if after.SSOSub != "" || after.SSOUsername != "" || after.SSOEmail != "" || after.SSOLinkedAt != 0 {
		t.Fatalf("the SSO link survived the password change: %+v", after)
	}

	// And it resolves to nobody afterwards: with auto-provisioning off, the
	// same identity must be refused rather than signed in anywhere.
	settings := srv.ssoStore.Load()
	settings.AutoProvision = false
	if err := srv.ssoStore.Save(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	got := runSSOFlow(t, srv, idp, nil, false)
	if got.Code != http.StatusForbidden {
		t.Fatalf("post-revocation SSO login status = %d, want 403: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
	if sessionCookieFrom(got) != nil {
		t.Fatal("a revoked SSO link still issued a session")
	}
}

// The admin paths (deactivate, reset-password, clear-MFA) all go through this
// one function, so the link is cut there rather than at three call sites.
func TestRevokeAllUserCredentialsClearsTheSSOLink(t *testing.T) {
	srv, _ := setupSSOTestServer(t)
	u := localAccount(t, srv, "linked")

	if err := srv.users.LinkSSO(u.ID, "sso-sub-admin-path", "linked_sso", "linked@urlxl.com"); err != nil {
		t.Fatalf("LinkSSO: %v", err)
	}
	u, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if err := srv.revokeAllUserCredentials(u); err != nil {
		t.Fatalf("revokeAllUserCredentials: %v", err)
	}
	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload after revocation: %v", err)
	}
	if after.SSOSub != "" {
		t.Fatalf("SSOSub = %q after revocation, want it cleared", after.SSOSub)
	}
	if _, err := srv.users.GetBySSOSub("sso-sub-admin-path"); err == nil {
		t.Fatal("the revoked subject still resolves to an account")
	}

	// An account that was never linked is not an error, just nothing to do.
	if err := srv.revokeAllUserCredentials(after); err != nil {
		t.Fatalf("second revocation on an unlinked account: %v", err)
	}
}

// The public SSO routes reach an outbound request to the operator's identity
// provider, and nothing else in front of them bounds it.
func TestSSOLoginIsRateLimitedPerIP(t *testing.T) {
	srv, _ := setupSSOTestServer(t)
	if srv.loginParamsLimiter == nil {
		t.Fatal("no login params limiter on the test server")
	}

	const flooder = "203.0.113.44"
	limited := false
	for i := range loginParamsBurst + 1 {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
		req.Host = ssoTestHost
		req.RemoteAddr = flooder + ":50000"
		rec := httptest.NewRecorder()
		srv.handleSSOLogin(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if rec.Code != http.StatusFound {
			t.Fatalf("request %d: status = %d, want 302: %s", i, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	if !limited {
		t.Fatalf("%d SSO login requests from one address were all served; the route is unmetered", loginParamsBurst+1)
	}

	// Another address still signs in: the meter is per IP, not global.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = ssoTestHost
	req.RemoteAddr = "203.0.113.45:50000"
	rec := httptest.NewRecorder()
	srv.handleSSOLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("a different address got status = %d, want 302", rec.Code)
	}
}

// The link write creates a credential, so a session alone must not authorize it.
//
// This is the attack the step-up closes: an attacker holding a stolen session
// cookie completes the flow at the IdP as THEMSELVES, and linkSSOIdentity binds
// their sub to the victim's account. handleSSOCallback then resolves a sign-in
// from that sub and an Active check alone, so they hold the mailbox for as long
// as the link does.
func TestSSOLinkRequiresTheAccountCredential(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	victim := localAccount(t, srv, "victim")

	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), victim.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	stolen := sessionCookieFrom(rec)
	if stolen == nil {
		t.Fatal("no session cookie")
	}

	// The stolen session, with no password, gets no ticket.
	if got := startSSOLink(t, srv, stolen, "", ""); got.Code == http.StatusOK {
		t.Fatal("a session with no credential authorized an SSO link")
	}
	if got := startSSOLink(t, srv, stolen, "not-the-victims-password", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}

	// Nor can they skip the mint and drive the callback themselves. The state
	// cookie is browser-supplied and unsigned, so an attacker holding the session
	// can write a self-consistent one, tag and all — the grant is the part they
	// cannot write, because it lives on the session server-side.
	forged := runSSOFlowWithMode(t, srv, idp, stolen, ssoModeLink+":"+ssoSessionTag(requestWithSession(stolen)))
	if forged.Code == http.StatusFound {
		t.Fatal("a forged link-mode state cookie completed the link")
	}
	if forged.Code != http.StatusForbidden {
		t.Fatalf("forged link status = %d, want 403: %s", forged.Code, strings.TrimSpace(forged.Body.String()))
	}
	after, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if after.SSOSub != "" {
		t.Fatalf("the identity was linked without a credential: sub=%q", after.SSOSub)
	}
}

// A step-up authorizes exactly one link, so the same flow cannot be replayed.
func TestSSOLinkGrantIsSingleUse(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	victim := localAccount(t, srv, "victim")

	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), victim.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	sess := sessionCookieFrom(rec)

	start := startSSOLink(t, srv, sess, "victim-password-123", "")
	if start.Code != http.StatusOK {
		t.Fatalf("link start status = %d: %s", start.Code, strings.TrimSpace(start.Body.String()))
	}
	mode := linkModeFromStateCookie(t, start)

	if got := runSSOFlowWithMode(t, srv, idp, sess, mode); got.Code != http.StatusFound {
		t.Fatalf("first redemption status = %d, want 302: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
	// Same session, same cookie, second callback: the grant was spent by the first.
	if got := runSSOFlowWithMode(t, srv, idp, sess, mode); got.Code != http.StatusForbidden {
		t.Fatalf("replayed link status = %d, want 403: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
}
