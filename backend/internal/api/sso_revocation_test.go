package api

import (
	"context"
	"encoding/json"
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
	if !after.SSOLinkRevoked() {
		t.Fatalf("the SSO link survived the password change: %+v", after)
	}
	// Revoked by flag, not by erasure: the subject is the directory's address
	// for this account, so it has to keep resolving. See TestSyncWebhookCan-
	// ReactivateAfterRevocation for what erasing it costs.
	if after.SSOSub != "sso-sub-12345" {
		t.Fatalf("SSOSub = %q, want the subject kept as the sync address", after.SSOSub)
	}
	if _, err := srv.users.GetBySSOSub("sso-sub-12345"); err != nil {
		t.Fatalf("the revoked subject no longer resolves: %v", err)
	}

	// /api/auth/me is what the Security page reads to decide between "linked"
	// and the re-link form, and it carries the subject — so it has to carry the
	// revocation too or the page shows a dead link as live and hides the form.
	// A fresh session, because the password change revoked every old one.
	rec = httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), victim.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	fresh := sessionCookieFrom(rec)
	me := httptest.NewRecorder()
	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meReq.AddCookie(fresh)
	srv.handleMe(me, meReq)
	var status struct {
		SSOSub         string `json:"ssoSub"`
		SSOLinkRevoked bool   `json:"ssoLinkRevoked"`
	}
	if err := json.Unmarshal(me.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode /api/auth/me: %v", err)
	}
	if !status.SSOLinkRevoked || status.SSOSub == "" {
		t.Fatalf("/api/auth/me reports a revoked link as live: %s", me.Body.String())
	}

	// And it signs nobody in afterwards. Auto-provisioning is left ON, which is
	// the harder case: a refusal that fell through to provisioning would hand
	// the attacker's subject a second, empty account instead of the mailbox.
	before, err := srv.users.List()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	got := runSSOFlow(t, srv, idp, nil, false)
	if got.Code != http.StatusForbidden {
		t.Fatalf("post-revocation SSO login status = %d, want 403: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
	if sessionCookieFrom(got) != nil {
		t.Fatal("a revoked SSO link still issued a session")
	}
	if now, err := srv.users.List(); err != nil || len(now) != len(before) {
		t.Fatalf("account count %d -> %d: the revoked subject was auto-provisioned a duplicate (err=%v)",
			len(before), len(now), err)
	}

	// Re-linking is the way back, and it clears the revocation. The step-up
	// takes the NEW password, which is the point: the credential the victim
	// changed is what re-authorizes the link.
	start := startSSOLink(t, srv, fresh, "a-brand-new-password-456", "")
	if start.Code != http.StatusOK {
		t.Fatalf("re-link start status = %d: %s", start.Code, strings.TrimSpace(start.Body.String()))
	}
	if got := runSSOFlowWithMode(t, srv, idp, fresh, linkModeFromStateCookie(t, start)); got.Code != http.StatusFound {
		t.Fatalf("re-link status = %d: %s", got.Code, strings.TrimSpace(got.Body.String()))
	}
	relinked, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload after re-link: %v", err)
	}
	if relinked.SSOLinkRevoked() {
		t.Fatalf("re-linking left the revocation in place: %+v", relinked)
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
	if !after.SSOLinkRevoked() {
		t.Fatalf("the link survived revocation: %+v", after)
	}
	if _, err := srv.users.GetBySSOSub("sso-sub-admin-path"); err != nil {
		t.Fatalf("the revoked subject no longer resolves: %v", err)
	}

	// Both views that show a link must show that it is dead. The subject is
	// still there — it has to be — so a viewer given the subject and nothing
	// else reads a revoked link as live, and the Security page hides the
	// re-link form that is the way back.
	if pub := after.Public(); !pub.SSOLinkRevoked || pub.SSOSub == "" {
		t.Fatalf("users.Public reports a revoked link as live: %+v", pub)
	}

	// Revoking twice is not an error, and neither is an account that was never
	// linked at all.
	if err := srv.revokeAllUserCredentials(after); err != nil {
		t.Fatalf("second revocation on an already-revoked account: %v", err)
	}
	if err := srv.revokeAllUserCredentials(localAccount(t, srv, "unlinked")); err != nil {
		t.Fatalf("revocation on an unlinked account: %v", err)
	}
}

// An auto-provisioned account has no password: the link is not a fourth
// credential there, it is the only one. Revoking it would leave an account
// nothing can authenticate to, and no way back — a re-link needs a step-up, and
// a step-up needs the credential the account does not have.
func TestRevocationKeepsTheLinkWhenItIsTheOnlyCredential(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	// The test IdP's own subject, so the sign-in below actually resolves here.
	u, err := srv.users.CreateSSOUser("provisioned", users.RoleUser,
		"sso-sub-12345", "provisioned", "provisioned@urlxl.com")
	if err != nil {
		t.Fatalf("CreateSSOUser: %v", err)
	}
	if u.HasLocalCredential() {
		t.Fatalf("precondition: an auto-provisioned account stores a credential: %+v", u)
	}

	if err := srv.revokeAllUserCredentials(u); err != nil {
		t.Fatalf("revokeAllUserCredentials: %v", err)
	}
	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.SSOLinkRevoked() {
		t.Fatal("revocation stranded an account whose only credential is the link")
	}

	// Nor can such an account step up its way to a link, so the gate says so
	// plainly rather than answering "invalid credentials" forever.
	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), u.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	got := startSSOLink(t, srv, sessionCookieFrom(rec), "any-password-at-all", "")
	if got.Code != http.StatusConflict {
		t.Fatalf("link start on a passwordless account = %d, want 409: %s",
			got.Code, strings.TrimSpace(got.Body.String()))
	}

	// Keeping the link is safe because the link is not what authorizes a
	// sign-in on its own: the account still has to be active. That is the
	// property the admin paths actually need, and it survives the kept link.
	if _, err := srv.users.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	login := runSSOFlow(t, srv, idp, nil, false)
	if login.Code != http.StatusForbidden {
		t.Fatalf("deactivated SSO-only login = %d, want 403: %s",
			login.Code, strings.TrimSpace(login.Body.String()))
	}
	if sessionCookieFrom(login) != nil {
		t.Fatal("a deactivated account signed in through its kept link")
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
