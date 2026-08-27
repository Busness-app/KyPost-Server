package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/sso"
	"kypost-server/backend/internal/sso/ssotest"
	"kypost-server/backend/internal/users"
)

const ssoTestHost = "localhost:5866"

func setupSSOTestServer(t *testing.T) (*Server, *ssotest.IdP) {
	t.Helper()
	srv := newTestServer(t)
	// SSO needs an explicitly configured external URL: ssoRedirectURI reads
	// SERVER_BASE_URL and nothing else, because redirect_uri is where the
	// provider sends an authorization code.
	srv.serverBaseURL = "http://" + ssoTestHost
	idp := ssotest.New(t, "kypost-test")

	if err := srv.ssoStore.Save(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     idp.URL(),
		ClientID:      idp.ClientID,
		ClientSecret:  "test-secret",
		AutoProvision: true,
	}); err != nil {
		t.Fatalf("save sso settings: %v", err)
	}
	return srv, idp
}

// runSSOFlow drives login → provider authorization → callback, exactly as a
// browser would, and returns the callback's response.
func runSSOFlow(t *testing.T, srv *Server, idp *ssotest.IdP, sessionCookie *http.Cookie, link bool) *httptest.ResponseRecorder {
	t.Helper()

	// A link starts at the gated POST — the public GET cannot begin one — so the
	// helper pays the step-up the real Security page pays.
	if link {
		start := startSSOLink(t, srv, sessionCookie, linkTestPassword, "")
		if start.Code != http.StatusOK {
			t.Fatalf("handleSSOLinkStart status = %d (%s), want 200", start.Code, strings.TrimSpace(start.Body.String()))
		}
		return redeemSSOLink(t, srv, idp, sessionCookie, start)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = ssoTestHost
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	srv.handleSSOLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("handleSSOLogin status = %d (%s), want 302", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	authorizeURL := rec.Header().Get("Location")

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("the SSO flow did not set the state cookie")
	}

	code, state := idp.Authorize(t, authorizeURL)

	rec = httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	cbReq.Host = ssoTestHost
	cbReq.AddCookie(stateCookie)
	if sessionCookie != nil {
		cbReq.AddCookie(sessionCookie)
	}
	srv.handleSSOCallback(rec, cbReq)
	return rec
}

func sessionCookieFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypost_session" {
			return c
		}
	}
	return nil
}

func TestSSOConfigAndAdmin(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	rec := httptest.NewRecorder()
	srv.handleSSOConfig(rec, httptest.NewRequest(http.MethodGet, "/api/auth/sso-config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSSOConfig status = %d, want 200", rec.Code)
	}
	var cfgResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&cfgResp)
	if cfgResp["enabled"] != true || cfgResp["issuerUrl"] != idp.URL() {
		t.Errorf("unexpected sso-config response: %+v", cfgResp)
	}

	putBody, _ := json.Marshal(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     "https://auth.urlxl.com",
		ClientID:      "kypost-prod",
		AutoProvision: false,
	})
	rec = httptest.NewRecorder()
	srv.handleAdminSSOPut(rec, httptest.NewRequest(http.MethodPut, "/api/admin/sso", bytes.NewReader(putBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleAdminSSOPut status = %d: %s", rec.Code, rec.Body.String())
	}
	if loaded := srv.ssoStore.Load(); loaded.ClientID != "kypost-prod" || loaded.AutoProvision {
		t.Errorf("unexpected updated settings: %+v", loaded)
	}
}

// A configuration that cannot be used safely is refused where the operator can
// still see why, rather than at the next sign-in attempt.
func TestAdminSSOPutRejectsUnsafeConfig(t *testing.T) {
	srv := newTestServer(t)

	for _, tc := range []struct {
		name string
		cfg  sso.SSOSettings
	}{
		{"cleartext LAN issuer", sso.SSOSettings{Enabled: true, IssuerURL: "http://192.168.1.50:9000", ClientID: "x"}},
		{"no client id", sso.SSOSettings{Enabled: true, IssuerURL: "https://auth.urlxl.com"}},
		{"not a URL", sso.SSOSettings{Enabled: true, IssuerURL: "auth.urlxl.com", ClientID: "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.cfg)
			rec := httptest.NewRecorder()
			srv.handleAdminSSOPut(rec, httptest.NewRequest(http.MethodPut, "/api/admin/sso", bytes.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			if srv.ssoStore.Load().Enabled {
				t.Error("rejected settings were saved anyway")
			}
		})
	}

	// The same issuer becomes acceptable once the operator opts in.
	body, _ := json.Marshal(sso.SSOSettings{
		Enabled: true, IssuerURL: "http://192.168.1.50:9000", ClientID: "x", AllowInsecureIssuer: true,
	})
	rec := httptest.NewRecorder()
	srv.handleAdminSSOPut(rec, httptest.NewRequest(http.MethodPut, "/api/admin/sso", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("opted-in insecure issuer status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestSSOLoginAndCallback(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	rec := runSSOFlow(t, srv, idp, nil, false)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/read" {
		t.Fatalf("callback status = %d, loc = %s, want 302 to /read (body: %s)",
			rec.Code, rec.Header().Get("Location"), strings.TrimSpace(rec.Body.String()))
	}

	sessCookie := sessionCookieFrom(rec)
	if sessCookie == nil {
		t.Fatal("expected kypost_session cookie after successful SSO login")
	}

	u, err := srv.users.GetBySSOSub("sso-sub-12345")
	if err != nil || u.Username != "admin_sso" || u.Role != users.RoleAdmin {
		t.Errorf("unexpected provisioned user: %+v, err: %v", u, err)
	}

	// Unlinking needs somewhere to sign in from afterwards; an auto-provisioned
	// account has nowhere until it sets a password. See
	// TestUnlinkRefusesWhenTheLinkIsTheOnlyCredential.
	if _, err := srv.users.SetPassword(context.Background(), u.ID, "a-local-password-123", false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/settings/sso/unlink", nil)
	req.AddCookie(sessCookie)
	srv.handleSSOUnlink(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSSOUnlink status = %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if u, _ = srv.users.Get(u.ID); u.SSOSub != "" {
		t.Errorf("expected SSOSub cleared after unlink, got: %s", u.SSOSub)
	}
}

// The account-seizure path. A directory identity that has never been linked
// here must not inherit a local account merely by carrying its name — not even
// when the provider genuinely signed that name.
func TestSSOCallbackDoesNotSeizeAccountByUsername(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	victim, err := srv.users.Create(context.Background(), "owner", "owner-password-123", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	// A low-privilege directory user who has set preferred_username=owner.
	idp.SetClaims(map[string]any{
		"sub":                "attacker-sub-999",
		"preferred_username": "owner",
		"email":              "attacker@evil.example.com",
	})

	rec := runSSOFlow(t, srv, idp, nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	// The victim's account must be untouched: no SSO identity attached to it.
	after, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if after.SSOSub != "" {
		t.Fatalf("SSO identity %q was linked to the pre-existing account %q", after.SSOSub, after.Username)
	}

	// And the attacker must have landed on a separate, distinctly named account.
	attacker, err := srv.users.GetBySSOSub("attacker-sub-999")
	if err != nil {
		t.Fatalf("expected the attacker to be provisioned separately: %v", err)
	}
	if attacker.ID == victim.ID {
		t.Fatal("attacker was provisioned onto the victim's account")
	}
	if strings.EqualFold(attacker.Username, "owner") {
		t.Fatalf("attacker took the victim's username: %q", attacker.Username)
	}
}

// The other seizure path: the state cookie used to name the account to link,
// so anyone who knew a user id could bind their identity to it.
func TestSSOLinkRequiresAnAuthenticatedSession(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	victim, err := srv.users.Create(context.Background(), "victim", "victim-password-123", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	// Start an ordinary (unauthenticated) login to obtain a usable state cookie.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = ssoTestHost
	srv.handleSSOLogin(rec, req)

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

	// Forge the cookie the way the old format allowed: name the victim.
	parts := strings.Split(stateCookie.Value, "|")
	forged := &http.Cookie{
		Name:  ssoCookieName,
		Value: strings.Join([]string{parts[0], parts[1], parts[2], victim.ID}, "|"),
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	req.Host = ssoTestHost
	req.AddCookie(forged)
	srv.handleSSOCallback(rec, req)

	after, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if after.SSOSub != "" {
		t.Fatalf("a forged state cookie linked SSO identity %q to the victim's account", after.SSOSub)
	}

	// Starting a link with nobody signed in is refused at the only route that
	// can start one. The public GET no longer has a link mode at all.
	if got := startSSOLink(t, srv, nil, "victim-password-123", ""); got.Code != http.StatusUnauthorized {
		t.Errorf("link start without a session: status = %d, want 401", got.Code)
	}
}

// Linking works for the signed-in user, and targets exactly that account.
func TestSSOLinkBindsTheCallersOwnAccount(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	u, err := srv.users.Create(context.Background(), "linker", linkTestPassword, users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	clearMustChangePassword(t, srv, u.ID)
	rec := httptest.NewRecorder()
	if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), u.ID); err != nil {
		t.Fatalf("startSession: %v", err)
	}
	sessCookie := sessionCookieFrom(rec)
	if sessCookie == nil {
		t.Fatal("no session cookie")
	}

	rec = runSSOFlow(t, srv, idp, sessCookie, true)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/settings?sso=linked" {
		t.Fatalf("link callback status = %d loc = %q: %s",
			rec.Code, rec.Header().Get("Location"), strings.TrimSpace(rec.Body.String()))
	}

	after, err := srv.users.Get(u.ID)
	if err != nil || after.SSOSub != "sso-sub-12345" {
		t.Fatalf("expected the caller's own account to be linked, got %+v err=%v", after, err)
	}
}

// A subject shorter than the slice the old code took sliced out of range and
// panicked the callback.
func TestSSOCallbackHandlesShortSubject(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	// No preferred_username either, so the subject-derived name is used.
	idp.SetClaims(map[string]any{"sub": "42"})

	rec := runSSOFlow(t, srv, idp, nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	u, err := srv.users.GetBySSOSub("42")
	if err != nil {
		t.Fatalf("expected a user provisioned for sub=42: %v", err)
	}
	if err := users.ValidateUsername(u.Username); err != nil {
		t.Errorf("derived username %q is not valid: %v", u.Username, err)
	}
}

// An unverifiable token must not produce a session, whatever it claims.
func TestSSOCallbackRefusesUnsignedToken(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	idp.Unsigned = true
	idp.SetClaims(map[string]any{
		"sub":                "attacker",
		"preferred_username": "owner",
		"role":               "admin",
	})

	rec := runSSOFlow(t, srv, idp, nil, false)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("callback status = %d, want 502 for an unverifiable token", rec.Code)
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("an unsigned id_token produced a session cookie")
	}
	if _, err := srv.users.GetBySSOSub("attacker"); err == nil {
		t.Fatal("an unsigned id_token provisioned a user")
	}
}

// With auto-provisioning off, an unknown identity is refused rather than
// matched against anything local.
func TestSSOCallbackWithoutAutoProvisionRefusesUnknownIdentity(t *testing.T) {
	srv, idp := setupSSOTestServer(t)
	s := srv.ssoStore.Load()
	s.AutoProvision = false
	if err := srv.ssoStore.Save(s); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := srv.users.Create(context.Background(), "admin_sso", "local-password-123", users.RoleAdmin); err != nil {
		t.Fatalf("create colliding local user: %v", err)
	}

	rec := runSSOFlow(t, srv, idp, nil, false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("callback status = %d, want 403", rec.Code)
	}
	if sessionCookieFrom(rec) != nil {
		t.Fatal("a refused SSO login still issued a session")
	}
}

// --- sync webhook -------------------------------------------------------

func postSync(t *testing.T, srv *Server, ev map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(ev)
	mac := hmac.New(sha256.New, []byte(srv.pairingSecret))
	mac.Write(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sync/webhook", bytes.NewReader(body))
	req.Header.Set("X-Sync-Signature", hex.EncodeToString(mac.Sum(nil)))
	srv.handleSyncWebhook(rec, req)
	return rec
}

func syncEvent(name string, user map[string]any) map[string]any {
	return map[string]any{"event": name, "user": user}
}

func TestSyncWebhook(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	user := map[string]any{
		"id": "sso-sub-replicated-1", "username": "replicated_admin",
		"role": "admin", "active": true, "email": "rep@urlxl.com",
	}

	if rec := postSync(t, srv, syncEvent("user.created", user)); rec.Code != http.StatusOK {
		t.Fatalf("user.created status = %d: %s", rec.Code, rec.Body.String())
	}
	u, err := srv.users.GetBySSOSub("sso-sub-replicated-1")
	if err != nil || u.Username != "replicated_admin" || u.Role != users.RoleAdmin {
		t.Fatalf("unexpected synced user: %+v, err: %v", u, err)
	}

	// Deleting is only permitted because the bootstrap admin still exists.
	if rec := postSync(t, srv, syncEvent("user.deleted", user)); rec.Code != http.StatusOK {
		t.Fatalf("user.deleted status = %d: %s", rec.Code, rec.Body.String())
	}
	if u, _ = srv.users.Get(u.ID); u.Active {
		t.Error("expected deactivated user after user.deleted")
	}
}

// Deactivation revokes the SSO link, and every event here is addressed by the
// directory's user id — which IS the SSO subject. So revocation must not erase
// the subject: an account that cannot be found is an account the directory can
// never reactivate, and applySyncEvent answers 200 for a subject it does not
// know, so the directory stops retrying and never learns.
func TestSyncWebhookCanReactivateAfterRevocation(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	user := map[string]any{
		"id": "sso-sub-rehired", "username": "rehired_user",
		"role": "user", "active": true, "email": "rehired@urlxl.com",
	}
	if rec := postSync(t, srv, syncEvent("user.created", user)); rec.Code != http.StatusOK {
		t.Fatalf("user.created status = %d: %s", rec.Code, rec.Body.String())
	}
	created, err := srv.users.GetBySSOSub("sso-sub-rehired")
	if err != nil {
		t.Fatalf("GetBySSOSub after create: %v", err)
	}
	// A password of their own, or revokeAllUserCredentialsExcept takes the
	// HasLocalCredential skip and RevokeSSOLink is never reached — which would
	// make everything below assert sync round-trips on a link that was never
	// revoked, passing even if revocation went back to erasing the subject.
	if _, err := srv.users.SetPassword(context.Background(), created.ID, "a-local-password-123", false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	clearMustChangePassword(t, srv, created.ID)

	suspended := map[string]any{
		"id": "sso-sub-rehired", "username": "rehired_user",
		"role": "user", "active": false, "email": "rehired@urlxl.com",
	}
	if rec := postSync(t, srv, syncEvent("user.updated", suspended)); rec.Code != http.StatusOK {
		t.Fatalf("suspend status = %d: %s", rec.Code, rec.Body.String())
	}
	suspendedUser, err := srv.users.Get(created.ID)
	if err != nil {
		t.Fatalf("reload suspended: %v", err)
	}
	if suspendedUser.Active {
		t.Fatal("the account is still active after user.updated{active:false}")
	}
	// The revocation actually ran — otherwise the rest of this test proves
	// nothing about what revocation does to the subject.
	if !suspendedUser.SSOLinkRevoked() {
		t.Fatalf("deactivation did not revoke the link: %+v", suspendedUser)
	}
	// And the address the next event will arrive on still resolves.
	if _, err := srv.users.GetBySSOSub("sso-sub-rehired"); err != nil {
		t.Fatalf("revocation lost the subject the directory addresses: %v", err)
	}

	// The directory rehires them. This is the event that used to be answered
	// 200 while doing nothing at all.
	if rec := postSync(t, srv, syncEvent("user.updated", user)); rec.Code != http.StatusOK {
		t.Fatalf("reactivate status = %d: %s", rec.Code, rec.Body.String())
	}
	back, err := srv.users.Get(created.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !back.Active {
		t.Fatal("user.updated{active:true} reported success without reactivating the account")
	}

	// A role change is addressed the same way, and stops applying for the same
	// reason if the subject is gone.
	promoted := map[string]any{
		"id": "sso-sub-rehired", "username": "rehired_user",
		"role": "admin", "active": true, "email": "rehired@urlxl.com",
	}
	if rec := postSync(t, srv, syncEvent("user.updated", promoted)); rec.Code != http.StatusOK {
		t.Fatalf("promote status = %d: %s", rec.Code, rec.Body.String())
	}
	if u, _ := srv.users.Get(created.ID); u.Role != users.RoleAdmin {
		t.Fatalf("role = %q after promotion, want admin", u.Role)
	}

	// And a second user.created for the same directory id stays idempotent
	// rather than colliding on the username or provisioning a duplicate.
	before, err := srv.users.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if rec := postSync(t, srv, syncEvent("user.created", user)); rec.Code != http.StatusOK {
		t.Fatalf("repeat user.created status = %d: %s", rec.Code, rec.Body.String())
	}
	if now, err := srv.users.List(); err != nil || len(now) != len(before) {
		t.Fatalf("account count %d -> %d on a repeat create (err=%v)", len(before), len(now), err)
	}
}

// A 200 {"ok":true} that hides a failed write tells the directory the removal
// landed and stops it retrying.
func TestSyncWebhookReportsFailures(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected one bootstrap user: %+v %v", all, err)
	}
	admin := all[0]
	if err := srv.users.LinkSSO(admin.ID, "sso-only-admin", "admin", "admin@urlxl.com"); err != nil {
		t.Fatalf("LinkSSO: %v", err)
	}

	// Removing the only administrator cannot succeed, and must not be
	// reported as if it had.
	rec := postSync(t, srv, syncEvent("user.deleted", map[string]any{"id": "sso-only-admin"}))
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleting the last admin: status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if u, _ := srv.users.Get(admin.ID); !u.Active {
		t.Error("the last admin was deactivated despite the refusal")
	}

	// An event this server does not understand is not a success either.
	rec = postSync(t, srv, syncEvent("user.exploded", map[string]any{"id": "sso-only-admin"}))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown event: status = %d, want 400", rec.Code)
	}
}

// An HMAC proves who wrote an event, never when. Re-delivering a stale
// promotion must not re-apply it.
func TestSyncWebhookRefusesReplayAndStaleEvents(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	user := map[string]any{"id": "sso-sub-replay", "username": "replay_user", "role": "user", "active": true}
	if rec := postSync(t, srv, syncEvent("user.created", user)); rec.Code != http.StatusOK {
		t.Fatalf("setup create failed: %d %s", rec.Code, rec.Body.String())
	}

	promote := map[string]any{
		"jti": "event-1", "iat": time.Now().Unix(),
		"event": "user.updated",
		"user":  map[string]any{"id": "sso-sub-replay", "username": "replay_user", "role": "admin", "active": true},
	}
	if rec := postSync(t, srv, promote); rec.Code != http.StatusOK {
		t.Fatalf("promotion status = %d: %s", rec.Code, rec.Body.String())
	}
	u, _ := srv.users.GetBySSOSub("sso-sub-replay")
	if u.Role != users.RoleAdmin {
		t.Fatalf("promotion did not apply: %+v", u)
	}

	// The directory later demotes them by other means.
	if _, err := srv.users.SetRole(u.ID, users.RoleUser); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// Replaying the captured promotion must change nothing.
	rec := postSync(t, srv, promote)
	if rec.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want a 200 ack: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp["duplicate"] != true {
		t.Errorf("replay was not reported as a duplicate: %+v", resp)
	}
	if u, _ = srv.users.GetBySSOSub("sso-sub-replay"); u.Role == users.RoleAdmin {
		t.Fatal("a replayed event re-promoted a demoted user")
	}

	// A fresh id but an old timestamp is outside the window.
	stale := map[string]any{
		"jti": "event-2", "iat": time.Now().Add(-time.Hour).Unix(),
		"event": "user.updated",
		"user":  map[string]any{"id": "sso-sub-replay", "username": "replay_user", "role": "admin", "active": true},
	}
	if rec := postSync(t, srv, stale); rec.Code != http.StatusBadRequest {
		t.Errorf("stale event: status = %d, want 400", rec.Code)
	}
	if u, _ = srv.users.GetBySSOSub("sso-sub-replay"); u.Role == users.RoleAdmin {
		t.Fatal("a stale event was applied")
	}
}

// Events without jti/iat are accepted for now so an un-upgraded KySignOn keeps
// working, and refused outright once the operator turns the setting on.
func TestSyncWebhookRequireFreshEvents(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	ev := syncEvent("user.created", map[string]any{
		"id": "sso-sub-nofresh", "username": "nofresh_user", "role": "user", "active": true,
	})
	if rec := postSync(t, srv, ev); rec.Code != http.StatusOK {
		t.Fatalf("un-upgraded sender status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	if err := srv.ssoStore.Save(sso.SSOSettings{RequireFreshEvents: true}); err != nil {
		t.Fatalf("save: %v", err)
	}
	rec := postSync(t, srv, syncEvent("user.created", map[string]any{
		"id": "sso-sub-nofresh-2", "username": "nofresh_user2", "role": "user", "active": true,
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 once fresh events are required: %s", rec.Code, rec.Body.String())
	}
	if _, err := srv.users.GetBySSOSub("sso-sub-nofresh-2"); err == nil {
		t.Error("a rejected event was applied anyway")
	}
}

// An event with no directory user id must not provision an account with an
// empty SSO subject, which every later lookup would then match on.
func TestSyncWebhookRefusesEventWithoutUserID(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	before, err := srv.users.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	rec := postSync(t, srv, syncEvent("user.created", map[string]any{"username": "ghost", "active": true}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	after, err := srv.users.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("an event with no user id created an account: %d -> %d", len(before), len(after))
	}
}

// The state cookie is browser-supplied and unsigned, so a link flow must be
// useless in any session but the one that started it.
func TestSSOLinkCookieIsBoundToItsOwnSession(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	attacker, err := srv.users.Create(context.Background(), "attacker", "attacker-password-123", users.RoleUser)
	if err != nil {
		t.Fatalf("create attacker: %v", err)
	}
	clearMustChangePassword(t, srv, attacker.ID)
	victim, err := srv.users.Create(context.Background(), "victim2", "victim-password-123", users.RoleAdmin)
	if err != nil {
		t.Fatalf("create victim: %v", err)
	}

	session := func(id string) *http.Cookie {
		t.Helper()
		rec := httptest.NewRecorder()
		if err := srv.startSession(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), id); err != nil {
			t.Fatalf("startSession: %v", err)
		}
		c := sessionCookieFrom(rec)
		if c == nil {
			t.Fatal("no session cookie")
		}
		return c
	}

	// The attacker starts a link flow in their own session, paying the step-up
	// with their OWN credential — which they have, so the gate does not stop
	// them here. What must stop them is the tag: the cookie it mints is useless
	// in anyone else's session.
	attackerSession := session(attacker.ID)
	rec := startSSOLink(t, srv, attackerSession, "attacker-password-123", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("link start status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode link start response: %v", err)
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
	code, state := idp.Authorize(t, body.AuthorizeURL)

	// ...then plants that state cookie in the victim's browser.
	rec = httptest.NewRecorder()
	cbReq := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	cbReq.Host = ssoTestHost
	cbReq.AddCookie(stateCookie)
	cbReq.AddCookie(session(victim.ID))
	srv.handleSSOCallback(rec, cbReq)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a link cookie from another session", rec.Code)
	}
	after, err := srv.users.Get(victim.ID)
	if err != nil {
		t.Fatalf("reload victim: %v", err)
	}
	if after.SSOSub != "" {
		t.Fatalf("a planted link cookie bound SSO identity %q to the victim", after.SSOSub)
	}
}

// The redirect_uri must follow the configured external URL and nothing else.
// Behind a reverse proxy r.Host is the internal name, and a redirect_uri built
// from it matches nothing registered at the provider; worse, OAuth pins
// redirect_uri across the authorize and token calls, so a Host-derived value
// lets a request header influence where an authorization code is sent.
func TestSSORedirectURIFollowsConfiguredBaseURL(t *testing.T) {
	srv, _ := setupSSOTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = "kypost.internal:5866"

	srv.serverBaseURL = ""
	if got := srv.ssoRedirectURI(); got != "" {
		t.Errorf("without a configured base URL, ssoRedirectURI() = %q, want empty — "+
			"the Host header must never supply it", got)
	}

	srv.serverBaseURL = "https://mail.urlxl.com/"
	want := "https://mail.urlxl.com/api/auth/oidc/callback"
	if got := srv.ssoRedirectURI(); got != want {
		t.Errorf("ssoRedirectURI() = %q, want %q", got, want)
	}

	// The authorization request the provider actually receives carries it.
	rec := httptest.NewRecorder()
	srv.handleSSOLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("handleSSOLogin status = %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := loc.Query().Get("redirect_uri"); got != want {
		t.Errorf("authorization request redirect_uri = %q, want %q", got, want)
	}
}

// redeemSSOLink drives the provider round trip for the flow a startSSOLink
// response actually began, carrying that flow's own state cookie through — the
// grant is bound to it, so this is the only way a link completes.
func redeemSSOLink(t *testing.T, srv *Server, idp *ssotest.IdP, sessionCookie *http.Cookie, start *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	var body struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode link start response: %v", err)
	}
	var stateCookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("the link start did not set the state cookie")
	}

	code, state := idp.Authorize(t, body.AuthorizeURL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	req.Host = ssoTestHost
	req.AddCookie(stateCookie)
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	srv.handleSSOCallback(rec, req)
	return rec
}

// startSSOLink posts the step-up that authorizes one link, the way the Security
// page does. Exported through the handler rather than minting a ticket directly,
// so a test cannot pass by proving something the browser never proves.
func startSSOLink(t *testing.T, srv *Server, sessionCookie *http.Cookie, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"password": password, "code": code})
	if err != nil {
		t.Fatalf("marshal link request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/settings/sso/link", bytes.NewReader(body))
	req.Host = ssoTestHost
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
		srv.sessMu.RLock()
		sess, ok := srv.sessions[sessionCookie.Value]
		srv.sessMu.RUnlock()
		if ok {
			req.Header.Set("X-CSRF-Token", sess.CSRFToken)
		}
	}
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleSSOLinkStart)(rec, req)
	return rec
}

// requestWithSession builds the minimal request ssoSessionTag needs, so a test
// can derive the tag a given session cookie would produce.
func requestWithSession(sessionCookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	return req
}

// runSSOFlowWithMode drives the provider round trip against a state cookie this
// test wrote itself, which is what an attacker holding the session can do.
func runSSOFlowWithMode(t *testing.T, srv *Server, idp *ssotest.IdP, sessionCookie *http.Cookie, mode string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = ssoTestHost
	srv.handleSSOLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("handleSSOLogin status = %d, want 302", rec.Code)
	}
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("handleSSOLogin did not set the SSO state cookie")
	}
	// Same state/verifier/nonce, attacker-chosen mode.
	parts := strings.Split(stateCookie.Value, "|")
	if len(parts) < 4 {
		t.Fatalf("state cookie has %d fields, want 4", len(parts))
	}
	stateCookie.Value = strings.Join([]string{parts[0], parts[1], parts[2], mode}, "|")

	code, state := idp.Authorize(t, rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/auth/oidc/callback?code=%s&state=%s", code, state), nil)
	req.Host = ssoTestHost
	req.AddCookie(stateCookie)
	if sessionCookie != nil {
		req.AddCookie(sessionCookie)
	}
	srv.handleSSOCallback(rec, req)
	return rec
}
