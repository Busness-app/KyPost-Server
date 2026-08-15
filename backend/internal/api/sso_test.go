package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/sso"
	"kypost-server/backend/internal/users"
)

func setupSSOTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	srv := newTestServer(t)

	// Mock OIDC IdP server
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/oauth/authorize",
				"token_endpoint":         "http://" + r.Host + "/oauth/token",
				"userinfo_endpoint":      "http://" + r.Host + "/oauth/userinfo",
			})
		case "/oauth/token":
			payload := map[string]any{
				"sub":                "sso-sub-12345",
				"email":              "admin_sso@urlxl.com",
				"preferred_username": "admin_sso",
				"role":               "admin",
			}
			payloadBytes, _ := json.Marshal(payload)
			idToken := "header." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".sig"

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "mock-access-token",
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(idp.Close)

	_ = srv.ssoStore.Save(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     idp.URL,
		ClientID:      "kypost-test",
		ClientSecret:  "test-secret",
		AutoProvision: true,
	})

	return srv, idp
}

func TestSSOConfigAndAdmin(t *testing.T) {
	srv, idp := setupSSOTestServer(t)

	// 1. GET /api/auth/sso-config
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso-config", nil)
	srv.handleSSOConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSSOConfig status = %d, want 200", rec.Code)
	}
	var cfgResp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&cfgResp)
	if cfgResp["enabled"] != true || cfgResp["issuerUrl"] != idp.URL {
		t.Errorf("unexpected sso-config response: %+v", cfgResp)
	}

	// 2. Admin GET / PUT
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/sso", nil)
	srv.handleAdminSSOGet(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleAdminSSOGet status = %d", rec.Code)
	}

	putBody, _ := json.Marshal(sso.SSOSettings{
		Enabled:       true,
		IssuerURL:     "https://auth.urlxl.com",
		ClientID:      "kypost-prod",
		AutoProvision: false,
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/api/admin/sso", bytes.NewReader(putBody))
	srv.handleAdminSSOPut(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleAdminSSOPut status = %d", rec.Code)
	}

	loaded := srv.ssoStore.Load()
	if loaded.ClientID != "kypost-prod" || loaded.AutoProvision != false {
		t.Errorf("unexpected updated settings: %+v", loaded)
	}
}

func TestSSOLoginAndCallback(t *testing.T) {
	srv, _ := setupSSOTestServer(t)

	// 1. GET /api/auth/oidc/login
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/login", nil)
	req.Host = "localhost:5866"
	srv.handleSSOLogin(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("handleSSOLogin status = %d, want 302 redirect", rec.Code)
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("expected redirect Location header")
	}

	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoCookieName {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatalf("expected sso state cookie set")
	}

	// 2. GET /api/auth/oidc/callback (Login & Auto-Provision)
	state := stateCookie.Value[:32] // state portion
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/auth/oidc/callback?code=mock_code&state=%s", state), nil)
	req.Host = "localhost:5866"
	req.AddCookie(stateCookie)

	srv.handleSSOCallback(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/read" {
		t.Fatalf("handleSSOCallback status = %d, loc = %s, want 302 to /read", rec.Code, rec.Header().Get("Location"))
	}

	// Verify session cookie was issued
	var sessCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "kypost_session" {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatalf("expected kypost_session cookie after successful SSO login")
	}

	// Verify user was provisioned
	u, err := srv.users.GetBySSOSub("sso-sub-12345")
	if err != nil || u.Username != "admin_sso" || u.Role != users.RoleAdmin {
		t.Errorf("unexpected provisioned user: %+v, err: %v", u, err)
	}

	// 3. SSO Unlink
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/settings/sso/unlink", nil)
	req.AddCookie(sessCookie)
	srv.handleSSOUnlink(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSSOUnlink status = %d", rec.Code)
	}

	u, _ = srv.users.Get(u.ID)
	if u.SSOSub != "" {
		t.Errorf("expected SSOSub to be cleared after unlink, got: %s", u.SSOSub)
	}
}

func TestSyncWebhook(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = "super-secret-pairing-key"

	userPayload := SyncUserPayload{
		ID:       "sso-sub-replicated-1",
		Username: "replicated_admin",
		Role:     "admin",
		Active:   true,
		Email:    "rep@urlxl.com",
	}
	ev := SyncWebhookEvent{
		Event: "user.created",
		User:  userPayload,
	}
	body, _ := json.Marshal(ev)

	// Compute HMAC
	mac := hmac.New(sha256.New, []byte(srv.pairingSecret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/sync/webhook", bytes.NewReader(body))
	req.Header.Set("X-Sync-Signature", sig)
	srv.handleSyncWebhook(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSyncWebhook status = %d, want 200", rec.Code)
	}

	u, err := srv.users.GetBySSOSub("sso-sub-replicated-1")
	if err != nil || u.Username != "replicated_admin" || u.Role != users.RoleAdmin {
		t.Errorf("unexpected synced user: %+v, err: %v", u, err)
	}

	// Test user.deleted
	ev.Event = "user.deleted"
	body, _ = json.Marshal(ev)
	mac = hmac.New(sha256.New, []byte(srv.pairingSecret))
	mac.Write(body)
	sig = hex.EncodeToString(mac.Sum(nil))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/sync/webhook", bytes.NewReader(body))
	req.Header.Set("X-Sync-Signature", sig)
	srv.handleSyncWebhook(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleSyncWebhook delete status = %d", rec.Code)
	}

	u, _ = srv.users.Get(u.ID)
	if u.Active {
		t.Errorf("expected deactivated user after user.deleted event")
	}
}
