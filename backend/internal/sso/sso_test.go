package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSOSettingsStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	// Default
	def := store.Load()
	if !def.AutoProvision || def.Enabled {
		t.Errorf("unexpected default settings: %+v", def)
	}

	// Save
	cfg := SSOSettings{
		Enabled:       true,
		IssuerURL:     "https://auth.urlxl.com",
		ClientID:      "kypost",
		ClientSecret:  "secret123",
		AutoProvision: true,
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Reload
	store2 := NewStore(tmpDir)
	got := store2.Load()
	if !got.Enabled || got.IssuerURL != "https://auth.urlxl.com" || got.ClientID != "kypost" {
		t.Errorf("unexpected loaded settings: %+v", got)
	}
}

func TestDiscoverEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"authorization_endpoint": "http://" + r.Host + "/custom/auth",
				"token_endpoint":         "http://" + r.Host + "/custom/token",
				"userinfo_endpoint":      "http://" + r.Host + "/custom/userinfo",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	disc, err := DiscoverEndpoints(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	if disc.AuthorizationEndpoint != srv.URL+"/custom/auth" || disc.TokenEndpoint != srv.URL+"/custom/token" {
		t.Errorf("unexpected discovery result: %+v", disc)
	}
}

func TestPKCE(t *testing.T) {
	v, c, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	if len(v) != 64 || len(c) == 0 {
		t.Errorf("unexpected verifier/challenge: %s / %s", v, c)
	}
}

func TestClaimsIsAdmin(t *testing.T) {
	// 1. Role admin
	c1 := &SSOTokenClaims{Role: "admin"}
	if !c1.IsAdmin() {
		t.Errorf("expected c1 to be admin")
	}

	// 2. Authentik group
	c2 := &SSOTokenClaims{Groups: []string{"authentik default admins"}}
	if !c2.IsAdmin() {
		t.Errorf("expected c2 to be admin")
	}

	// 3. Keycloak realm role
	c3 := &SSOTokenClaims{}
	c3.RealmAccess.Roles = []string{"admin"}
	if !c3.IsAdmin() {
		t.Errorf("expected c3 to be admin")
	}

	// 4. Regular user
	c4 := &SSOTokenClaims{Role: "user", Groups: []string{"users"}}
	if c4.IsAdmin() {
		t.Errorf("expected c4 to not be admin")
	}
}

func TestParseClaims(t *testing.T) {
	payload := map[string]any{
		"sub":                "sub-12345",
		"email":              "user@urlxl.com",
		"preferred_username": "yoshi",
		"role":               "admin",
	}
	payloadBytes, _ := json.Marshal(payload)
	idToken := "header." + base64.RawURLEncoding.EncodeToString(payloadBytes) + ".sig"

	claims, err := ParseClaims(context.Background(), idToken, "", "")
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}
	if claims.Sub != "sub-12345" || claims.Email != "user@urlxl.com" || claims.PreferredUsername != "yoshi" || !claims.IsAdmin() {
		t.Errorf("unexpected parsed claims: %+v", claims)
	}
}
