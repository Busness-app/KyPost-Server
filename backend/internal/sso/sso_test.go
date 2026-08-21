package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/sso/ssotest"
)

const testClientID = "kypost-test"

func testSettings(issuer string) SSOSettings {
	return SSOSettings{
		Enabled:       true,
		IssuerURL:     issuer,
		ClientID:      testClientID,
		ClientSecret:  "test-secret",
		AutoProvision: true,
	}
}

// exchange drives one complete flow against idp and returns what the server
// concluded about the identity.
func exchange(t *testing.T, idp *ssotest.IdP) (*SSOTokenClaims, error) {
	t.Helper()
	p, err := NewProvider(context.Background(), testSettings(idp.URL()), "https://mail.example.com/api/auth/oidc/callback")
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE() error = %v", err)
	}
	nonce, err := RandomToken(16)
	if err != nil {
		t.Fatalf("RandomToken() error = %v", err)
	}
	code, _ := idp.Authorize(t, p.AuthCodeURL("state-abc", nonce, challenge))
	return p.Exchange(context.Background(), code, verifier, nonce)
}

func TestSSOSettingsStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewStore(tmpDir)

	def := store.Load()
	if !def.AutoProvision || def.Enabled {
		t.Errorf("unexpected default settings: %+v", def)
	}
	if def.AllowInsecureIssuer || def.RequireFreshEvents {
		t.Errorf("insecure options must default off, got: %+v", def)
	}

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

	got := NewStore(tmpDir).Load()
	if !got.Enabled || got.IssuerURL != "https://auth.urlxl.com" || got.ClientID != "kypost" {
		t.Errorf("unexpected loaded settings: %+v", got)
	}
}

func TestClaimsIsAdmin(t *testing.T) {
	c1 := &SSOTokenClaims{Role: "admin"}
	if !c1.IsAdmin() {
		t.Errorf("expected role=admin to be admin")
	}
	c2 := &SSOTokenClaims{Groups: []string{"authentik default admins"}}
	if !c2.IsAdmin() {
		t.Errorf("expected authentik group to be admin")
	}
	c3 := &SSOTokenClaims{}
	c3.RealmAccess.Roles = []string{"admin"}
	if !c3.IsAdmin() {
		t.Errorf("expected keycloak realm role to be admin")
	}
	c4 := &SSOTokenClaims{Role: "user", Groups: []string{"users"}}
	if c4.IsAdmin() {
		t.Errorf("expected regular user not to be admin")
	}
}

// A correctly signed token is accepted and its claims survive intact.
func TestExchangeAcceptsSignedToken(t *testing.T) {
	idp := ssotest.New(t, testClientID)

	claims, err := exchange(t, idp)
	if err != nil {
		t.Fatalf("Exchange() error = %v, want success", err)
	}
	if claims.Sub != "sso-sub-12345" || claims.PreferredUsername != "admin_sso" || claims.Email != "admin_sso@urlxl.com" {
		t.Errorf("unexpected claims: %+v", claims)
	}
	if !claims.IsAdmin() {
		t.Errorf("expected role=admin to survive verification")
	}
	if claims.Issuer != idp.URL() {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, idp.URL())
	}
}

// Each of these is a token the removed ParseClaims would have accepted, or
// would have had no opinion about. Every one must now be refused.
func TestExchangeRefusesUnverifiableTokens(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(*ssotest.IdP)
		want  string
	}{
		{
			// The headline bug: base64 JSON with a decorative ".sig".
			name:  "unsigned token",
			spoil: func(i *ssotest.IdP) { i.Unsigned = true },
			want:  "id_token verification failed",
		},
		{
			name:  "signed by a key that is not in the JWKS",
			spoil: func(i *ssotest.IdP) { i.ForeignKey = true },
			want:  "id_token verification failed",
		},
		{
			name:  "alg none",
			spoil: func(i *ssotest.IdP) { i.AlgNone = true },
			want:  "id_token verification failed",
		},
		{
			name:  "expired",
			spoil: func(i *ssotest.IdP) { i.Expired = true },
			want:  "id_token verification failed",
		},
		{
			name:  "audience belongs to another client",
			spoil: func(i *ssotest.IdP) { i.WrongAudience = "some-other-app" },
			want:  "id_token verification failed",
		},
		{
			name:  "issuer is not the configured one",
			spoil: func(i *ssotest.IdP) { i.WrongIssuer = "https://evil.example.com" },
			want:  "id_token verification failed",
		},
		{
			// A token minted for a different login of this same client.
			name:  "nonce absent",
			spoil: func(i *ssotest.IdP) { i.DropNonce = true },
			want:  "nonce does not match",
		},
		{
			name:  "no sub claim",
			spoil: func(i *ssotest.IdP) { i.SetClaims(map[string]any{"preferred_username": "admin"}) },
			want:  "no sub claim",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := ssotest.New(t, testClientID)
			tc.spoil(idp)

			claims, err := exchange(t, idp)
			if err == nil {
				t.Fatalf("Exchange() accepted a %s and returned %+v", tc.name, claims)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Exchange() error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A provider whose discovery document disagrees about its own identity is the
// signal that the URL an operator typed is not the issuer it claims to be.
func TestNewProviderRefusesIssuerMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://evil.example.com",
			"authorization_endpoint":"https://evil.example.com/a",
			"token_endpoint":"https://evil.example.com/t",
			"jwks_uri":"https://evil.example.com/j"}`))
	}))
	defer srv.Close()

	if _, err := NewProvider(context.Background(), testSettings(srv.URL), "https://mail.example.com/cb"); err == nil {
		t.Fatal("NewProvider() accepted a discovery document claiming a different issuer")
	}
}

// Discovery must not be able to move the client secret onto a cleartext or
// unrelated-scheme endpoint.
func TestNewProviderRefusesUnsafeDiscoveredEndpoints(t *testing.T) {
	for _, tc := range []struct{ name, tokenEndpoint string }{
		{"cleartext token endpoint on a public host", "http://tokens.example.com/t"},
		{"non-http scheme", "ftp://tokens.example.com/t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = writeJSONDoc(w, map[string]any{
					"issuer":                 srv.URL,
					"authorization_endpoint": srv.URL + "/a",
					"token_endpoint":         tc.tokenEndpoint,
					"jwks_uri":               srv.URL + "/j",
				})
			}))
			defer srv.Close()

			_, err := NewProvider(context.Background(), testSettings(srv.URL), "https://mail.example.com/cb")
			if err == nil {
				t.Fatal("NewProvider() accepted an unsafe token endpoint")
			}
			if !strings.Contains(err.Error(), "token endpoint") {
				t.Errorf("error = %q, want it to name the token endpoint", err)
			}
		})
	}
}

// The provider must not be led somewhere the scheme policy never inspected.
func TestNewProviderRefusesRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	_, err := NewProvider(context.Background(), testSettings(srv.URL), "https://mail.example.com/cb")
	if err == nil {
		t.Fatal("NewProvider() followed a redirect away from the issuer")
	}
	if !strings.Contains(err.Error(), "refusing redirect") {
		t.Errorf("error = %q, want it to name the refused redirect", err)
	}
}

// An endpoint that streams forever must not be able to exhaust this process.
func TestNewProviderBoundsResponseBodies(t *testing.T) {
	idp := ssotest.New(t, testClientID)
	idp.PadDiscovery = maxOIDCResponseBytes + 4096

	if _, err := NewProvider(context.Background(), testSettings(idp.URL()), "https://mail.example.com/cb"); err == nil {
		t.Fatal("NewProvider() accepted a discovery document larger than the ceiling")
	}
}

func TestValidateIssuerURL(t *testing.T) {
	for _, tc := range []struct {
		name          string
		raw           string
		allowInsecure bool
		wantErr       bool
	}{
		{"https is always fine", "https://auth.urlxl.com", false, false},
		{"loopback http is fine for development", "http://127.0.0.1:9000", false, false},
		{"localhost http is fine for development", "http://localhost:9000", false, false},
		{"ipv6 loopback http is fine", "http://[::1]:9000", false, false},

		// The client secret and authorization code travel this link.
		{"cleartext http on a LAN host is refused", "http://192.168.1.50:9000", false, true},
		{"cleartext http on a public host is refused", "http://auth.urlxl.com", false, true},

		// ...unless an operator turned the knob deliberately.
		{"LAN http is allowed once opted in", "http://192.168.1.50:9000", true, false},

		{"other schemes are refused", "ftp://auth.urlxl.com", false, true},
		{"embedded credentials are refused", "https://user:pass@auth.urlxl.com", false, true},
		{"a bare host is refused", "auth.urlxl.com", false, true},
		{"empty is refused", "", false, true},
		{"a query string is refused", "https://auth.urlxl.com?x=1", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIssuerURL(tc.raw, tc.allowInsecure)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateIssuerURL(%q, %v) error = %v, wantErr = %v", tc.raw, tc.allowInsecure, err, tc.wantErr)
			}
		})
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
	v2, _, _ := GeneratePKCE()
	if v == v2 {
		t.Error("GeneratePKCE() returned the same verifier twice")
	}
}

// writeJSONDoc keeps the discovery stubs above readable.
func writeJSONDoc(w http.ResponseWriter, doc map[string]any) error {
	return json.NewEncoder(w).Encode(doc)
}

// A thin ID token is topped up from userinfo, without losing what the signed
// token did say and without accepting a profile for a different subject.
func TestExchangeMergesUserInfo(t *testing.T) {
	t.Run("fills only the blanks", func(t *testing.T) {
		idp := ssotest.New(t, testClientID)
		// Signed token carries sub and email but no username.
		idp.SetClaims(map[string]any{"sub": "sub-thin", "email": "signed@urlxl.com"})
		// Userinfo supplies the username and disagrees about the email.
		idp.UserInfo = map[string]any{"preferred_username": "yoshi", "email": "userinfo@urlxl.com"}

		claims, err := exchange(t, idp)
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
		if claims.PreferredUsername != "yoshi" {
			t.Errorf("PreferredUsername = %q, want the userinfo value to fill the blank", claims.PreferredUsername)
		}
		if claims.Email != "signed@urlxl.com" {
			t.Errorf("Email = %q, want the signed token's value to survive", claims.Email)
		}
		if claims.Sub != "sub-thin" {
			t.Errorf("Sub = %q, want the verified subject", claims.Sub)
		}
	})

	t.Run("ignores a profile for a different subject", func(t *testing.T) {
		idp := ssotest.New(t, testClientID)
		idp.SetClaims(map[string]any{"sub": "sub-thin"})
		idp.UserInfo = map[string]any{"preferred_username": "somebody_else", "email": "other@urlxl.com"}
		idp.UserInfoSub = "a-different-subject"

		claims, err := exchange(t, idp)
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
		if claims.PreferredUsername != "" || claims.Email != "" {
			t.Errorf("userinfo for a different sub was merged in: %+v", claims)
		}
	})
}
