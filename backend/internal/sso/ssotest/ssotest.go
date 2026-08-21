// Package ssotest runs a real OpenID Connect provider for tests: it publishes
// a JWKS and signs its ID tokens with the matching private key.
//
// It exists because the fake provider it replaces returned
// "header." + base64(claims) + ".sig" and the server accepted it. A test
// double that cannot produce a valid signature cannot tell a passing test from
// a total authentication bypass, so every tamper case below — unsigned, wrong
// key, alg none, expired, wrong audience, wrong nonce — is something a test
// can now actually ask for and watch get refused.
package ssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// IdP is a signing OIDC provider bound to one client ID.
type IdP struct {
	Server   *httptest.Server
	ClientID string

	// Tamper knobs. All default to off, so the zero value is a provider that
	// behaves correctly.
	Unsigned      bool   // emit the legacy "header.<payload>.sig" shape
	ForeignKey    bool   // sign with a key absent from the published JWKS
	AlgNone       bool   // emit an alg:none token
	Expired       bool   // emit a token whose exp is in the past
	DropNonce     bool   // omit the nonce the authorization request asked for
	WrongAudience string // put this in aud instead of ClientID
	WrongIssuer   string // put this in iss instead of the real issuer
	PadDiscovery  int    // pad the discovery document with this many bytes

	// UserInfo, when set, is served from the userinfo endpoint. UserInfoSub
	// overrides the `sub` it reports, so a test can check that a mismatched
	// subject is ignored rather than merged in.
	UserInfo    map[string]any
	UserInfoSub string

	mu     sync.Mutex
	claims map[string]any
	nonce  string

	signKey    *rsa.PrivateKey
	foreignKey *rsa.PrivateKey
}

// New starts a provider issuing tokens for clientID.
func New(t *testing.T, clientID string) *IdP {
	t.Helper()

	signKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}

	idp := &IdP{
		ClientID:   clientID,
		signKey:    signKey,
		foreignKey: foreignKey,
		claims: map[string]any{
			"sub":                "sso-sub-12345",
			"email":              "admin_sso@urlxl.com",
			"preferred_username": "admin_sso",
			"role":               "admin",
		},
	}
	idp.Server = httptest.NewServer(http.HandlerFunc(idp.route))
	t.Cleanup(idp.Server.Close)
	return idp
}

// URL is the issuer URL, an http loopback address that the transport policy
// permits without an insecure-issuer opt-in.
func (i *IdP) URL() string { return i.Server.URL }

// SetClaims replaces the claim set the next ID token carries.
func (i *IdP) SetClaims(c map[string]any) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.claims = c
}

// Authorize plays the part of the browser following the redirect to the
// provider: it records the nonce so the ID token can echo it, and returns the
// code and state the provider would send back.
func (i *IdP) Authorize(t *testing.T, rawAuthURL string) (code, state string) {
	t.Helper()
	u, err := url.Parse(rawAuthURL)
	if err != nil {
		t.Fatalf("authorization URL is not parseable: %v", err)
	}
	q := u.Query()
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization request is missing PKCE: %s", u.RawQuery)
	}
	if q.Get("nonce") == "" {
		t.Fatalf("authorization request is missing a nonce: %s", u.RawQuery)
	}
	i.mu.Lock()
	i.nonce = q.Get("nonce")
	i.mu.Unlock()
	return "mock_code", q.Get("state")
}

func (i *IdP) route(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		doc := map[string]any{
			"issuer":                                i.Server.URL,
			"authorization_endpoint":                i.Server.URL + "/oauth/authorize",
			"token_endpoint":                        i.Server.URL + "/oauth/token",
			"userinfo_endpoint":                     i.Server.URL + "/oauth/userinfo",
			"jwks_uri":                              i.Server.URL + "/.well-known/jwks.json",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if i.PadDiscovery > 0 {
			doc["padding"] = string(make([]byte, i.PadDiscovery))
		}
		_ = json.NewEncoder(w).Encode(doc)
	case "/.well-known/jwks.json":
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       i.signKey.Public(),
			KeyID:     "test-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}}})
	case "/oauth/userinfo":
		if i.UserInfo == nil {
			http.NotFound(w, r)
			return
		}
		i.mu.Lock()
		sub, _ := i.claims["sub"].(string)
		i.mu.Unlock()
		if i.UserInfoSub != "" {
			sub = i.UserInfoSub
		}
		doc := map[string]any{"sub": sub}
		for k, v := range i.UserInfo {
			doc[k] = v
		}
		_ = json.NewEncoder(w).Encode(doc)
	case "/oauth/token":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "mock-access-token",
			"id_token":     i.idToken(),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	default:
		http.NotFound(w, r)
	}
}

// payload assembles the claim set, applying whichever tamper knobs are set.
func (i *IdP) payload() map[string]any {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()
	exp := now.Add(time.Hour)
	if i.Expired {
		exp = now.Add(-time.Hour)
	}

	p := map[string]any{
		"iss": i.Server.URL,
		"aud": i.ClientID,
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}
	if i.WrongIssuer != "" {
		p["iss"] = i.WrongIssuer
	}
	if i.WrongAudience != "" {
		p["aud"] = i.WrongAudience
	}
	if !i.DropNonce && i.nonce != "" {
		p["nonce"] = i.nonce
	}
	for k, v := range i.claims {
		p[k] = v
	}
	return p
}

// idToken serialises the payload the way this IdP has been told to.
func (i *IdP) idToken() string {
	body, err := json.Marshal(i.payload())
	if err != nil {
		return ""
	}
	b64 := base64.RawURLEncoding.EncodeToString(body)

	switch {
	case i.Unsigned:
		// Exactly what the removed ParseClaims accepted as proof of identity.
		return "header." + b64 + ".sig"
	case i.AlgNone:
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		return header + "." + b64 + "."
	}

	key := i.signKey
	if i.ForeignKey {
		key = i.foreignKey
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		return ""
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return ""
	}
	out, err := sig.CompactSerialize()
	if err != nil {
		return ""
	}
	return out
}
