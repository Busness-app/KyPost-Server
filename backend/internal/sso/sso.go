// Package sso implements OpenID Connect single sign-on against an
// administrator-configured identity provider.
//
// Verification is delegated to github.com/coreos/go-oidc, not hand-rolled.
// The predecessor of this file base64-decoded the ID token payload and trusted
// it: no signature, issuer, audience, expiry or nonce check. Anything that
// could answer the token endpoint could mint `{"role":"admin"}` and get an
// administrator session. Authentication protocols are the wrong place to save
// a dependency.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"kypost-server/backend/internal/fsutil"
)

// SSOSettings holds the OpenID Connect SSO configuration.
type SSOSettings struct {
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuerUrl"`
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret,omitempty"`
	AutoProvision bool   `json:"autoProvision"`

	// AllowInsecureIssuer permits a cleartext http:// issuer on a
	// non-loopback host. The client secret and the authorization code both
	// travel over that link, so this is off unless an operator turns it on
	// deliberately for a LAN identity provider that has no TLS.
	AllowInsecureIssuer bool `json:"allowInsecureIssuer"`

	// RequireFreshEvents rejects directory replication events that carry no
	// event id and timestamp. It defaults off so an existing KySignOn that
	// does not send them yet keeps working; once it does, an operator turns
	// this on and replayed events stop being accepted at all.
	RequireFreshEvents bool `json:"requireFreshEvents"`
}

// Store handles persisting SSOSettings to disk.
type Store struct {
	path string
	mu   sync.RWMutex
}

// NewStore constructs an SSO settings store.
func NewStore(configDir string) *Store {
	return &Store{
		path: filepath.Join(configDir, "sso.json"),
	}
}

// Load reads SSO settings from disk, returning default values if not configured.
func (s *Store) Load() SSOSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		return SSOSettings{
			AutoProvision: true,
		}
	}

	var cfg SSOSettings
	if err := json.Unmarshal(data, &cfg); err != nil {
		return SSOSettings{
			AutoProvision: true,
		}
	}
	return cfg
}

// Save persists SSO settings atomically to disk.
func (s *Store) Save(cfg SSOSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return fsutil.AtomicWriteFile(s.path, data, 0o600)
}

// maxOIDCResponseBytes bounds every body read from the identity provider.
// A discovery document is a few kilobytes and a JWKS rarely more; without a
// ceiling a hostile or broken endpoint streams until the process dies.
const maxOIDCResponseBytes = 1 << 20

// allowedSigningAlgs is the exact set of ID token signature algorithms this
// server will verify. All are asymmetric: the provider signs with a private
// key we never hold, and we check it against the published JWKS.
//
// The HMAC family (HS256 and friends) is deliberately absent. It signs with
// the client secret, which turns "which algorithm is this token?" into a
// question the token itself answers — the classic confusion attack. `none` is
// refused by go-oidc unconditionally.
var allowedSigningAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512,
}

// boundedTransport caps every response body at maxOIDCResponseBytes.
type boundedTransport struct{ base http.RoundTripper }

func (t *boundedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, maxOIDCResponseBytes), resp.Body}
	return resp, nil
}

// httpClient builds the only client this package talks to a provider with:
// bounded bodies, a hard timeout, and no redirects at all.
//
// Redirects are refused rather than followed-and-checked. Every endpoint here
// is one the discovery document named explicitly; a 302 away from it is either
// a misconfiguration or an attempt to move the client secret somewhere the
// scheme policy below never got to inspect.
func httpClient() *http.Client {
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &boundedTransport{base: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("refusing redirect to %s: OIDC endpoints must answer directly", req.URL.Redacted())
		},
	}
}

// isLoopbackHost reports whether host names this machine. Loopback http is the
// one cleartext case that is genuinely safe: nothing leaves the box.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// requireSafeURL applies this package's transport policy to one URL.
//
// Note what it does NOT do: it does not refuse private or reserved
// destinations the way internal/netguard does for CardDAV and UnifiedPush.
// Those are URLs an ordinary user supplies, so reaching the operator's LAN is
// the whole attack. This one is typed by an administrator into the admin
// panel, and the overwhelmingly common answer for a self-hosted mail server is
// an identity provider on that same LAN or tailnet. Refusing it would break
// the intended deployment while protecting nobody from anybody.
func requireSafeURL(what, raw string, allowInsecure bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", what, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL including a host", what)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not embed credentials", what)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		if allowInsecure {
			return nil
		}
		return fmt.Errorf(
			"%s uses cleartext http on %s, which would send the OAuth client secret and authorization code unencrypted; "+
				"use https, or set allowInsecureIssuer if this provider is on a trusted network and has no TLS",
			what, u.Hostname())
	default:
		return fmt.Errorf("%s must use https (got scheme %q)", what, u.Scheme)
	}
}

// ValidateIssuerURL checks an issuer before it is saved and again before it is
// used, so a bad value is refused at the admin panel rather than at 3am.
func ValidateIssuerURL(raw string, allowInsecure bool) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("issuer URL is required")
	}
	u, err := url.Parse(trimmed)
	if err == nil && (u.RawQuery != "" || u.Fragment != "") {
		return errors.New("issuer URL must not carry a query string or fragment")
	}
	return requireSafeURL("issuer URL", trimmed, allowInsecure)
}

// SSOTokenClaims captures identity claims across OIDC providers (KySignOn, Authentik, Keycloak).
//
// Every field is populated only from an ID token whose signature, issuer,
// audience, expiry and nonce have already been checked.
type SSOTokenClaims struct {
	Issuer            string   `json:"iss"`
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	Username          string   `json:"username"`
	Name              string   `json:"name"`
	Role              string   `json:"role"`
	Admin             bool     `json:"admin"`
	Groups            []string `json:"groups"`
	AKGroups          []string `json:"ak_groups"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// IsAdmin returns true if claims identify an administrator across KySignOn, Authentik, or Keycloak.
func (c *SSOTokenClaims) IsAdmin() bool {
	if c == nil {
		return false
	}
	if strings.EqualFold(c.Role, "admin") || c.Admin {
		return true
	}

	adminNames := map[string]bool{
		"admin":                    true,
		"admins":                   true,
		"administrator":            true,
		"administrators":           true,
		"kypost_admin":             true,
		"kypost-admin":             true,
		"authentik default admins": true,
	}

	for _, g := range c.Groups {
		if adminNames[strings.ToLower(strings.TrimSpace(g))] {
			return true
		}
	}
	for _, g := range c.AKGroups {
		if adminNames[strings.ToLower(strings.TrimSpace(g))] {
			return true
		}
	}
	for _, r := range c.RealmAccess.Roles {
		if adminNames[strings.ToLower(strings.TrimSpace(r))] {
			return true
		}
	}
	return false
}

// GeneratePKCE creates an ephemeral code_verifier and SHA-256 code_challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = hex.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

// RandomToken returns n bytes of hex-encoded cryptographic randomness, used
// for the `state` and `nonce` values that bind a login to one browser.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Provider is a discovered, policy-checked OIDC provider bound to one client.
type Provider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
	client   *http.Client
	issuer   string
}

// Discovery is cached, keyed on the settings that produced it.
//
// oidc.NewProvider issues a network GET to the issuer's
// .well-known/openid-configuration every time it is called, and it was called
// once per request by four PUBLIC routes — so any unauthenticated GET to
// /api/auth/oidc/login cost the operator's identity provider one request and
// this process one socket held for up to the client timeout, with nothing in
// front of it. The cached Provider also carries go-oidc's remote key set, so a
// callback no longer re-fetches the JWKS either.
//
// A settings change IS the invalidation: the key covers every field
// NewProvider reads, so different settings are a different entry and the old
// one is never consulted again. The TTL covers the other direction — a
// provider that rotates its own endpoints while nothing here changed.
const (
	providerCacheTTL     = 5 * time.Minute
	providerCacheEntries = 8
)

type cachedProvider struct {
	provider *Provider
	expires  time.Time
}

var (
	providerCacheMu sync.Mutex
	providerCache   = map[string]cachedProvider{}
)

// providerCacheKey fingerprints everything NewProvider reads. Hashed rather
// than concatenated because the client secret is one of those things, and a map
// key is exactly the sort of value that turns up in a heap dump. Each part is
// length-prefixed so no two settings can join into the same string.
func providerCacheKey(cfg SSOSettings, redirectURI string) string {
	h := sha256.New()
	for _, part := range []string{
		cfg.IssuerURL,
		cfg.ClientID,
		cfg.ClientSecret,
		redirectURI,
		strconv.FormatBool(cfg.AllowInsecureIssuer),
	} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cachedProviderFor(key string) *Provider {
	providerCacheMu.Lock()
	defer providerCacheMu.Unlock()
	entry, ok := providerCache[key]
	if !ok || time.Now().After(entry.expires) {
		return nil
	}
	return entry.provider
}

func cacheProvider(key string, p *Provider) {
	providerCacheMu.Lock()
	defer providerCacheMu.Unlock()
	now := time.Now()
	for k, entry := range providerCache {
		if now.After(entry.expires) {
			delete(providerCache, k)
		}
	}
	// The keys are admin-configured, so this is tidiness rather than a bound on
	// an attacker. Past the ceiling, start over: an install has one issuer, and
	// a handful of stale entries are not worth an eviction policy.
	if len(providerCache) >= providerCacheEntries {
		clear(providerCache)
	}
	providerCache[key] = cachedProvider{provider: p, expires: now.Add(providerCacheTTL)}
}

// NewProvider returns the discovered, policy-checked provider for these
// settings, performing discovery only when the cache above cannot answer.
//
// Failures are deliberately not cached: a provider that was down a second ago
// may be up now, and pinning an outage for the TTL would make a restarted IdP
// look broken for minutes. What bounds the cost of a failing issuer is the
// per-IP rate limit on the public routes, not this.
func NewProvider(ctx context.Context, cfg SSOSettings, redirectURI string) (*Provider, error) {
	key := providerCacheKey(cfg, redirectURI)
	if p := cachedProviderFor(key); p != nil {
		return p, nil
	}
	p, err := discoverProvider(ctx, cfg, redirectURI)
	if err != nil {
		return nil, err
	}
	cacheProvider(key, p)
	return p, nil
}

// discoverProvider performs OIDC discovery and builds a verifier for it.
//
// oidc.NewProvider refuses a discovery document whose own `issuer` is not the
// URL we asked, which is the check that makes trusting the endpoints it names
// meaningful. Every endpoint is then held to the same transport policy as the
// issuer, so a discovery document cannot downgrade the token endpoint to
// cleartext and collect the client secret.
func discoverProvider(ctx context.Context, cfg SSOSettings, redirectURI string) (*Provider, error) {
	if err := ValidateIssuerURL(cfg.IssuerURL, cfg.AllowInsecureIssuer); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("client ID is required")
	}

	issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	client := httpClient()
	ctx = oidc.ClientContext(ctx, client)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for %s: %w", issuer, err)
	}

	var extra struct {
		JWKSURI          string `json:"jwks_uri"`
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := provider.Claims(&extra); err != nil {
		return nil, fmt.Errorf("unreadable OIDC discovery document: %w", err)
	}
	for _, ep := range []struct{ what, raw string }{
		{"authorization endpoint", provider.Endpoint().AuthURL},
		{"token endpoint", provider.Endpoint().TokenURL},
		{"JWKS URI", extra.JWKSURI},
		{"userinfo endpoint", extra.UserinfoEndpoint},
	} {
		if strings.TrimSpace(ep.raw) == "" {
			continue
		}
		if err := requireSafeURL(ep.what, ep.raw, cfg.AllowInsecureIssuer); err != nil {
			return nil, fmt.Errorf("provider advertised an unusable %s: %w", ep.what, err)
		}
	}

	return &Provider{
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURI,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: provider.VerifierContext(ctx, &oidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: allowedSigningAlgs,
		}),
		provider: provider,
		client:   client,
		issuer:   issuer,
	}, nil
}

// AuthCodeURL builds the authorization request, binding it to this browser
// with state, to this token with nonce, and to this exchange with PKCE.
func (p *Provider) AuthCodeURL(state, nonce, challenge string) string {
	return p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange redeems the authorization code and returns claims only from an ID
// token that verified against the provider's JWKS.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*SSOTokenClaims, error) {
	ctx = oidc.ClientContext(ctx, p.client)

	tok, err := p.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, errors.New("token response contained no id_token")
	}

	// Signature against the provider's JWKS, `iss` equal to the discovered
	// issuer, `aud` containing our client ID, and `exp`/`iat` within skew.
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	// Bind the token to the login that started in this browser. Without it a
	// valid token captured from any other session of the same client replays.
	if idToken.Nonce != nonce {
		return nil, errors.New("id_token nonce does not match this login")
	}

	// go-oidc checks exp and iat but not nbf; a provider that issues one is
	// telling us the token is not valid yet.
	var timing struct {
		NotBefore int64 `json:"nbf"`
	}
	if err := idToken.Claims(&timing); err == nil && timing.NotBefore > 0 {
		if time.Now().Add(30 * time.Second).Before(time.Unix(timing.NotBefore, 0)) {
			return nil, errors.New("id_token is not valid yet (nbf is in the future)")
		}
	}

	// When the provider published at_hash, hold the access token to it, so a
	// verified ID token cannot be paired with somebody else's access token.
	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(tok.AccessToken); err != nil {
			return nil, fmt.Errorf("access token does not match id_token at_hash: %w", err)
		}
	}

	if strings.TrimSpace(idToken.Subject) == "" {
		return nil, errors.New("id_token carries no sub claim")
	}

	claims := &SSOTokenClaims{}
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("unreadable id_token claims: %w", err)
	}
	// Take identity from the verified token object, never from the decoded
	// JSON, so a duplicate key in the payload cannot disagree with it.
	claims.Sub = idToken.Subject
	claims.Issuer = idToken.Issuer

	p.fillFromUserInfo(ctx, tok, claims)
	normalizeUsername(claims)
	return claims, nil
}

// fillFromUserInfo tops up a thin ID token from the userinfo endpoint.
//
// Best effort: a provider that does not offer userinfo, or refuses it, still
// produces a usable login from the ID token alone. What is not optional is
// that userinfo's `sub` equals the ID token's — OIDC Core 5.3.2 — otherwise a
// second identity's profile gets stapled onto the first one's subject.
func (p *Provider) fillFromUserInfo(ctx context.Context, tok *oauth2.Token, claims *SSOTokenClaims) {
	if claims.PreferredUsername != "" && claims.Email != "" {
		return
	}
	if tok.AccessToken == "" {
		return
	}
	info, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil || info.Subject != claims.Sub {
		return
	}
	var extra SSOTokenClaims
	if err := info.Claims(&extra); err != nil {
		return
	}
	fillEmptyClaims(claims, &extra)
}

// fillEmptyClaims copies only the fields the ID token left blank.
//
// Filling rather than replacing: the reason to call userinfo is a thin ID
// token, and overwriting the whole struct with the response would discard
// whatever the signed token did say — an ID token carrying an email but no
// preferred_username would come back with neither if userinfo omits the email.
// Sub and Issuer are never touched; they come from the verified token.
func fillEmptyClaims(dst, src *SSOTokenClaims) {
	if dst.Email == "" {
		dst.Email, dst.EmailVerified = src.Email, src.EmailVerified
	}
	if dst.PreferredUsername == "" {
		dst.PreferredUsername = src.PreferredUsername
	}
	if dst.Username == "" {
		dst.Username = src.Username
	}
	if dst.Name == "" {
		dst.Name = src.Name
	}
	if dst.Role == "" {
		dst.Role = src.Role
	}
	if !dst.Admin {
		dst.Admin = src.Admin
	}
	if len(dst.Groups) == 0 {
		dst.Groups = src.Groups
	}
	if len(dst.AKGroups) == 0 {
		dst.AKGroups = src.AKGroups
	}
	if len(dst.RealmAccess.Roles) == 0 {
		dst.RealmAccess.Roles = src.RealmAccess.Roles
	}
}

// normalizeUsername picks the best display name the provider gave us.
func normalizeUsername(claims *SSOTokenClaims) {
	if claims.PreferredUsername == "" && claims.Username != "" {
		claims.PreferredUsername = claims.Username
	}
	if claims.PreferredUsername == "" && claims.Name != "" {
		claims.PreferredUsername = claims.Name
	}
	if claims.PreferredUsername == "" && claims.Email != "" {
		claims.PreferredUsername = strings.Split(claims.Email, "@")[0]
	}
}
