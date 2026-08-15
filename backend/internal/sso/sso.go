package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// SSOSettings holds the OpenID Connect SSO configuration.
type SSOSettings struct {
	Enabled       bool   `json:"enabled"`
	IssuerURL     string `json:"issuerUrl"`
	ClientID      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret,omitempty"`
	AutoProvision bool   `json:"autoProvision"`
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

// OIDCDiscovery represents the discovered endpoints from .well-known/openid-configuration.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// DiscoverEndpoints queries the OIDC provider's discovery document with fallback to standard endpoints.
func DiscoverEndpoints(ctx context.Context, issuerURL string) (*OIDCDiscovery, error) {
	cleanIssuer := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if cleanIssuer == "" {
		return nil, fmt.Errorf("empty issuer URL")
	}

	discoveryURL := cleanIssuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		var disc OIDCDiscovery
		if err := json.NewDecoder(resp.Body).Decode(&disc); err == nil && disc.AuthorizationEndpoint != "" && disc.TokenEndpoint != "" {
			return &disc, nil
		}
	}

	// Fallback to standard OIDC endpoints
	return &OIDCDiscovery{
		Issuer:                cleanIssuer,
		AuthorizationEndpoint: cleanIssuer + "/oauth/authorize",
		TokenEndpoint:         cleanIssuer + "/oauth/token",
		UserinfoEndpoint:      cleanIssuer + "/oauth/userinfo",
		JWKSURI:               cleanIssuer + "/.well-known/jwks.json",
	}, nil
}

// SSOTokenClaims captures identity claims across OIDC providers (KySignOn, Authentik, Keycloak).
type SSOTokenClaims struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
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

// TokenResponse models the OAuth 2.0 token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
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

// ExchangeCode performs PKCE token exchange with the OIDC token endpoint.
func ExchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	if clientSecret != "" {
		data.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	return &tok, nil
}

// ParseClaims decodes claims from id_token and optionally userinfo endpoint.
func ParseClaims(ctx context.Context, idToken, accessToken, userinfoEndpoint string) (*SSOTokenClaims, error) {
	claims := &SSOTokenClaims{}

	// Decode ID Token payload if present
	if idToken != "" {
		parts := strings.Split(idToken, ".")
		if len(parts) >= 2 {
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				_ = json.Unmarshal(payloadBytes, claims)
			}
		}
	}

	// If claims missing details and userinfoEndpoint is available, fetch userinfo
	if (claims.Sub == "" || (claims.PreferredUsername == "" && claims.Username == "")) && userinfoEndpoint != "" && accessToken != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Accept", "application/json")
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				_ = json.NewDecoder(resp.Body).Decode(claims)
			}
		}
	}

	if claims.PreferredUsername == "" && claims.Username != "" {
		claims.PreferredUsername = claims.Username
	}
	if claims.PreferredUsername == "" && claims.Name != "" {
		claims.PreferredUsername = claims.Name
	}
	if claims.PreferredUsername == "" && claims.Email != "" {
		claims.PreferredUsername = strings.Split(claims.Email, "@")[0]
	}

	if claims.Sub == "" {
		return nil, fmt.Errorf("no sub claim found in ID token or userinfo")
	}

	return claims, nil
}
