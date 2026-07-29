// Package captcha lets an operator require a CAPTCHA solution on login,
// verified server-side against a third-party provider. It's an operator
// opt-in on top of the account-lockout in the api package (server.go's
// loginLockout) — not required for the app to function.
package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider identifies which CAPTCHA service to verify tokens against.
type Provider string

const (
	ProviderNone      Provider = ""
	ProviderTurnstile Provider = "turnstile"
	ProviderFriendly  Provider = "friendly"
	// ProviderPoW is self-hosted: it verifies a proof-of-work this server
	// issued rather than a token from someone else's service. See pow.go.
	ProviderPoW Provider = "pow"
)

// Verifier checks a client-submitted CAPTCHA token server-side. remoteIP is
// optional context passed through to the provider when known.
type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) (bool, error)
}

// Config is the operator-supplied CAPTCHA configuration. Which fields matter
// depends on Provider: the two third-party providers use SiteKey/SecretKey,
// and the self-hosted pow provider uses HMACKey/MaxNumber instead — it has no
// upstream to hold a secret with, and no public site key to publish.
type Config struct {
	Provider  Provider
	SiteKey   string
	SecretKey string

	// HMACKey signs pow challenges. Not operator-supplied: api's
	// resolvePoWSecret generates and persists it, following the same
	// "generate it rather than ask an operator to invent one" reasoning as
	// resolvePairingSecret.
	HMACKey []byte
	// MaxNumber is the pow search space; <= 0 means defaultPoWMaxNumber.
	MaxNumber int
}

// NewVerifier builds a Verifier for cfg.Provider. A nil Verifier (with no
// error) means CAPTCHA is disabled — callers must treat that as "no check
// required", not as a failure to construct one.
func NewVerifier(cfg Config) (Verifier, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	switch cfg.Provider {
	case ProviderNone:
		return nil, nil
	case ProviderTurnstile:
		if strings.TrimSpace(cfg.SecretKey) == "" {
			return nil, errors.New("captcha: secret key is required for turnstile")
		}
		return &turnstileVerifier{secretKey: cfg.SecretKey, verifyURL: turnstileVerifyURL, client: client}, nil
	case ProviderFriendly:
		if strings.TrimSpace(cfg.SecretKey) == "" {
			return nil, errors.New("captcha: secret key is required for friendly")
		}
		return &friendlyVerifier{secretKey: cfg.SecretKey, verifyURL: friendlyVerifyURL, client: client}, nil
	case ProviderPoW:
		return NewPoWVerifier(cfg.HMACKey, cfg.MaxNumber)
	default:
		return nil, fmt.Errorf("captcha: unknown provider %q (want %q, %q or %q)",
			cfg.Provider, ProviderTurnstile, ProviderFriendly, ProviderPoW)
	}
}

// verifyResponse is the response shape both Turnstile and Friendly Captcha's
// siteverify endpoints share (the fields this package needs, at least).
type verifyResponse struct {
	Success bool `json:"success"`
}

func postSiteverify(ctx context.Context, client *http.Client, req *http.Request) (bool, error) {
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("captcha: siteverify returned status %d", resp.StatusCode)
	}
	var out verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("captcha: decode siteverify response: %w", err)
	}
	return out.Success, nil
}

// ---- Cloudflare Turnstile ----------------------------------------------

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileVerifier struct {
	secretKey string
	verifyURL string
	client    *http.Client
}

func (v *turnstileVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if strings.TrimSpace(token) == "" {
		return false, nil
	}
	form := url.Values{"secret": {v.secretKey}, "response": {token}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return postSiteverify(ctx, v.client, req)
}

// ---- Friendly Captcha ---------------------------------------------------

const friendlyVerifyURL = "https://api.friendlycaptcha.com/api/v1/siteverify"

type friendlyVerifier struct {
	secretKey string
	verifyURL string
	client    *http.Client
}

func (v *friendlyVerifier) Verify(ctx context.Context, token, remoteIP string) (bool, error) {
	if strings.TrimSpace(token) == "" {
		return false, nil
	}
	body, err := json.Marshal(map[string]string{"solution": token, "secret": v.secretKey})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(string(body)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	return postSiteverify(ctx, v.client, req)
}
