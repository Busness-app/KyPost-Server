package api

import (
	"strings"
	"testing"

	"kypost-server/backend/internal/captcha"
)

// run-4 hardening note 1: the CSP listed cdn.jsdelivr.net in script-src and
// connect-src unconditionally, for a Friendly Captcha widget that is OFF by
// default.
//
// jsDelivr serves arbitrary npm and GitHub content, so naming it as a script
// source hands script execution on this origin to anything that can get a
// package published there — which defeats the header's own stated purpose:
// "a future DOMPurify bypass lands on a page that still can't run injected
// script". Turnstile's sources had the same problem in the other direction.
//
// Every allowance is now tied to the provider actually configured, so the
// default install (no CAPTCHA) carries neither.

func TestCSPOmitsCaptchaSourcesWhenNoProviderIsConfigured(t *testing.T) {
	policy := buildContentSecurityPolicy("")

	for _, forbidden := range []string{"cdn.jsdelivr.net", "challenges.cloudflare.com", "wasm-unsafe-eval", "blob:"} {
		if strings.Contains(policy, forbidden) {
			t.Fatalf("default policy names %q for a CAPTCHA that is not configured:\n%s", forbidden, policy)
		}
	}
	// The rest of the policy must survive.
	if !strings.Contains(policy, "default-src 'self'") || !strings.Contains(policy, "object-src 'none'") {
		t.Fatalf("policy lost its baseline directives:\n%s", policy)
	}
	if !strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("policy lost frame-ancestors:\n%s", policy)
	}
}

func TestCSPAllowsOnlyFriendlySourcesForFriendly(t *testing.T) {
	policy := buildContentSecurityPolicy(captcha.ProviderFriendly)

	if !strings.Contains(policy, "https://cdn.jsdelivr.net") {
		t.Fatalf("friendly needs jsDelivr:\n%s", policy)
	}
	if !strings.Contains(policy, "'wasm-unsafe-eval'") || !strings.Contains(policy, "worker-src 'self' blob:") {
		t.Fatalf("friendly needs wasm and a blob worker:\n%s", policy)
	}
	if strings.Contains(policy, "challenges.cloudflare.com") {
		t.Fatalf("friendly must not pull in Turnstile's sources:\n%s", policy)
	}
}

func TestCSPAllowsOnlyTurnstileSourcesForTurnstile(t *testing.T) {
	policy := buildContentSecurityPolicy(captcha.ProviderTurnstile)

	if !strings.Contains(policy, "script-src") || !strings.Contains(policy, "https://challenges.cloudflare.com") {
		t.Fatalf("turnstile needs its script and frame sources:\n%s", policy)
	}
	if !strings.Contains(policy, "frame-src https://challenges.cloudflare.com") {
		t.Fatalf("turnstile needs frame-src:\n%s", policy)
	}
	if strings.Contains(policy, "cdn.jsdelivr.net") {
		t.Fatalf("turnstile must not pull in jsDelivr:\n%s", policy)
	}
	if strings.Contains(policy, "'wasm-unsafe-eval'") {
		t.Fatalf("turnstile does not need wasm-unsafe-eval:\n%s", policy)
	}
}

// Whatever the provider, the things that make this header worth having must be
// present and must never gain a wildcard or an inline-script escape.
func TestCSPNeverAllowsInlineOrWildcardScript(t *testing.T) {
	for _, provider := range []captcha.Provider{"", captcha.ProviderFriendly, captcha.ProviderTurnstile} {
		policy := buildContentSecurityPolicy(provider)
		if strings.Contains(policy, "'unsafe-inline'") {
			// style-src legitimately carries 'unsafe-inline'; script-src must not.
			for _, directive := range strings.Split(policy, "; ") {
				if strings.HasPrefix(directive, "script-src") && strings.Contains(directive, "'unsafe-inline'") {
					t.Fatalf("provider %q: script-src allows inline script:\n%s", provider, policy)
				}
			}
		}
		if strings.Contains(policy, "'unsafe-eval'") && !strings.Contains(policy, "'wasm-unsafe-eval'") {
			t.Fatalf("provider %q: policy allows unsafe-eval:\n%s", provider, policy)
		}
		for _, directive := range strings.Split(policy, "; ") {
			if strings.HasPrefix(directive, "script-src") && strings.Contains(directive, " *") {
				t.Fatalf("provider %q: wildcard script source:\n%s", provider, policy)
			}
		}
	}
}

// The self-hosted proof-of-work provider needs no third-party origin, no
// WASM, and no blob: worker — it is same-origin fetch plus crypto.subtle.
// That is the main reason to choose it over Turnstile or Friendly Captcha, so
// it is worth a test rather than a comment.
func TestCSPAddsNothingForSelfHostedPoW(t *testing.T) {
	policy := buildContentSecurityPolicy(captcha.ProviderPoW)

	if policy != buildContentSecurityPolicy(captcha.ProviderNone) {
		t.Fatalf("pow must not widen the default policy:\n got: %s\nwant: %s",
			policy, buildContentSecurityPolicy(captcha.ProviderNone))
	}
	for _, forbidden := range []string{
		"cdn.jsdelivr.net", "challenges.cloudflare.com", "wasm-unsafe-eval", "blob:",
	} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("pow policy names %q, which it has no use for:\n%s", forbidden, policy)
		}
	}
	// The worker-src the Friendly widget needs must stay 'self'-only here.
	if !strings.Contains(policy, "worker-src 'self';") {
		t.Errorf("pow policy should keep worker-src at 'self':\n%s", policy)
	}
}
