package api

import (
	"net/http"
	"strings"

	"kypost-server/backend/internal/captcha"
)

// buildContentSecurityPolicy returns the app-wide CSP for the CAPTCHA provider
// this instance is actually running.
//
// This is the second line of defense for the riskiest thing the app does —
// rendering sender-controlled HTML email — so a DOMPurify bypass still lands
// on a page that cannot run injected script. Every allowance is tied to a
// concrete feature, and third-party origins are emitted ONLY for the provider
// actually configured: jsDelivr serves arbitrary npm and GitHub content, so
// naming it unconditionally would hand script execution on this origin to
// anything publishable there, on installs that never enabled the widget.
//
//   - challenges.cloudflare.com (script + frame): Turnstile
//   - cdn.jsdelivr.net (script + connect), 'wasm-unsafe-eval', blob: workers:
//     the Friendly Captcha widget and its WASM proof-of-work
//   - the self-hosted 'pow' provider needs nothing: same-origin fetch plus
//     crypto.subtle. Pinned by TestCSPAddsNothingForSelfHostedPoW.
//   - no font or stylesheet origin at all: Space Grotesk and IBM Plex Mono are
//     served from this origin out of the Vite bundle. fonts.googleapis.com and
//     fonts.gstatic.com used to be named here, which meant every session
//     disclosed its IP and User-Agent to Google before login. Do not put them
//     back — TestCSPNamesNoThirdPartyFontOrigin fails if you do.
//   - style-src 'unsafe-inline': the Quill compose editor's inline style
//     attributes. Sanitized email HTML carries none — see emailHtml.ts.
//   - img-src/media-src https: http: data:: remote email content, shown only
//     after the user opts in per message
//
// Never add 'unsafe-inline'/'unsafe-eval' to script-src, or a wildcard script
// or connect source.
func buildContentSecurityPolicy(provider captcha.Provider) string {
	scriptSrc := []string{"'self'"}
	connectSrc := []string{"'self'"}
	workerSrc := []string{"'self'"}
	var frameSrc []string

	switch provider {
	case captcha.ProviderTurnstile:
		scriptSrc = append(scriptSrc, "https://challenges.cloudflare.com")
		frameSrc = append(frameSrc, "https://challenges.cloudflare.com")
	case captcha.ProviderFriendly:
		// 'wasm-unsafe-eval' and the blob: worker are the widget's WASM
		// proof-of-work; they are not needed by anything else here.
		scriptSrc = append(scriptSrc, "'wasm-unsafe-eval'", "https://cdn.jsdelivr.net")
		connectSrc = append(connectSrc, "https://cdn.jsdelivr.net")
		workerSrc = append(workerSrc, "blob:")
	}

	directives := []string{
		"default-src 'self'",
		"script-src " + strings.Join(scriptSrc, " "),
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data: https: http:",
		"media-src 'self' data: https: http:",
		"font-src 'self' data:",
		"connect-src " + strings.Join(connectSrc, " "),
	}
	if len(frameSrc) > 0 {
		directives = append(directives, "frame-src "+strings.Join(frameSrc, " "))
	}
	directives = append(directives,
		"worker-src "+strings.Join(workerSrc, " "),
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self'",
	)
	return strings.Join(directives, "; ")
}

// permissionsPolicy denies the powerful features this app never uses.
//
// An empty allowlist is a denial, and it applies to embedded content too — so a
// sender's HTML that survives DOMPurify still cannot reach for the camera,
// microphone or location from inside EmailBodyFrame. Nothing here is a
// capability the app wants: it composes and reads mail.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), display-capture=(), " +
	"encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), " +
	"midi=(), payment=(), usb=(), xr-spatial-tracking=()"

// withSecurityHeaders stamps defense-in-depth headers on every response the
// server produces — API JSON, frontend assets, attachment downloads, the
// CardDAV surface, and the unauthenticated pickup page alike. HSTS is only
// meaningful (and only safe to assert) once the request demonstrably arrived
// over TLS, so it keys off isRequestSecure rather than being unconditional.
//
// Cross-Origin-Opener-Policy matters more here than in a typical app: for a
// client-protected account this origin holds an UNLOCKED OpenPGP private key in
// module memory (lib/keyVault.ts). same-origin severs window.opener for anything
// this page opens or is opened by, which is the link EmailBodyFrame's
// allow-popups-to-escape-sandbox plus <base target="_blank"> otherwise creates
// for every link in every message.
//
// Cross-Origin-Embedder-Policy is deliberately NOT set. require-corp would give
// full cross-origin isolation, and it would also break every third-party
// subresource the CSP allows on purpose — the Turnstile frame and the Friendly
// Captcha WASM bundle from jsDelivr. (Google Fonts was on that list until the
// fonts moved into the bundle, so an install running the self-hosted 'pow'
// provider now loads nothing cross-origin at all.) Buying isolation by breaking
// the CAPTCHA that guards the login form is the wrong trade; revisit if those
// origins ever serve CORP headers.
func withSecurityHeaders(next http.Handler, policy string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", permissionsPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if isRequestSecure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
