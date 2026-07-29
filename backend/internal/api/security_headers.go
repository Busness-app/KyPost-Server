package api

import (
	"net/http"
	"strings"

	"kypost-server/backend/internal/captcha"
)

// buildContentSecurityPolicy returns the app-wide CSP for the CAPTCHA provider
// this instance is actually running.
//
// The CSP is the second line of defense for the single riskiest thing this app
// does — rendering sender-controlled HTML email — so a future DOMPurify bypass
// lands on a page that still cannot run injected script. Every allowance is
// tied to a concrete feature:
//
//   - challenges.cloudflare.com (script + frame): the Turnstile login CAPTCHA
//   - cdn.jsdelivr.net (script + connect), 'wasm-unsafe-eval' and blob:
//     workers: the Friendly Captcha widget and its WASM proof-of-work
//   - the self-hosted 'pow' provider deliberately appears nowhere below: it
//     is a same-origin fetch plus crypto.subtle, so it needs no third-party
//     origin, no WASM, and no blob: worker. Pinned by
//     TestCSPAddsNothingForSelfHostedPoW.
//   - fonts.googleapis.com / fonts.gstatic.com: the fonts index.html loads
//   - style-src 'unsafe-inline': inline style attributes in the Quill compose
//     editor (sanitized email HTML no longer carries any — see emailHtml.ts)
//   - img-src/media-src https: http: data:: remote email content, shown only
//     after the user opts in per message
//
// Those CAPTCHA sources used to be listed unconditionally, for widgets that are
// OFF by default. jsDelivr in particular serves arbitrary npm and GitHub
// content, so naming it as a script source on every install handed script
// execution on this origin to anything that could get a package published
// there — which is precisely the protection the header exists to provide. They
// are emitted only for the provider actually configured now, so a default
// install (no CAPTCHA) carries neither.
//
// Notably absent in every case: 'unsafe-inline'/'unsafe-eval' for scripts, and
// any wildcard script or connect source.
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
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"img-src 'self' data: https: http:",
		"media-src 'self' data: https: http:",
		"font-src 'self' data: https://fonts.gstatic.com",
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

// withSecurityHeaders stamps defense-in-depth headers on every response the
// server produces — API JSON, frontend assets, attachment downloads, the
// CardDAV surface, and the unauthenticated pickup page alike. HSTS is only
// meaningful (and only safe to assert) once the request demonstrably arrived
// over TLS, so it keys off isRequestSecure rather than being unconditional.
func withSecurityHeaders(next http.Handler, policy string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if isRequestSecure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
