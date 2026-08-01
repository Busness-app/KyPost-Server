package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersOnAllResponses(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	for _, directive := range []string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing directive %q; got %q", directive, csp)
		}
	}
	// The email read view needs remote images once the user opts in.
	if allowance := "img-src 'self' data: https: http:"; !strings.Contains(csp, allowance) {
		t.Errorf("CSP missing required allowance %q; got %q", allowance, csp)
	}
	// run-4 hardening note 1 changed this deliberately. Both CAPTCHA origins
	// used to be asserted here unconditionally, which is what the header
	// actually did — and jsDelivr serves arbitrary npm and GitHub content, so
	// naming it as a script source on an install with no CAPTCHA configured
	// handed script execution on this origin to anything publishable there.
	// This test server configures no provider, so neither may appear.
	// buildContentSecurityPolicy's own tests cover the enabled cases.
	//
	// The two Google Fonts hosts joined them once the fonts moved into the
	// bundle: a default install must now reach no third-party origin at all.
	// TestCSPNamesNoThirdPartyFontOrigin is the stricter form of that.
	for _, forbidden := range []string{
		"https://challenges.cloudflare.com",
		"https://cdn.jsdelivr.net",
		"https://fonts.googleapis.com",
		"https://fonts.gstatic.com",
	} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("CSP names third-party origin %q; got %q", forbidden, csp)
		}
	}

	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("plain-HTTP response must not carry HSTS, got %q", got)
	}
}

func TestHSTSOnSecureRequestsOnly(t *testing.T) {
	// httptest.NewRequest's default peer is 192.0.2.1, so trust that as the
	// TLS-terminating proxy: X-Forwarded-Proto is only believed from a
	// configured trusted peer now, not on any connection.
	trustProxyCIDRsForTest(t, "192.0.2.0/24")
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	srv.routes().ServeHTTP(rec, req)

	if got := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=") {
		t.Fatalf("Strict-Transport-Security = %q, want a max-age directive on a TLS-terminated request", got)
	}
}
