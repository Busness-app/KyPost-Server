// What the server is willing to believe about an inbound request: whether
// X-Forwarded-* may be trusted at all (trustProxyHeaders), and the three
// answers that depend on it — the caller's IP for lockout keying and logging,
// the externally-reachable base URL, and whether the connection was really TLS
// (which decides the session cookie's Secure flag).
//
// Small, but collected here on purpose: every one of these is a trust decision,
// and clientIP in particular is a lockout key. Scattering them through a
// 4,500-line file is how the left-most vs right-most X-Forwarded-For hop
// question gets answered twice, differently.
package api

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// trustProxyHeaders reports whether X-Forwarded-Proto/Host/For may be
// believed. Defaults to false (fail closed) — the shipped docker-compose.yml
// exposes the container directly with no reverse proxy in front, so trusting
// these headers by default would let any client forge its own IP and defeat
// the login/CardDAV lockouts. Deployments that do put a TLS-terminating
// reverse proxy in front must explicitly set TRUST_PROXY_HEADERS=true.
func trustProxyHeaders() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")), "true")
}

func externalBaseURL(r *http.Request) string {
	var proto, host string
	if trustProxyHeaders() {
		proto = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		host = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	}
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host
}

// clientIP best-effort resolves the caller's IP for logging, CAPTCHA
// context, and lockout keying: X-Forwarded-For's first hop when proxy
// headers are trusted (see trustProxyHeaders — this app then also trusts
// X-Forwarded-* for scheme/host in externalBaseURL/isRequestSecure), falling
// back to the raw connection address with its port stripped. When used as a
// lockout key, a client forging X-Forwarded-For on a directly-exposed
// deployment could dodge or misdirect lockouts — set TRUST_PROXY_HEADERS=false
// there.
func clientIP(r *http.Request) string {
	if trustProxyHeaders() {
		// Use the RIGHT-most hop — the address the nearest trusted proxy
		// appended — not the left-most one. A client can prepend arbitrary
		// values to X-Forwarded-For (an appending proxy like nginx's
		// $proxy_add_x_forwarded_for turns a client-sent "a" into "a, <realip>"),
		// so keying the login lockout on the left-most hop let a client rotate
		// it and evade the lockout. This assumes a single trusted proxy in
		// front; multi-proxy deployments should set TRUST_PROXY_HEADERS=false
		// and rely on RemoteAddr, or terminate the chain at a known hop.
		if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
			parts := strings.Split(xff, ",")
			if fwd := strings.TrimSpace(parts[len(parts)-1]); fwd != "" {
				return fwd
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// isRequestSecure reports whether r was received over HTTPS, either
// directly or (per X-Forwarded-Proto) via a TLS-terminating reverse proxy.
// Used to decide whether the session cookie can carry the Secure attribute
// without breaking plain-HTTP local/dev deployments.
func isRequestSecure(r *http.Request) bool {
	if trustProxyHeaders() {
		if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
			return strings.EqualFold(proto, "https")
		}
	}
	return r.TLS != nil
}
