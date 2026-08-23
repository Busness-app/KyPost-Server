package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// trustProxyCIDRsForTest points trustedProxyNets at the given CIDRs for the
// duration of a test.
//
// The list is parsed once at package init from TRUSTED_PROXY_CIDRS, so
// t.Setenv cannot reach it — and it deliberately stays that way, because
// re-parsing CIDRs on every request to make a test convenient would put work on
// the hot path of every lockout key lookup. Same seam as outboundIPGuard.
func trustProxyCIDRsForTest(t *testing.T, cidrs string) {
	t.Helper()
	old := trustedProxyNets
	trustedProxyNets = parseTrustedProxyCIDRs(cidrs)
	t.Cleanup(func() { trustedProxyNets = old })
}

func forwardedRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://backend.internal/api/health", nil)
	req.RemoteAddr = "203.0.113.50:40000"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	return req
}

// Default behavior (no trusted proxies configured): the listener may be reached
// directly, so X-Forwarded-* must NOT be trusted — otherwise any client can
// forge its own IP and defeat the login/CardDAV lockouts. This pins the
// fail-closed default.
func TestProxyHeadersIgnoredByDefault(t *testing.T) {
	trustProxyCIDRsForTest(t, "")
	req := forwardedRequest(t)
	if isRequestSecure(req) {
		t.Fatal("default: a forged X-Forwarded-Proto must not mark a plain-HTTP request secure")
	}
	if got := clientIP(req); got != "203.0.113.50" {
		t.Fatalf("default: clientIP = %q, want the connection's own address", got)
	}
}

// A request arriving FROM a configured trusted proxy has its forwarded headers
// honored.
func TestProxyHeadersTrustedFromConfiguredProxy(t *testing.T) {
	// 203.0.113.50 is the peer in forwardedRequest.
	trustProxyCIDRsForTest(t, "203.0.113.0/24")
	req := forwardedRequest(t)
	if !isRequestSecure(req) {
		t.Fatal("trusted peer: X-Forwarded-Proto=https should mark the request secure")
	}
	if got := clientIP(req); got != "10.0.0.99" {
		t.Fatalf("trusted peer: clientIP = %q, want the forwarded address", got)
	}
}

// THE REGRESSION TEST FOR THE REAL BUG: forwarded headers must be ignored when
// the request did not come from a trusted proxy, even though trust is
// configured.
//
// The old TRUST_PROXY_HEADERS=true was a global boolean, so it trusted headers
// on every connection from any peer. The shipped compose file published 5866 on
// 0.0.0.0 and the README told operators to set the flag, so an attacker
// connecting straight to 5866 — bypassing the proxy entirely — got to name its
// own IP and thereby defeat every IP-keyed lockout and rate limit at once.
func TestProxyHeadersIgnoredFromUntrustedPeer(t *testing.T) {
	// A proxy is configured, but it is not the peer making this request.
	trustProxyCIDRsForTest(t, "10.10.0.0/16")
	req := forwardedRequest(t) // peer 203.0.113.50, outside the trusted range

	if isRequestSecure(req) {
		t.Error("untrusted peer: a forged X-Forwarded-Proto must not mark the request secure")
	}
	if got := clientIP(req); got != "203.0.113.50" {
		t.Errorf("untrusted peer: clientIP = %q, want the peer address — a caller who can choose "+
			"this value has defeated every lockout keyed on it", got)
	}
}

// Every X-Forwarded-* header must be read at the RIGHT-most hop, not just
// X-Forwarded-For.
//
// clientIP already read the right-most element because the left-most is
// client-prepended; isRequestSecure, in the same file, read the left-most. That
// asymmetry meant the Secure flag on the session cookie and the HSTS header
// were decided by a value the client supplies.
func TestForwardedHeadersAllUseRightmostHop(t *testing.T) {
	trustProxyCIDRsForTest(t, "203.0.113.0/24")
	req := httptest.NewRequest(http.MethodGet, "http://backend.internal/api/x", nil)
	req.RemoteAddr = "203.0.113.9:5000"

	// In each case the left-most value is what a client prepended and the
	// right-most is what the trusted proxy actually appended.
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.77")
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Host", "attacker.example, real.example")

	if got := clientIP(req); got != "203.0.113.77" {
		t.Errorf("clientIP = %q, want the right-most hop 203.0.113.77 (not the client-prepended 1.1.1.1)", got)
	}
	if isRequestSecure(req) {
		t.Error("isRequestSecure honored the client-prepended https over the proxy's own http; " +
			"this decides the session cookie's Secure flag")
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		peer  string
		trust bool
	}{
		{"cidr match", "10.0.0.0/8", "10.1.2.3", true},
		{"cidr miss", "10.0.0.0/8", "192.168.1.1", false},
		// A bare IP is what a compose sidecar proxy looks like.
		{"bare ip match", "172.18.0.1", "172.18.0.1", true},
		{"bare ip miss", "172.18.0.1", "172.18.0.2", false},
		{"ipv6 cidr", "::1/128", "::1", true},
		{"multiple entries", "10.0.0.0/8, 172.18.0.1", "172.18.0.1", true},
		{"whitespace tolerated", "  10.0.0.0/8  ", "10.9.9.9", true},
		// A typo must narrow trust, never widen it, and must not be fatal.
		{"malformed entry skipped", "not-an-ip, 10.0.0.0/8", "10.0.0.1", true},
		{"malformed entry alone trusts nothing", "not-an-ip", "10.0.0.1", false},
		{"empty trusts nothing", "", "10.0.0.1", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trustProxyCIDRsForTest(t, c.raw)
			req := httptest.NewRequest(http.MethodGet, "http://x/api/y", nil)
			req.RemoteAddr = net.JoinHostPort(c.peer, "1234")
			req.Header.Set("X-Forwarded-For", "9.9.9.9")

			got := clientIP(req) == "9.9.9.9"
			if got != c.trust {
				t.Errorf("TRUSTED_PROXY_CIDRS=%q peer=%s: headers trusted = %v, want %v",
					c.raw, c.peer, got, c.trust)
			}
		})
	}
}

// TestCFConnectingIPPreferredOverForwardedFor is the cloudflared case.
//
// Cloudflare's edge APPENDS the visitor IP to X-Forwarded-For, so for a plain
// Cloudflare proxy the right-most element is correct. But when a tunnel daemon
// (or a second proxy) sits between the edge and this server and appends its own
// address after it, the right-most element becomes a loopback address — and every
// visitor then resolves to the same key. That is not a small degradation: the
// per-IP login lockout becomes one shared bucket, so 50 failures from anyone
// locks out sign-in for everyone.
//
// CF-Connecting-IP carries exactly one value with no chain, and Cloudflare's
// rules engine will not let a transform rule rewrite a cf- header, so it is both
// unambiguous and unforgeable through the edge.
func TestCFConnectingIPPreferredOverForwardedFor(t *testing.T) {
	trustProxyCIDRsForTest(t, "127.0.0.1/32")
	req := httptest.NewRequest(http.MethodGet, "http://backend.internal/api/x", nil)
	req.RemoteAddr = "127.0.0.1:41000" // cloudflared, on loopback

	// What the origin actually sees when cloudflared appends its own hop.
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1")
	req.Header.Set("CF-Connecting-IP", "203.0.113.9")

	if got := clientIP(req); got != "203.0.113.9" {
		t.Errorf("clientIP = %q, want the visitor address 203.0.113.9. Falling back to the "+
			"right-most XFF hop here yields 127.0.0.1 for every visitor, which collapses the "+
			"per-IP lockout into a single shared bucket", got)
	}
}

func TestCFConnectingIPIgnoredFromUntrustedPeer(t *testing.T) {
	// A configured proxy that is not this peer.
	trustProxyCIDRsForTest(t, "10.0.0.0/8")
	req := httptest.NewRequest(http.MethodGet, "http://backend.internal/api/x", nil)
	req.RemoteAddr = "203.0.113.50:40000"
	req.Header.Set("CF-Connecting-IP", "1.2.3.4")

	if got := clientIP(req); got != "203.0.113.50" {
		t.Errorf("clientIP = %q, want the peer address: CF-Connecting-IP is just a header and any "+
			"client can send one", got)
	}
}

// TestClientIPFallsBackWhenHeadersDoNotParse guards the lockout-key space.
//
// The resolved value becomes a key in a bounded map. A trusted-but-buggy proxy
// sending "unknown", an empty element from a trailing comma, or arbitrary text
// would otherwise mint keys that match nothing real and grow without limit.
func TestClientIPFallsBackWhenHeadersDoNotParse(t *testing.T) {
	trustProxyCIDRsForTest(t, "127.0.0.1/32")

	cases := []struct {
		name string
		cf   string
		xff  string
		want string
	}{
		{"unknown literal", "unknown", "", "127.0.0.1"},
		{"empty trailing element", "", "203.0.113.1, ", "127.0.0.1"},
		{"arbitrary text", "not-an-ip", "also-not-an-ip", "127.0.0.1"},
		// A malformed CF header must not shadow a usable XFF.
		{"bad cf falls through to xff", "garbage", "203.0.113.7", "203.0.113.7"},
		// Proxies in the wild send ip:port in XFF; accept it rather than
		// discarding a perfectly good address.
		{"xff with port", "", "203.0.113.8:5555", "203.0.113.8"},
		{"cf with port", "203.0.113.9:443", "", "203.0.113.9"},
		// IPv6 in both forms.
		{"ipv6 bare", "2001:db8::1", "", "2001:db8::1"},
		{"ipv6 bracketed with port", "[2001:db8::2]:443", "", "2001:db8::2"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://backend.internal/api/x", nil)
			req.RemoteAddr = "127.0.0.1:41000"
			if c.cf != "" {
				req.Header.Set("CF-Connecting-IP", c.cf)
			}
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := clientIP(req); got != c.want {
				t.Errorf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

// TestStatusReportsResolvedClientIP covers the diagnostic.
//
// It exists because there was no way to verify a proxy deployment: nothing logs
// the client IP (see log_privacy_test.go), so an operator had no way to tell
// whether the lockouts were keying off real callers or off the proxy — a failure
// that is silent in both directions.
func TestStatusReportsResolvedClientIP(t *testing.T) {
	srv := newTestServer(t)
	u, err := users0(t, srv)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	call := func() (string, bool) {
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.RemoteAddr = "127.0.0.1:41000"
		req.Header.Set("CF-Connecting-IP", "203.0.113.42")
		rec := httptest.NewRecorder()
		srv.handleStatus(rec, authedRequestForTest(req, u))
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d (%s)", rec.Code, rec.Body.String())
		}
		var out struct {
			ClientIP            string `json:"clientIp"`
			ProxyHeadersTrusted bool   `json:"proxyHeadersTrusted"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		return out.ClientIP, out.ProxyHeadersTrusted
	}

	// Untrusted peer: reports the connection address and says trust is off, which
	// is the signal that TRUSTED_PROXY_CIDRS needs setting.
	trustProxyCIDRsForTest(t, "")
	ip, trusted := call()
	if trusted {
		t.Error("proxyHeadersTrusted is true with no CIDRs configured")
	}
	if ip != "127.0.0.1" {
		t.Errorf("clientIp = %q, want the peer address 127.0.0.1", ip)
	}

	// Trusted peer: reports the real visitor address.
	trustProxyCIDRsForTest(t, "127.0.0.1/32")
	ip, trusted = call()
	if !trusted {
		t.Error("proxyHeadersTrusted is false for a configured peer")
	}
	if ip != "203.0.113.42" {
		t.Errorf("clientIp = %q, want the visitor address 203.0.113.42", ip)
	}
}

// users0 creates a throwaway non-admin account for the status call.
func users0(t *testing.T, srv *Server) (users.User, error) {
	t.Helper()
	return srv.users.Create(context.Background(), "status-probe", "correct-horse-battery-staple", users.RoleUser)
}

// authedRequestForTest attaches an AuthContext, since handleStatus reads the
// caller from the context rather than re-authenticating.
func authedRequestForTest(req *http.Request, u users.User) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}))
}
