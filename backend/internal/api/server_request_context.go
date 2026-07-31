// What the server is willing to believe about an inbound request: whether
// X-Forwarded-* may be trusted at all (proxyHeadersTrusted), and the three
// answers that depend on it — the caller's IP for lockout keying and logging,
// the externally-reachable base URL, and whether the connection was really TLS
// (which decides the session cookie's Secure flag).
//
// Collected here because every one of these is a trust decision and clientIP in
// particular is a lockout key. Scattered through a 4,500-line file, the
// left-most vs right-most X-Forwarded-For hop question gets answered twice,
// differently. All three now go through lastForwardedValue.
package api

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/logging"
)

// trustedProxyNets is the set of peer addresses whose X-Forwarded-* headers may
// be believed, from TRUSTED_PROXY_CIDRS (comma-separated CIDRs or bare IPs).
//
// This replaces a bare TRUST_PROXY_HEADERS=true boolean, which was not a trust
// decision at all: it trusted the headers on EVERY connection, from any peer
// that could reach the port. With the container port published, that let anyone
// connecting directly to 5866 name their own IP and bypass every IP-keyed
// control at once — the login, CardDAV and device lockouts, the WKD limiter, and
// the proof-of-work escalation and challenge-to-client binding.
//
// Empty (the default) means trust nothing and use RemoteAddr, the only safe
// default for a directly-exposed listener.
var trustedProxyNets = parseTrustedProxyCIDRs(os.Getenv("TRUSTED_PROXY_CIDRS"))

// parseTrustedProxyCIDRs accepts CIDRs ("10.0.0.0/8", "::1/128") and bare IPs
// ("172.18.0.1", which is what a docker-compose sidecar proxy looks like),
// normalizing the latter to single-host CIDRs.
//
// A malformed entry is skipped rather than silently widening trust, and is not
// fatal: refusing to boot over one typo would take the mail server down to
// protect a header, and skipping fails toward trusting less.
func parseTrustedProxyCIDRs(raw string) []*net.IPNet {
	var nets []*net.IPNet
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(field); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(field); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

// proxyHeadersTrusted reports whether r's X-Forwarded-* headers may be believed,
// which is true only when the request's own peer address is inside
// trustedProxyNets — the one thing about a request a client cannot forge.
func proxyHeadersTrusted(r *http.Request) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// lastForwardedValue returns the RIGHT-most value of a comma-separated
// X-Forwarded-* header, or "" if absent.
//
// Right-most, always, for every one of these headers. An appending proxy
// (nginx's $proxy_add_x_forwarded_for) turns a client-sent "a" into
// "a, <realip>", so the left-most element is whatever the client chose to
// prepend and the right-most is what the nearest trusted hop actually observed.
// Reading the left-most for the scheme while reading the right-most for the
// address is how the session cookie's Secure flag ended up decided by a
// client-supplied value.
//
// Assumes a single trusted proxy in front; multi-proxy deployments should
// terminate the chain at a known hop.
func lastForwardedValue(r *http.Request, header string) string {
	raw := r.Header.Get(header)
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	return strings.TrimSpace(parts[len(parts)-1])
}

func externalBaseURL(r *http.Request) string {
	var proto, host string
	if proxyHeadersTrusted(r) {
		proto = lastForwardedValue(r, "X-Forwarded-Proto")
		host = lastForwardedValue(r, "X-Forwarded-Host")
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

// clientIP resolves the caller's IP for logging, CAPTCHA context, and lockout
// keying.
//
// This is a lockout key, so getting it wrong does not degrade gracefully. A
// caller who can choose what this returns has defeated every rate limit keyed on
// it, and a value that is CONSTANT across callers is just as broken the other
// way: every visitor shares one bucket, so 50 failures from anyone locks out
// everyone. Hence the trust test on the peer address rather than a global flag,
// and the order below.
//
// When the peer is a trusted proxy (see proxyHeadersTrusted), in order:
//
//  1. CF-Connecting-IP, which Cloudflare sets to exactly the visitor's address.
//     Preferred over X-Forwarded-For because the correct XFF element depends on
//     how many hops appended to it: a tunnel daemon or a second proxy can append
//     its own address after Cloudflare's, silently making the right-most element
//     a loopback address and collapsing per-client keying for the whole instance.
//     Cloudflare's rules engine cannot rewrite a cf- header, only remove it, so
//     it cannot be forged through the edge.
//  2. The right-most X-Forwarded-For element, for every other proxy.
//
// Untrusted peers, and anything that does not parse as an IP, fall through to
// the connection's own address.
//
// This returns the caller's ACTUAL address. Callers using it as a lockout or
// rate-limit key must pass it through lockoutKeyForIP first, which folds IPv6 to
// a /64 so a budget cannot be reset by rotating inside one prefix.
func clientIP(r *http.Request) string {
	if proxyHeadersTrusted(r) {
		// Single-valued, so read it whole rather than through
		// lastForwardedValue: a comma in this header is not a hop list, it is a
		// malformed value, and taking the last element of one would be inventing
		// structure that is not there.
		if ip := parseClientAddr(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		if ip := parseClientAddr(lastForwardedValue(r, "X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// lockoutKeyForIP normalizes an address for use as a lockout or rate-limit map
// key, collapsing IPv6 onto its /64 prefix and passing IPv4 through unchanged.
//
// Every key in this package is a budget of N attempts per window, which bounds
// an attacker only if acquiring the next key costs something. For IPv4 it does;
// for IPv6 it costs nothing — the smallest allocation a residential ISP hands
// out is a /64, so one visitor holds 2^64 addresses and SLAAC privacy extensions
// already rotate through them unprompted. Keyed on the full address, every
// control here is defeated by one `ip -6 addr add`.
//
// /64 and not /56 or /48: a /64 is the one length guaranteed to belong to a
// single subscriber, being the smallest SLAAC-capable unit and the minimum
// assignment RFC 6177 tells ISPs to make. Masking further would be closer to one
// budget per subscriber, but on a provider handing /64s to distinct customers a
// /48 key puts unrelated people in one bucket, where a stranger's failures lock
// you out.
//
// Deliberately NOT applied where the caller's real address is wanted: logging,
// the MFA push's ipAddress, /api/status's clientIp, the address handed to a
// CAPTCHA provider (Turnstile's siteverify wants a real remoteip), and the
// proof-of-work challenge binding, which compares the exact address a challenge
// was issued to.
func lockoutKeyForIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		// Not an address at all: an empty RemoteAddr from a synthetic request, or
		// a value some future caller passed in. Pass it through rather than
		// collapsing every unparseable value onto one shared key.
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		// Canonical 4-byte form, so ::ffff:203.0.113.7 and 203.0.113.7 are one
		// key rather than two budgets for one host.
		return v4.String()
	}
	// Suffixed because this is a prefix and not an address. Without it a log line
	// or a test failure reads as though a caller connected from 2001:db8:1:2::,
	// and the value would be indistinguishable from a client that really did.
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// parseClientAddr normalizes a proxy-supplied address, returning "" if it is not
// one.
//
// Validated rather than passed through, because the result becomes a lockout map
// key: an unvalidated header lets a misconfigured or buggy proxy turn "unknown",
// an empty element from a trailing comma, or arbitrary text into keys —
// unbounded cardinality in a table this codebase works to keep bounded.
//
// Accepts a bare IP and an ip:port pair, because proxies in the wild send both.
func parseClientAddr(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// isRequestSecure reports whether r was received over HTTPS, either
// directly or (per X-Forwarded-Proto) via a TLS-terminating reverse proxy.
// Used to decide whether the session cookie can carry the Secure attribute
// without breaking plain-HTTP local/dev deployments.
func isRequestSecure(r *http.Request) bool {
	if proxyHeadersTrusted(r) {
		if proto := lastForwardedValue(r, "X-Forwarded-Proto"); proto != "" {
			return strings.EqualFold(proto, "https")
		}
	}
	if r.TLS != nil {
		return true
	}
	// SERVER_BASE_URL is the operator's own statement of the scheme users reach them
	// on, and is already trusted to mint pickup and pairing links. With TLS
	// terminated at a proxy and TRUSTED_PROXY_CIDRS unset, this predicate is
	// otherwise false, so the session cookie and the CSRF double-submit value both
	// ship without Secure and no HSTS is sent. Users on https cannot be locked out
	// by honouring it: their browser is already on TLS.
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(os.Getenv("SERVER_BASE_URL"))), "https://")
}

// uploadReadDeadline is how long a request that carries a multi-megabyte body
// gets to finish sending it.
const uploadReadDeadline = 10 * time.Minute

// withUploadDeadline extends this request's read deadline past the server-wide
// ReadTimeout, for the routes that accept a real upload.
//
// http.Server's ReadTimeout covers the entire request including the body, so one
// global value has to serve both a 200-byte login and a 25 MiB attachment. At
// 60 s a 25 MiB body needs a sustained 3.5 Mbit/s upload, which residential DSL
// and mobile networks do not provide, so large attachments failed with a
// connection reset the frontend could not tell from a network blip. Raising the
// global value would hand every other route the same generosity, and those
// routes are exactly where a dribbling body should be cut off.
//
// Only the READ deadline moves. WriteTimeout (10 min) already covers the
// response and ReadHeaderTimeout (10 s) is unaffected, so header slowloris is
// still refused on these routes.
func withUploadDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Ignored on purpose: a failure here means the connection does not
		// support deadlines (a test's in-memory pipe, say), and the caller's
		// upload is not less valid because the deadline could not be moved.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadReadDeadline))
		next(w, r)
	}
}

// warnOnRetiredProxyEnv complains loudly if the operator still has the retired
// TRUST_PROXY_HEADERS set without configuring its replacement. Ignoring it
// silently would be a security regression delivered by an upgrade: the operator
// believes forwarded headers are trusted, so believes their session cookies
// carry Secure and their lockouts key off the real caller.
func warnOnRetiredProxyEnv(logger *logging.Logger) {
	if logger == nil {
		return
	}
	if strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")) == "" {
		return
	}
	if len(trustedProxyNets) > 0 {
		logger.Info("TRUST_PROXY_HEADERS is retired and ignored; TRUSTED_PROXY_CIDRS is configured, which is what now controls proxy trust")
		return
	}
	logger.Error("TRUST_PROXY_HEADERS is set but is RETIRED and ignored, and TRUSTED_PROXY_CIDRS is empty: " +
		"forwarded headers are NOT being trusted. Session cookies will not be marked Secure and the login, " +
		"CardDAV and device lockouts are keying off your proxy's address instead of the caller's. " +
		"Set TRUSTED_PROXY_CIDRS to your reverse proxy's address (e.g. 127.0.0.1/32) to restore the previous behaviour.")
}

// unusedProxyHeaderWarning fires warnOnUnusedProxyHeaders' message at most once
// per process. This is a standing misconfiguration, not an event: repeating it on
// every request would bury the log it is trying to be found in.
var unusedProxyHeaderWarning sync.Once

// warnOnUnusedProxyHeaders complains, once, when requests demonstrably arrive
// through a proxy whose forwarding headers this server is discarding.
//
// warnOnRetiredProxyEnv above covers the operator who upgraded from
// TRUST_PROXY_HEADERS. This covers the far more common case: a fresh deployment
// that puts Cloudflare or nginx in front and never sets TRUSTED_PROXY_CIDRS,
// because nothing asks them to. Failing closed is right, but failing closed
// silently means clientIP returns the proxy's address for every caller — not
// merely wrong but CONSTANT, collapsing every control keyed on it into one
// shared bucket.
//
// The trigger is a forwarding header present while trust is unconfigured, which
// is unambiguous: something upstream is telling us who the caller is and we are
// throwing it away. A directly-exposed server sees no such header and stays
// quiet.
func (s *Server) warnOnUnusedProxyHeaders(r *http.Request) {
	if s.logger == nil || len(trustedProxyNets) != 0 {
		return
	}
	header := "CF-Connecting-IP"
	forwarded := parseClientAddr(r.Header.Get(header))
	if forwarded == "" {
		header = "X-Forwarded-For"
		forwarded = parseClientAddr(lastForwardedValue(r, header))
	}
	if forwarded == "" {
		return
	}
	unusedProxyHeaderWarning.Do(func() {
		s.logger.Error("TRUSTED_PROXY_CIDRS is empty but requests are arriving with forwarding headers, so they "+
			"are being ignored: every caller is being keyed as the proxy's own address. The login, CardDAV, "+
			"device and proof-of-work lockouts and the WKD rate limit therefore share ONE bucket for all "+
			"callers (enough failures from anyone locks out everyone), and the MFA sign-in approval push "+
			"reports the proxy's address rather than the person signing in. Set TRUSTED_PROXY_CIDRS to your "+
			"proxy's address, and narrow KYPOST_BIND so the port cannot be reached around it.",
			"peer", clientIP(r),
			"header", header,
			"header_reports", forwarded)
	})
}
