package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kypost-server/backend/internal/netguard"
)

// isPrivateOrReservedIP defers to netguard, which is the single definition
// shared with internal/processor's UnifiedPush endpoint guard. It stays a named
// function here only so outboundIPGuard below has something to point at.
func isPrivateOrReservedIP(ip net.IP) bool {
	return netguard.IsPrivateOrReserved(ip)
}

// outboundIPGuard decides whether an IP is forbidden for user-supplied
// outbound requests. It exists as a variable, rather than validateOutboundURL
// and ssrfSafeDialContext calling isPrivateOrReservedIP directly, solely so
// tests in this package can relax it to reach httptest's loopback listeners
// — production code must never reassign it.
var outboundIPGuard = isPrivateOrReservedIP

// outboundCardDAVSchemes are the schemes a user-supplied CardDAV server URL
// may use.
//
// https only, and a var for the same single reason outboundIPGuard is one:
// httptest listeners speak plain http. Production must never widen it. Every
// request to a CardDAV URL carries the user's password in an HTTP Basic
// header, and outboundIPGuard already refuses loopback and private space, so
// an http:// target is necessarily a public host reached in the clear.
var outboundCardDAVSchemes = []string{"https"}

// validateOutboundURL rejects URLs that are not safe for this server to make
// requests to on a user's behalf: schemes outside allowedSchemes, and hosts
// that (as an IP literal or via DNS) resolve to a private/loopback/link-local
// address. Intended as an up-front check at configuration time; see
// ssrfSafeDialContext for the dial-time recheck that also covers DNS
// rebinding and redirects.
func validateOutboundURL(rawURL string, allowedSchemes ...string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	schemeOK := false
	for _, s := range allowedSchemes {
		if strings.EqualFold(u.Scheme, s) {
			schemeOK = true
			break
		}
	}
	if !schemeOK {
		return fmt.Errorf("URL must use one of: %s", strings.Join(allowedSchemes, ", "))
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("URL missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if outboundIPGuard(ip) {
			return errors.New("URL resolves to a private or reserved address")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve host: %w", err)
	}
	for _, ip := range ips {
		if outboundIPGuard(ip) {
			return fmt.Errorf("host resolves to a private or reserved address (%s)", ip)
		}
	}
	return nil
}

// ssrfSafeDialContext re-resolves the target host at actual dial time and
// refuses to connect if every candidate address is private/reserved. Run at
// dial time (not just once up front via validateOutboundURL) so a hostname
// that was public when the caller configured it but has since been rebound
// to an internal address (DNS rebinding) is still blocked — and so
// redirects, which make Go's http.Client dial again, get the same check
// applied to their target.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var chosen net.IP
	for _, ip := range ips {
		if !outboundIPGuard(ip) {
			chosen = ip
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("refusing to dial %q: no public address available", host)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(chosen.String(), port))
}

// maxOutboundResponseBytes bounds how much of a response from a user-supplied
// host this process will read.
//
// The CardDAV REPORT path applies its own 16 MiB LimitReader, but go-webdav's
// discovery PROPFINDs decode straight from resp.Body with none — upstream even
// carries a TODO noting the response can be quite large — and the walk-up loop
// repeats discovery per candidate path. XML decoding into a multistatus struct
// costs several times the wire size in resident memory, so an unbounded
// response from a host the user configured is a memory-exhaustion primitive
// against the shared container.
//
// Bounding at the transport rather than at each call site is what makes this
// cover every current and future go-webdav call at once.
const maxOutboundResponseBytes = 32 << 20

// boundedBodyTransport caps every response body it returns.
//
// Note the failure mode: a truncated body surfaces to the caller as a parse
// error rather than a clean "too large". That is acceptable here because the
// limit is far above any legitimate CardDAV response, so reaching it already
// means the remote server is misbehaving.
type boundedBodyTransport struct {
	base  http.RoundTripper
	limit int64
}

type boundedBody struct {
	io.Reader
	io.Closer
}

func (t *boundedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = boundedBody{Reader: io.LimitReader(resp.Body, t.limit), Closer: resp.Body}
	return resp, nil
}

// newSSRFSafeHTTPClient builds an http.Client for outbound requests whose
// destination host is supplied by a user (e.g. a CardDAV server URL): every
// dial, including ones made for redirects, is re-resolved and checked against
// isPrivateOrReservedIP immediately before connecting, and every response body
// is bounded at maxOutboundResponseBytes.
func newSSRFSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &boundedBodyTransport{
			base:  &http.Transport{DialContext: ssrfSafeDialContext},
			limit: maxOutboundResponseBytes,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
				return fmt.Errorf("refusing cross-origin redirect to %s", req.URL.Redacted())
			}
			return nil
		},
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}
