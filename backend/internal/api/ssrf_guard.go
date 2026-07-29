package api

import (
	"context"
	"errors"
	"fmt"
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

// newSSRFSafeHTTPClient builds an http.Client for outbound requests whose
// destination host is supplied by a user (e.g. a CardDAV server URL): every
// dial, including ones made for redirects, is re-resolved and checked
// against isPrivateOrReservedIP immediately before connecting.
func newSSRFSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: ssrfSafeDialContext},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			// Refuse a downgrade to plaintext. ssrfSafeDialContext checks where
			// each hop connects, but not how: a server reached over https could
			// answer 302 to an http:// URL and Go would follow it happily,
			// putting the user's CardDAV credentials on the wire in the clear
			// for a passive observer. A redirect that lowers the protection the
			// caller asked for is refused rather than followed.
			if len(via) > 0 && strings.EqualFold(via[0].URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing redirect from https to %s", req.URL.Scheme)
			}
			return nil
		},
	}
}
