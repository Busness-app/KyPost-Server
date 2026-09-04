package classifier

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/netguard"
)

// This file is the transport policy for the classifier endpoint: which base
// URLs this server will send mail to, and where it will follow a redirect to.
//
// It matters more here than the name "LLM endpoint" suggests. Every classify
// request carries the sender, the subject and up to 2000 bytes of the message
// body, plus the configured API key in an Authorization header. That is
// correspondence, leaving the deployment, to a destination named in a config
// field an admin types into a web form. Two ways that went wrong had no guard
// at all:
//
//   - http:// to a public host. The mail and the API key both cross the network
//     in the clear. A single mistyped scheme is enough, and nothing anywhere
//     reported it — the classifier keeps working, which is exactly why it would
//     never be noticed.
//   - redirects. The client used Go's default policy, which follows up to ten
//     of them. A 307/308 replays the POST body — the email — at whatever host
//     the far end names. Go strips the Authorization header across domains, so
//     the key does not follow; the message does.
//
// The CardDAV client next door reached the same conclusions first
// (api/ssrf_guard.go). This is deliberately NOT that code: CardDAV refuses
// private addresses because the URL comes from an end user, whereas the
// classifier is normally SUPPOSED to be a private address — the bundled Ollama
// on loopback, or a sibling container. So the rule is inverted rather than
// shared: private destinations are the expected case and may be plaintext,
// public ones must be TLS.

// resolveHost is net.LookupIP behind a variable so tests can decide what a name
// resolves to without needing DNS. Production must never reassign it.
var resolveHost = net.LookupIP

// ValidateBaseURL reports whether raw is a base URL this server may send mail
// to.
//
// The rule: absolute http(s) URL, with a host, and no credentials embedded in
// it. https is always allowed. http is allowed only when the destination is
// inside the deployment — a private, loopback or otherwise reserved address —
// because that is where the bundled Ollama and any sibling container live, and
// nowhere else is plaintext defensible.
//
// A host that does not resolve is accepted. Startup order is real (a compose
// sibling may not be up when config is first saved) and refusing to configure a
// name that is merely not answering yet would be worse than the risk: dial-time
// still goes nowhere, and a name that later resolves public reaches a plaintext
// endpoint that was already reachable before this check existed.
func ValidateBaseURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("classifier base URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("classifier base URL is not a valid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("classifier base URL must start with http:// or https://")
	}
	// Rejected rather than tolerated: a URL of the form
	// http://user:pass@host puts a credential somewhere it will be logged and
	// echoed, and the classifier client authenticates with a Bearer header.
	if u.User != nil {
		return errors.New("classifier base URL must not embed credentials")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("classifier base URL is missing a host")
	}
	if scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if netguard.IsPrivateOrReserved(ip) {
			return nil
		}
		return plaintextPublicError(host)
	}
	ips, err := resolveHost(host)
	if err != nil {
		// Unresolvable: see the doc comment. Not provably public, so not refused.
		return nil
	}
	for _, ip := range ips {
		if !netguard.IsPrivateOrReserved(ip) {
			return plaintextPublicError(host)
		}
	}
	return nil
}

// refuseCrossOriginRedirect is this client's redirect policy, replacing Go's
// default (follow up to ten, anywhere).
//
// A classify request is a POST whose body is somebody's email. A 307 or 308
// re-sends that body verbatim to wherever the response's Location points, so
// under the default policy the endpoint on the far end — or anything that can
// answer as it — chooses who else receives the mail. Go strips Authorization
// across domains, so the API key does not travel; nothing strips the body.
//
// Same-origin redirects are allowed because they are the shape a real one takes
// (a path moving, http upgrading to https on the same host) and they land back
// at the operator's own endpoint. Anything else is refused, and refused rather
// than silently returned, so it surfaces as a classify error an operator can
// see instead of a delivery they never learn about.
func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects from the classifier endpoint")
	}
	if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
		return fmt.Errorf("refusing cross-origin classifier redirect to %s", req.URL.Redacted())
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// plaintextPublicError deliberately does not name the resolved address. The
// message is shown to an admin, but it is produced by a code path that performs
// a DNS lookup on request, and echoing what a name resolved to is how a
// configuration form becomes a resolver oracle.
func plaintextPublicError(host string) error {
	return fmt.Errorf("classifier base URL %q is a public host and must use https:// — "+
		"email content and the API key would otherwise be sent in the clear", host)
}
