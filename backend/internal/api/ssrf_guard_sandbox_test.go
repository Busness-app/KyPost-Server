package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The allowlist exists for one job: let a sandbox deployment point KyPost
// Server at a demo CardDAV host that lives on a private network. Every test
// here is about making sure it cannot do anything more than that.

func TestSandboxPrivateHostsDefaultsToEmpty(t *testing.T) {
	if len(parseSandboxPrivateHosts("")) != 0 {
		t.Fatal("unset SANDBOX_PRIVATE_HOSTS must allow nothing")
	}
	if len(parseSandboxPrivateHosts("   ,  , ")) != 0 {
		t.Fatal("blank entries must allow nothing")
	}
	// The production default, as actually wired up.
	if len(sandboxPrivateHosts) != 0 {
		t.Fatalf("sandboxPrivateHosts = %v, want empty in a normal test environment", sandboxPrivateHosts)
	}
}

func TestSandboxPrivateHostsMatchesExactHostnamesOnly(t *testing.T) {
	allowed := parseSandboxPrivateHosts("kypost-demo-mail, Demo.Internal ")

	for _, host := range []string{"kypost-demo-mail", "demo.internal", "DEMO.INTERNAL"} {
		if !sandboxHostAllowed(allowed, host) {
			t.Errorf("sandboxHostAllowed(%q) = false, want true", host)
		}
	}

	// Suffix and prefix matching is how an allowlist becomes a vulnerability:
	// an attacker who controls a domain names a host to swallow the entry.
	for _, host := range []string{
		"kypost-demo-mail.evil.com",
		"evil.com/kypost-demo-mail",
		"notkypost-demo-mail",
		"kypost-demo-mail.",
		"demo.internal.evil.com",
		"sub.demo.internal",
		"",
	} {
		if sandboxHostAllowed(allowed, host) {
			t.Errorf("sandboxHostAllowed(%q) = true, want false", host)
		}
	}
}

func TestSandboxPrivateHostsNeverAllowsIPLiterals(t *testing.T) {
	// An operator who lists an IP gets nothing: the guard's whole point is that
	// a URL naming a private address is refused, and an allowlist that accepted
	// literals would turn one typo into a full SSRF primitive.
	allowed := parseSandboxPrivateHosts("172.30.0.20, 127.0.0.1, ::1")
	for _, host := range []string{"172.30.0.20", "127.0.0.1", "::1"} {
		if sandboxHostAllowed(allowed, host) {
			t.Errorf("sandboxHostAllowed(%q) = true, want false for an IP literal", host)
		}
	}

	if err := validateOutboundURLWithSandbox("https://172.30.0.20/dav/", allowed, "https"); err == nil {
		t.Error("validateOutboundURL accepted a private IP literal that was in the allowlist, want refusal")
	}
}

func TestValidateOutboundURLAllowsListedSandboxHost(t *testing.T) {
	allowed := parseSandboxPrivateHosts("kypost-demo-mail")

	// The host does not resolve in a test environment, so a passing allowlist
	// check has to short-circuit resolution entirely — which is also what makes
	// it work inside a compose network the test host knows nothing about.
	if err := validateOutboundURLWithSandbox("https://kypost-demo-mail/carddav/alice/", allowed, "https"); err != nil {
		t.Errorf("validateOutboundURL(allowlisted host) = %v, want nil", err)
	}

	// Still https-only. The allowlist relaxes the address check, not the
	// scheme check that keeps the user's password off the wire in the clear.
	if err := validateOutboundURLWithSandbox("http://kypost-demo-mail/carddav/alice/", allowed, "https"); err == nil {
		t.Error("validateOutboundURL accepted http:// for an allowlisted host, want refusal on scheme")
	}

	// An unlisted private host is refused exactly as before.
	if err := validateOutboundURLWithSandbox("https://10.0.0.5/dav/", allowed, "https"); err == nil {
		t.Error("validateOutboundURL accepted an unlisted private host, want refusal")
	}
}

func TestSSRFSafeDialRefusesUnlistedPrivateHostAtDialTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)

	// No allowlist: the dial-time guard still refuses loopback, which is the
	// DNS-rebinding protection this change must not weaken.
	dial := sandboxAwareDialContext(nil)
	if _, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", u.Port())); err == nil {
		t.Fatal("dialed loopback with an empty allowlist, want refusal")
	}
}

func TestSSRFSafeDialAllowsListedSandboxHostAtDialTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	u, _ := url.Parse(ts.URL)

	// "localhost" stands in for the compose hostname: it resolves to private
	// space, so reaching it at all proves the allowlist is what let it through.
	dial := sandboxAwareDialContext(parseSandboxPrivateHosts("localhost"))
	conn, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost", u.Port()))
	if err != nil {
		t.Fatalf("dial of an allowlisted sandbox host = %v, want success", err)
	}
	conn.Close()

	// A host that merely looks like the allowlisted one is still refused at
	// dial time, not just at validation time.
	if _, err := dial(context.Background(), "tcp", net.JoinHostPort("localhost.evil.example", u.Port())); err == nil {
		t.Fatal("dialed a lookalike of an allowlisted host, want refusal")
	}
}
