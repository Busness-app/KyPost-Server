package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSameOriginRejectsCrossOriginCardDAVRedirects(t *testing.T) {
	origin, _ := url.Parse("https://dav.example:443/addressbook")
	for _, raw := range []string{"https://attacker.example/", "http://dav.example/", "https://dav.example:8443/"} {
		target, _ := url.Parse(raw)
		if sameOrigin(origin, target) {
			t.Fatalf("sameOrigin(%q) = true", raw)
		}
	}
	target, _ := url.Parse("https://DAV.example/other")
	if !sameOrigin(origin, target) {
		t.Fatal("implicit HTTPS port and hostname case should preserve origin")
	}
}

func TestValidateOutboundURLRejectsPrivateAndReservedTargets(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"public https", "https://example.com/dav", false},
		{"public http", "http://example.com/dav", false},
		{"loopback IPv4 literal", "http://127.0.0.1/dav", true},
		{"loopback IPv6 literal", "http://[::1]/dav", true},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"rfc1918 10/8", "http://10.0.0.5/", true},
		{"rfc1918 192.168/16", "http://192.168.1.1/", true},
		{"unspecified", "http://0.0.0.0/", true},
		{"disallowed scheme", "ftp://example.com/", true},
		{"file scheme", "file:///etc/passwd", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOutboundURL(c.url, "http", "https")
			if (err != nil) != c.wantErr {
				t.Errorf("validateOutboundURL(%q) error = %v, wantErr %v", c.url, err, c.wantErr)
			}
		})
	}
}

// TestSSRFSafeHTTPClientRefusesLoopbackAtDialTime proves the production dial
// path (ssrfSafeDialContext, wired in by newSSRFSafeHTTPClient) is actually
// active and not just the up-front validateOutboundURL check — this is what
// closes the DNS-rebinding gap, since it re-resolves and re-checks
// immediately before every connection, including ones made for redirects.
func TestSSRFSafeHTTPClientRefusesLoopbackAtDialTime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := newSSRFSafeHTTPClient(2e9)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("Do() to a loopback address should be refused by ssrfSafeDialContext")
	}
}

func TestIsPrivateOrReservedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.169.254", true}, // cloud metadata, covered via link-local
		{"10.1.2.3", true},
		{"172.16.0.1", true},
		{"192.168.0.1", true},
		{"0.0.0.0", true},
		{"224.0.0.1", true}, // multicast
		{"8.8.8.8", false},
		{"93.184.216.34", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("net.ParseIP(%q) failed", c.ip)
		}
		if got := isPrivateOrReservedIP(ip); got != c.want {
			t.Errorf("isPrivateOrReservedIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}
