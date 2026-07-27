package netguard

import (
	"net"
	"testing"
)

func TestIsPrivateOrReservedRefusesInternalDestinations(t *testing.T) {
	for _, tc := range []struct{ ip, why string }{
		{"127.0.0.1", "loopback"},
		{"::1", "IPv6 loopback"},
		{"10.1.2.3", "RFC1918"},
		{"172.16.0.1", "RFC1918"},
		{"192.168.1.1", "RFC1918"},
		{"fd00::1", "RFC4193 unique local"},
		{"169.254.169.254", "cloud metadata"},
		{"0.0.0.0", "unspecified"},
		{"224.0.0.1", "multicast"},

		// The gap this package was extracted to close: both call sites had
		// their own copy of the predicate and neither classified CGNAT, so a
		// tailnet was reachable from a user-supplied URL.
		{"100.64.0.1", "RFC 6598 CGNAT / Tailscale"},
		{"100.100.100.100", "Tailscale MagicDNS"},
		{"100.127.255.254", "top of CGNAT range"},
		{"::ffff:100.64.0.1", "CGNAT as an IPv4-mapped IPv6 literal"},

		{"192.0.0.1", "IETF protocol assignments"},
		{"198.18.0.1", "benchmarking"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"64:ff9b::a00:1", "NAT64-wrapped 10.0.0.1"},
		{"2002:a00:1::", "6to4-wrapped 10.0.0.1"},
	} {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test bug: %q is not a parseable IP", tc.ip)
		}
		if !IsPrivateOrReserved(ip) {
			t.Errorf("IsPrivateOrReserved(%s) = false, want true (%s)", tc.ip, tc.why)
		}
	}
}

// The guard must stay narrow enough that ordinary public destinations — a real
// CardDAV host, a real UnifiedPush server — still work.
func TestIsPrivateOrReservedAllowsPublicDestinations(t *testing.T) {
	for _, addr := range []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"99.255.255.255",  // immediately below 100.64/10
		"100.63.255.255",  // ditto, boundary
		"100.128.0.0",     // immediately above 100.64/10
		"2606:4700::1111", // public IPv6
	} {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("test bug: %q is not a parseable IP", addr)
		}
		if IsPrivateOrReserved(ip) {
			t.Errorf("IsPrivateOrReserved(%s) = true, want false — this is a public address", addr)
		}
	}
}

// A nil IP means the caller could not parse what it was given; refusing is the
// only safe answer, and it must not panic.
func TestIsPrivateOrReservedRefusesNil(t *testing.T) {
	if !IsPrivateOrReserved(nil) {
		t.Fatal("IsPrivateOrReserved(nil) = false, want true")
	}
}
