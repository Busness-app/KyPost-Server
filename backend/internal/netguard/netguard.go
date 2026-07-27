// Package netguard holds the single definition of "this IP is somewhere inside
// the deployment and must never be reached by an outbound request made on a
// user's behalf".
//
// It is a leaf package with no dependencies on the rest of this codebase
// because two packages need it and neither can import the other: internal/api
// guards user-supplied CardDAV server URLs, and internal/processor guards
// client-supplied UnifiedPush endpoint URLs. Those two had a copy each,
// character-identical and separately maintained, and they had already drifted
// out of correctness together — neither classified RFC 6598 shared address
// space, so on a box joined to a tailnet (where every node gets a 100.64/10
// address) both surfaces could reach the operator's whole private network.
// A security predicate with two homes is a predicate that will be fixed in one
// of them.
package netguard

import "net"

// extraReservedCIDRs are ranges Go's own net.IP predicates do not classify but
// which are just as much "inside" as RFC1918 is.
//
// 100.64.0.0/10 is the one that matters: RFC 6598 shared address space, and
// what Tailscale assigns to every node on a tailnet — a very common way to run
// a self-hosted server like this one. net.IP.IsPrivate returns false for it, so
// it has to be listed explicitly.
//
// The rest are small and cost nothing to refuse: IETF protocol assignments,
// benchmarking space, and the TEST-NET ranges, none of which is ever a real
// destination. The two IPv6 entries matter for a subtler reason — both embed an
// arbitrary IPv4 address (including a private one) inside an address that looks
// global, so a NAT64 or 6to4 literal is a way to smuggle 10.0.0.1 past a check
// that only inspects IPv6 predicates.
var extraReservedCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"100.64.0.0/10",   // RFC 6598 CGNAT / Tailscale
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"64:ff9b::/96",    // RFC 6052 NAT64 — wraps arbitrary IPv4
		"2002::/16",       // 6to4 — likewise
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsPrivateOrReserved reports whether ip must never be reached via a
// user-supplied outbound URL: loopback, RFC1918/RFC4193 private, link-local
// (which also covers the 169.254.169.254 cloud metadata address), multicast,
// unspecified, or any of extraReservedCIDRs.
func IsPrivateOrReserved(ip net.IP) bool {
	if ip == nil {
		// Not a resolvable destination. Refusing is the safe answer for a
		// value a caller failed to parse.
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() {
		return true
	}
	// Match in 4-byte form when there is one, so an IPv4-mapped IPv6 literal
	// (::ffff:100.64.0.1) is caught by the IPv4 CIDRs rather than sliding past
	// them, and in 16-byte form as well for the two IPv6 entries.
	if v4 := ip.To4(); v4 != nil {
		for _, n := range extraReservedCIDRs {
			if n.Contains(v4) {
				return true
			}
		}
	}
	for _, n := range extraReservedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
