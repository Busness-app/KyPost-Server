package api

import "testing"

// An IPv6 client holds a whole /64 — the smallest allocation a residential ISP
// hands out — and SLAAC privacy extensions already rotate through it unasked.
// Keyed on the full address, every budget in this package resets for free at each
// new one, which is the same "attempts per key" control IPv4 callers cannot
// escape. lockoutKeyForIP folds IPv6 to its /64 so the budget follows the
// subscriber rather than the address.
func TestLockoutKeyForIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"IPv4 passes through", "203.0.113.7", "203.0.113.7"},
		{
			// Otherwise one host spends two budgets depending on how it reached us.
			"IPv4-mapped IPv6 folds onto the IPv4 key",
			"::ffff:203.0.113.7", "203.0.113.7",
		},
		{"IPv6 masks to its /64", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"IPv6 already on the prefix", "2001:db8:1:2::", "2001:db8:1:2::/64"},
		{"loopback", "::1", "::/64"},
		{
			// The value is a prefix, not an address, and has to be readable as one
			// in a log line or a test failure.
			"the key is suffixed so it cannot be read as an address",
			"2001:db8::dead:beef", "2001:db8::/64",
		},
		{
			// Not an address: a synthetic request with an empty RemoteAddr, say.
			// Passed through rather than collapsed onto one shared key with every
			// other unparseable value.
			"unparseable passes through", "not-an-ip", "not-an-ip",
		},
		{"empty passes through", "", ""},
		{"surrounding space is ignored", "  2001:db8:1:2::9  ", "2001:db8:1:2::/64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockoutKeyForIP(tc.in); got != tc.want {
				t.Errorf("lockoutKeyForIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// Two addresses in one /64 must share a budget, and two /64s must not. The second
// half is what stops this from being a fix that trades one bug for a worse one:
// masking too far would put unrelated subscribers in one bucket, where a
// stranger's failures lock you out.
func TestLockoutKeyForIPSeparatesPrefixesNotAddresses(t *testing.T) {
	const (
		first  = "2001:db8:aaaa:1::1"
		second = "2001:db8:aaaa:1:ffff:ffff:ffff:ffff"
		other  = "2001:db8:aaaa:2::1"
	)
	if lockoutKeyForIP(first) != lockoutKeyForIP(second) {
		t.Errorf("addresses in one /64 got different keys (%q vs %q): an IPv6 caller "+
			"resets its budget by rotating inside its own prefix",
			lockoutKeyForIP(first), lockoutKeyForIP(second))
	}
	if lockoutKeyForIP(first) == lockoutKeyForIP(other) {
		t.Errorf("two different /64s share the key %q: unrelated subscribers land in "+
			"one bucket, so a stranger's failures lock you out", lockoutKeyForIP(first))
	}
}

// The end-to-end shape of the same thing, through a real lockout. Mirrors
// TestDeviceLockoutScopedToClientIP, which proves the IPv4 half; this proves an
// IPv6 attacker cannot walk out of the budget that test establishes.
func TestDeviceLockoutFollowsIPv6PrefixNotAddress(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "victim-device")

	// Burn the budget from one address in the prefix.
	for i := 0; i < deviceMaxFailures; i++ {
		req := deviceRequest(deviceID, "wrong-secret")
		req.RemoteAddr = "[2001:db8:aaaa:1::1]:40000"
		srv.deviceAuthFromRequest(req)
	}

	// A different address in the SAME /64 is the same subscriber, one `ip -6 addr
	// add` away, and must not get a fresh budget.
	rotated := deviceRequest(deviceID, deviceSecret)
	rotated.RemoteAddr = "[2001:db8:aaaa:1::99]:40000"
	if _, _, ok, _ := srv.deviceAuthFromRequest(rotated); ok {
		t.Error("an address in the same /64 was not locked out: an IPv6 attacker resets " +
			"every per-IP budget in this package by rotating inside its own prefix")
	}

	// A different /64 is a different subscriber and must be unaffected.
	owner := deviceRequest(deviceID, deviceSecret)
	owner.RemoteAddr = "[2001:db8:aaaa:2::1]:40000"
	if _, _, ok, _ := srv.deviceAuthFromRequest(owner); !ok {
		t.Error("a different /64 is locked out because another prefix burned the budget; " +
			"the fold must not reach past a single subscriber's subnet")
	}
}
