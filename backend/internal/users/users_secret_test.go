package users

import "testing"

func TestDeviceSecretRoundTrips(t *testing.T) {
	const secret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddccbbaa9988"
	stored := HashDeviceSecret(secret)
	if stored == secret {
		t.Fatal("HashDeviceSecret returned the secret unchanged")
	}
	if !VerifyDeviceSecret(stored, secret) {
		t.Fatal("VerifyDeviceSecret rejected the secret it just hashed")
	}
	if VerifyDeviceSecret(stored, secret+"x") {
		t.Fatal("VerifyDeviceSecret accepted a wrong secret")
	}
	if VerifyDeviceSecret(stored, "") {
		t.Fatal("VerifyDeviceSecret accepted an empty secret")
	}
}

func TestVerifyDeviceSecretStillAcceptsLegacyScryptHashes(t *testing.T) {
	// Devices paired before HashDeviceSecret existed hold a scrypt hash.
	// Rejecting those would silently unpair every phone on every existing
	// install on upgrade.
	const secret = "legacy-device-secret"
	legacy, err := HashPassword(secret)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !VerifyDeviceSecret(legacy, secret) {
		t.Fatal("VerifyDeviceSecret rejected a legacy scrypt hash; every already-paired device would be unpaired by the upgrade")
	}
	if VerifyDeviceSecret(legacy, "wrong") {
		t.Fatal("VerifyDeviceSecret accepted a wrong secret against a legacy hash")
	}
}

func TestVerifyDeviceSecretRejectsMalformedTaggedHash(t *testing.T) {
	for _, stored := range []string{"sha256:", "sha256:zzzz", "sha256:abcd"} {
		if VerifyDeviceSecret(stored, "anything") {
			t.Errorf("VerifyDeviceSecret(%q) accepted a malformed hash", stored)
		}
	}
}

func TestVerifyScryptHashRejectsAbsurdCostParameters(t *testing.T) {
	// n/r/p are parsed out of a file. Unbounded, scrypt.Key allocates
	// 128*r*N bytes of whatever it is told to, so one bad value OOM-kills the
	// process on the next login attempt — and supervisord restarts it into
	// the same crash on the retry.
	cases := map[string]string{
		"absurd n":             "scrypt$1099511627776$8$1$c2FsdHNhbHQ=$aGFzaGhhc2g=",
		"absurd r":             "scrypt$16384$1000000$1$c2FsdHNhbHQ=$aGFzaGhhc2g=",
		"absurd p":             "scrypt$16384$8$1000000$c2FsdHNhbHQ=$aGFzaGhhc2g=",
		"n below floor":        "scrypt$2$8$1$c2FsdHNhbHQ=$aGFzaGhhc2g=",
		"n not a power of two": "scrypt$16385$8$1$c2FsdHNhbHQ=$aGFzaGhhc2g=",
	}
	for name, encoded := range cases {
		if verifyScryptHash(encoded, "anything") {
			t.Errorf("%s: verifyScryptHash accepted it", name)
		}
	}
}

func TestVerifyScryptHashStillAcceptsTheHashesWeMint(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !verifyScryptHash(h, "correct horse battery staple") {
		t.Fatal("the cost bounds rejected a hash HashPassword just produced")
	}
}
