package users

import "testing"

// TestDeriveAuthSecretMatchesTheBrowser is the cross-implementation pin.
//
// The server's derivation only means anything if it produces the SAME bytes the
// browser produces — a mismatch would not fail closed, it would refuse every
// legitimate legacy upgrade and lock users out. The expected value below was
// computed with WebCrypto using exactly the algorithm in
// frontend/src/lib/authSecret.ts:
//
//	PBKDF2-SHA256(password, base64decode(salt), iterations, 32)
//	  -> HKDF-SHA256(stretch, salt="", info="kypost/auth/v1", 32) -> hex
//
// If this test fails, the two implementations have drifted and sign-in for
// converting accounts is broken; do not "fix" it by changing the constant.
func TestDeriveAuthSecretMatchesTheBrowser(t *testing.T) {
	const (
		password = "correct-horse-battery-staple"
		salt     = "AAAAAAAAAAAAAAAAAAAAAA=="
		want     = "da9fc5d333fdab121f3c302b6191b68657bf806030a32c0cbd47b39b720dc860"
	)
	got, err := DeriveAuthSecret(password, salt, MinLoginIterations)
	if err != nil {
		t.Fatalf("DeriveAuthSecret: %v", err)
	}
	if got != want {
		t.Fatalf("server derivation disagrees with frontend/src/lib/authSecret.ts:\n got  %s\n want %s", got, want)
	}
}
