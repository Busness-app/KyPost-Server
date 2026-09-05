package mfa

import "testing"

func TestRecoveryCodeDigestNormalises(t *testing.T) {
	codes, err := GenerateRecoveryCodes(2)
	if err != nil {
		t.Fatal(err)
	}
	if codes[0] == codes[1] {
		t.Fatal("two codes collided")
	}
	if len(codes[0]) != 14 || codes[0][4] != '-' || codes[0][9] != '-' {
		t.Fatalf("code %q is not xxxx-xxxx-xxxx", codes[0])
	}
	want := RecoveryCodeDigest(codes[0])
	if got := RecoveryCodeDigest(" " + codes[0] + " "); got != want {
		t.Fatalf("whitespace changed the digest: %s vs %s", got, want)
	}
	if got := RecoveryCodeDigest(codes[0][:4] + codes[0][5:9] + codes[0][10:]); got != want {
		t.Fatalf("dropping the dashes changed the digest")
	}
	if len(want) != 64 {
		t.Fatalf("digest is %d chars, want 64 hex", len(want))
	}
}
