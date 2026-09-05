package mfa

import (
	"path/filepath"
	"strings"
	"testing"
)

// testDigester builds a digester over a fresh key, so a test never depends on
// (or creates) a key file outside its own temp dir.
func testDigester(t *testing.T) func(string) string {
	t.Helper()
	d, err := NewRecoveryCodeDigester(filepath.Join(t.TempDir(), "totp-secret.key"))
	if err != nil {
		t.Fatalf("NewRecoveryCodeDigester: %v", err)
	}
	return d
}

func TestRecoveryCodeDigestNormalises(t *testing.T) {
	digest := testDigester(t)
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
	want := digest(codes[0])
	if got := digest(" " + codes[0] + " "); got != want {
		t.Fatalf("whitespace changed the digest: %s vs %s", got, want)
	}
	if got := digest(codes[0][:4] + codes[0][5:9] + codes[0][10:]); got != want {
		t.Fatalf("dropping the dashes changed the digest")
	}
	if got := digest(strings.ToUpper(codes[0])); got != want {
		t.Fatalf("case changed the digest: %s vs %s", got, want)
	}
	if len(want) != 64 {
		t.Fatalf("digest is %d chars, want 64 hex", len(want))
	}
}

// TestRecoveryCodeDigestIsKeyed is the property the digest exists for: an
// attacker holding users.json but not SECRET_DIR cannot recompute a digest,
// so a 60-bit code is not searchable offline. Two keys, one code, two answers.
func TestRecoveryCodeDigestIsKeyed(t *testing.T) {
	a, b := testDigester(t), testDigester(t)
	const code = "89et-bhu3-ilh3"
	if a(code) == b(code) {
		t.Fatal("the digest is the same under two different keys — it is not keyed, " +
			"and a copy of the store alone yields a working second factor")
	}
	// And not the bare SHA-256 this replaced, under either key.
	const bareSHA256 = "20045afeb9f542fb56177ce4bd521611e00253971fdb508e595d5ea4397dd1ea"
	if a(code) == bareSHA256 || b(code) == bareSHA256 {
		t.Fatal("the digest is still an unkeyed SHA-256 of the normalised code")
	}
}

// TestRecoveryCodeDigesterIsStableAcrossProcesses pins that the key is
// persisted, not per-call: a code minted before a restart must still redeem
// after one.
func TestRecoveryCodeDigesterIsStableAcrossProcesses(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "totp-secret.key")
	first, err := NewRecoveryCodeDigester(keyPath)
	if err != nil {
		t.Fatalf("NewRecoveryCodeDigester: %v", err)
	}
	second, err := NewRecoveryCodeDigester(keyPath)
	if err != nil {
		t.Fatalf("NewRecoveryCodeDigester (reopen): %v", err)
	}
	const code = "89et-bhu3-ilh3"
	if first(code) != second(code) {
		t.Fatal("reloading the key changed the digest — every issued recovery code would " +
			"stop redeeming on restart")
	}
}
