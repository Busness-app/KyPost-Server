package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run-4 hardening note 10: PAIRING_SECRET was the one secret in this system
// that an operator had to invent by hand.
//
// Every other key — IMAP_CONFIG_KEY_FILE, TOTP_SECRET_KEY_FILE,
// PGP_PRIVATE_KEY_FILE, PICKUP_STORE_KEY_FILE — goes through
// cryptutil.LoadOrCreateKey: 32 bytes of crypto/rand on first use, persisted,
// never the operator's problem. PAIRING_SECRET was read straight from the
// environment and handed to hmac.New, with Dockerfile and docker-compose
// defaulting it to empty and .env.example offering a bare "PAIRING_SECRET="
// with no generation hint.
//
// Empty already failed closed correctly (503 everywhere, logged). The gap was
// PAIRING_SECRET=hunter2 — silently accepted, producing forgeable HMACs for
// pickup links, PGP QR key exchange, and device pairing.
//
// It is generated like the others now. The environment variable still wins when
// set, because a multi-replica deployment needs every replica to share one
// secret and a per-container generated file cannot provide that.

func TestPairingSecretIsGeneratedWhenTheEnvIsUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pairing.key")
	t.Setenv("PAIRING_SECRET", "")

	secret := resolvePairingSecret(path, nil)

	if secret == "" {
		t.Fatal("no pairing secret was produced; pickup links and QR exchange would stay disabled")
	}
	if len(secret) < 32 {
		t.Fatalf("generated secret is only %d characters; it should carry 32 bytes of entropy", len(secret))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the generated secret was not persisted: %v", err)
	}
}

// Persisted, so pairing tokens and pickup links survive a restart. A secret
// that changed on every boot would invalidate every outstanding pickup link.
func TestPairingSecretIsStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pairing.key")
	t.Setenv("PAIRING_SECRET", "")

	first := resolvePairingSecret(path, nil)
	second := resolvePairingSecret(path, nil)

	if first != second {
		t.Fatalf("secret changed between calls (%q vs %q); every outstanding pickup link would break on restart", first, second)
	}
}

// Two installs must not share a secret. Not proof of a CSPRNG, but it catches a
// constant or anything derived from a fixed input.
func TestPairingSecretDiffersBetweenInstalls(t *testing.T) {
	t.Setenv("PAIRING_SECRET", "")

	a := resolvePairingSecret(filepath.Join(t.TempDir(), "pairing.key"), nil)
	b := resolvePairingSecret(filepath.Join(t.TempDir(), "pairing.key"), nil)

	if a == b {
		t.Fatal("two independent installs generated the same pairing secret")
	}
}

// The override is what makes multi-replica work: every replica reads the same
// value from its environment instead of generating its own.
func TestPairingSecretEnvOverridesTheGeneratedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pairing.key")
	t.Setenv("PAIRING_SECRET", "operator-chosen-shared-secret")

	secret := resolvePairingSecret(path, nil)

	if secret != "operator-chosen-shared-secret" {
		t.Fatalf("secret = %q, want the operator's value", secret)
	}
	// And it must not have written a file that a later unset-env boot would
	// silently prefer... or rather, would silently differ from.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an env-supplied secret still created a key file (err=%v)", err)
	}
}

func TestPairingSecretEnvIsTrimmed(t *testing.T) {
	t.Setenv("PAIRING_SECRET", "  padded-secret  ")

	if got := resolvePairingSecret(filepath.Join(t.TempDir(), "pairing.key"), nil); got != "padded-secret" {
		t.Fatalf("secret = %q, want it trimmed", got)
	}
}

// If the key file cannot be written — a read-only secrets volume, a
// permissions problem — the result must be an empty secret, which every
// consumer already treats as "not configured" and answers 503 to. Failing
// closed is the pre-existing behaviour and must survive this change; the
// alternative is signing with something weak because writing the good one
// failed.
func TestPairingSecretFailsClosedWhenItCannotBeGenerated(t *testing.T) {
	t.Setenv("PAIRING_SECRET", "")

	// A path whose parent is a FILE, so MkdirAll cannot create the directory.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if got := resolvePairingSecret(filepath.Join(blocker, "pairing.key"), nil); got != "" {
		t.Fatalf("secret = %q, want empty so every consumer fails closed", got)
	}
}

// The generated value is printable text, like an operator-supplied one. Binary
// in a string field would work for HMAC but reads badly in a log or a config
// dump and invites someone to "fix" it later.
func TestGeneratedPairingSecretIsPrintable(t *testing.T) {
	t.Setenv("PAIRING_SECRET", "")

	secret := resolvePairingSecret(filepath.Join(t.TempDir(), "pairing.key"), nil)

	for _, r := range secret {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("generated secret contains a non-printable character %q: %q", r, secret)
		}
	}
	if strings.TrimSpace(secret) != secret {
		t.Fatal("generated secret has surrounding whitespace")
	}
}
