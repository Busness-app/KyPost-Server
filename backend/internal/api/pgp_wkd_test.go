package api

import (
	"testing"

	"kypost-server/backend/internal/pgpmail"
)

func TestWKDHashLocalPart(t *testing.T) {
	// Canonical vector from the WKD spec (draft-koch-openpgp-webkey-service):
	// local-part "Joe.Doe" hashes to this z-base-32 string.
	got := wkdHashLocalPart("Joe.Doe")
	want := "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
	if got != want {
		t.Fatalf("wkdHashLocalPart = %q, want %q", got, want)
	}
}

func TestValidateDiscoveredKeyAcceptsMatchingUsableKey(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	fp, err := validateDiscoveredKey(id.ArmoredPublicKey, "alice@example.com")
	if err != nil {
		t.Fatalf("validateDiscoveredKey: %v", err)
	}
	if fp == "" {
		t.Fatalf("expected a non-empty fingerprint")
	}
}

func TestValidateDiscoveredKeyRejectsWrongUID(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := validateDiscoveredKey(id.ArmoredPublicKey, "mallory@example.com"); err == nil {
		t.Fatalf("expected rejection when the queried address is not a UID")
	}
}
