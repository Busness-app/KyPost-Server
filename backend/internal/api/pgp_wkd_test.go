package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
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

func TestFetchWKDKeyDirectMethod(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	// WKD serves the BINARY key. Convert the armored test key to bytes.
	key, err := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	binKey, err := key.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	hu := wkdHashLocalPart("bob")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(binKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	armored, fp, err := fetchWKDKey(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("fetchWKDKey: %v", err)
	}
	if fp != key.GetFingerprint() {
		t.Fatalf("fingerprint = %q, want %q", fp, key.GetFingerprint())
	}
	if !strings.Contains(armored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("expected armored key, got: %q", armored[:min(40, len(armored))])
	}
}

func TestFetchWKDKeyNotFound(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	if _, _, err := fetchWKDKey(context.Background(), "nobody@example.com"); err == nil {
		t.Fatalf("expected error when no key is published")
	}
}
