package api

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpautocrypt"
	"kypost-server/backend/internal/pgpdiscovery"
)

// generateArmoredKey makes a throwaway key carrying email as its UID.
func generateArmoredKey(t *testing.T, email string) string {
	t.Helper()
	key, err := crypto.PGP().KeyGeneration().AddUserId("Test", email).New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return armored
}

func TestBuildAutocryptHeaderRoundTrips(t *testing.T) {
	pub := generateArmoredKey(t, "alice@example.com")
	value, ok := buildAutocryptHeader(pub, "alice@example.com")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !strings.HasPrefix(value, "addr=alice@example.com; keydata=") {
		t.Fatalf("unexpected value: %q", value)
	}
	// The base64 keydata must decode and re-parse to a usable key carrying the addr.
	addr, keydata, err := pgpautocrypt.ParseAutocryptHeader(value)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "alice@example.com" {
		t.Fatalf("addr = %q", addr)
	}
	if _, err := crypto.NewKey(keydata); err != nil {
		t.Fatalf("keydata is not a parseable binary key: %v", err)
	}
	_ = base64.StdEncoding // keydata already decoded by the parser
}

func TestBuildAutocryptHeaderSkips(t *testing.T) {
	if _, ok := buildAutocryptHeader("", "alice@example.com"); ok {
		t.Fatal("empty key must skip")
	}
	pub := generateArmoredKey(t, "alice@example.com")
	if _, ok := buildAutocryptHeader(pub, "someoneelse@example.com"); ok {
		t.Fatal("addr not a UID on the key must skip")
	}
	if _, ok := buildAutocryptHeader("not a real key", "alice@example.com"); ok {
		t.Fatal("unparseable armor must skip")
	}
}

// seedUserPGPKey stores an armored public key (carrying email as its UID) on
// the given user, mirroring how a real PGP identity gets persisted, without
// needing a working private-key envelope for these header-only tests.
func seedUserPGPKey(t *testing.T, s *Server, userID, email string) string {
	t.Helper()
	pub := generateArmoredKey(t, email)
	if _, err := s.users.SetPGPIdentity(userID, "fingerprint", "keyid", pub, "", "generated", "2026-07-24T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	return pub
}

func TestOutboundAutocryptHeaderAdvertisesWhenEnabled(t *testing.T) {
	s := newTestServer(t)
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	userID := all[0].ID
	seedUserPGPKey(t, s, userID, "alice@example.com")
	if err := pgpdiscovery.Save(s.userStateDir(userID), pgpdiscovery.Settings{AdvertiseAutocrypt: true}); err != nil {
		t.Fatalf("Save settings: %v", err)
	}

	got := s.outboundAutocryptHeader(userID, "alice@example.com")
	if !strings.HasPrefix(got, "addr=alice@example.com; keydata=") {
		t.Fatalf("expected header addressed to the envelope address, got %q", got)
	}
}

func TestOutboundAutocryptHeaderEmptyWhenAdvertiseDisabled(t *testing.T) {
	s := newTestServer(t)
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	userID := all[0].ID
	seedUserPGPKey(t, s, userID, "alice@example.com")
	if err := pgpdiscovery.Save(s.userStateDir(userID), pgpdiscovery.Settings{AdvertiseAutocrypt: false}); err != nil {
		t.Fatalf("Save settings: %v", err)
	}

	if got := s.outboundAutocryptHeader(userID, "alice@example.com"); got != "" {
		t.Fatalf("expected empty header when AdvertiseAutocrypt is off, got %q", got)
	}
}

func TestOutboundAutocryptHeaderEmptyWithNoUserKey(t *testing.T) {
	s := newTestServer(t)
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	userID := all[0].ID
	// AdvertiseAutocrypt defaults to true when no settings file has been
	// written (pgpdiscovery.Load), so this exercises "no PGPPublicKey" in
	// isolation rather than the discovery-settings gate.
	if got := s.outboundAutocryptHeader(userID, "alice@example.com"); got != "" {
		t.Fatalf("expected empty header when user has no PGP key, got %q", got)
	}
}

// TestOutboundAutocryptHeaderUsesEnvelopeAddress guards the
// envelopeFrom-vs-headerFrom choice at the handleMailSend call site: the addr
// passed in must be the bare envelope address. A display-name-decorated
// From value (what headerFrom carries) is not a UID match and must not
// produce a header.
func TestOutboundAutocryptHeaderUsesEnvelopeAddress(t *testing.T) {
	s := newTestServer(t)
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	userID := all[0].ID
	seedUserPGPKey(t, s, userID, "alice@example.com")
	if err := pgpdiscovery.Save(s.userStateDir(userID), pgpdiscovery.Settings{AdvertiseAutocrypt: true}); err != nil {
		t.Fatalf("Save settings: %v", err)
	}

	if got := s.outboundAutocryptHeader(userID, "Alice <alice@example.com>"); got != "" {
		t.Fatalf("expected empty header for a display-name-decorated (headerFrom-shaped) address, got %q", got)
	}
	got := s.outboundAutocryptHeader(userID, "alice@example.com")
	if !strings.HasPrefix(got, "addr=alice@example.com; keydata=") {
		t.Fatalf("expected header for the bare envelope address, got %q", got)
	}
}
