package api

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpautocrypt"
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
}
