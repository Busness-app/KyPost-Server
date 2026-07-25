package pgpmail

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if id.ArmoredPublicKey == "" {
		t.Fatal("expected non-empty armored public key")
	}
}

// userIDEmails returns the lowercased email of every User ID on an armored
// key, which is what the address-binding checks elsewhere in the codebase
// (validateDiscoveredKey, buildAutocryptHeader) match against.
func userIDEmails(t *testing.T, armored string) []string {
	t.Helper()
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("parse armored key: %v", err)
	}
	entity := key.GetEntity()
	if entity == nil {
		t.Fatal("key has no entity")
	}
	var out []string
	for _, uid := range entity.Identities {
		out = append(out, strings.ToLower(uid.UserId.Email))
	}
	sort.Strings(out)
	return out
}

func TestGenerateIdentityCarriesAdditionalAddressesAsUserIDs(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com", "alice@other.example", "sales@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	got := userIDEmails(t, id.ArmoredPublicKey)
	want := []string{"alice@example.com", "alice@other.example", "sales@example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("user ID emails: got %v want %v", got, want)
	}
}

// TestGenerateIdentitySkipsDuplicateAndEmptyAdditionalAddresses covers the
// two inputs the send-as store can realistically hand this function: the
// account address itself showing up again as a verified alias, and a blank
// entry. Neither may produce a duplicate or empty User ID.
func TestGenerateIdentitySkipsDuplicateAndEmptyAdditionalAddresses(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com", "ALICE@example.com", "  ", "alice@other.example", "alice@other.example")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	got := userIDEmails(t, id.ArmoredPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("user ID emails: got %v want %v", got, want)
	}
}

// TestUserIDEmailsListsEveryAddressNormalized covers the cheap public-key
// gate the reconciler uses to decide whether any private-key work is needed
// at all.
func TestUserIDEmailsListsEveryAddressNormalized(t *testing.T) {
	id, err := GenerateIdentity("Alice", "Alice@Example.com", "alice@other.example")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	got, err := UserIDEmails(id.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("UserIDEmails: %v", err)
	}
	sort.Strings(got)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("UserIDEmails: got %v want %v", got, want)
	}
}

func TestUserIDEmailsRejectsUnparseableKey(t *testing.T) {
	if _, err := UserIDEmails("not an armored key"); err == nil {
		t.Fatal("expected an error for an unparseable key")
	}
}

func TestAddUserIDAddsAddressToExistingKey(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	fingerprintBefore := id.Fingerprint

	added, err := id.AddUserID("Alice", "alice@other.example")
	if err != nil {
		t.Fatalf("AddUserID: %v", err)
	}
	if !added {
		t.Fatal("AddUserID reported no change for a new address")
	}
	got := userIDEmails(t, id.ArmoredPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("user ID emails: got %v want %v", got, want)
	}
	// Adding a User ID must not mint a new key: the fingerprint is what
	// contacts and published-key consumers pin.
	if id.Fingerprint != fingerprintBefore {
		t.Fatalf("fingerprint changed: got %s want %s", id.Fingerprint, fingerprintBefore)
	}
}

// TestAddUserIDIsIdempotent matters because alias verification can re-run
// (a re-added alias, a restored backup); a second call must not append a
// duplicate User ID for an address the key already carries.
func TestAddUserIDIsIdempotent(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := id.AddUserID("Alice", "alice@other.example"); err != nil {
		t.Fatalf("AddUserID: %v", err)
	}
	added, err := id.AddUserID("Alice", "ALICE@other.example")
	if err != nil {
		t.Fatalf("AddUserID (repeat): %v", err)
	}
	if added {
		t.Fatal("AddUserID reported a change for an address the key already carries")
	}
	got := userIDEmails(t, id.ArmoredPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("user ID emails: got %v want %v", got, want)
	}
}

// TestAddUserIDSurvivesSealRoundTrip confirms the added User ID is carried
// by the private key material too, not just the in-memory armored public
// key — the alias-verification path re-seals and reloads the identity.
func TestAddUserIDSurvivesSealRoundTrip(t *testing.T) {
	id, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := id.AddUserID("Alice", "alice@other.example"); err != nil {
		t.Fatalf("AddUserID: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "pgp-private-key.key")
	sealed, err := id.SealPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	opened, err := OpenPrivateKey(sealed, keyPath)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	got := userIDEmails(t, opened.ArmoredPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("user ID emails after round trip: got %v want %v", got, want)
	}
}

func TestSealOpenPrivateKeyRoundTrip(t *testing.T) {
	id, err := GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "pgp-private-key.key")

	sealed, err := id.SealPrivateKey(keyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if sealed == "" {
		t.Fatal("expected non-empty sealed envelope")
	}

	opened, err := OpenPrivateKey(sealed, keyPath)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	if opened.Fingerprint != id.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", opened.Fingerprint, id.Fingerprint)
	}
}

func TestImportIdentityWithPassphrase(t *testing.T) {
	keyGen := crypto.PGP().KeyGeneration().AddUserId("Carol", "carol@example.com").New()
	key, err := keyGen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	locked, err := crypto.PGP().LockKey(key, []byte("s3cret"))
	if err != nil {
		t.Fatalf("LockKey: %v", err)
	}
	armoredLocked, err := locked.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}

	id, err := ImportIdentity(armoredLocked, "s3cret")
	if err != nil {
		t.Fatalf("ImportIdentity: %v", err)
	}
	if id.Fingerprint != key.GetFingerprint() {
		t.Fatalf("fingerprint mismatch: got %s want %s", id.Fingerprint, key.GetFingerprint())
	}

	if _, err := ImportIdentity(armoredLocked, "wrong-passphrase"); err == nil {
		t.Fatal("expected error unlocking with wrong passphrase")
	}
}

func TestImportIdentityRejectsPublicOnlyKey(t *testing.T) {
	id, err := GenerateIdentity("Dave", "dave@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := ImportIdentity(id.ArmoredPublicKey, ""); err == nil {
		t.Fatal("expected error importing a public-only key as a private identity")
	}
}
