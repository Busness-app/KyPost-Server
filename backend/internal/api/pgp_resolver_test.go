package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

func TestResolveUsesWKDAndPinsContact(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Erin", "erin@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("erin")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	kr := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	got := kr.resolve(context.Background(), "erin@example.com")
	if !got.Usable || got.Tier != tierWKD {
		t.Fatalf("expected usable WKD tier, got %+v", got)
	}
	if _, ok := findContactPGPKey(store, "erin@example.com"); !ok {
		t.Fatalf("expected the WKD key to be pinned to a contact")
	}
}

// generateExpiredIdentity builds a same-shape key to GenerateIdentity's
// output, except it is already expired (generated in the past with a short
// lifetime) — mirroring the pattern in keystatus_test.go. The resolver's
// pinned-key gate (resolve step 1) only falls through to WKD/keyserver
// discovery when the pinned key is no longer usable, so the TOFU-mismatch
// branch (tierKeyChanged) can only be exercised with a stale pinned key,
// not two equally-fresh identities.
func generateExpiredIdentity(t *testing.T, name, email string) (armored, fingerprint string) {
	t.Helper()
	past := time.Now().Add(-48 * time.Hour)
	key, err := crypto.PGP().KeyGeneration().
		GenerationTime(past.Unix()).
		Lifetime(3600).
		AddUserId(name, email).
		New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (expired): %v", err)
	}
	armored, err = key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	return armored, key.GetFingerprint()
}

func TestResolveTOFUMismatchDoesNotSwitch(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	// Contact pinned with identity A's (now-expired, so no-longer-usable)
	// key and fingerprint; WKD serves identity B's key for the same
	// address. The resolver must not switch to B — it reports
	// tierKeyChanged/Usable=false and leaves the pinned key alone.
	armoredA, fpA := generateExpiredIdentity(t, "Alice A", "alice@example.com")
	idB, err := pgpmail.GenerateIdentity("Alice B", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity B: %v", err)
	}

	keyB, _ := crypto.NewKeyFromArmored(idB.ArmoredPublicKey)
	binKeyB, _ := keyB.GetPublicKey()
	hu := wkdHashLocalPart("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKeyB)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}

	pinned, err := store.Upsert(contacts.Contact{
		FormattedName:     "Alice",
		Emails:            []contacts.ContactValue{{Value: "alice@example.com"}},
		PGPKey:            armoredA,
		PGPKeyFingerprint: fpA,
		PGPKeySource:      contacts.PGPSourceManual,
		PGPKeyVerified:    true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	kr := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	got := kr.resolve(context.Background(), "alice@example.com")
	if got.Tier != tierKeyChanged {
		t.Fatalf("expected tierKeyChanged, got %+v", got)
	}
	if got.Usable {
		t.Fatalf("expected Usable=false on key-changed TOFU mismatch, got %+v", got)
	}

	after, ok := store.Get(pinned.UID)
	if !ok {
		t.Fatalf("expected contact %s to still exist", pinned.UID)
	}
	if after.PGPKey != armoredA {
		t.Fatalf("expected pinned key to remain identity A's key, got a different key")
	}
	if after.PGPKeyFingerprint != fpA {
		t.Fatalf("expected pinned fingerprint to remain %s, got %s", fpA, after.PGPKeyFingerprint)
	}
}
