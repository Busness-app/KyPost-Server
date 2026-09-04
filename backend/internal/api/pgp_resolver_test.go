package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
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
	if _, ok := must2(findContactPGPKey(store, "erin@example.com")); !ok {
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

	after, ok := must2(store.Get(pinned.UID))
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

// TestResolvePreservesManualVerificationOnSameFingerprint covers the pin()
// fix: when WKD re-serves the *same* key (same fingerprint) already pinned
// to a manually verified contact — e.g. the pinned copy expired and the
// resolver falls through to WKD, which happens to be serving a renewed,
// unexpired self-signature over the identical primary key — the refresh
// must not downgrade the contact's existing manual verification.
func TestResolvePreservesManualVerificationOnSameFingerprint(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	// Identity A's pinned copy carries an already-expired self-signature
	// (mirrors generateExpiredIdentity) so resolve() falls through past
	// step 1 to WKD discovery.
	past := time.Now().Add(-48 * time.Hour)
	genKey, err := crypto.PGP().KeyGeneration().
		GenerationTime(past.Unix()).
		Lifetime(3600).
		AddUserId("Alice A", "alice@example.com").
		New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (expired): %v", err)
	}
	armoredA, err := genKey.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	fpA := genKey.GetFingerprint()

	// Build a "renewed" copy of the SAME primary key — same fingerprint,
	// since the primary key packet (and its creation time) is unchanged —
	// by re-signing the identity with a fresh, unexpired self-signature.
	// This simulates WKD serving a refreshed/re-signed copy of the key
	// already pinned to the contact.
	entity := genKey.GetEntity()
	var ident *openpgp.Identity
	for _, v := range entity.Identities {
		ident = v
		break
	}
	if ident == nil || len(ident.SelfCertifications) == 0 {
		t.Fatalf("expected an identity with a self-certification")
	}
	selfCert := ident.SelfCertifications[0]
	renewedLifetime := uint32(365 * 24 * 3600)
	selfCert.Packet.KeyLifetimeSecs = &renewedLifetime
	if err := selfCert.Packet.SignUserId(ident.UserId.Id, entity.PrimaryKey, entity.PrivateKey, nil); err != nil {
		t.Fatalf("re-sign renewed self-signature: %v", err)
	}
	selfCert.Valid = nil // force re-verification against the new signature bytes
	renewedKey, err := crypto.NewKeyFromEntity(entity)
	if err != nil {
		t.Fatalf("NewKeyFromEntity: %v", err)
	}
	if renewedKey.GetFingerprint() != fpA {
		t.Fatalf("expected renewed key to share fingerprint %s, got %s", fpA, renewedKey.GetFingerprint())
	}
	binKey, err := renewedKey.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey (renewed, binary): %v", err)
	}
	hu := wkdHashLocalPart("alice")
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
	if !got.Usable || got.Tier != tierWKD {
		t.Fatalf("expected usable WKD tier, got %+v", got)
	}
	if !strings.EqualFold(got.Fingerprint, fpA) {
		t.Fatalf("expected resolved fingerprint to match identity A's %s, got %s", fpA, got.Fingerprint)
	}

	after, ok := must2(store.Get(pinned.UID))
	if !ok {
		t.Fatalf("expected contact %s to still exist", pinned.UID)
	}
	if after.PGPKeySource != contacts.PGPSourceManual {
		t.Fatalf("expected PGPKeySource to remain %q, got %q", contacts.PGPSourceManual, after.PGPKeySource)
	}
	if !after.PGPKeyVerified {
		t.Fatalf("expected PGPKeyVerified to remain true on same-fingerprint refresh")
	}
}

func TestResolveMarksDiscoveryCreatedOnNewContact(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Gale", "gale@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("gale")
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

	if got := kr.resolve(context.Background(), "gale@example.com"); got.Tier != tierWKD {
		t.Fatalf("expected tierWKD, got %+v", got)
	}
	c, ok := must2(findContact(store, "gale@example.com"))
	if !ok {
		t.Fatalf("expected an auto-created contact")
	}
	if !c.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=true on an auto-created contact")
	}
}

func TestResolveDoesNotMarkDiscoveryCreatedOnExistingContact(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Hana", "hana@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("hana")
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
	// Pre-existing contact with no key — the user made this one.
	pinned, err := store.Upsert(contacts.Contact{
		FormattedName: "Hana",
		Emails:        []contacts.ContactValue{{Value: "hana@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	kr := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	if got := kr.resolve(context.Background(), "hana@example.com"); got.Tier != tierWKD {
		t.Fatalf("expected tierWKD, got %+v", got)
	}
	after, ok := must2(store.Get(pinned.UID))
	if !ok {
		t.Fatalf("expected contact %s to still exist", pinned.UID)
	}
	if after.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=false when pinning onto a pre-existing contact")
	}
}

func TestResolveSkipsSuppressedAddress(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	// A WKD server that FAILS the test if it is ever hit — a suppressed
	// address must not trigger any discovery lookup.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("WKD lookup fired for a suppressed address: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	kr := &keyResolver{
		store:      store,
		settings:   pgpdiscovery.Settings{StoreDiscoveredKeys: true},
		discover:   true,
		suppressed: map[string]bool{"erin@example.com": true},
	}

	got := kr.resolve(context.Background(), "Erin@Example.com")
	if got.Tier != tierNone {
		t.Fatalf("expected tierNone for a suppressed address, got %+v", got)
	}
	if _, ok := must2(findContact(store, "erin@example.com")); ok {
		t.Fatalf("expected no contact to be auto-created for a suppressed address")
	}
}

func TestResolveSuppressionDoesNotBlockManualKey(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Fred", "fred@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName:     "Fred",
		Emails:            []contacts.ContactValue{{Value: "fred@example.com"}},
		PGPKey:            id.ArmoredPublicKey,
		PGPKeyFingerprint: key.GetFingerprint(),
		PGPKeySource:      contacts.PGPSourceManual,
		PGPKeyVerified:    true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	kr := &keyResolver{
		store:      store,
		settings:   pgpdiscovery.Settings{StoreDiscoveredKeys: true},
		discover:   true,
		suppressed: map[string]bool{"fred@example.com": true},
	}

	got := kr.resolve(context.Background(), "fred@example.com")
	if !got.Usable || got.Tier != tierContactVerified {
		t.Fatalf("expected a suppressed address to still use its manual pinned key, got %+v", got)
	}
}
