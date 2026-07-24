package processor

import (
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpmail"
)

// autocryptTestKey returns a fresh armored public key + fingerprint for addr.
func autocryptTestKey(t *testing.T, name, addr string) (armored, fingerprint string) {
	t.Helper()
	id, err := pgpmail.GenerateIdentity(name, addr)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id.ArmoredPublicKey, id.Fingerprint
}

func TestHarvestPinCreatesContact(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Alice", "alice@example.com")

	action, err := harvestPinAutocryptKey(store, "alice@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestCreated {
		t.Fatalf("action = %q, want created", action)
	}
	c, ok := findContactByEmail(store, "alice@example.com")
	if !ok {
		t.Fatalf("expected a created contact")
	}
	if c.PGPKeySource != contacts.PGPSourceAutocrypt || c.PGPKeyFingerprint != fp || c.PGPKeyVerified {
		t.Fatalf("unexpected provenance: %+v", c)
	}
	if !c.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=true on an auto-created contact")
	}
}

func TestHarvestPinFillsExistingContactGap(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Bob", "bob@example.com")

	action, err := harvestPinAutocryptKey(store, "bob@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestPinned {
		t.Fatalf("action = %q, want pinned", action)
	}
	c, _ := store.Get(existing.UID)
	if c.PGPKeySource != contacts.PGPSourceAutocrypt || c.PGPKeyFingerprint != fp {
		t.Fatalf("expected autocrypt key pinned, got %+v", c)
	}
	if c.DiscoveryCreated {
		t.Fatalf("DiscoveryCreated must stay false on a pre-existing contact")
	}
}

func TestHarvestPinSkipsStrongerSource(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	manualArmored, manualFP := autocryptTestKey(t, "Carol Manual", "carol@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Carol",
		Emails:            []contacts.ContactValue{{Value: "carol@example.com"}},
		PGPKey:            manualArmored,
		PGPKeyFingerprint: manualFP,
		PGPKeySource:      contacts.PGPSourceWKD,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	autoArmored, autoFP := autocryptTestKey(t, "Carol Auto", "carol@example.com")

	action, err := harvestPinAutocryptKey(store, "carol@example.com", autoArmored, autoFP)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestSkipped {
		t.Fatalf("action = %q, want skipped", action)
	}
	c, _ := store.Get(existing.UID)
	if c.PGPKeyFingerprint != manualFP || c.PGPKeySource != contacts.PGPSourceWKD {
		t.Fatalf("existing wkd key must be untouched, got %+v", c)
	}
}

func TestHarvestPinUpdatesOlderAutocryptKey(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	oldArmored, oldFP := autocryptTestKey(t, "Dave Old", "dave@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Dave",
		Emails:            []contacts.ContactValue{{Value: "dave@example.com"}},
		PGPKey:            oldArmored,
		PGPKeyFingerprint: oldFP,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	newArmored, newFP := autocryptTestKey(t, "Dave New", "dave@example.com")
	if newFP == oldFP {
		t.Fatalf("test setup: expected two distinct fingerprints")
	}

	action, err := harvestPinAutocryptKey(store, "dave@example.com", newArmored, newFP)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestUpdated {
		t.Fatalf("action = %q, want updated", action)
	}
	c, _ := store.Get(existing.UID)
	if c.PGPKeyFingerprint != newFP {
		t.Fatalf("expected newest autocrypt key to win, got %+v", c)
	}
}

func TestHarvestPinSameAutocryptFingerprintIsNoop(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Erin", "erin@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Erin",
		Emails:            []contacts.ContactValue{{Value: "erin@example.com"}},
		PGPKey:            armored,
		PGPKeyFingerprint: fp,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	action, err := harvestPinAutocryptKey(store, "erin@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestUnchanged {
		t.Fatalf("action = %q, want unchanged", action)
	}
	c, _ := store.Get(existing.UID)
	if c.Rev != existing.Rev {
		t.Fatalf("no-op must not bump Rev: was %d now %d", existing.Rev, c.Rev)
	}
}
