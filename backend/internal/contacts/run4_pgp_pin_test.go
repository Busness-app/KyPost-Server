package contacts

import (
	"testing"
)

// run-4 M3: the TOFU key pin was stripped by three of five contact write paths.
//
// backfillPGPKeyFingerprint exists so an unpinned manual key cannot be silently
// overwritten by a later WKD lookup once it expires, but it was applied only at
// the two JSON handlers. POST /api/contacts/sync, CardDAV PutAddressObject and
// vCard import all went straight to Upsert, and contactPayload.toContact never
// copied PGPKeyFingerprint/PGPKeySource/PGPKeyVerified — so one routine phone
// sync left the key in place with fingerprint="" and verified=false.
//
// That matters because the resolver's tierKeyChanged refusal is gated on
// pinnedFP != "". Once the pin is gone, an expired or revoked key lets the next
// WKD result be auto-trusted, pinned, and used to encrypt — which is the silent
// key-substitution the pin exists to prevent.
//
// Fixed in upsertLocked rather than at the call sites, so a sixth write path
// cannot miss it.

const testArmoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"
const otherArmoredKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nxyz\n-----END PGP PUBLIC KEY BLOCK-----"

func seedPinnedContact(t *testing.T) (*Store, Contact) {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := store.Upsert(Contact{
		FormattedName:     "Bob",
		PGPKey:            testArmoredKey,
		PGPKeyFingerprint: "AAAA1111BBBB2222",
		PGPKeySource:      "manual",
		PGPKeyVerified:    true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return store, c
}

// The exact reproduction: a sync/CardDAV/import write echoes the key back but
// carries no provenance, because its payload type has no field for it.
func TestUpsertKeepsPinWhenWriterOmitsProvenance(t *testing.T) {
	store, seeded := seedPinnedContact(t)

	updated, err := store.Upsert(Contact{
		UID:           seeded.UID,
		FormattedName: "Bob Smith",
		PGPKey:        testArmoredKey,
		// No PGPKeyFingerprint / PGPKeySource / PGPKeyVerified.
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if updated.PGPKeyFingerprint != "AAAA1111BBBB2222" {
		t.Fatalf("pin was stripped: %q", updated.PGPKeyFingerprint)
	}
	if updated.PGPKeySource != "manual" {
		t.Fatalf("key source was stripped: %q", updated.PGPKeySource)
	}
	if !updated.PGPKeyVerified {
		t.Fatal("verified flag was stripped")
	}
	// The rest of the write must still land.
	if updated.FormattedName != "Bob Smith" {
		t.Fatalf("name did not update: %q", updated.FormattedName)
	}
}

// Carrying the pin forward must survive a round trip through the file, not just
// the in-memory copy the caller gets back.
func TestUpsertPinSurvivesReRead(t *testing.T) {
	store, seeded := seedPinnedContact(t)

	if _, err := store.Upsert(Contact{UID: seeded.UID, FormattedName: "Bob", PGPKey: testArmoredKey}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok := store.Get(seeded.UID)
	if !ok {
		t.Fatal("contact not found")
	}
	if got.PGPKeyFingerprint != "AAAA1111BBBB2222" || got.PGPKeySource != "manual" || !got.PGPKeyVerified {
		t.Fatalf("provenance lost on re-read: %+v", got)
	}
}

// A genuinely different key is a genuinely different pin. Carrying the old
// fingerprint onto new key material would be worse than dropping it — the
// record would claim a pin that does not describe the key it sits next to, and
// the resolver's tierKeyChanged check would compare against a fingerprint no
// key has.
func TestUpsertDoesNotCarryPinOntoADifferentKey(t *testing.T) {
	store, seeded := seedPinnedContact(t)

	updated, err := store.Upsert(Contact{
		UID:           seeded.UID,
		FormattedName: "Bob",
		PGPKey:        otherArmoredKey,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if updated.PGPKeyFingerprint == "AAAA1111BBBB2222" {
		t.Fatal("the old pin was carried onto different key material")
	}
}

// Removing the key removes the pin with it: a pin with no key describes
// nothing.
func TestUpsertClearingTheKeyClearsTheProvenance(t *testing.T) {
	store, seeded := seedPinnedContact(t)

	updated, err := store.Upsert(Contact{UID: seeded.UID, FormattedName: "Bob"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if updated.PGPKeyFingerprint != "" || updated.PGPKeySource != "" || updated.PGPKeyVerified {
		t.Fatalf("provenance outlived the key it described: %+v", updated)
	}
}

// A writer that DOES supply provenance is authoritative — this is how the
// resolver re-pins after a verified key change, and how backfill fills in a
// fingerprint for a manually pasted key.
func TestUpsertLetsAnExplicitWriterSetProvenance(t *testing.T) {
	store, seeded := seedPinnedContact(t)

	updated, err := store.Upsert(Contact{
		UID:               seeded.UID,
		FormattedName:     "Bob",
		PGPKey:            testArmoredKey,
		PGPKeyFingerprint: "CCCC3333DDDD4444",
		PGPKeySource:      "wkd",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if updated.PGPKeyFingerprint != "CCCC3333DDDD4444" {
		t.Fatalf("explicit pin was overridden: %q", updated.PGPKeyFingerprint)
	}
	if updated.PGPKeySource != "wkd" {
		t.Fatalf("explicit source was overridden: %q", updated.PGPKeySource)
	}
}
