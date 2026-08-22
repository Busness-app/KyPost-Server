package contacts

import "testing"

// TestPGPKeyGenerationChangesWhenKeyMaterialChanges pins the signal that lets
// cached signature verdicts be invalidated by EVERY writer.
//
// invalidatePGPVerdictsOnKeyChange is called from three handler sites and is the
// only caller of mailcache.InvalidatePGPVerdicts. Eight other paths write a
// contact's PGP key — suppress-contact (the product's own "remove this key"
// button), mobile sync, CardDAV PUT, CardDAV pull, vCard import, the resolver's
// pin, dedupe, and the daemon's Autocrypt harvest — and none of them invalidate.
// The daemon ones cannot use a handler-level helper at all: they run in another
// process with no *http.Request.
//
// A generation counter on the store is what every writer inherits for free, in
// both processes, because it travels with the file.
func TestPGPKeyGenerationChangesWhenKeyMaterialChanges(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := store.Upsert(Contact{
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "KEY-A",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	before := mustPGPKeyGeneration(t, store)

	c.PGPKey = "KEY-B"
	if _, err := store.Upsert(c); err != nil {
		t.Fatalf("Upsert (key change): %v", err)
	}
	if mustPGPKeyGeneration(t, store) == before {
		t.Fatal("generation unchanged after a contact's PGP key was replaced")
	}
}

// TestPGPKeyGenerationChangesWhenAnAddressIsRemoved covers the case the
// handler-level helper explicitly misses: it returns early when
// before.PGPKey == after.PGPKey, so narrowing a contact's addresses — which
// directly narrows what the key is an anchor for — invalidated nothing.
func TestPGPKeyGenerationChangesWhenAnAddressIsRemoved(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := store.Upsert(Contact{
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}, {Value: "bob@old.example"}},
		PGPKey:        "KEY-A",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	before := mustPGPKeyGeneration(t, store)

	c.Emails = []ContactValue{{Value: "bob@example.com"}}
	if _, err := store.Upsert(c); err != nil {
		t.Fatalf("Upsert (address removal): %v", err)
	}
	if mustPGPKeyGeneration(t, store) == before {
		t.Fatal("generation unchanged after a contact's address set narrowed")
	}
}

// TestPGPKeyGenerationIsStableForUnrelatedEdits guards against over-triggering:
// renaming a contact must not invalidate every cached verdict on the instance.
func TestPGPKeyGenerationIsStableForUnrelatedEdits(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c, err := store.Upsert(Contact{
		FormattedName: "Bob",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "KEY-A",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	before := mustPGPKeyGeneration(t, store)

	c.FormattedName = "Robert"
	if _, err := store.Upsert(c); err != nil {
		t.Fatalf("Upsert (rename): %v", err)
	}
	if mustPGPKeyGeneration(t, store) != before {
		t.Fatal("a rename bumped the key generation, invalidating unrelated verdicts")
	}
}
