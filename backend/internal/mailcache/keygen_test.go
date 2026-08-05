package mailcache

import (
	"path/filepath"
	"testing"
)

// TestSyncContactKeyGenerationDropsVerdictsFromAnOlderGeneration pins the
// mechanism that makes verdict invalidation cover every contact writer.
//
// The handler-level helper is called from three sites and misses eight — mobile
// sync, CardDAV PUT, CardDAV pull, vCard import, the resolver's pin, dedupe, the
// discovery-suppression button (the product's own "remove this key" control),
// and the daemon's three Autocrypt writes. The daemon ones cannot use it at all,
// having no *http.Request. A generation carried with the verdict is what every
// writer bumps for free.
func TestSyncContactKeyGenerationDropsVerdictsFromAnOlderGeneration(t *testing.T) {
	dir := t.TempDir()
	store, err := New(filepath.Join(dir))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Upsert("INBOX", []Entry{{
		UID:                     1,
		MessageID:               "1",
		Body:                    "hello",
		PGPSigned:               true,
		PGPVerified:             true,
		PGPSignerFingerprint:    "AAAA",
		PGPVerdictSchemaVersion: PGPVerdictSchema,
		ContactKeyGen:           7,
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Same generation: the verdict stands.
	if err := store.SyncContactKeyGeneration(7); err != nil {
		t.Fatalf("SyncContactKeyGeneration: %v", err)
	}
	entries, _ := store.Snapshot("INBOX", 10)
	if len(entries) != 1 || !entries[0].PGPVerified {
		t.Fatalf("verdict was dropped despite an unchanged address book: %+v", entries)
	}

	// The address book changed: the verdict's basis has moved.
	if err := store.SyncContactKeyGeneration(8); err != nil {
		t.Fatalf("SyncContactKeyGeneration: %v", err)
	}
	entries, _ = store.Snapshot("INBOX", 10)
	if len(entries) == 1 && entries[0].PGPVerified {
		t.Fatal("a cached 'signature verified' verdict survived a change to the " +
			"address book it was derived from")
	}
}
