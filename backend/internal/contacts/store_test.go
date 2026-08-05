package contacts

import (
	"fmt"
	"testing"
)

// TestUpsertEnforcesAPerUserContactCap pins the bound every sibling store has
// and this one does not.
//
// groups caps at 1000, rules at 100, send-as at 20, native devices at 20,
// pickups at 100 and contact photos at 200 MiB. contacts has no total cap at
// all: maxContactsSyncChanges bounds one REQUEST, not the store, so an
// unmetered device-credential sync loop grows contacts.json without limit on a
// volume shared with every other user's mail cache and sealed key material.
func TestUpsertEnforcesAPerUserContactCap(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedContactsToCap(t, store)
	if _, err := store.Upsert(Contact{FormattedName: "one too many"}); err == nil {
		t.Fatalf("store accepted more than %d contacts", MaxContactsPerUser)
	}
}

// TestUpsertAtTheCapStillAllowsUpdates is the control: the cap must bound
// growth, not freeze the address book. Editing an existing contact at the cap
// has to keep working, or a full store becomes read-only.
func TestUpsertAtTheCapStillAllowsUpdates(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	seedContactsToCap(t, store)
	all := store.List()
	if len(all) != MaxContactsPerUser {
		t.Fatalf("seeded %d contacts, want %d", len(all), MaxContactsPerUser)
	}
	first := all[0]
	first.FormattedName = "renamed"
	if _, err := store.Upsert(first); err != nil {
		t.Fatalf("updating an existing contact at the cap must still work: %v", err)
	}
}

// seedContactsToCap fills the store to exactly MaxContactsPerUser using a single
// batch, because Upsert persists the whole file per call and doing that
// MaxContactsPerUser times is quadratic.
func seedContactsToCap(t *testing.T, store *Store) {
	t.Helper()
	ops := make([]BatchOp, 0, MaxContactsPerUser)
	for i := 0; i < MaxContactsPerUser; i++ {
		ops = append(ops, BatchOp{Contact: Contact{
			UID:           fmt.Sprintf("seed-%d", i),
			FormattedName: fmt.Sprintf("c%d", i),
		}})
	}
	if err := store.ApplyBatch(ops); err != nil {
		t.Fatalf("ApplyBatch seeding to cap: %v", err)
	}
}
