package users

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestValidEnvelopeSlot(t *testing.T) {
	tests := []struct {
		slot string
		want bool
	}{
		{"recovery", true},
		{"device:abc123", true},
		{"password", false}, // written only via RewrapPGPPrivateKey
		{"device:", false},
		{"", false},
		{"nonsense", false},
		{"device:has space", false},
		{"device:has\nnewline", false},
	}
	for _, tc := range tests {
		if got := ValidEnvelopeSlot(tc.slot); got != tc.want {
			t.Errorf("ValidEnvelopeSlot(%q) = %v, want %v", tc.slot, got, tc.want)
		}
	}
}

// The legacy single-blob field must present as the password slot, so callers
// have one way to ask "every sealing of this key" and legacy accounts need no
// migration pass over users.json.
func TestWrappedEnvelopesSynthesisesLegacyPasswordSlot(t *testing.T) {
	u := User{PGPPrivateKeyWrapped: `{"v":2}`}
	got := u.WrappedEnvelopes()
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[0].Envelope != `{"v":2}` {
		t.Fatalf("unexpected entry: %+v", got[0])
	}
}

func TestWrappedEnvelopesCombinesLegacyAndList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: `{"v":2,"slot":"pw"}`,
		PGPWrappedEnvelopes: []WrappedEnvelope{
			{Slot: EnvelopeSlotRecovery, Envelope: `{"v":2,"slot":"rec"}`},
		},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[1].Slot != EnvelopeSlotRecovery {
		t.Fatalf("unexpected order/slots: %+v", got)
	}
}

// A list entry claiming the password slot must not shadow the legacy field:
// one slot, one writer. Otherwise a caller that could write the list could
// replace the password envelope without going through RewrapPGPPrivateKey and
// its ErrNotClientProtected guard.
func TestWrappedEnvelopesIgnoresPasswordSlotInList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: "legit",
		PGPWrappedEnvelopes:  []WrappedEnvelope{{Slot: EnvelopeSlotPassword, Envelope: "impostor"}},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 1 || got[0].Envelope != "legit" {
		t.Fatalf("list entry shadowed the legacy password envelope: %+v", got)
	}
}

func TestWrappedEnvelopesEmptyWhenNoIdentity(t *testing.T) {
	if got := (User{}).WrappedEnvelopes(); len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

// clone() must deep-copy PGPWrappedEnvelopes for the same reason it deep-copies
// RecoveryCodesHash: Get and List hand callers a value read straight out of the
// Store's cache, and a slice field left shallow-copied still aliases the
// cache's own backing array. Mutating a slot through one Get's result must not
// be visible to the next Get — that's the store's read-your-writes contract for
// every OTHER caller, not just this one connection.
func TestGetClonesWrappedEnvelopesFromCache(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "dana", "pw-dana-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// No writer for PGPWrappedEnvelopes exists yet (Task 2+ adds one); mutate
	// sets the field directly through the store's own file-locked path, exactly
	// as a future slot-writer would.
	if _, err := store.mutate(u.ID, func(u *User) error {
		u.PGPWrappedEnvelopes = []WrappedEnvelope{{Slot: EnvelopeSlotRecovery, Envelope: "original"}}
		return nil
	}); err != nil {
		t.Fatalf("mutate: %v", err)
	}

	first, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	first.PGPWrappedEnvelopes[0].Envelope = "corrupted"

	second, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if second.PGPWrappedEnvelopes[0].Envelope != "original" {
		t.Fatalf("clone() shared the cache's backing array: second Get saw %q, want %q",
			second.PGPWrappedEnvelopes[0].Envelope, "original")
	}
}

func newClientProtectedUser(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "slotuser", "pw-slotuser-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR", "KID",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":true}`, "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return store, u.ID
}

func TestSetPGPWrappedEnvelopeAddsAndReplaces(t *testing.T) {
	store, id := newClientProtectedUser(t)

	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != 1 || got.PGPWrappedEnvelopes[0].Envelope != `{"v":2,"rec":1}` {
		t.Fatalf("after add: %+v", got.PGPWrappedEnvelopes)
	}

	// Replacing the same slot must overwrite in place, not append a second one:
	// two entries for one slot means an unlock path with no deterministic answer.
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":2}`, "2026-08-05T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope replace: %v", err)
	}
	got, _ = store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 1 || got.PGPWrappedEnvelopes[0].Envelope != `{"v":2,"rec":2}` {
		t.Fatalf("after replace: %+v", got.PGPWrappedEnvelopes)
	}
	// The password envelope is untouched by slot writes.
	if got.PGPPrivateKeyWrapped != `{"v":2,"pw":true}` {
		t.Fatalf("password envelope was disturbed: %q", got.PGPPrivateKeyWrapped)
	}
}

func TestSetPGPWrappedEnvelopeRejectsPasswordSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	_, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotPassword, `{"v":2}`, "")
	if !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}

func TestSetPGPWrappedEnvelopeRejectsUnknownSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, "nonsense", `{"v":2}`, ""); !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}

func TestSetPGPWrappedEnvelopeRequiresClientProtection(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "legacy", "pw-legacy-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed", "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	// A server-custody account has no browser envelope, so an extra sealing of
	// "the key" would seal nothing the user holds.
	if _, err := store.SetPGPWrappedEnvelope(u.ID, EnvelopeSlotRecovery, `{"v":2}`, ""); !errors.Is(err, ErrNotClientProtected) {
		t.Fatalf("err = %v, want ErrNotClientProtected", err)
	}
}

func TestDeletePGPWrappedEnvelope(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("DeletePGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("still present: %+v", got.PGPWrappedEnvelopes)
	}
	// Deleting an absent slot is not an error: the caller's goal is "this slot
	// is gone", and that is already true.
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	// The password envelope survives, so the account is never left unopenable.
	got, _ = store.Get(id)
	if got.PGPPrivateKeyWrapped == "" {
		t.Fatal("delete removed the password envelope")
	}
}

// The filter's whole job is the e.Slot != slot condition. With only one slot
// ever populated, a bug that deleted every envelope regardless of slot would
// pass every other test here — so this one populates two distinct slots
// (covering both accepted shapes: EnvelopeSlotRecovery and a device: slot),
// deletes one, and checks the other survives with its original value.
func TestDeletePGPWrappedEnvelopeLeavesOtherSlotsIntact(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope recovery: %v", err)
	}
	if _, err := store.SetPGPWrappedEnvelope(id, "device:abc123", `{"v":2,"dev":1}`, "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope device: %v", err)
	}

	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("DeletePGPWrappedEnvelope: %v", err)
	}

	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got.PGPWrappedEnvelopes), got.PGPWrappedEnvelopes)
	}
	if got.PGPWrappedEnvelopes[0].Slot != "device:abc123" || got.PGPWrappedEnvelopes[0].Envelope != `{"v":2,"dev":1}` {
		t.Fatalf("surviving slot corrupted or wrong: %+v", got.PGPWrappedEnvelopes[0])
	}
	// The password envelope is untouched by a slot delete.
	if got.PGPPrivateKeyWrapped != `{"v":2,"pw":true}` {
		t.Fatalf("password envelope was disturbed: %q", got.PGPPrivateKeyWrapped)
	}
}

func TestDeletePGPWrappedEnvelopeRejectsPasswordSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotPassword); !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}

// A new identity means every non-password slot seals a key this account no
// longer advertises. Leaving them would tell the user a recovery code still
// opens their mail when it opens a key nobody encrypts to any more.
func TestSetPGPIdentityClientProtectedDropsStaleSlots(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"old":true}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.SetPGPIdentityClientProtected(id, "FPR2", "KID2",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":2}`, "generated", "2026-08-06T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("stale slots survived an identity replacement: %+v", got.PGPWrappedEnvelopes)
	}
}

func TestClearPGPIdentityDropsSlots(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.ClearPGPIdentity(id); err != nil {
		t.Fatalf("ClearPGPIdentity: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("slots survived ClearPGPIdentity: %+v", got.PGPWrappedEnvelopes)
	}
}
