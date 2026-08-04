package users

import (
	"context"
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
