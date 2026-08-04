package users

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if got.PGPWrappedEnvelopes[0].AddedAt != "2026-08-04T00:00:00Z" {
		t.Fatalf("after add: AddedAt = %q, want 2026-08-04T00:00:00Z", got.PGPWrappedEnvelopes[0].AddedAt)
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
	// A stale AddedAt would pass a check that only compares Envelope, and the
	// browser renders this value as "recovery code created on X" — a rotated
	// slot must report the rotation's own timestamp, not the original add's.
	if got.PGPWrappedEnvelopes[0].AddedAt != "2026-08-05T00:00:00Z" {
		t.Fatalf("after replace: AddedAt = %q, want 2026-08-05T00:00:00Z (stale timestamp)", got.PGPWrappedEnvelopes[0].AddedAt)
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

// Adding fills to maxWrappedEnvelopeSlots must be refused past the cap, but a
// REPLACE of a slot already held must keep working exactly at the cap — a
// user who reaches it still needs to rotate a compromised recovery code or
// re-pair a device, and the cap exists to bound growth, not to lock them out
// of the slots they already have.
func TestSetPGPWrappedEnvelopeEnforcesCapOnAddNotReplace(t *testing.T) {
	store, id := newClientProtectedUser(t)

	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope recovery: %v", err)
	}
	for i := 0; i < maxWrappedEnvelopeSlots-1; i++ {
		slot := fmt.Sprintf("device:d%d", i)
		if _, err := store.SetPGPWrappedEnvelope(id, slot, `{"v":2}`, ""); err != nil {
			t.Fatalf("SetPGPWrappedEnvelope(%s): %v", slot, err)
		}
	}
	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != maxWrappedEnvelopeSlots {
		t.Fatalf("len = %d, want %d (at cap)", len(got.PGPWrappedEnvelopes), maxWrappedEnvelopeSlots)
	}

	// One more NEW slot must be refused.
	if _, err := store.SetPGPWrappedEnvelope(id, "device:one-too-many", `{"v":2}`, ""); !errors.Is(err, ErrTooManyEnvelopeSlots) {
		t.Fatalf("err = %v, want ErrTooManyEnvelopeSlots", err)
	}
	got, _ = store.Get(id)
	if len(got.PGPWrappedEnvelopes) != maxWrappedEnvelopeSlots {
		t.Fatalf("a refused add still changed the slot count: len = %d", len(got.PGPWrappedEnvelopes))
	}

	// Replacing an EXISTING slot must still succeed at the cap.
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":2}`, ""); err != nil {
		t.Fatalf("replace at cap: %v", err)
	}
	got, _ = store.Get(id)
	if len(got.PGPWrappedEnvelopes) != maxWrappedEnvelopeSlots {
		t.Fatalf("replace at cap changed slot count: len = %d", len(got.PGPWrappedEnvelopes))
	}
	for _, e := range got.PGPWrappedEnvelopes {
		if e.Slot == EnvelopeSlotRecovery && e.Envelope != `{"v":2,"rec":2}` {
			t.Fatalf("replace at cap did not take effect: %+v", e)
		}
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

// TestWrappedEnvelopeByteBoundIsEnforcedByTheStore is run-7 finding F4.
//
// maxWrappedEnvelopeSlots' safety argument is "32 slots x 128 KiB", but the byte
// half of that product lived only in package api as an io.LimitReader on the
// request body — and PGPPrivateKeyWrapped has a second writer, POST
// /api/auth/password, whose reader allowed 1 MiB. A package's own invariant
// cannot depend on a bound another package may or may not apply.
func TestWrappedEnvelopeByteBoundIsEnforcedByTheStore(t *testing.T) {
	store := newTestStore(t)
	u, err := store.Create(context.Background(), "someone", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	oversized := strings.Repeat("<", MaxWrappedEnvelopeBytes+1)

	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR", "KID", "PUB", oversized, "generated", ""); !errors.Is(err, ErrWrappedEnvelopeTooLarge) {
		t.Errorf("SetPGPIdentityClientProtected: err = %v, want ErrWrappedEnvelopeTooLarge", err)
	}
	if _, err := store.RewrapPGPPrivateKey(u.ID, oversized); !errors.Is(err, ErrWrappedEnvelopeTooLarge) {
		t.Errorf("RewrapPGPPrivateKey: err = %v, want ErrWrappedEnvelopeTooLarge", err)
	}
	if _, err := store.SetPGPWrappedEnvelope(u.ID, EnvelopeSlotRecovery, oversized, ""); !errors.Is(err, ErrWrappedEnvelopeTooLarge) {
		t.Errorf("SetPGPWrappedEnvelope: err = %v, want ErrWrappedEnvelopeTooLarge", err)
	}
	// The path the audit actually found unbounded.
	if _, err := store.SetDerivedAuthAndRewrapPGP(context.Background(), u.ID,
		strings.Repeat("a", 64), base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		600_000, false, oversized); !errors.Is(err, ErrWrappedEnvelopeTooLarge) {
		t.Errorf("SetDerivedAuthAndRewrapPGP: err = %v, want ErrWrappedEnvelopeTooLarge", err)
	}
}

// TestUsersFileIsNotHTMLEscaped is the other half of F4: the byte bounds above
// are applied to input, but json.MarshalIndent escaped '<' to '<' on
// OUTPUT, so a bounded field still landed on disk six times its size.
func TestUsersFileIsNotHTMLEscaped(t *testing.T) {
	store := newTestStore(t)
	path := store.path
	u, err := store.Create(context.Background(), "someone", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const payloadLen = 4096
	envelope := strings.Repeat("<", payloadLen)
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR", "KID", "PUB", envelope, "generated", ""); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, []byte("\\u003c")) {
		t.Fatal("users.json still HTML-escapes '<' to \\u003c, inflating every stored byte 6x " +
			"in a file that is rewritten whole under a global lock on every mutation")
	}
	// The whole point is the size on disk, so assert it directly: 4 KiB in must
	// not become 24 KiB out.
	if len(raw) > payloadLen*2 {
		t.Fatalf("users.json is %d bytes for a %d-byte envelope; the encoder is inflating it",
			len(raw), payloadLen)
	}
	if !bytes.Contains(raw, []byte(envelope)) {
		t.Fatal("the envelope did not round-trip verbatim")
	}
}

// TestSetPushMFAEnabledSkipsRedundantWrite is the third part of F4: an
// unthrottled session-only endpoint that rewrites the whole file on every call,
// even when it changes nothing, is a free instance-wide stall.
func TestSetPushMFAEnabledSkipsRedundantWrite(t *testing.T) {
	store := newTestStore(t)
	path := store.path
	u, err := store.Create(context.Background(), "someone", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPushMFAEnabled(u.ID, false); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	// Re-set the value it already holds, the shape of the attack.
	for i := 0; i < 5; i++ {
		got, err := store.SetPushMFAEnabled(u.ID, false)
		if err != nil {
			t.Fatalf("SetPushMFAEnabled: %v", err)
		}
		if got.ID != u.ID {
			t.Fatalf("a no-op mutation must still return the user, got %+v", got)
		}
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("re-setting PushMFAEnabled to its current value rewrote users.json; a whole-file " +
			"marshal+fsync under the global lock must not be reachable by an unthrottled no-op")
	}
	// And a real change still writes.
	if _, err := store.SetPushMFAEnabled(u.ID, true); err != nil {
		t.Fatalf("SetPushMFAEnabled(true): %v", err)
	}
	got, err := store.Get(u.ID)
	if err != nil || !got.PushMFAEnabled {
		t.Fatalf("a genuine change must still persist: %+v err=%v", got, err)
	}
}

// TestReplacingTheSameIdentityKeepsSlots covers the run-7 hardening note: the
// slot wipe is justified by "every non-password slot seals the OLD key", but the
// code never checked that the key actually changed. Re-posting the identical
// identity — a retried request, a client re-running setup — silently destroyed a
// live recovery sealing, with a 200 and no log line.
func TestReplacingTheSameIdentityKeepsSlots(t *testing.T) {
	store := newTestStore(t)
	u, err := store.Create(context.Background(), "someone", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR-A", "KID", "PUB", `{"v":2}`, "generated", ""); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	if _, err := store.SetPGPWrappedEnvelope(u.ID, EnvelopeSlotRecovery, "RECOVERY-SEALED", ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}

	// Same fingerprint: the sealing is still valid and must survive.
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR-A", "KID", "PUB", `{"v":2,"rewrapped":true}`, "generated", ""); err != nil {
		t.Fatalf("re-post same identity: %v", err)
	}
	got, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != 1 {
		t.Fatalf("re-posting the SAME identity destroyed a live recovery sealing: slots = %+v",
			got.PGPWrappedEnvelopes)
	}

	// A genuinely different key must still drop them.
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR-B", "KID", "PUB", `{"v":2}`, "generated", ""); err != nil {
		t.Fatalf("replace identity: %v", err)
	}
	got, err = store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("a real identity change must drop sealings of the old key: slots = %+v",
			got.PGPWrappedEnvelopes)
	}
}

// A device: slot is a payload in flight, not a record. Once the device has
// fetched and re-sealed it locally the server's copy is dead weight, and the
// device cannot delete it (no session). Expiry is how it goes away.
func TestDeviceSlotExpires(t *testing.T) {
	store, id := newClientProtectedUser(t)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	if _, err := store.SetPGPWrappedEnvelope(id, "device:abc", `{"v":2,"dev":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.WrappedEnvelopes()) != 2 {
		t.Fatalf("fresh device slot should be visible: %+v", got.WrappedEnvelopes())
	}
	// ExpiresAt must be stamped automatically — a caller is not trusted to remember.
	if got.PGPWrappedEnvelopes[0].ExpiresAt == "" {
		t.Fatal("SetPGPWrappedEnvelope did not stamp ExpiresAt on a device slot")
	}

	// Force it into the past and it must disappear from the synthesised view.
	got.PGPWrappedEnvelopes[0].ExpiresAt = past
	if _, err := store.SetPGPWrappedEnvelope(id, "device:abc", `{"v":2,"dev":1}`, ""); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	expired := User{
		PGPPrivateKeyWrapped: `{"v":2,"pw":true}`,
		PGPWrappedEnvelopes:  []WrappedEnvelope{{Slot: "device:abc", Envelope: "x", ExpiresAt: past}},
	}
	if slots := expired.WrappedEnvelopes(); len(slots) != 1 || slots[0].Slot != EnvelopeSlotPassword {
		t.Fatalf("expired device slot still visible: %+v", slots)
	}
}

// The recovery slot is a durable sealing, not cargo. It must never expire.
func TestRecoverySlotDoesNotExpire(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if got.PGPWrappedEnvelopes[0].ExpiresAt != "" {
		t.Fatalf("recovery slot was given an expiry: %q", got.PGPWrappedEnvelopes[0].ExpiresAt)
	}
}

// An expired slot must not consume cap headroom — otherwise a device that
// enrolled and went quiet permanently costs the user a slot. This must go
// through SetPGPWrappedEnvelope's own cap check (the `live` counter), not
// just WrappedEnvelopes()'s read-side filter — that mechanism is already
// covered by TestDeviceSlotExpires.
func TestExpiredSlotsDoNotCountTowardTheCap(t *testing.T) {
	store, id := newClientProtectedUser(t)

	// Fill to exactly the cap with live device slots, and confirm the cap
	// still bites — this pins that the cap is not simply gone.
	for i := 0; i < maxWrappedEnvelopeSlots; i++ {
		slot := fmt.Sprintf("device:%02d", i)
		if _, err := store.SetPGPWrappedEnvelope(id, slot, "x", ""); err != nil {
			t.Fatalf("fill slot %d: %v", i, err)
		}
	}
	if _, err := store.SetPGPWrappedEnvelope(id, "device:overflow", "x", ""); !errors.Is(err, ErrTooManyEnvelopeSlots) {
		t.Fatalf("cap did not bite on a full table: %v", err)
	}

	// Age every slot into the past. SetPGPWrappedEnvelope always stamps a
	// fresh future expiry, so there is no way to produce a past one through
	// the public API — write it directly to the store's backing file via
	// store.mutate, the same internal seam TestGetClonesWrappedEnvelopesFromCache
	// above already uses for the same reason (no writer for this field exists
	// yet through the public surface). No new test-only seam is added.
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := store.mutate(id, func(u *User) error {
		for i := range u.PGPWrappedEnvelopes {
			u.PGPWrappedEnvelopes[i].ExpiresAt = past
		}
		return nil
	}); err != nil {
		t.Fatalf("age slots: %v", err)
	}

	// The table is still nominally full, but every slot is expired: this is
	// the headroom actually freeing.
	if _, err := store.SetPGPWrappedEnvelope(id, "device:overflow", "x", ""); err != nil {
		t.Fatalf("add after expiry should have succeeded, freeing headroom: %v", err)
	}
}

// TestExpiredSlotsAreCompactedOnTheNextWrite is run-8 finding F5's new half.
//
// 73d846f made expired device envelopes invisible: WrappedEnvelopes() filters
// them on read and the slot cap counts only live ones. Nothing removed them.
// The rows stayed on disk, inside the file users.Store rewrites WHOLE on every
// account mutation and every authenticated request reads through — 4 MiB per
// account per week, permanently, with the visible slot count pinned and no
// operator surface that could see it. The 32-slot cap, whose own comment exists
// to bound each account's share of that shared cost, stopped bounding anything.
func TestExpiredSlotsAreCompactedOnTheNextWrite(t *testing.T) {
	store, id := newClientProtectedUser(t)

	for i := 0; i < 4; i++ {
		if _, err := store.SetPGPWrappedEnvelope(id, fmt.Sprintf("device:%02d", i), "x", ""); err != nil {
			t.Fatalf("add slot %d: %v", i, err)
		}
	}
	// Age them all, exactly as TestExpiredSlotsDoNotCountTowardTheCap does:
	// SetPGPWrappedEnvelope always stamps a future expiry, so a past one has to
	// be written through the store's own mutate seam.
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := store.mutate(id, func(u *User) error {
		for i := range u.PGPWrappedEnvelopes {
			u.PGPWrappedEnvelopes[i].ExpiresAt = past
		}
		return nil
	}); err != nil {
		t.Fatalf("age slots: %v", err)
	}

	// The rows are still THERE — invisible to WrappedEnvelopes(), but on disk.
	// Read the raw field, not the filtered accessor, or this test cannot see
	// the thing it is about.
	before, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(before.PGPWrappedEnvelopes) != 4 {
		t.Fatalf("test setup: expected 4 aged rows on disk, got %d", len(before.PGPWrappedEnvelopes))
	}

	// Any subsequent write — this one touches nothing to do with envelopes —
	// must reclaim them.
	if _, err := store.SetPushMFAEnabled(id, true); err != nil {
		t.Fatalf("SetPushMFAEnabled: %v", err)
	}
	after, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(after.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("%d expired rows survived a write; they are invisible to every reader "+
			"and to the slot cap, so nothing else will ever remove them", len(after.PGPWrappedEnvelopes))
	}
}

// TestDeletingAnAbsentSlotDoesNotWrite is run-8 finding F5's second live
// amplifier. DELETE /api/pgp/identity/envelope/{slot} returned nil
// unconditionally from its mutate fn, so it always paid a whole-file marshal
// and two fsyncs under the global lock — measured at 393 rewrites/s from one
// looping caller, against a file every authenticated request reads through.
//
// UpdatedAt is the observable: mutateGuarded stamps it only when it writes.
func TestDeletingAnAbsentSlotDoesNotWrite(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, "x", ""); err != nil {
		t.Fatalf("seed slot: %v", err)
	}
	before, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// The stamp has one-second resolution, so a write would have to land in the
	// same second to hide. Wait past the boundary first.
	time.Sleep(1100 * time.Millisecond)
	if _, err := store.DeletePGPWrappedEnvelope(id, "device:never-existed"); err != nil {
		t.Fatalf("deleting an absent slot should succeed: %v", err)
	}
	after, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Fatalf("deleting a slot that was not there rewrote users.json (UpdatedAt %s -> %s)",
			before.UpdatedAt, after.UpdatedAt)
	}

	// ...and a real delete still writes.
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("DeletePGPWrappedEnvelope: %v", err)
	}
	deleted, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(deleted.WrappedEnvelopes()) != 1 {
		t.Fatalf("a real delete did not remove the slot: %+v", deleted.WrappedEnvelopes())
	}
}

// TestSweepExpiredEnvelopesReclaimsIdleAccounts is the guarantee half of the
// TTL. Compaction inside mutateGuarded covers every account that is being
// written to; this covers the one that is not — a device envelope expires,
// nothing else about the account ever changes, and the row stays in users.json
// forever, invisible to WrappedEnvelopes() and to the slot cap but inside the
// file every authenticated request reads through.
func TestSweepExpiredEnvelopesReclaimsIdleAccounts(t *testing.T) {
	store, id := newClientProtectedUser(t)

	for i := 0; i < 3; i++ {
		if _, err := store.SetPGPWrappedEnvelope(id, fmt.Sprintf("device:%02d", i), "x", ""); err != nil {
			t.Fatalf("add device slot %d: %v", i, err)
		}
	}
	// A recovery slot, which never expires: the sweep must not take it.
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, "keep-me", ""); err != nil {
		t.Fatalf("add recovery slot: %v", err)
	}

	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	if _, err := store.mutate(id, func(u *User) error {
		for i := range u.PGPWrappedEnvelopes {
			if strings.HasPrefix(u.PGPWrappedEnvelopes[i].Slot, EnvelopeSlotDevicePrefix) {
				u.PGPWrappedEnvelopes[i].ExpiresAt = past
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("age device slots: %v", err)
	}

	before, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// The account is now idle: nothing will write to it again, and the raw rows
	// are still on disk.
	// Four raw rows: recovery plus three device. The password sealing is the
	// legacy PGPPrivateKeyWrapped field, which WrappedEnvelopes() surfaces as a
	// synthetic entry and which is not a row here.
	if len(before.PGPWrappedEnvelopes) != 4 {
		t.Fatalf("test setup: expected 4 raw rows (recovery + 3 device), got %d",
			len(before.PGPWrappedEnvelopes))
	}
	stamp := before.UpdatedAt

	removed, err := store.SweepExpiredEnvelopes()
	if err != nil {
		t.Fatalf("SweepExpiredEnvelopes: %v", err)
	}
	if removed != 3 {
		t.Fatalf("sweep removed %d rows, want 3", removed)
	}

	after, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(after.PGPWrappedEnvelopes) != 1 || after.PGPWrappedEnvelopes[0].Slot != EnvelopeSlotRecovery {
		t.Fatalf("the sweep did not leave exactly the untimed recovery slot: %+v", after.PGPWrappedEnvelopes)
	}
	// And the password sealing is still reachable, so the account is not
	// stranded by its own maintenance.
	if len(after.WrappedEnvelopes()) != 2 {
		t.Fatalf("expected the recovery and password sealings to remain: %+v", after.WrappedEnvelopes())
	}
	// A maintenance pass that removes rows nobody could see is not a
	// modification anyone made.
	if after.UpdatedAt != stamp {
		t.Fatalf("the sweep bumped UpdatedAt (%s -> %s), reporting a change no observer can see",
			stamp, after.UpdatedAt)
	}
}

// A sweep with nothing to reclaim must not write at all: it runs hourly on
// every instance, and users.json is rewritten whole under a global
// cross-process lock that every authenticated request reads through.
func TestSweepWithNothingExpiredDoesNotWrite(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, "device:live", "x", ""); err != nil {
		t.Fatalf("add slot: %v", err)
	}
	path := store.path
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	removed, err := store.SweepExpiredEnvelopes()
	if err != nil {
		t.Fatalf("SweepExpiredEnvelopes: %v", err)
	}
	if removed != 0 {
		t.Fatalf("sweep removed %d rows with nothing expired", removed)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("an empty sweep rewrote users.json; it runs hourly and takes the global " +
			"lock every authenticated request reads through")
	}
}
