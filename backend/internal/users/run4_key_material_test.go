package users

import (
	"errors"
	"path/filepath"
	"testing"
)

// run-4 M16: the send-as reconcile snapshots the user, evaluates
// HasServerReadableKey() on that snapshot, then spends hundreds of microseconds
// re-signing before writing the result back with SetPGPIdentity.
//
// The custody half of that race is already closed — SetPGPIdentity refuses to
// overwrite a client-held identity, re-reading under the lock (see
// ErrWouldDowngradeCustody). The other half was not: if the user replaces their
// key with a *different* server-custody key during that window, the reconcile
// writes its stale copy back and the new key is silently reverted.
//
// UpdatePGPKeyMaterial is the narrow write the reconcile actually needs: same
// key, new User IDs. Making the expected fingerprint a required argument is
// what closes the window, and it also stops the reconcile rewriting source,
// creation time and protection, none of which it has any business changing.

func newKeyMaterialStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	all, err := store.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("expected a bootstrapped user: %v", err)
	}
	return store, all[0].ID
}

func seedServerKey(t *testing.T, store *Store, id, fingerprint string) {
	t.Helper()
	if _, err := store.SetPGPIdentity(id, fingerprint, "KEYID", "PUBLIC-"+fingerprint,
		"SEALED-"+fingerprint, "generated", "2026-07-27T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
}

func TestUpdatePGPKeyMaterialWritesWhenTheFingerprintStillMatches(t *testing.T) {
	store, id := newKeyMaterialStore(t)
	seedServerKey(t, store, id, "FPR-1")

	updated, err := store.UpdatePGPKeyMaterial(id, "FPR-1", "PUBLIC-WITH-UID", "SEALED-WITH-UID")
	if err != nil {
		t.Fatalf("UpdatePGPKeyMaterial: %v", err)
	}
	if updated.PGPPublicKey != "PUBLIC-WITH-UID" || updated.PGPPrivateKeyEnc != "SEALED-WITH-UID" {
		t.Fatalf("key material was not written: %+v", updated)
	}
	if updated.PGPFingerprint != "FPR-1" {
		t.Fatalf("fingerprint changed: %q", updated.PGPFingerprint)
	}
}

// The race itself: the key was replaced while the caller was re-signing.
func TestUpdatePGPKeyMaterialRefusesAfterTheKeyWasReplaced(t *testing.T) {
	store, id := newKeyMaterialStore(t)
	seedServerKey(t, store, id, "FPR-1")

	// The user generates a new key while the reconcile is mid-flight.
	seedServerKey(t, store, id, "FPR-2")

	_, err := store.UpdatePGPKeyMaterial(id, "FPR-1", "STALE-PUBLIC", "STALE-SEALED")
	if !errors.Is(err, ErrPGPFingerprintChanged) {
		t.Fatalf("err = %v, want ErrPGPFingerprintChanged", err)
	}

	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PGPFingerprint != "FPR-2" || got.PGPPublicKey != "PUBLIC-FPR-2" {
		t.Fatalf("the newer key was reverted by a stale write: %+v", got)
	}
}

// The custody half, asserted here too so the two preconditions cannot drift
// apart: migrating to client custody mid-flight must also refuse, and must not
// resurrect a server-readable copy of the private key.
func TestUpdatePGPKeyMaterialRefusesAfterMigrationToClientCustody(t *testing.T) {
	store, id := newKeyMaterialStore(t)
	seedServerKey(t, store, id, "FPR-1")

	if _, err := store.SetPGPIdentityClientProtected(id, "FPR-1", "KEYID", "PUBLIC-FPR-1",
		"WRAPPED-ENVELOPE", "generated", "2026-07-27T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}

	_, err := store.UpdatePGPKeyMaterial(id, "FPR-1", "PUBLIC-WITH-UID", "SEALED-WITH-UID")
	if !errors.Is(err, ErrWouldDowngradeCustody) {
		t.Fatalf("err = %v, want ErrWouldDowngradeCustody", err)
	}

	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PGPPrivateKeyEnc != "" {
		t.Fatal("a server-readable private key was resurrected")
	}
	if got.PGPPrivateKeyWrapped != "WRAPPED-ENVELOPE" {
		t.Fatalf("the browser envelope was destroyed: %q", got.PGPPrivateKeyWrapped)
	}
}

// Provenance is not this call's to change. The reconcile adds User IDs to an
// existing key; it does not re-source it or re-date it.
func TestUpdatePGPKeyMaterialLeavesProvenanceAlone(t *testing.T) {
	store, id := newKeyMaterialStore(t)
	if _, err := store.SetPGPIdentity(id, "FPR-1", "KEYID", "PUBLIC-FPR-1", "SEALED-FPR-1",
		"imported", "2020-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	updated, err := store.UpdatePGPKeyMaterial(id, "FPR-1", "PUBLIC-WITH-UID", "SEALED-WITH-UID")
	if err != nil {
		t.Fatalf("UpdatePGPKeyMaterial: %v", err)
	}
	if updated.PGPKeySource != "imported" {
		t.Fatalf("key source was rewritten: %q", updated.PGPKeySource)
	}
	if updated.PGPKeyCreatedAt != "2020-01-01T00:00:00Z" {
		t.Fatalf("creation time was rewritten: %q", updated.PGPKeyCreatedAt)
	}
	if updated.PGPKeyID != "KEYID" {
		t.Fatalf("key id was rewritten: %q", updated.PGPKeyID)
	}
}

func TestUpdatePGPKeyMaterialRefusesAnEmptyExpectation(t *testing.T) {
	store, id := newKeyMaterialStore(t)
	seedServerKey(t, store, id, "FPR-1")

	// An empty expectation would make the precondition vacuous for an account
	// that has no key at all, which is exactly when a stale write is worst.
	if _, err := store.UpdatePGPKeyMaterial(id, "", "PUBLIC", "SEALED"); err == nil {
		t.Fatal("an empty expected fingerprint was accepted")
	}
}
