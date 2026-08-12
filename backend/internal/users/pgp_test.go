package users

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSetAndClearPGPIdentity(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "erin", "pw-erin-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.SetPGPIdentity(u.ID, "AAAA1111", "1111AAAA",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"version":1,"nonce":"x","ciphertext":"y"}`, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	got, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PGPFingerprint != "AAAA1111" || got.PGPKeyID != "1111AAAA" || got.PGPKeySource != "generated" {
		t.Fatalf("unexpected PGP identity fields: %+v", got)
	}
	if got.Public().PGPFingerprint != "AAAA1111" {
		t.Fatal("expected PGPFingerprint to round-trip through Public()")
	}

	if _, err := store.ClearPGPIdentity(u.ID); err != nil {
		t.Fatalf("ClearPGPIdentity: %v", err)
	}
	got, err = store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PGPFingerprint != "" || got.PGPPrivateKeyEnc != "" {
		t.Fatalf("expected PGP identity cleared, got %+v", got)
	}
}

// TestSetPasswordPreservesTheWrappedKeyAndEnvelopes pins the property every
// recovery path after an admin password reset rests on, and which nothing
// tested before: a reset must not touch the client-protected key material.
//
// It matters because the product used to claim the opposite. The admin UI said
// a reset made the key "permanently unrecoverable" and told the user to
// generate a new identity — and generating one overwrites PGPPrivateKeyWrapped
// and nulls PGPWrappedEnvelopes, so following that advice turned a recoverable
// state into real data loss. The key is only inaccessible under the NEW
// password: the wrapping salt lives inside the envelope, not in LoginSalt, so
// the previous password still opens it.
//
// If this test ever fails, the "Key won't unlock?" recovery flow is dead and
// the old warning becomes true.
func TestSetPasswordPreservesTheWrappedKeyAndEnvelopes(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "frank", "pw-frank-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const wrapped = `{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"c2FsdA==","iv":"aXY=","ciphertext":"U0VDUkVU"}`
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR-1", "KID-1", "PUBLIC",
		wrapped, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	// A recovery slot has no expiry, so compactExpiredEnvelopes must leave it
	// alone across the reset too.
	if _, err := store.SetPGPWrappedEnvelope(u.ID, EnvelopeSlotRecovery, `{"v":2,"slot":"recovery"}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}

	if _, err := store.SetPassword(context.Background(), u.ID, "a-new-temporary-password", true); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	got, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.PGPPrivateKeyWrapped != wrapped {
		t.Fatalf("the reset altered the wrapped private key:\n got %q\nwant %q",
			got.PGPPrivateKeyWrapped, wrapped)
	}
	if len(got.PGPWrappedEnvelopes) != 1 || got.PGPWrappedEnvelopes[0].Slot != EnvelopeSlotRecovery {
		t.Fatalf("the reset dropped a recovery envelope that has no expiry: %+v", got.PGPWrappedEnvelopes)
	}
	if got.PGPFingerprint != "FPR-1" || got.PGPPublicKey != "PUBLIC" {
		t.Fatalf("the reset altered the identity itself: %+v", got)
	}
	if !got.MustChangePassword {
		t.Fatal("expected MustChangePassword after an admin reset")
	}
}
