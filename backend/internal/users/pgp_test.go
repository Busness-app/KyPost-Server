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
