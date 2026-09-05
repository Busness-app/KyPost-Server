package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

// TestHashPasswordUsesCurrentCost pins the format new hashes are written in:
// Argon2id, and it must verify.
func TestHashPasswordUsesCurrentCost(t *testing.T) {
	hash, err := HashPassword(context.Background(), "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash prefix = %q, want $argon2id$", hash[:min(len(hash), 24)])
	}
	if ok, _ := VerifySecretHash(context.Background(), hash, "correct-horse-battery-staple"); !ok {
		t.Error("a freshly written hash does not verify")
	}
}

// TestNeedsRehashOnlyUpgrades is the safety property: every scrypt hash is
// retired regardless of the cost it was stored at, but an Argon2id hash at or
// above the current cost must never report true, or an operator who
// deliberately raised it would have their accounts silently weakened on next
// login.
func TestNeedsRehashOnlyUpgrades(t *testing.T) {
	cases := []struct {
		name    string
		encoded string
		want    bool
	}{
		// Every scrypt hash is retired, regardless of the cost it carries.
		{"scrypt old N", "scrypt$16384$8$1$c2FsdA==$aGFzaA==", true},
		{"scrypt current cost", "scrypt$131072$8$1$c2FsdA==$aGFzaA==", true},
		{"scrypt stronger than default", "scrypt$1048576$8$1$c2FsdA==$aGFzaA==", true},
		// Argon2id follows the currently configured cost (production default:
		// 64 MiB, t=3, p=4).
		{"argon2id below current", "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA==$aGFzaA==", true},
		{"argon2id at current", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA==$aGFzaA==", false},
		// Deliberately stronger than the current default: leave it alone.
		{"argon2id stronger", "$argon2id$v=19$m=131072,t=5,p=4$c2FsdA==$aGFzaA==", false},
		// Not ours to rehash.
		{"foreign format", "argon2id$v=19$m=65536,t=3,p=4$abc$def", false},
		{"garbage", "not-a-hash", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NeedsRehash(c.encoded); got != c.want {
				t.Errorf("NeedsRehash(%q) = %v, want %v", c.encoded, got, c.want)
			}
		})
	}
}

// TestRehashPasswordUpgradesInPlace covers the upgrade itself: same password,
// stronger hash, nothing else touched.
func TestRehashPasswordUpgradesInPlace(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	const pw = "correct-horse-battery-staple"
	u, err := store.Create(context.Background(), "upgrade-me", pw, RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Plant a legacy-cost hash, the way an existing install's file looks.
	legacy, err := hashPasswordAtCost(pw, 16384, 8, 1)
	if err != nil {
		t.Fatalf("hashPasswordAtCost: %v", err)
	}
	if _, err := store.mutate(u.ID, func(x *User) error {
		x.PasswordHash = legacy
		x.MustChangePassword = false
		return nil
	}); err != nil {
		t.Fatalf("plant legacy hash: %v", err)
	}

	before, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !NeedsRehash(before.PasswordHash) {
		t.Fatal("planted hash does not report as needing a rehash")
	}

	if err := store.RehashPassword(context.Background(), u.ID, pw); err != nil {
		t.Fatalf("RehashPassword: %v", err)
	}

	after, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get after rehash: %v", err)
	}
	if NeedsRehash(after.PasswordHash) {
		t.Errorf("hash still at the old cost after rehash: %q", after.PasswordHash)
	}
	if ok, _ := VerifyPassword(context.Background(), after, pw); !ok {
		t.Error("the password no longer verifies after the rehash — this locks the user out")
	}
	if after.PasswordHash == before.PasswordHash {
		t.Error("the hash did not change")
	}
	// Invisible to the user: nothing else may move.
	if after.MustChangePassword != before.MustChangePassword {
		t.Error("RehashPassword changed MustChangePassword; the upgrade must be invisible")
	}
	if after.Username != before.Username || after.Role != before.Role || after.Active != before.Active {
		t.Error("RehashPassword altered unrelated fields")
	}
}

// TestRehashPasswordRefusesAWrongCandidate is the fail-closed property. The
// function overwrites a credential, so a bug at the call site must not be able
// to set the password to an arbitrary string.
func TestRehashPasswordRefusesAWrongCandidate(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	const pw = "correct-horse-battery-staple"
	u, err := store.Create(context.Background(), "no-takeover", pw, RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.RehashPassword(context.Background(), u.ID, "attacker-chosen-password"); err == nil {
		t.Fatal("RehashPassword accepted a candidate that does not match the stored hash")
	}

	after, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok, _ := VerifyPassword(context.Background(), after, "attacker-chosen-password"); ok {
		t.Fatal("the account's password was replaced by the rejected candidate")
	}
	if ok, _ := VerifyPassword(context.Background(), after, pw); !ok {
		t.Error("the original password stopped working")
	}
}

// hashPasswordAtCost mints a hash at explicit cost parameters, so a test can
// plant what an older install's users.json actually contains.
func hashPasswordAtCost(password string, n, r, p int) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash, err := scrypt.Key([]byte(password), salt, n, r, p, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", n, r, p,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash)), nil
}
