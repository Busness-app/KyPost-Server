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

// TestHashPasswordUsesCurrentCost pins the cost parameters new hashes are
// written with. 16384 was scrypt's 2009 interactive figure — the floor of
// current guidance, not a target.
func TestHashPasswordUsesCurrentCost(t *testing.T) {
	hash, err := HashPassword(context.Background(), "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "scrypt$131072$8$1$") {
		t.Errorf("hash prefix = %q, want scrypt$131072$8$1$ (N=2^17)", hash[:min(len(hash), 24)])
	}
	if scryptN != 1<<17 {
		t.Errorf("scryptN = %d, want %d", scryptN, 1<<17)
	}
	// And it must still verify.
	if ok, _ := verifyScryptHash(context.Background(), hash, "correct-horse-battery-staple"); !ok {
		t.Error("a freshly written hash does not verify")
	}
}

// TestNeedsRehashOnlyUpgrades is the safety property: this must never report
// true for a hash stored at a HIGHER cost, or an operator who deliberately
// raised it would have their accounts silently weakened on next login.
func TestNeedsRehashOnlyUpgrades(t *testing.T) {
	cases := []struct {
		name    string
		encoded string
		want    bool
	}{
		{"old N", "scrypt$16384$8$1$c2FsdA==$aGFzaA==", true},
		{"old r", "scrypt$131072$4$1$c2FsdA==$aGFzaA==", true},
		{"old p", "scrypt$131072$8$0$c2FsdA==$aGFzaA==", true},
		{"current", "scrypt$131072$8$1$c2FsdA==$aGFzaA==", false},
		// Deliberately stronger than the current default: leave it alone.
		{"stronger N", "scrypt$1048576$8$1$c2FsdA==$aGFzaA==", false},
		{"stronger r", "scrypt$131072$16$1$c2FsdA==$aGFzaA==", false},
		// Not ours to rehash.
		{"foreign format", "argon2id$v=19$m=65536,t=3,p=4$abc$def", false},
		{"garbage", "not-a-hash", false},
		{"empty", "", false},
		{"wrong field count", "scrypt$131072$8$1$c2FsdA==", false},
		{"non-numeric N", "scrypt$abc$8$1$c2FsdA==$aGFzaA==", false},
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
