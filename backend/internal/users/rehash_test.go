package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/password"
	"golang.org/x/crypto/scrypt"
)

// TestHashPasswordUsesCurrentCost pins the format AND the cost new hashes are
// written with under production params: Argon2id at hashParams, which starts
// as password.DefaultParams() and is changed only by SetHashParamsForTest —
// so a test that never calls it (this one) runs at real production strength.
func TestHashPasswordUsesCurrentCost(t *testing.T) {
	if hashParams != password.DefaultParams() {
		t.Fatalf("hashParams = %+v, want the production default %+v — some other test in this "+
			"package leaked an override", hashParams, password.DefaultParams())
	}
	hash, err := HashPassword(context.Background(), "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash prefix = %q, want $argon2id$", hash[:min(len(hash), 24)])
	}
	wantCost := fmt.Sprintf("$%s$m=%d,t=%d,p=%d$", argon2VersionSegment, hashParams.Memory, hashParams.Time, hashParams.Threads)
	if !strings.Contains(hash, wantCost) {
		t.Errorf("hash = %q, does not carry the production cost segment %q", hash, wantCost)
	}
	if ok, _ := VerifySecretHash(context.Background(), hash, "correct-horse-battery-staple"); !ok {
		t.Error("a freshly written hash does not verify")
	}
}

// mintArgon2 mints a real Argon2id hash at p, so a NeedsRehash fixture that is
// supposed to look like something this package or the library actually wrote
// is exactly that — not a hand-assembled string with a salt too short for
// password.Verify to accept.
func mintArgon2(t *testing.T, p password.Params) string {
	t.Helper()
	h, err := password.HashWith("needs-rehash-fixture", p)
	if err != nil {
		t.Fatalf("password.HashWith(%+v): %v", p, err)
	}
	return h
}

// withSegment replaces the $-delimited segment of hash at index (0 is the
// empty segment before the leading $, 2 is the version, 3 is the params),
// for fixtures that need to corrupt exactly one field of an otherwise-real
// hash.
func withSegment(hash string, index int, replacement string) string {
	parts := strings.Split(hash, "$")
	parts[index] = replacement
	return strings.Join(parts, "$")
}

// TestNeedsRehashOnlyUpgrades is the safety property: every scrypt hash is
// retired regardless of the cost it was stored at, but an Argon2id hash that
// is not strictly weaker than the current cost on some axis must never report
// true. That must hold per axis — memory, time, AND thread count — or an
// operator who deliberately raised only one of them would have it silently
// downgraded back down on the next login.
func TestNeedsRehashOnlyUpgrades(t *testing.T) {
	atCurrent := mintArgon2(t, password.DefaultParams())
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
		{"argon2id below current", mintArgon2(t, password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}), true},
		{"argon2id at current", atCurrent, false},
		// Deliberately stronger than the current default on every axis: leave
		// it alone.
		{"argon2id stronger", mintArgon2(t, password.Params{Memory: 131072, Time: 5, Threads: 4}), false},
		// Stronger ONLY on the thread axis: the axis most likely to regress if
		// the comparison were symmetric ("!=" instead of "<") rather than
		// directional. Must not report true either.
		{"argon2id more threads is not a downgrade", mintArgon2(t, password.Params{Memory: 65536, Time: 3, Threads: 8}), false},
		// A hash this package's own dependency would refuse to read is not
		// ours to rehash on a guess.
		{"argon2id wrong version segment", withSegment(atCurrent, 2, "v=13"), false},
		{"argon2id non-canonical params (leading zero)", withSegment(atCurrent, 3, "m=65536,t=3,p=04"), false},
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
