package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// TestBootstrapAdminSeedsAUsableAccount is the end-to-end check that the Go
// bootstrap produces exactly what LoadOrMigrate expects — the contract the
// removed `node -e` scrypt one-liner used to satisfy. If the hash format or
// the admin.env keys drift, the install comes up with an admin nobody can log
// in as.
func TestBootstrapAdminSeedsAUsableAccount(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONFIG_DIR", dir)
	t.Setenv("BOOTSTRAP_ADMIN_USER", "")
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "")

	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}

	pwBody, err := os.ReadFile(filepath.Join(dir, bootstrapPasswordFile))
	if err != nil {
		t.Fatalf("read password file: %v", err)
	}
	password := ""
	for _, line := range strings.Split(string(pwBody), "\n") {
		if rest, ok := strings.CutPrefix(line, "password: "); ok {
			password = strings.TrimSpace(rest)
		}
	}
	if password == "" {
		t.Fatalf("no password in %s:\n%s", bootstrapPasswordFile, pwBody)
	}

	store, err := users.LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.GetByUsername("admin")
	if err != nil {
		t.Fatalf("GetByUsername(admin): %v", err)
	}
	if !users.VerifyPassword(u, password) {
		t.Fatal("the generated password does not verify against the seeded hash")
	}
	if !u.MustChangePassword {
		t.Fatal("seeded admin is not flagged MustChangePassword; a first-run credential would grant full access")
	}
	if u.Role != users.RoleAdmin {
		t.Fatalf("seeded user role = %q, want admin", u.Role)
	}
}

func TestBootstrapAdminSecretsAreOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONFIG_DIR", dir)
	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	for _, name := range []string{"admin.env", bootstrapPasswordFile} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600 — it holds a plaintext or hashed admin credential", name, perm)
		}
	}
}

func TestBootstrapAdminIsIdempotent(t *testing.T) {
	// It runs on every container start. A second run must not mint new
	// credentials over a live install's account store.
	dir := t.TempDir()
	t.Setenv("CONFIG_DIR", dir)
	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("first BootstrapAdmin: %v", err)
	}
	first, err := os.ReadFile(filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("read admin.env: %v", err)
	}
	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("second BootstrapAdmin: %v", err)
	}
	second, err := os.ReadFile(filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("re-read admin.env: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("a second run rewrote admin.env; every restart would reset the admin credential")
	}
}

// TestBootstrapAdminSkipsWhenUsersJSONExists covers the upgrade path: an
// install seeded before this code existed has users.json and no admin.env.
func TestBootstrapAdminSkipsWhenUsersJSONExists(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(`{"version":1,"users":[]}`), 0o600); err != nil {
		t.Fatalf("seed users.json: %v", err)
	}
	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.env")); !os.IsNotExist(err) {
		t.Fatal("BootstrapAdmin wrote admin.env over an install that already has users.json")
	}
}

func TestBootstrapAdminDoesNotWriteAnOperatorSuppliedPasswordToDisk(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CONFIG_DIR", dir)
	t.Setenv("BOOTSTRAP_ADMIN_PASS", "operator-chose-this-one")
	if err := BootstrapAdmin(); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, bootstrapPasswordFile)); !os.IsNotExist(err) {
		t.Fatal("wrote a password file for a password the operator already has")
	}
}
