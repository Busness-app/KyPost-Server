package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/users"
)

// bootstrapPasswordFile is where a generated first-run admin password is left
// for the operator to read once. Aliased rather than redeclared: the standalone
// bootstrap path in users.LoadOrMigrate writes the same file, and two spellings
// of the name is how the two paths drifted apart in the first place.
const bootstrapPasswordFile = users.BootstrapPasswordFile

// BootstrapAdmin seeds admin.env with first-run admin credentials if no
// account store exists yet. It is the `--mode bootstrap-admin` entry point,
// run once by scripts/entrypoint.sh before any service starts.
//
// Hashing lives here rather than in the shell so the runtime image needs no
// JavaScript interpreter; scripts/AGENTS.md holds that as a contract.
//
// A generated password goes to a 0600 file in CONFIG_DIR, never stdout —
// stdout is the container log stream, which is unrotated, kept for the life of
// the container, readable via the Docker socket, and forwarded to any log
// aggregator. MUST_CHANGE_PASSWORD narrows the window; it does not stop the
// password sitting in a log forever.
func BootstrapAdmin() error {
	configDir := config.ConfigDir()
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	usersPath := filepath.Join(configDir, "users.json")
	adminEnvPath := filepath.Join(configDir, "admin.env")
	// users.json is the real store; admin.env is only the seed LoadOrMigrate
	// imports from on first start. Either one existing means this install is
	// already bootstrapped.
	for _, p := range []string{usersPath, adminEnvPath} {
		if _, err := os.Stat(p); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	if username == "" {
		username = "admin"
	}

	password := os.Getenv("BOOTSTRAP_ADMIN_PASS")
	generated := password == ""
	if generated {
		var err error
		if password, err = randomPassword(); err != nil {
			return fmt.Errorf("generate admin password: %w", err)
		}
	}

	hash, err := users.HashPassword(context.Background(), password)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	env := fmt.Sprintf("ADMIN_USER=%s\nADMIN_PASS_HASH=%s\nMUST_CHANGE_PASSWORD=true\n", username, hash)
	if err := fsutil.AtomicWriteFile(adminEnvPath, []byte(env), 0o600); err != nil {
		return fmt.Errorf("write admin.env: %w", err)
	}

	if !generated {
		// The operator supplied it; they already have it, and writing it back
		// out would create a copy they did not ask for.
		fmt.Println("Seeded first-run admin credentials from BOOTSTRAP_ADMIN_PASS")
		fmt.Printf("Username: %s\n", username)
		fmt.Println("Password change is required on first login")
		return nil
	}

	pwPath, err := users.WriteFirstRunPassword(configDir, username, password)
	if err != nil {
		return err
	}

	fmt.Println("Generated first-run admin credentials in the config volume")
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Password: written to %s (read it, then delete it)\n", pwPath)
	fmt.Println("Password change is required on first login")
	return nil
}

// randomPassword returns 18 bytes of crypto/rand as base64url — the same
// length and alphabet the shell bootstrap produced, so an operator's notes
// about what to expect stay accurate.
func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
