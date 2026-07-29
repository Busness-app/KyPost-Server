package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run-4 hardening note 7: the VAPID private key was written to CONFIG_DIR while
// every other secret in this system lives in SECRET_DIR.
//
// CONFIG_DIR and SECRET_DIR are separate Docker volumes with separate
// lifecycles; an operator who backs up or copies "the config" reasonably does
// not expect a signing key in it, and the inconsistency is exactly the kind
// that survives until a backup policy treats the two directories differently.
//
// The default moved. An install that already has a path recorded in config.yaml
// keeps it — the VAPID public key is registered with every browser that has
// ever subscribed, so relocating an existing key would invalidate every live
// web-push subscription for no security gain.

func TestNewInstallPutsTheVAPIDKeyInSecretDir(t *testing.T) {
	configDir := t.TempDir()
	secretDir := t.TempDir()

	var cfg Config
	if _, err := ensureNotificationKeyMaterial(configDir, secretDir, &cfg); err != nil {
		t.Fatalf("ensureNotificationKeyMaterial: %v", err)
	}

	if !strings.HasPrefix(cfg.Notifications.PrivateKeyPath, secretDir) {
		t.Fatalf("PrivateKeyPath = %q, want it under the secret dir %q",
			cfg.Notifications.PrivateKeyPath, secretDir)
	}
	if _, err := os.Stat(cfg.Notifications.PrivateKeyPath); err != nil {
		t.Fatalf("the key was not written: %v", err)
	}
	// And nothing key-shaped may be left in the config dir.
	entries, err := os.ReadDir(configDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "vapid") {
			t.Fatalf("a VAPID key file was written to the config dir: %s", e.Name())
		}
	}
}

// An install that already records a path keeps it. Moving the key would
// invalidate every existing browser push subscription, which is a worse outcome
// than the key sitting in a directory it should not have been in.
func TestExistingInstallKeepsItsRecordedVAPIDPath(t *testing.T) {
	configDir := t.TempDir()
	secretDir := t.TempDir()

	legacyPath := filepath.Join(configDir, "notifications-vapid-private.pem")
	var seed Config
	if _, err := ensureNotificationKeyMaterial(configDir, configDir, &seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed.Notifications.PrivateKeyPath != legacyPath {
		t.Fatalf("seed wrote %q, wanted the legacy layout at %q", seed.Notifications.PrivateKeyPath, legacyPath)
	}
	originalPublic := seed.Notifications.PublicKey

	// Now start with the new default in play; the recorded path must win.
	if _, err := ensureNotificationKeyMaterial(configDir, secretDir, &seed); err != nil {
		t.Fatalf("ensureNotificationKeyMaterial: %v", err)
	}
	if seed.Notifications.PrivateKeyPath != legacyPath {
		t.Fatalf("PrivateKeyPath moved to %q; an existing install must keep %q",
			seed.Notifications.PrivateKeyPath, legacyPath)
	}
	if seed.Notifications.PublicKey != originalPublic {
		t.Fatal("the public key changed, which would invalidate every existing push subscription")
	}
}

func TestVAPIDKeyIsStableAcrossCalls(t *testing.T) {
	configDir := t.TempDir()
	secretDir := t.TempDir()

	var first Config
	if _, err := ensureNotificationKeyMaterial(configDir, secretDir, &first); err != nil {
		t.Fatalf("first: %v", err)
	}
	second := first
	if _, err := ensureNotificationKeyMaterial(configDir, secretDir, &second); err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Notifications.PublicKey != second.Notifications.PublicKey {
		t.Fatal("the VAPID identity changed between calls")
	}
}
