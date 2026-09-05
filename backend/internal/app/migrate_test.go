package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

func TestMigrateLegacySingleUserData(t *testing.T) {
	configDir := t.TempDir()
	stateDir := t.TempDir()
	logDir := t.TempDir()

	logger, err := logging.New(logDir)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	defer logger.Close()

	// Legacy global files.
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), []byte(`{"lastCheckpoint":"42","processed":{}}`), 0o600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "decisions.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write decisions.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "TUNING.md"), []byte("## Allowed Labels\n- Important\n"), 0o600); err != nil {
		t.Fatalf("write TUNING.md: %v", err)
	}
	configFile := filepath.Join(configDir, "config.yaml")
	legacyYAML := "notifications:\n  mode: keywords\n  keywords:\n    - urgent\n"
	if err := os.WriteFile(configFile, []byte(legacyYAML), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}

	usersStore, err := users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	admin, err := usersStore.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}

	// app.Run captures the legacy prefs before LoadOrInit rewrites
	// config.yaml with the trimmed schema; mirror that order here.
	legacyPrefs, legacyPrefsOK := config.LoadLegacyNotificationPrefs(configFile)
	if !legacyPrefsOK {
		t.Fatalf("expected legacy prefs to parse")
	}

	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, legacyPrefs, legacyPrefsOK); err != nil {
		t.Fatalf("migrateLegacySingleUserData: %v", err)
	}

	userStateDir := filepath.Join(stateDir, "users", admin.ID)
	userConfigDir := filepath.Join(configDir, "users", admin.ID)

	if b, err := os.ReadFile(filepath.Join(userStateDir, "state.json")); err != nil || string(b) == "" {
		t.Fatalf("expected migrated state.json, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(userStateDir, "decisions.json")); err != nil {
		t.Fatalf("expected migrated decisions.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(userConfigDir, "tuning.md")); err != nil {
		t.Fatalf("expected migrated tuning.md: %v", err)
	}
	settings, err := config.LoadUserSettings(filepath.Join(userConfigDir, "config.yaml"))
	if err != nil {
		t.Fatalf("LoadUserSettings: %v", err)
	}
	if settings.Notifications.Mode != "keywords" || len(settings.Notifications.Keywords) != 1 || settings.Notifications.Keywords[0] != "urgent" {
		t.Fatalf("unexpected migrated notification prefs: %+v", settings.Notifications)
	}

	// Running the migration again must not clobber the per-user copies.
	if err := os.WriteFile(filepath.Join(userConfigDir, "tuning.md"), []byte("customized"), 0o600); err != nil {
		t.Fatalf("write customized tuning: %v", err)
	}
	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, legacyPrefs, legacyPrefsOK); err != nil {
		t.Fatalf("second migrateLegacySingleUserData: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(userConfigDir, "tuning.md"))
	if err != nil || string(b) != "customized" {
		t.Fatalf("second migration clobbered user file: content=%q err=%v", string(b), err)
	}
}

// TestCopyIfMissing_MissingSourceStaysSilent verifies that a genuinely-missing source file
// doesn't produce a log error (expected condition).
func TestCopyIfMissing_MissingSourceStaysSilent(t *testing.T) {
	var logOutput bytes.Buffer
	logger, err := logging.NewWithOutput(&logOutput)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	defer logger.Close()

	dstDir := t.TempDir()
	dst := filepath.Join(dstDir, "nonexistent.txt")

	// Copy from a source that doesn't exist.
	copyIfMissing(logger, "/this/path/does/not/exist", dst)

	// Destination should not exist (copy didn't happen).
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected destination to not exist, err=%v", err)
	}

	// Check logs: should have no error logs (expected condition).
	logBytes, err := logOutput.Bytes(), error(nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected error reading log: %v", err)
	}
	logContent := string(logBytes)
	if strings.Contains(logContent, "ERROR") || strings.Contains(logContent, "failed to migrate legacy file") {
		t.Fatalf("expected no error logs for missing source file, but got:\n%s", logContent)
	}
}

// TestCopyIfMissing_ReadErrorLogged verifies that unexpected read errors (not os.ErrNotExist)
// are logged appropriately.
func TestCopyIfMissing_ReadErrorLogged(t *testing.T) {
	var logOutput bytes.Buffer
	logger, err := logging.NewWithOutput(&logOutput)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	defer logger.Close()

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create a source that is a directory (not a file).
	// Reading it with os.ReadFile will fail with a different error than os.ErrNotExist.
	src := filepath.Join(srcDir, "is_a_directory")
	if err := os.Mkdir(src, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	dst := filepath.Join(dstDir, "destination.txt")

	// Attempt to copy from a directory.
	copyIfMissing(logger, src, dst)

	// Destination should not exist (copy failed).
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected destination to not exist, err=%v", err)
	}

	// Check logs: should have an error log for this unexpected condition.
	logBytes, err := logOutput.Bytes(), error(nil)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected error reading log: %v", err)
	}
	logContent := string(logBytes)
	if !strings.Contains(logContent, "failed to migrate legacy file") {
		t.Fatalf("expected error log for read error, but got:\n%s", logContent)
	}
}

// legacyMigrationEnv builds the shared fixture for the two regression tests
// below: an installation with a legacy global IMAP credential and legacy
// mailbox state, plus its first admin.
func legacyMigrationEnv(t *testing.T) (logger *logging.Logger, usersStore *users.Store, configDir, stateDir, adminID string) {
	t.Helper()
	configDir, stateDir = t.TempDir(), t.TempDir()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { logger.Close() })

	// config.SecretFile reads IMAP_CONFIG_FILE, which is how a real legacy
	// install points at this file.
	t.Setenv("IMAP_CONFIG_FILE", filepath.Join(configDir, "imap-config.json"))
	if err := os.WriteFile(filepath.Join(configDir, "imap-config.json"), []byte(`{"sealed":"CREDENTIAL"}`), 0o600); err != nil {
		t.Fatalf("write legacy imap-config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "state.json"), []byte(`{"lastCheckpoint":"42","processed":{}}`), 0o600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "decisions.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write decisions.json: %v", err)
	}

	usersStore, err = users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	admin, err := usersStore.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}
	return logger, usersStore, configDir, stateDir, admin.ID
}

// TestDeletedIMAPCredentialsDoNotResurrect is run-8 finding F7.
//
// migrateLegacySingleUserData runs on EVERY app.Run — twice per container
// start under supervisord, forever — and copyIfMissing skipped only when the
// destination existed, never retiring the source. DELETE /api/imap/config is a
// bare os.Remove, so a credential the user withdrew (usually because it leaked)
// was restored on the next boot and the poller resumed using it.
//
// Variant B is the same root cause: FirstAdminFrom skips inactive admins, so
// deactivating the legacy owner re-pointed the migration and wrote their sealed
// IMAP/SMTP credential into the NEXT admin's config directory. The sealing key
// is instance-wide, so that admin's webmail could read and send as them — no
// request, no audit row.
func TestDeletedIMAPCredentialsDoNotResurrect(t *testing.T) {
	logger, usersStore, configDir, stateDir, adminID := legacyMigrationEnv(t)
	legacyIMAP := filepath.Join(configDir, "imap-config.json")
	adminIMAP := filepath.Join(configDir, "users", adminID, "imap-config.json")

	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, config.UserNotificationSettings{}, false); err != nil {
		t.Fatalf("first migration: %v", err)
	}
	if _, err := os.Stat(adminIMAP); err != nil {
		t.Fatalf("the legacy credential was not migrated at all: %v", err)
	}
	if _, err := os.Stat(legacyIMAP); err == nil {
		t.Fatal("the legacy source survived the migration that consumed it")
	}

	// The user withdraws the credential, exactly as DELETE /api/imap/config
	// does it.
	if err := os.Remove(adminIMAP); err != nil {
		t.Fatalf("remove migrated config: %v", err)
	}

	// Next boot.
	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, config.UserNotificationSettings{}, false); err != nil {
		t.Fatalf("second migration: %v", err)
	}
	if _, err := os.Stat(adminIMAP); err == nil {
		t.Fatal("a deleted IMAP credential came back on the next start; the poller resumes " +
			"with the password the user withdrew")
	}
}

// TestTuningSourceIsNotConsumed pins the other half of F7's fix. copyIfMissing
// is shared with the TUNING.md candidate loop, whose source is the
// image-shipped prompt the classifier reads on EVERY run. Retiring that one
// would silently disable tuning instance-wide, so only the IMAP credential is a
// one-shot handover.
func TestTuningSourceIsNotConsumed(t *testing.T) {
	logger, usersStore, configDir, stateDir, _ := legacyMigrationEnv(t)
	tuning := filepath.Join(configDir, "TUNING.md")
	if err := os.WriteFile(tuning, []byte("## Allowed Labels\n- Important\n"), 0o600); err != nil {
		t.Fatalf("write TUNING.md: %v", err)
	}

	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, config.UserNotificationSettings{}, false); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := os.Stat(tuning); err != nil {
		t.Fatalf("the shipped TUNING.md was retired; the classifier reads it on every run: %v", err)
	}
}

// TestOpenStoresMigratesBeforeStateNewConsumesTheSource is run-8 finding F14.
//
// state.New's migrateJSONIfPresent imports the legacy root state.json /
// decisions.json into the root state.db and RENAMES them to .migrated. Run
// opened the state store FIRST, so migrateLegacySingleUserData found no source,
// copyIfMissing returned silently, and the per-user copy could not happen on any
// real installation — the data landed in the root state.db, which holds only
// install-wide flags. Observable on a pre-2026-07-29 upgrade as the admin's
// decisions feed disappearing and every UNSEEN message being re-processed,
// re-classified and re-notified once.
//
// This goes through openStores, which is the whole sequence Run runs. Calling
// the migration directly — what migrate_test.go above does — cannot see the
// defect, which is why it stayed green.
func TestOpenStoresMigratesBeforeStateNewConsumesTheSource(t *testing.T) {
	logger, _, configDir, stateDir, _ := legacyMigrationEnv(t)

	usersStore, store, err := openStores(logger, configDir, stateDir, config.UserNotificationSettings{}, false)
	if err != nil {
		t.Fatalf("openStores: %v", err)
	}
	defer store.Close()
	admin, err := usersStore.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}

	userStateDir := filepath.Join(stateDir, "users", admin.ID)
	for _, name := range []string{"state.json", "decisions.json"} {
		if _, err := os.Stat(filepath.Join(userStateDir, name)); err != nil {
			t.Fatalf("%s never reached the admin's per-user state dir: %v — state.New renamed "+
				"the source out from under the migration", name, err)
		}
	}

	// And state.New still did its own job: the legacy sources are retired.
	if _, err := os.Stat(filepath.Join(stateDir, "state.json")); err == nil {
		t.Fatal("state.New did not consume the legacy root state.json")
	}
}
