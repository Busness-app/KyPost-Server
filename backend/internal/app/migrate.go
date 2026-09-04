package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/state"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// migrateLegacySingleUserData copies the pre-multi-user global files into
// the first admin's per-user directories, once. It is idempotent — each copy
// is skipped when the destination already exists — and safe to run
// concurrently from the api and daemon processes, since each write is atomic
// and both processes derive identical content from the same sources.
//
// It runs on every app.Run, i.e. twice per container start under supervisord,
// forever. That is why "left in place, dead but harmless" was wrong for the
// IMAP source: DELETE /api/imap/config is a bare os.Remove, so a credential
// the user WITHDREW — the whole point of the button, usually because it
// leaked — came back on the next boot and the poller resumed using it. Worse,
// FirstAdminFrom skips inactive admins, so deactivating the admin who owned
// the legacy credential re-pointed this migration and wrote their sealed
// IMAP/SMTP credential into the NEXT admin's config directory; the sealing key
// is instance-wide, so that admin's webmail could then read and send as them,
// with no request and no audit row.
func migrateLegacySingleUserData(logger *logging.Logger, usersStore *users.Store, configDir, stateDir string, legacyPrefs config.UserNotificationSettings, legacyPrefsOK bool) error {
	admin, err := usersStore.FirstAdmin()
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			return nil
		}
		return err
	}

	userStateDir := filepath.Join(stateDir, "users", admin.ID)
	userConfigDir := filepath.Join(configDir, "users", admin.ID)

	// Mailbox state: checkpoint/processed set and the decisions audit trail.
	copyIfMissing(logger, filepath.Join(stateDir, "state.json"), filepath.Join(userStateDir, "state.json"))
	copyIfMissing(logger, filepath.Join(stateDir, "decisions.json"), filepath.Join(userStateDir, "decisions.json"))

	// Encrypted IMAP credentials (still encrypted under the global master key).
	//
	// consumeIfPresent, not copyIfMissing: this source must be retired, and the
	// other two must not be. See consumeIfPresent.
	legacyIMAP := config.SecretFile("IMAP_CONFIG_FILE", "imap-config.json")
	consumeIfPresent(logger, legacyIMAP, filepath.Join(userConfigDir, "imap-config.json"))

	// Tuning prompt: first existing legacy candidate wins.
	tuningCandidates := []string{strings.TrimSpace(os.Getenv("TUNING_FILE")), filepath.Join(configDir, "TUNING.md"), "TUNING.md", "/opt/kypost/TUNING.md"}
	for _, candidate := range tuningCandidates {
		if candidate == "" {
			continue
		}
		if _, err := os.Stat(candidate); err == nil {
			copyIfMissing(logger, candidate, filepath.Join(userConfigDir, "tuning.md"))
			break
		}
	}

	// Notification delivery preferences captured from the legacy global
	// config.yaml before LoadOrInit rewrote it with the trimmed schema.
	userSettingsPath := filepath.Join(userConfigDir, "config.yaml")
	if _, err := os.Stat(userSettingsPath); errors.Is(err, os.ErrNotExist) && legacyPrefsOK {
		settings := config.DefaultUserSettings()
		settings.Notifications = legacyPrefs
		if err := config.SaveUserSettings(userSettingsPath, settings); err != nil {
			logger.Error("failed to migrate legacy notification preferences", "error", err.Error())
		} else {
			logger.Info("migrated legacy notification preferences", "user_id", admin.ID)
		}
	}

	return nil
}

// consumeIfPresent is copyIfMissing plus retiring the source, for a legacy
// file that must migrate exactly once and then stop existing.
//
// The rename happens whether or not this call did the copying, because the
// steady state is "destination already there" and that is precisely the state
// in which a later delete would otherwise be undone on the next boot.
//
// Deliberately NOT folded into copyIfMissing. That helper is shared with the
// TUNING.md candidate loop, whose source is the image-shipped prompt the
// classifier reads on every run — renaming it would silently disable tuning
// instance-wide. Only the IMAP credential is a one-shot handover.
func consumeIfPresent(logger *logging.Logger, src, dst string) {
	copyIfMissing(logger, src, dst)
	if _, err := os.Stat(src); err != nil {
		return
	}
	retired := src + ".migrated"
	if err := os.Rename(src, retired); err != nil {
		logger.Error("failed to retire migrated legacy file; it will be re-migrated on the next start",
			"src", src, "error", err.Error())
		return
	}
	logger.Info("retired migrated legacy file", "src", src, "renamed_to", retired)
}

func copyIfMissing(logger *logging.Logger, src, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	b, err := os.ReadFile(src)
	if err != nil {
		// Expected: source doesn't exist. Unexpected: any other read error should be logged.
		if !errors.Is(err, os.ErrNotExist) {
			logger.Error("failed to migrate legacy file", "src", src, "dst", dst, "error", err.Error())
		}
		return
	}
	if err := fsutil.AtomicWriteFile(dst, b, 0o600); err != nil {
		logger.Error("failed to migrate legacy file", "src", src, "dst", dst, "error", err.Error())
		return
	}
	logger.Info("migrated legacy file", "src", src, "dst", dst)
}

// openStores loads the users store, migrates the legacy single-user data, and
// opens the state store — in that order, which is the point of the function.
//
// state.New runs migrateJSONIfPresent, which imports the legacy root
// state.json/decisions.json into the root state.db and RENAMES them to
// .migrated. Opening it first left migrateLegacySingleUserData with no source
// at all: copyIfMissing found nothing and returned silently, so the per-user
// copy could never happen on any real installation. The data went into the root
// state.db, which holds only install-wide flags — orphaned rather than lost,
// but on a pre-2026-07-29 upgrade the admin's decisions feed disappeared and
// the empty checkpoint made every UNSEEN message re-process, re-classify and
// re-notify once.
//
// The three calls live here rather than inline in Run so a test can execute the
// real sequence. migrate_test.go was green throughout the bug because it called
// the migration directly with no preceding state.New, certifying an ordering
// production could not produce.
func openStores(logger *logging.Logger, configDir, stateDir string, legacyPrefs config.UserNotificationSettings, legacyPrefsOK bool) (*users.Store, *state.Store, error) {
	usersStore, err := users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		return nil, nil, fmt.Errorf("load users store: %w", err)
	}

	if err := migrateLegacySingleUserData(logger, usersStore, configDir, stateDir, legacyPrefs, legacyPrefsOK); err != nil {
		logger.Error("legacy single-user data migration failed", "error", err.Error())
	}

	store, err := state.New(stateDir)
	if err != nil {
		return nil, nil, fmt.Errorf("create state store: %w", err)
	}
	return usersStore, store, nil
}
