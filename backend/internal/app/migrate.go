package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/users"
)

// migrateLegacySingleUserData copies the pre-multi-user global files into
// the first admin's per-user directories, once. Legacy sources are left in
// place (dead but harmless). It is idempotent — each copy is skipped when
// the destination already exists — and safe to run concurrently from the
// api and daemon processes, since each write is atomic and both processes
// derive identical content from the same sources.
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
	legacyIMAP := config.SecretFile("IMAP_CONFIG_FILE", "imap-config.json")
	copyIfMissing(logger, legacyIMAP, filepath.Join(userConfigDir, "imap-config.json"))

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
