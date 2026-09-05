package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

// DefaultBackupKeep is how many sealed capsules a local backup directory keeps.
const DefaultBackupKeep = 7

// BackupConfig is the operator's default for the backup schedule and the
// local destination. The schedule the admin sets in the UI overrides
// DepositInterval; the directory and the private-recovery switch are env only.
type BackupConfig struct {
	DepositInterval      time.Duration
	Dir                  string
	Keep                 int
	AllowPrivateRecovery bool
}

// LoadBackupConfig reads KYPOST_BACKUP_DEPOSIT_INTERVAL (default 24h; 0 off;
// otherwise within the library's [MinInterval, MaxInterval]), KYPOST_BACKUP_DIR
// (absolute, empty off), KYPOST_BACKUP_KEEP (default 7, at least 1) and
// KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY (true/false).
func LoadBackupConfig() (BackupConfig, error) {
	c := BackupConfig{DepositInterval: 24 * time.Hour, Keep: DefaultBackupKeep}
	if raw := strings.TrimSpace(os.Getenv("KYPOST_BACKUP_DEPOSIT_INTERVAL")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return c, fmt.Errorf("KYPOST_BACKUP_DEPOSIT_INTERVAL %q: %w", raw, err)
		}
		if d != 0 && (d < recoveryclient.MinInterval || d > recoveryclient.MaxInterval) {
			return c, fmt.Errorf("KYPOST_BACKUP_DEPOSIT_INTERVAL %s: %w", d, recoveryclient.ErrBadInterval)
		}
		c.DepositInterval = d
	}
	if dir := strings.TrimSpace(os.Getenv("KYPOST_BACKUP_DIR")); dir != "" {
		if !filepath.IsAbs(dir) {
			return c, fmt.Errorf("KYPOST_BACKUP_DIR %q must be an absolute path", dir)
		}
		c.Dir = filepath.Clean(dir)
	}
	if raw := strings.TrimSpace(os.Getenv("KYPOST_BACKUP_KEEP")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return c, fmt.Errorf("KYPOST_BACKUP_KEEP %q: %w", raw, recoveryclient.ErrBadKeep)
		}
		c.Keep = n
	}
	if raw := strings.TrimSpace(os.Getenv("KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY")); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return c, fmt.Errorf("KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY must be a boolean")
		}
		c.AllowPrivateRecovery = enabled
	}
	return c, nil
}
