package config

import (
	"testing"
	"time"
)

func clearBackupEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"KYPOST_BACKUP_DEPOSIT_INTERVAL", "KYPOST_BACKUP_DIR", "KYPOST_BACKUP_KEEP", "KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY"} {
		t.Setenv(k, "")
	}
}

func TestLoadBackupConfigDefaults(t *testing.T) {
	clearBackupEnv(t)
	c, err := LoadBackupConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.DepositInterval != 24*time.Hour || c.Dir != "" || c.Keep != 7 || c.AllowPrivateRecovery {
		t.Fatalf("defaults wrong: %+v", c)
	}
}

func TestLoadBackupConfigRejectsBadValues(t *testing.T) {
	cases := map[string][2]string{
		"interval below floor":    {"KYPOST_BACKUP_DEPOSIT_INTERVAL", "5m"},
		"interval above ceiling":  {"KYPOST_BACKUP_DEPOSIT_INTERVAL", "9000h"},
		"interval not a duration": {"KYPOST_BACKUP_DEPOSIT_INTERVAL", "daily"},
		"relative dir":            {"KYPOST_BACKUP_DIR", "backups"},
		"keep zero":               {"KYPOST_BACKUP_KEEP", "0"},
	}
	for name, kv := range cases {
		t.Run(name, func(t *testing.T) {
			clearBackupEnv(t)
			t.Setenv(kv[0], kv[1])
			if _, err := LoadBackupConfig(); err == nil {
				t.Fatalf("%s=%s accepted", kv[0], kv[1])
			}
		})
	}
}

func TestLoadBackupConfigAcceptsOffAndPrivate(t *testing.T) {
	clearBackupEnv(t)
	t.Setenv("KYPOST_BACKUP_DEPOSIT_INTERVAL", "0")
	t.Setenv("KYPOST_BACKUP_DIR", t.TempDir())
	t.Setenv("KYPOST_BACKUP_KEEP", "3")
	t.Setenv("KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY", "TRUE")
	c, err := LoadBackupConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.DepositInterval != 0 || c.Keep != 3 || !c.AllowPrivateRecovery {
		t.Fatalf("got %+v", c)
	}
}
