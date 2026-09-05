package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
)

// ErrNotFound is what Setting returns for a key never written or deleted. A key
// set to "" is present. The backup adapter maps this onto the library's.
var ErrNotFound = errors.New("state: setting not found")

// Setting reads one install-wide key from meta.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting writes one install-wide key.
func (s *Store) SetSetting(key, value string) error { return setMeta(s.db, key, value) }

// DeleteSetting removes one key; absent is not an error.
func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`DELETE FROM meta WHERE key = ?`, key)
	return err
}

// BackupAudit is one row of the backup audit.
type BackupAudit struct {
	ID      int64  `json:"id"`
	At      string `json:"at"`
	Action  string `json:"action"`
	Actor   string `json:"actor"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Details string `json:"details"`
}

// RecordBackupAudit appends one row. details is marshalled to JSON; nil is "{}".
func (s *Store) RecordBackupAudit(action, actor, target, outcome string, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	d, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("backup audit details: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO backup_audit(at, action, actor, target, outcome, details) VALUES(?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), action, actor, target, outcome, string(d))
	return err
}

// RecentBackupAudit returns up to limit rows, newest first.
func (s *Store) RecentBackupAudit(limit int) ([]BackupAudit, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, at, action, actor, target, outcome, details FROM backup_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackupAudit{}
	for rows.Next() {
		var r BackupAudit
		if err := rows.Scan(&r.ID, &r.At, &r.Action, &r.Actor, &r.Target, &r.Outcome, &r.Details); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SnapshotDB returns a consistent copy of the SQLite database at path,
// including rows still in its WAL, through the library's VACUUM INTO. It opens
// a fresh handle because the collector runs in whichever process was asked
// (api or daemon) and neither holds every user's store; WAL locking is what
// makes a third reader safe. scratchDir must be a 0700 directory the caller
// owns and removes; the copy is written there under a fresh name and read back.
func SnapshotDB(ctx context.Context, path, scratchDir string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String()+"?mode=rw&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	dest := filepath.Join(scratchDir, fmt.Sprintf("snap-%d.db", time.Now().UnixNano()))
	defer os.Remove(dest)
	if err := recoveryclient.SQLiteSnapshot(ctx, db, dest); err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", path, err)
	}
	f, err := os.Open(dest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, recoveryclient.MaxCapsuleFileBytes+1))
}

// BackupSettingsTransaction publishes a multi-row pairing change atomically.
func (s *Store) BackupSettingsTransaction(fn func(recoveryclient.Settings) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(backupSettingsTx{tx}); err != nil {
		return err
	}
	return tx.Commit()
}

type backupSettingsTx struct{ tx *sql.Tx }

func (s backupSettingsTx) Get(k string) (string, error) {
	var v string
	err := s.tx.QueryRow("SELECT value FROM meta WHERE key = ?", k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (s backupSettingsTx) Set(k, v string) error { return setMeta(s.tx, k, v) }
func (s backupSettingsTx) Delete(k string) error {
	_, err := s.tx.Exec("DELETE FROM meta WHERE key = ?", k)
	return err
}
