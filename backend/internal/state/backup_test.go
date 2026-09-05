package state

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Setting("kyrecovery_url"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent key: err=%v want ErrNotFound", err)
	}
	if err := s.SetSetting("kyrecovery_url", "https://r.example"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Setting("kyrecovery_url"); err != nil || v != "https://r.example" {
		t.Fatalf("got %q err=%v", v, err)
	}
	if err := s.SetSetting("empty", ""); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Setting("empty"); err != nil || v != "" {
		t.Fatalf("a key set to empty is present, not ErrNotFound: %q %v", v, err)
	}
	if err := s.DeleteSetting("kyrecovery_url"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Setting("kyrecovery_url"); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete did not remove the key")
	}
	if err := s.DeleteSetting("never-set"); err != nil {
		t.Fatalf("deleting an absent key must be a no-op, got %v", err)
	}
}

func TestBackupAuditIsAppendOnlyNewestFirst(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RecordBackupAudit("admin.backup_pair", "alice", "key:abc", "success", map[string]any{"allow_private": true}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordBackupAudit("admin.backup_run", "system", "cap:1", "failure", map[string]any{"error": "boom"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.RecentBackupAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Action != "admin.backup_run" || rows[1].Actor != "alice" {
		t.Fatalf("got %+v", rows)
	}
	if rows[0].Details != `{"error":"boom"}` {
		t.Fatalf("details %q", rows[0].Details)
	}
}

func TestSnapshotDBCarriesUncheckpointedWALRow(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetSetting("probe", "in-wal"); err != nil {
		t.Fatal(err)
	}
	raw, err := SnapshotDB(context.Background(), filepath.Join(dir, "state.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", out)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'probe'`).Scan(&v); err != nil || v != "in-wal" {
		t.Fatalf("snapshot missing the WAL row: v=%q err=%v", v, err)
	}
}
