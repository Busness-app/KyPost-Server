package backup

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/state"
)

func fixtureDirs(t *testing.T) Dirs {
	t.Helper()
	d := Dirs{Config: t.TempDir(), State: t.TempDir(), Secret: t.TempDir()}
	must := func(p string, b []byte) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must(filepath.Join(d.Config, "config.yaml"), []byte("x: 1\n"))
	must(filepath.Join(d.Config, "users.json"), []byte(`{"users":[]}`))
	must(filepath.Join(d.Config, "users", "u1", "imap-config.json"), []byte("{}"))
	must(filepath.Join(d.Secret, "imap-config.key"), []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))))
	must(filepath.Join(d.Secret, "totp-secret.key"), []byte(base64.StdEncoding.EncodeToString(make([]byte, 32))))
	must(filepath.Join(d.Secret, "pairing.key"), []byte("k"))
	must(filepath.Join(d.State, "users", "u1", "contacts.json"), []byte("[]"))
	must(filepath.Join(d.State, "users", "u1", "mailcache.json"), []byte(`{"big":"cache"}`))
	must(filepath.Join(d.State, "users", "u1", "state.json.migrated"), []byte("old"))
	for _, dir := range []string{d.State, filepath.Join(d.State, "users", "u1")} {
		st, err := state.New(dir)
		if err != nil {
			t.Fatal(err)
		}
		st.Close()
	}
	return d
}

func openService(t *testing.T, d Dirs, bc config.BackupConfig) *Service {
	t.Helper()
	st, err := state.New(d.State)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if bc.Keep == 0 {
		bc.Keep = 7
	}
	svc, err := New(d, bc, st, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCollectSealsConfigKeysAndDatabasesNotMail(t *testing.T) {
	svc := openService(t, fixtureDirs(t), config.BackupConfig{})
	p, err := svc.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if p.ServiceName != "KyPost" || p.AppVersion != "0.0.0-test" {
		t.Fatalf("manifest identity %q %q", p.ServiceName, p.AppVersion)
	}
	paths := map[string]bool{}
	for _, f := range p.Files {
		paths[f.Path] = true
	}
	for _, want := range []string{
		"config/config.yaml", "config/users.json", "config/users/u1/imap-config.json",
		"private/imap-config.key", "private/pairing.key",
		"state/state.db", "state/users/u1/state.db", "state/users/u1/contacts.json",
	} {
		if !paths[want] {
			t.Errorf("missing %s (have %v)", want, paths)
		}
	}
	for _, no := range []string{"state/users/u1/mailcache.json", "state/users/u1/state.json.migrated"} {
		if paths[no] {
			t.Errorf("%s must not be sealed", no)
		}
	}
	if p.VerificationRecipe["mail"] != ErrMailExcluded {
		t.Fatalf("recipe must say mail is excluded, got %v", p.VerificationRecipe["mail"])
	}
	if entries, _ := os.ReadDir(filepath.Join(svc.dirs.State, "backup-scratch")); len(entries) != 0 {
		t.Fatalf("scratch left behind: %v", entries)
	}
}

func TestNewRefusesWithoutMasterKey(t *testing.T) {
	d := fixtureDirs(t)
	os.Remove(filepath.Join(d.Secret, "imap-config.key"))
	st, _ := state.New(d.State)
	defer st.Close()
	svc, err := New(d, config.BackupConfig{Keep: 7}, st, "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Collect(); err == nil {
		t.Fatal("New must refuse when the master key that seals the token is missing")
	}
}

func TestCollectRefusesOversizedFile(t *testing.T) {
	d := fixtureDirs(t)
	if err := os.WriteFile(filepath.Join(d.Config, "TUNING.md"), make([]byte, 65<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := openService(t, d, config.BackupConfig{})
	_, err := svc.Collect()
	if err == nil || !strings.Contains(err.Error(), "TUNING.md") || !strings.Contains(err.Error(), "64 MiB") {
		t.Fatalf("want an error naming the file and the cap, got %v", err)
	}
}
