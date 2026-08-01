package users

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFreshInstallHandsThePasswordOverInAFileNotOnStderr covers the standalone
// bootstrap path's credential handoff.
//
// LoadOrMigrate used to print the generated admin password to stderr. In the
// container that branch is unreachable (scripts/bootstrap.sh writes admin.env
// first), which is why it survived: SECURITY.md's "the password is never
// logged" was true of the path the maintainer ran and false of the one a
// systemd or CI install takes, where stderr is the journal — centralized,
// retained, and readable by more people than the config directory.
//
// The file is asserted to hold the credential that actually works, not merely
// to exist. A handoff that writes the wrong string is the same lockout as no
// handoff at all, and this is the only copy of a password nobody chose.
func TestFreshInstallHandsThePasswordOverInAFileNotOnStderr(t *testing.T) {
	dir := t.TempDir()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	realStderr := os.Stderr
	os.Stderr = w
	store, loadErr := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	os.Stderr = realStderr
	_ = w.Close()
	printed, _ := io.ReadAll(r)
	_ = r.Close()
	if loadErr != nil {
		t.Fatalf("LoadOrMigrate: %v", loadErr)
	}

	pwPath := filepath.Join(dir, BootstrapPasswordFile)
	info, err := os.Stat(pwPath)
	if err != nil {
		t.Fatalf("no %s written on a fresh install: %v", BootstrapPasswordFile, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s mode = %o, want 600", BootstrapPasswordFile, perm)
	}

	body, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatalf("read %s: %v", BootstrapPasswordFile, err)
	}
	password := ""
	for _, line := range strings.Split(string(body), "\n") {
		if rest, ok := strings.CutPrefix(line, "password: "); ok {
			password = strings.TrimSpace(rest)
		}
	}
	if password == "" {
		t.Fatalf("no password line in %s:\n%s", BootstrapPasswordFile, body)
	}

	users, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("fresh install has %d users, want 1", len(users))
	}
	if ok, _ := VerifyPassword(context.Background(), users[0], password); !ok {
		t.Fatal("the password in the handoff file does not authenticate the account it was written for")
	}

	// The whole point: the credential is in the file and nowhere else. The
	// path may be printed; the secret may not.
	if strings.Contains(string(printed), password) {
		t.Errorf("the generated password was printed to stderr:\n%s", printed)
	}
	if !strings.Contains(string(printed), pwPath) {
		t.Errorf("stderr does not tell the operator where to find the password:\n%s", printed)
	}
}

// TestFreshInstallFailsRatherThanStrandTheAdmin covers the recovery-hostile
// case: users.json is created, so the next start will not bootstrap again, and
// the only account on it has a random password. If that password cannot be
// handed over, there is nothing to fall back to — startup has to fail loudly
// and say how to retry, not return a store nobody can log into.
func TestFreshInstallFailsRatherThanStrandTheAdmin(t *testing.T) {
	dir := t.TempDir()

	// A directory where the handoff file belongs: AtomicWriteFile cannot
	// replace it, so the write fails while users.json itself succeeds.
	if err := os.MkdirAll(filepath.Join(dir, BootstrapPasswordFile), 0o700); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	realStderr := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Stderr = devNull
	_, loadErr := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	os.Stderr = realStderr
	_ = devNull.Close()

	if loadErr == nil {
		t.Fatal("LoadOrMigrate reported success after failing to hand over the generated password")
	}
	// The operator has to be told how to get out of it, since deleting
	// users.json is the only way back to a bootstrap.
	if !strings.Contains(loadErr.Error(), "users.json") {
		t.Errorf("error does not name the file to delete to retry: %v", loadErr)
	}
}
