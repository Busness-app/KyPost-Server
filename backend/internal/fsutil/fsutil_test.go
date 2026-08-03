package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// Everything routed through AtomicWriteFile is per-account data written 0600 —
// users.json, encrypted IMAP credentials, sealed PGP keys, contact photos. The
// directories it creates on the way must not be looser than the files inside
// them.
func TestAtomicWriteFileCreatesOwnerOnlyDirectories(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "users", "some-user-id", "state.json")

	if err := AtomicWriteFile(path, []byte(`{"secret":true}`), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	for _, dir := range []string{
		filepath.Join(root, "users"),
		filepath.Join(root, "users", "some-user-id"),
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s created with mode %04o, want 0700 — it holds 0600 secrets", dir, perm)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode %04o, want 0600", perm)
	}
}

func TestSafePathComponentRejectsTraversal(t *testing.T) {
	for _, value := range []string{"", ".", "..", "../outside", `..\outside`, "nested/name", "nul\x00byte"} {
		if SafePathComponent(value) {
			t.Errorf("SafePathComponent(%q) = true, want false", value)
		}
	}
	for _, value := range []string{"user-a", "550e8400-e29b-41d4-a716-446655440000"} {
		if !SafePathComponent(value) {
			t.Errorf("SafePathComponent(%q) = false, want true", value)
		}
	}
}

// MkdirAll leaves an existing directory's mode alone, so tightening the create
// mode must not disturb a volume that already has one.
func TestAtomicWriteFileLeavesExistingDirectoryModeAlone(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "preexisting")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := AtomicWriteFile(filepath.Join(dir, "f.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Errorf("existing directory was re-moded to %04o; MkdirAll should have left it at 0755", perm)
	}
}

// The write must be atomic and leave no temp file behind.
func TestAtomicWriteFileLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := AtomicWriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "f.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want just f.json", names)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("content = %q, want %q", got, "payload")
	}
}
