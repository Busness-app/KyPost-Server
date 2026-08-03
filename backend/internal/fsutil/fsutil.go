package fsutil

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafePathComponent reports whether value can be used as one directory or
// file-name component. It rejects both platform separators so data written on
// one OS cannot become a traversal when the volume is used on another.
func SafePathComponent(value string) bool {
	return value != "" && value != "." && value != ".." &&
		filepath.Base(value) == value &&
		!strings.ContainsAny(value, `/\\`) && !strings.ContainsRune(value, 0)
}

// AtomicWriteFile writes payload to path via a temp file + rename so readers
// never observe a partially-written file, and fsyncs both the temp file and
// the containing directory so the write survives a crash.
//
// Both fsyncs matter and they are not the same guarantee. Without the file
// fsync, the rename can reach the disk while the data behind it has not,
// leaving a file that exists and is empty or garbage. Without the directory
// fsync, the rename itself can be lost. This is not theoretical for files
// like users.json: it holds every account, and the failure mode is a server
// that will not start because the only copy no longer parses.
func AtomicWriteFile(path string, payload []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	// 0700, not 0755. Everything routed through here is per-account data —
	// users.json, encrypted IMAP credentials, sealed PGP keys, contact photos —
	// written 0600, and creating their parent directories world-readable
	// contradicted that for no gain: only this process's user ever reads them.
	// (MkdirAll leaves an existing directory's mode alone, so this changes
	// nothing for a volume that already has one.)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// SyncDir fsyncs a directory so a rename or link into it is durable. A failure
// to open the directory read-only is not fatal on filesystems that don't allow
// it; a failed Sync on a directory we did open is.
//
// Exported because AtomicWriteFile is not the only way a file appears in a
// directory: users.Store.createInitial links its temp file into place instead,
// to get exclusive creation, and needs exactly the same durability step
// afterwards.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	return nil
}

// LoadJSONFile reads path and json-unmarshals it into a fresh V, passing it
// to apply on success. If the file doesn't exist, it calls onMissing instead
// (nil to treat a missing file as a no-op) — callers use this to distinguish
// first-run seeding (persist an initial empty file) from an in-run refresh
// (keep the current in-memory state). Shared by the per-user JSON stores
// (rules/groups/contacts/mailcache), which otherwise duplicate this
// read-or-seed branch identically for both their load and refresh paths.
func LoadJSONFile[V any](path string, apply func(V), onMissing func() error) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if onMissing != nil {
				return onMissing()
			}
			return nil
		}
		return err
	}
	var v V
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	apply(v)
	return nil
}

// PersistJSONFile marshals v as indented JSON and atomically writes it to
// path with owner-only permissions.
func PersistJSONFile[V any](path string, v V) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWriteFile(path, b, 0o600)
}

// NewUUIDv4 returns a random RFC 4122 version-4 UUID string.
func NewUUIDv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
