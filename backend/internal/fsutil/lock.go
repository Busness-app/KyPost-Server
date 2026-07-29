package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithFileLock runs fn while holding an exclusive advisory lock covering
// path, serializing a whole read-modify-write cycle against every other
// process using this helper for the same path.
//
// A sync.Mutex is not enough: supervisord runs `--mode server` and
// `--mode daemon` as two processes that both write users.json, every per-user
// state file, and the WKD claims file. Re-reading before writing narrows the
// lost-update window; only holding a lock across the whole cycle closes it.
//
// The lock must be on the sibling "<path>.lock", never on path itself — the
// stores publish by rename (AtomicWriteFile), so a lock on the original inode
// detaches the moment a write lands. The lock file is never unlinked, for the
// same reason: two processes would end up holding locks on two inodes.
//
// Readers do not need this. Rename-publish means a reader sees either the
// whole previous file or the whole next one.
func WithFileLock(path string, fn func() error) error {
	release, err := LockFile(path)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// LockFile is WithFileLock for callers whose return signature does not fit a
// func() error closure. The caller must defer the returned release
// immediately. Prefer WithFileLock where the closure form fits; it cannot be
// misused by forgetting the defer.
func LockFile(path string) (release func(), err error) {
	// Per-user state dirs are created lazily by the stores' own save paths, so
	// on a first-ever write the directory may not exist yet.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create dir for lock file %s: %w", path, err)
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file for %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
