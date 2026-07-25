package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WithFileLock runs fn while holding an exclusive advisory lock covering
// path, serializing a whole read-modify-write cycle against every other
// process that uses this same helper for the same path.
//
// This exists because every JSON store in this codebase mutates its file by
// reading the whole thing, changing it in memory, and writing the whole
// thing back. A sync.Mutex makes that safe against other goroutines and
// nothing else — and this server does not run as one process. supervisord
// starts `kypost-server --mode server` and `kypost-server --mode daemon` as
// two independent processes (see supervisord.conf) that share
// CONFIG_DIR/users.json, every per-user STATE_DIR file, and the instance
// WKD claims file. Both of them write. Re-reading from disk immediately
// before a write narrows the lost-update window; it does not close it.
//
// The lock is taken on a sibling "<path>.lock" file rather than on path
// itself, because the stores write via AtomicWriteFile (temp file +
// rename): a lock held on the original inode would be silently detached
// from the file the moment the rename replaced it. The lock file is created
// once and never removed — unlinking it while another process holds it open
// would hand two processes locks on two different inodes.
//
// Readers do not need this. AtomicWriteFile publishes by rename, so a reader
// always observes either the whole previous file or the whole next one,
// never a mixture.
func WithFileLock(path string, fn func() error) error {
	release, err := LockFile(path)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

// LockFile is WithFileLock for callers whose return signature does not fit a
// func() error closure. It takes the lock and returns the release func,
// which the caller must defer immediately:
//
//	release, err := fsutil.LockFile(s.path())
//	if err != nil {
//		return Thing{}, false, err
//	}
//	defer release()
//
// Prefer WithFileLock where the closure form fits; it cannot be misused by
// forgetting the defer.
func LockFile(path string) (release func(), err error) {
	// The lock is taken before the store writes anything, so on a first-ever
	// write the containing directory may not exist yet (per-user state dirs
	// are created lazily by the stores' own save paths).
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
