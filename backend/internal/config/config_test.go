package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestLoadOrCreateNotificationPrivateKey_WritesWithOwnerOnlyPermissions
// proves the private key file is owner-only (0600) at the moment the write
// returns. The implementation must never route through os.Create (which
// defaults to world/group-readable perms until a later os.Chmod) — it must
// build the PEM in memory and hand it to fsutil.AtomicWriteFile, which
// chmods the temp file *before* the rename that makes it visible under the
// final name. That is verified here by immediate-permission inspection, and
// by code inspection of loadOrCreateNotificationPrivateKey (see config.go).
func TestLoadOrCreateNotificationPrivateKey_WritesWithOwnerOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notifications-vapid-private.pem")

	if _, err := loadOrCreateNotificationPrivateKey(path); err != nil {
		t.Fatalf("loadOrCreateNotificationPrivateKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600 immediately after write, got %o", perm)
	}
}

// TestLoadOrCreateNotificationPrivateKey_ConcurrentCallersConverge simulates
// the daemon/server cross-process race on a fresh install: many concurrent
// callers race to be first to see "file doesn't exist" and generate a
// keypair. Without a lock, more than one caller generates its own keypair
// and whichever writes last "wins" on disk while other callers return a
// DIFFERENT in-memory key than what's now persisted. With the flock fix,
// exactly one caller may generate+write; every other caller must re-read the
// winner's key from disk after acquiring the lock, so all callers converge
// on a single keypair that matches what's on disk.
func TestLoadOrCreateNotificationPrivateKey_ConcurrentCallersConverge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notifications-vapid-private.pem")

	const n = 25
	var wg sync.WaitGroup
	start := make(chan struct{})
	keys := make([]*ecdsa.PrivateKey, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			key, err := loadOrCreateNotificationPrivateKey(path)
			keys[i] = key
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}

	first := keys[0]
	for i, key := range keys {
		if key == nil {
			t.Fatalf("caller %d returned nil key", i)
		}
		if !bytes.Equal(privateScalar(t, key), privateScalar(t, first)) {
			t.Fatalf("caller %d generated/returned a DIFFERENT keypair than caller 0 (D mismatch) — losing callers must re-read the winner's key from disk, not keep their own generated key", i)
		}
		if key.X.Cmp(first.X) != 0 || key.Y.Cmp(first.Y) != 0 {
			t.Fatalf("caller %d public key point differs from caller 0", i)
		}
	}

	// The key every caller converged on must also be the one actually
	// persisted on disk, i.e. config.yaml's public key can never end up
	// mismatched with the private key file.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted key: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("persisted file is not valid PEM")
	}
	onDisk, err := parseNotificationPrivateKeyPEM(b)
	if err != nil {
		t.Fatalf("parse persisted key: %v", err)
	}
	if !bytes.Equal(privateScalar(t, onDisk), privateScalar(t, first)) {
		t.Fatalf("key on disk does not match the keypair every caller converged on")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected file mode 0600, got %o", perm)
	}
}

// TestLoadOrCreateNotificationPrivateKey_ReadsExistingKeyUnchanged is a
// sanity check that once a key exists on disk, repeated (and concurrent)
// calls simply return it rather than ever regenerating.
func TestLoadOrCreateNotificationPrivateKey_ReadsExistingKeyUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notifications-vapid-private.pem")

	first, err := loadOrCreateNotificationPrivateKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	keys := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := loadOrCreateNotificationPrivateKey(path)
			if err != nil {
				t.Errorf("call %d: %v", i, err)
				return
			}
			keys[i] = key
		}(i)
	}
	wg.Wait()

	for i, key := range keys {
		if key == nil {
			continue
		}
		if !bytes.Equal(privateScalar(t, key), privateScalar(t, first)) {
			t.Fatalf("call %d returned a different key than the pre-existing one on disk", i)
		}
	}
}

// sanity: exercise the P256 curve constant the same way production code does,
// so a future refactor of the curve choice would be caught here too.
func TestLoadOrCreateNotificationPrivateKey_UsesP256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notifications-vapid-private.pem")
	key, err := loadOrCreateNotificationPrivateKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateNotificationPrivateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("expected P256 curve")
	}
}

// privateScalar returns a key's raw private scalar. The obvious spelling,
// key.D, is deprecated as of Go 1.26; ecdh.PrivateKey.Bytes() is the
// supported way to get the same value, and it comes back fixed-width.
func privateScalar(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	e, err := k.ECDH()
	if err != nil {
		t.Fatalf("convert key to ecdh: %v", err)
	}
	return e.Bytes()
}
