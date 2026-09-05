package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestDAVAppPasswordRehashesOnSuccessfulVerify plants a legacy scrypt hash in
// the CardDAV app-password file, exactly as an account created before the
// Argon2id migration still has on disk, and proves a successful Basic Auth
// verify upgrades it in place: the account's next sync attempt should not pay
// scrypt forever just because this file's format predates the switch.
//
// No t.Parallel(): this package writes users.hashCostN/hashParams from
// TestMain and withProductionHashCost, both unsynchronized package variables —
// see TestNoTestInThisPackageCallsParallel.
func TestDAVAppPasswordRehashesOnSuccessfulVerify(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-rehash", "dav-rehash-user-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const appPassword = "app-specific-password-1234"
	legacy, err := users.LegacyScryptHashForTest(context.Background(), appPassword)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if !strings.HasPrefix(legacy, "scrypt$") {
		t.Fatalf("fixture hash = %q, want a scrypt$ prefix", legacy)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{
		Hash:      legacy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	reached := false
	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest("PROPFIND", davPrefix+"/dav-rehash/", nil)
	req.SetBasicAuth(u.Username, appPassword)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("request did not reach the handler; got %d", rec.Code)
	}

	f, exists, err := srv.readDAVPassword(u.ID)
	if err != nil {
		t.Fatalf("readDAVPassword: %v", err)
	}
	if !exists {
		t.Fatal("carddav password file disappeared after a successful verify")
	}
	if !strings.HasPrefix(f.Hash, "$argon2id$") {
		t.Fatalf("stored hash = %q, want it upgraded to $argon2id$ after a successful verify", f.Hash)
	}
	if users.NeedsRehash(f.Hash) {
		t.Error("the upgraded hash still reports as needing a rehash")
	}
	ok, err := users.VerifySecretHash(context.Background(), f.Hash, appPassword)
	if err != nil {
		t.Fatalf("VerifySecretHash: %v", err)
	}
	if !ok {
		t.Fatal("the app password no longer verifies against its upgraded hash")
	}
}

// TestDAVAppPasswordRehashSkipsWhenRevocationRacesIt is the regression for the
// resurrection bug: rehashDAVAppPassword runs after two derivations that can
// each queue for up to KDFMaxQueueWait, long enough for
// revokeAllUserCredentialsExcept (or the DELETE handler) to delete the file in
// between. A write that ignores that must not land — it would recreate a
// credential that was just revoked, permanently, since nothing else will ever
// delete it again.
//
// There is no hook to interpose exactly between VerifySecretHash and
// HashPassword inside withDAVBasicAuth, so this drives rehashDAVAppPassword
// directly with a generation snapshotted BEFORE the simulated revocation,
// exactly as withDAVBasicAuth would have snapshotted it before the read that
// preceded both derivations.
func TestDAVAppPasswordRehashSkipsWhenRevocationRacesIt(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-rehash-revoke", "dav-rehash-revoke-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const appPassword = "app-specific-password-5678"
	legacy, err := users.LegacyScryptHashForTest(context.Background(), appPassword)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{
		Hash:      legacy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	// The generation withDAVBasicAuth would have snapshotted before reading
	// the file and verifying against it.
	gen := srv.davCredentials.currentGeneration()

	// A revocation races the two derivations: it invalidates the cache
	// (bumping the generation past gen) and deletes the credential file —
	// exactly what revokeAllUserCredentialsExcept and the DELETE handler do.
	srv.davCredentials.invalidateUser(u.Username)
	if err := os.Remove(srv.userCardDAVAuthPath(u.ID)); err != nil {
		t.Fatalf("simulate revocation: %v", err)
	}

	// The in-flight rehash, still carrying the pre-revocation hash and the
	// stale generation, finishes and tries to persist its upgrade.
	srv.rehashDAVAppPassword(context.Background(), u.ID, legacy, appPassword, gen)

	if _, exists, err := srv.readDAVPassword(u.ID); err != nil {
		t.Fatalf("readDAVPassword: %v", err)
	} else if exists {
		t.Fatal("a revoked carddav app password was resurrected by a racing rehash")
	}
}

// TestDAVAppPasswordWritersSerializeOnTheFileLock is the half the two
// generation tests cannot reach. Both of them invalidate BEFORE calling the
// rehash, so they only exercise the case the generation check trivially
// catches. The window that stayed open was between the rehash's re-read and
// its write — an AtomicWriteFile, so a file fsync and a directory fsync wide,
// not "microseconds" — and a revoke landing inside it resurrected the
// credential permanently.
//
// Holding the lock from outside stands in for whichever writer is mid-write.
// Both the rehash and the DELETE handler must wait for it, which is what makes
// read-verify-write and revoke mutually exclusive rather than merely narrow.
func TestDAVAppPasswordWritersSerializeOnTheFileLock(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-rehash-lock", "dav-rehash-lock-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const appPassword = "app-specific-password-9012"
	legacy, err := users.LegacyScryptHashForTest(context.Background(), appPassword)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{
		Hash:      legacy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	// blockedUntilUnlocked runs work while the credential file's lock is held
	// elsewhere, and fails if it finishes anyway.
	blockedUntilUnlocked := func(what string, work func()) {
		t.Helper()
		release, err := fsutil.LockFile(srv.userCardDAVAuthPath(u.ID))
		if err != nil {
			t.Fatalf("LockFile: %v", err)
		}
		var once sync.Once
		unlock := func() { once.Do(release) }
		defer unlock()

		done := make(chan struct{})
		go func() {
			work()
			close(done)
		}()
		select {
		case <-done:
			t.Fatalf("%s completed while another writer held the credential file's lock", what)
		case <-time.After(200 * time.Millisecond):
		}
		unlock()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s never completed after the lock was released", what)
		}
	}

	gen := srv.davCredentials.currentGeneration()
	blockedUntilUnlocked("the app-password rehash", func() {
		srv.rehashDAVAppPassword(context.Background(), u.ID, legacy, appPassword, gen)
	})
	f, exists, err := srv.readDAVPassword(u.ID)
	if err != nil || !exists {
		t.Fatalf("readDAVPassword after the rehash: exists=%v err=%v", exists, err)
	}
	if !strings.HasPrefix(f.Hash, "$argon2id$") {
		t.Fatalf("stored hash = %q, want it upgraded once the lock was free", f.Hash)
	}

	blockedUntilUnlocked("the DELETE handler", func() {
		req := httptest.NewRequest(http.MethodDelete, "/api/contacts/dav-password", nil)
		req = req.WithContext(context.WithValue(req.Context(), authContextKey{},
			AuthContext{UserID: u.ID, Username: u.Username, Role: users.RoleUser}))
		rec := httptest.NewRecorder()
		srv.handleContactsDAVPassword(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("DELETE dav-password: status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	if _, exists, err := srv.readDAVPassword(u.ID); err != nil {
		t.Fatalf("readDAVPassword after DELETE: %v", err)
	} else if exists {
		t.Fatal("the credential survived a DELETE that waited for the lock")
	}
}

// TestDAVAppPasswordRehashSkipsWhenRegenerateRacesIt covers the sibling race:
// POST-regenerate mints a brand new app password and hash while an old
// password's rehash is in flight. The in-flight rehash must not overwrite the
// freshly minted hash with a re-derivation of the OLD password.
func TestDAVAppPasswordRehashSkipsWhenRegenerateRacesIt(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-rehash-regen", "dav-rehash-regen-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const oldAppPassword = "old-app-specific-password-111"
	oldLegacy, err := users.LegacyScryptHashForTest(context.Background(), oldAppPassword)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{
		Hash:      oldLegacy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	gen := srv.davCredentials.currentGeneration()

	// POST /api/contacts/dav-password races the in-flight rehash: a new
	// password is generated and its hash replaces the old one, invalidating
	// the cache the same way DELETE and revocation do.
	newHash, err := users.HashPassword(context.Background(), "brand-new-app-password-222")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	newCreatedAt := time.Now().UTC().Format(time.RFC3339)
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{Hash: newHash, CreatedAt: newCreatedAt}); err != nil {
		t.Fatalf("writeDAVPassword (regenerate): %v", err)
	}
	srv.davCredentials.invalidateUser(u.Username)

	// The in-flight rehash, still carrying the OLD password and hash and the
	// stale generation, finishes and tries to persist its upgrade.
	srv.rehashDAVAppPassword(context.Background(), u.ID, oldLegacy, oldAppPassword, gen)

	f, exists, err := srv.readDAVPassword(u.ID)
	if err != nil {
		t.Fatalf("readDAVPassword: %v", err)
	}
	if !exists {
		t.Fatal("carddav password file disappeared")
	}
	if f.Hash != newHash {
		t.Fatalf("stored hash = %q, want the freshly regenerated %q untouched by the racing rehash", f.Hash, newHash)
	}
	if f.CreatedAt != newCreatedAt {
		t.Fatalf("CreatedAt = %q, want the regenerated %q untouched", f.CreatedAt, newCreatedAt)
	}
}
