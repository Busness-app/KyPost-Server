package users

import (
	"path/filepath"
	"testing"
)

func newCacheTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	return store, filepath.Join(dir, "users.json")
}

// TestReadCacheServesRepeatedLookups is the point of the cache: api.currentUser
// calls Get on every authenticated request, and it used to re-read and
// re-unmarshal every account's armored key material each time.
func TestReadCacheServesRepeatedLookups(t *testing.T) {
	store, _ := newCacheTestStore(t)
	admin, err := store.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}

	for range 50 {
		got, err := store.Get(admin.ID)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ID != admin.ID || got.Username != admin.Username {
			t.Fatalf("Get returned %+v, want %s/%s", got, admin.ID, admin.Username)
		}
	}
	if !store.cacheValid {
		t.Error("cache never became valid across 50 reads")
	}
}

// TestReadCacheSeesAnotherProcessWrite is the invariant that makes the cache
// safe to have at all.
//
// users.json is written by BOTH processes supervisord starts (api and daemon).
// An in-process invalidation hook cannot see the daemon's writes, so the cache
// is guarded by the file's mtime+size instead — and every writer goes through
// fsutil.AtomicWriteFile, which renames a fresh inode into place and therefore
// always moves the mtime.
//
// A second Store over the same path is exactly what the daemon is.
func TestReadCacheSeesAnotherProcessWrite(t *testing.T) {
	store, path := newCacheTestStore(t)
	// A dedicated account: the store refuses to demote or deactivate the last
	// active admin (guardNotLastActiveAdmin), and the seeded admin is exactly
	// that. The subject here is cache freshness, not that guard.
	subject, err := store.Create("victor", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Warm this store's cache.
	if got, err := store.Get(subject.ID); err != nil || !got.Active {
		t.Fatalf("Get: %+v err=%v, want an active user", got, err)
	}

	// "The daemon process": an independent Store over the same file.
	other := newStore(path)
	if _, err := other.Deactivate(subject.ID); err != nil {
		t.Fatalf("other.Deactivate: %v", err)
	}

	got, err := store.Get(subject.ID)
	if err != nil {
		t.Fatalf("Get after other-process write: %v", err)
	}
	if got.Active {
		t.Error("Get returned a stale cached Active=true after another process deactivated the " +
			"account — a deactivation would not take effect until this process restarted")
	}
}

// TestReadCacheInvalidatedByOwnWrite covers the same-process path.
func TestReadCacheInvalidatedByOwnWrite(t *testing.T) {
	store, _ := newCacheTestStore(t)
	admin, err := store.FirstAdmin()
	if err != nil {
		t.Fatalf("FirstAdmin: %v", err)
	}
	if _, err := store.Get(admin.ID); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if _, err := store.Deactivate(admin.ID); err != nil {
		// The last-active-admin guard may refuse; use a second account instead.
		u, cerr := store.Create("someone-else", "correct-horse-battery-staple", RoleUser)
		if cerr != nil {
			t.Fatalf("Create: %v", cerr)
		}
		if _, err := store.Get(u.ID); err != nil {
			t.Fatalf("Get new user: %v", err)
		}
		if _, err := store.Deactivate(u.ID); err != nil {
			t.Fatalf("Deactivate: %v", err)
		}
		got, err := store.Get(u.ID)
		if err != nil {
			t.Fatalf("Get after deactivate: %v", err)
		}
		if got.Active {
			t.Error("Get returned a cached Active=true after Deactivate committed")
		}
		return
	}

	got, err := store.Get(admin.ID)
	if err != nil {
		t.Fatalf("Get after deactivate: %v", err)
	}
	if got.Active {
		t.Error("Get returned a cached Active=true after Deactivate committed")
	}
}

// TestListDoesNotMutateTheCache guards the hazard the cache introduced: List
// used to sort the file's own slice in place and return it. That was harmless
// while every call re-read from disk and corrupts a shared cache.
func TestListDoesNotMutateTheCache(t *testing.T) {
	store, _ := newCacheTestStore(t)
	for _, name := range []string{"zoe", "adam", "mildred"} {
		if _, err := store.Create(name, "correct-horse-battery-staple", RoleUser); err != nil {
			t.Fatalf("Create(%s): %v", name, err)
		}
	}

	first, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// Mutating the returned slice must not be visible to anyone else.
	for i := range first {
		first[i].Username = "CLOBBERED"
	}
	first[0], first[len(first)-1] = first[len(first)-1], first[0]

	second, err := store.List()
	if err != nil {
		t.Fatalf("List (second): %v", err)
	}
	for _, u := range second {
		if u.Username == "CLOBBERED" {
			t.Fatal("a caller's mutation of List's result reached the cache")
		}
	}
	// And the ordering must still be correct, not whatever the caller left.
	for i := 1; i < len(second); i++ {
		if NormalizeUsername(second[i-1].Username) > NormalizeUsername(second[i].Username) {
			t.Fatalf("List is not sorted by username: %v", []string{second[i-1].Username, second[i].Username})
		}
	}
}

// TestGetReturnsADeepCopy covers the slice field specifically: a User is copied
// by value, but RecoveryCodesHash aliases the cache's backing array unless
// cloned.
func TestGetReturnsADeepCopy(t *testing.T) {
	store, _ := newCacheTestStore(t)
	u, err := store.Create("dana", "correct-horse-battery-staple", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.ReplaceRecoveryCodes(u.ID, []string{"hash-a", "hash-b", "hash-c"}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}

	got, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.RecoveryCodesHash) != 3 {
		t.Fatalf("RecoveryCodesHash = %v, want 3 entries", got.RecoveryCodesHash)
	}
	got.RecoveryCodesHash[0] = "CLOBBERED"

	again, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if again.RecoveryCodesHash[0] != "hash-a" {
		t.Errorf("mutating a returned RecoveryCodesHash corrupted the cache: got %q, want %q — "+
			"this would silently invalidate a user's recovery codes", again.RecoveryCodesHash[0], "hash-a")
	}
}
