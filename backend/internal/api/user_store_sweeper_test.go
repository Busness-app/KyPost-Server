package api

import (
	"testing"
	"time"
)

// TestIdleUserStoresAreReclaimed pins the bound on the per-user store caches.
// They were never evicted: every user who ever authenticated pinned a
// *state.Store — and with it that account's full processed-message set and
// decision history — in memory for the process lifetime.
func TestIdleUserStoresAreReclaimed(t *testing.T) {
	srv := newTestServer(t)

	if _, err := srv.userStore("user-a"); err != nil {
		t.Fatalf("userStore(user-a): %v", err)
	}
	if _, err := srv.userContactsStore("user-a"); err != nil {
		t.Fatalf("userContactsStore(user-a): %v", err)
	}
	if _, err := srv.userStore("user-b"); err != nil {
		t.Fatalf("userStore(user-b): %v", err)
	}

	srv.userMu.Lock()
	cached := len(srv.userStores)
	srv.userMu.Unlock()
	if cached != 2 {
		t.Fatalf("setup: %d cached state stores, want 2", cached)
	}

	// Nothing is idle yet, so nothing may be dropped.
	if removed := srv.sweepIdleUserStores(time.Now()); removed != 0 {
		t.Fatalf("sweep of fresh entries removed %d, want 0", removed)
	}

	if removed := srv.sweepIdleUserStores(time.Now().Add(userStoreIdleTTL + time.Minute)); removed != 2 {
		t.Fatalf("sweep of idle entries removed %d, want 2", removed)
	}

	srv.userMu.Lock()
	defer srv.userMu.Unlock()
	if len(srv.userStores) != 0 || len(srv.userContacts) != 0 || len(srv.userLastSeen) != 0 {
		t.Fatalf("after sweep: %d state, %d contacts, %d lastSeen — all six caches are swept together",
			len(srv.userStores), len(srv.userContacts), len(srv.userLastSeen))
	}
}

// TestActiveUserStoresSurviveTheSweep is the other half: a user still making
// requests must not have their stores pulled out from under them on a timer.
func TestActiveUserStoresSurviveTheSweep(t *testing.T) {
	srv := newTestServer(t)

	for _, id := range []string{"idle", "active"} {
		if _, err := srv.userStore(id); err != nil {
			t.Fatalf("userStore(%s): %v", id, err)
		}
	}
	// Both were just stamped with the real clock, so age "idle" by hand rather
	// than sweeping at a simulated future instant — that would age both.
	now := time.Now()
	srv.userMu.Lock()
	srv.userLastSeen["idle"] = now.Add(-userStoreIdleTTL - time.Minute)
	srv.userMu.Unlock()

	if removed := srv.sweepIdleUserStores(now); removed != 1 {
		t.Fatalf("sweep removed %d, want 1 (only the idle user)", removed)
	}

	srv.userMu.Lock()
	defer srv.userMu.Unlock()
	if _, ok := srv.userStores["active"]; !ok {
		t.Fatal("the sweep evicted a user who had just made a request")
	}
	if _, ok := srv.userStores["idle"]; ok {
		t.Fatal("the idle user's store survived the sweep")
	}
}

// TestEvictedStoreStaysUsableForItsHolder pins why the sweep must not Close.
//
// The caches hand out a bare *state.Store and release userMu before the caller
// has finished with it, and userLastSeen records when a store was ACQUIRED, not
// when it was released. "Idle for two hours" therefore does not mean "nobody is
// holding it": a stalled IMAP-backed handler inside the 10-minute WriteTimeout,
// a large attachment stream, or a goroutine that outlived its request can all
// still be using one.
//
// Closing at eviction severed the SQLite handle under exactly those callers and
// turned their next query into "database is closed" — a failure the evictor
// cannot predict, because it has a timestamp rather than a reference count.
// state.New registers a runtime cleanup instead, so the fd is released on
// unreachability and eviction is just a map delete.
func TestEvictedStoreStaysUsableForItsHolder(t *testing.T) {
	srv := newTestServer(t)

	// Acquire the store the way a request does, and keep holding it.
	held, err := srv.userStore("slow-caller")
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if _, err := held.Checkpoint(); err != nil {
		t.Fatalf("setup read failed before any sweep: %v", err)
	}

	if removed := srv.sweepIdleUserStores(time.Now().Add(userStoreIdleTTL + time.Minute)); removed != 1 {
		t.Fatalf("sweep removed %d, want 1", removed)
	}

	// The holder never learned about the eviction and must not have to.
	if _, err := held.Checkpoint(); err != nil {
		t.Fatalf("a caller still holding an evicted store got %v. The idle sweep closed a live "+
			"SQLite handle out from under it; eviction must drop the cache entry only.", err)
	}

	// And the next request transparently gets a fresh, working store.
	reopened, err := srv.userStore("slow-caller")
	if err != nil {
		t.Fatalf("reopen after eviction: %v", err)
	}
	if reopened == held {
		t.Error("the evicted store was handed back out; the cache entry was not dropped")
	}
	if _, err := reopened.Checkpoint(); err != nil {
		t.Fatalf("the reopened store is unusable: %v", err)
	}
}
