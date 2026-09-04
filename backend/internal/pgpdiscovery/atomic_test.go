package pgpdiscovery_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
)

// Update must serialize the whole read-modify-write, not just the read and
// the write individually: two concurrent callers that both Load, both mutate
// their own copy, and both Save would silently drop one caller's change.
func TestUpdateSerializesReadModifyWrite(t *testing.T) {
	dir := t.TempDir()

	var inFlight atomic.Int32
	var overlaps atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := pgpdiscovery.Update(dir, func(s pgpdiscovery.Settings) pgpdiscovery.Settings {
				if inFlight.Add(1) > 1 {
					overlaps.Add(1)
				}
				// Hold the critical section open long enough that an
				// unserialized implementation would reliably overlap.
				time.Sleep(2 * time.Millisecond)
				inFlight.Add(-1)
				s.AutoEncryptWhenKeyKnown = true
				return s
			})
			if err != nil {
				t.Errorf("Update: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := overlaps.Load(); got != 0 {
		t.Fatalf("mutate ran concurrently %d times; Update must serialize per directory", got)
	}
	final, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !final.AutoEncryptWhenKeyKnown {
		t.Fatal("the mutation should have persisted")
	}
}

// Update must not clobber fields it does not touch, and must see the value a
// prior Update wrote (not a stale pre-Update snapshot).
func TestUpdateSeesPriorWrite(t *testing.T) {
	dir := t.TempDir()

	if _, err := pgpdiscovery.Update(dir, func(s pgpdiscovery.Settings) pgpdiscovery.Settings {
		s.AdvertiseAutocrypt = false
		return s
	}); err != nil {
		t.Fatal(err)
	}
	got, err := pgpdiscovery.Update(dir, func(s pgpdiscovery.Settings) pgpdiscovery.Settings {
		if s.AdvertiseAutocrypt {
			t.Error("second Update saw a stale value; expected the prior write")
		}
		s.PublishWKD = false
		return s
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.AdvertiseAutocrypt {
		t.Fatal("prior write to AdvertiseAutocrypt was clobbered")
	}
	if got.PublishWKD {
		t.Fatal("PublishWKD should now be false")
	}
	// Untouched on-by-default field must survive both updates.
	if !got.StoreDiscoveredKeys {
		t.Fatal("StoreDiscoveredKeys should still be on")
	}
}

// AddSuppression is itself a read-modify-write over one shared file, so
// concurrent callers (contact deletion and explicit suppression both loop
// over addresses) must not lose entries.
func TestAddSuppressionConcurrentDoesNotLoseEntries(t *testing.T) {
	dir := t.TempDir()
	const n = 50

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", i)
			if err := pgpdiscovery.AddSuppression(dir, email, pgpdiscovery.ReasonDeleted); err != nil {
				t.Errorf("AddSuppression: %v", err)
			}
		}(i)
	}
	wg.Wait()

	set, err := pgpdiscovery.SuppressedSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != n {
		t.Fatalf("expected %d suppressions to survive concurrent writes, got %d", n, len(set))
	}
}

// RemoveSuppression races AddSuppression over the same file; interleaving
// must not resurrect a removed entry or drop an unrelated one.
func TestAddAndRemoveSuppressionConcurrently(t *testing.T) {
	dir := t.TempDir()
	const n = 30

	for i := 0; i < n; i++ {
		if err := pgpdiscovery.AddSuppression(dir, fmt.Sprintf("keep%d@example.com", i), pgpdiscovery.ReasonDeleted); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := pgpdiscovery.RemoveSuppression(dir, fmt.Sprintf("keep%d@example.com", i)); err != nil {
				t.Errorf("RemoveSuppression: %v", err)
			}
		}(i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := pgpdiscovery.AddSuppression(dir, fmt.Sprintf("new%d@example.com", i), pgpdiscovery.ReasonExplicit); err != nil {
				t.Errorf("AddSuppression: %v", err)
			}
		}(i)
	}
	wg.Wait()

	set, err := pgpdiscovery.SuppressedSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if set[fmt.Sprintf("keep%d@example.com", i)] {
			t.Fatalf("keep%d@example.com should have been removed", i)
		}
		if !set[fmt.Sprintf("new%d@example.com", i)] {
			t.Fatalf("new%d@example.com should have been added", i)
		}
	}
}
