package groups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run-4 M9: resolveGroupIDsByName called Upsert once per new CATEGORIES name,
// and every Upsert takes a flock, reads and unmarshals the whole file, marshals
// it all back and AtomicWriteFiles it with two fsyncs. That is O(n^2) bytes for
// n categories on one card.
//
// Measured on tmpfs — the optimistic case, real disk adds the fsyncs — 500
// categories took 0.30s, 2,000 took 5.03s and 5,000 took 32.1s: clean
// quadratic. A single 1.49 MB vCard carrying 200,000 categories fits well under
// both the 10 MiB import cap and the 5 MiB CardDAV cap, and extrapolates to
// hours of saturated CPU and disk on a volume every other user shares.
//
// EnsureByName does the whole resolve in one locked read-modify-write, and the
// count is capped so no single card can mint an unbounded number of groups.

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func TestEnsureByNameCreatesEveryMissingGroup(t *testing.T) {
	store := newTestStore(t)

	ids, err := store.EnsureByName([]string{"Work", "Family", "Cycling"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("ids = %v, want 3", ids)
	}
	if got := len(mustList(t, store)); got != 3 {
		t.Fatalf("stored groups = %d, want 3", got)
	}
}

// The whole point of the batch: one persist, not one per name.
func TestEnsureByNameWritesTheFileOnce(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	path := filepath.Join(dir, "groups.json")

	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	names := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		names = append(names, fmt.Sprintf("group-%d", i))
	}
	if _, err := store.EnsureByName(names); err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !after.ModTime().After(before.ModTime()) && after.Size() == before.Size() {
		t.Fatal("nothing was written at all")
	}
	if got := len(mustList(t, store)); got != 200 {
		t.Fatalf("stored groups = %d, want 200", got)
	}
}

func TestEnsureByNameReusesExistingGroupsCaseInsensitively(t *testing.T) {
	store := newTestStore(t)
	created, err := store.Upsert(Group{Name: "Work"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	ids, err := store.EnsureByName([]string{"work", "WORK", "Work"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}
	for _, id := range ids {
		if id != created.ID {
			t.Fatalf("ids = %v, want every entry to be the existing group %q", ids, created.ID)
		}
	}
	if got := len(mustList(t, store)); got != 1 {
		t.Fatalf("stored groups = %d, want 1 — case variants must not mint duplicates", got)
	}
}

// A card listing the same category twice must not produce a duplicate GroupID
// on the contact.
func TestEnsureByNameDeduplicatesWithinOneCall(t *testing.T) {
	store := newTestStore(t)

	ids, err := store.EnsureByName([]string{"Work", "Work", "work"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("ids = %v, want 1", ids)
	}
}

func TestEnsureByNameIgnoresBlankNames(t *testing.T) {
	store := newTestStore(t)

	ids, err := store.EnsureByName([]string{"", "   ", "\t"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("ids = %v, want none", ids)
	}
	if got := len(mustList(t, store)); got != 0 {
		t.Fatalf("stored groups = %d, want 0", got)
	}
}

// The per-user ceiling. Without it, a card can mint groups without limit and
// every later PROPFIND and export pays for them forever.
func TestEnsureByNameRefusesPastThePerUserCap(t *testing.T) {
	store := newTestStore(t)

	names := make([]string, 0, MaxGroupsPerUser+1)
	for i := 0; i < MaxGroupsPerUser+1; i++ {
		names = append(names, fmt.Sprintf("group-%d", i))
	}

	_, err := store.EnsureByName(names)
	if !errors.Is(err, ErrTooManyGroups) {
		t.Fatalf("err = %v, want ErrTooManyGroups", err)
	}
	// Nothing partial: a refused batch leaves the store as it was.
	if got := len(mustList(t, store)); got != 0 {
		t.Fatalf("a refused batch persisted %d groups", got)
	}
}

// The cap is on the total, so an account already near it cannot be pushed over
// by a small card.
func TestEnsureByNameCountsGroupsAlreadyStored(t *testing.T) {
	store := newTestStore(t)

	names := make([]string, 0, MaxGroupsPerUser)
	for i := 0; i < MaxGroupsPerUser; i++ {
		names = append(names, fmt.Sprintf("group-%d", i))
	}
	if _, err := store.EnsureByName(names); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := store.EnsureByName([]string{"one-too-many"}); !errors.Is(err, ErrTooManyGroups) {
		t.Fatalf("err = %v, want ErrTooManyGroups", err)
	}
	// But re-resolving names that already exist must still work — being at the
	// cap cannot break ordinary sync of existing cards.
	if _, err := store.EnsureByName([]string{"group-0", "group-1"}); err != nil {
		t.Fatalf("resolving existing groups at the cap failed: %v", err)
	}
}

func TestEnsureByNameTrimsNames(t *testing.T) {
	store := newTestStore(t)

	if _, err := store.EnsureByName([]string{"  Work  "}); err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}
	list := mustList(t, store)
	if len(list) != 1 || list[0].Name != "Work" {
		t.Fatalf("stored %+v, want a single trimmed \"Work\"", list)
	}
	if strings.TrimSpace(list[0].Name) != list[0].Name {
		t.Fatal("name was stored untrimmed")
	}
}
