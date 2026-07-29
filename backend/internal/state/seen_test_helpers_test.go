package state

import "testing"

// seenForTest is store.Seen with the error asserted away, so the many call sites
// that only care about the boolean stay readable. Seen returns an error because
// "I don't know" must not silently read as "not processed" in production — see
// Store.Seen.
func seenForTest(t *testing.T, store *Store, id string) bool {
	t.Helper()
	seen, err := store.Seen(id)
	if err != nil {
		t.Fatalf("store.Seen(%q): %v", id, err)
	}
	return seen
}

// checkpointForTest is store.Checkpoint with the error asserted away.
func checkpointForTest(t *testing.T, store *Store) string {
	t.Helper()
	cp, err := store.Checkpoint()
	if err != nil {
		t.Fatalf("store.Checkpoint(): %v", err)
	}
	return cp
}
