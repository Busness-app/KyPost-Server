package processor

import (
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/state"
)

// seenForTest is store.Seen with the error asserted away, so the many call sites
// that only care about the boolean stay readable. Seen returns an error because
// "I don't know" must not silently read as "not processed" in production — see
// state.Store.Seen.
func seenForTest(t *testing.T, store *state.Store, id string) bool {
	t.Helper()
	seen, err := store.Seen(id)
	if err != nil {
		t.Fatalf("store.Seen(%q): %v", id, err)
	}
	return seen
}
