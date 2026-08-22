package groups

import "testing"

// List/Get return an error so a failed disk re-read is never served as data
// (see refreshFromDiskLocked). Happy-path tests go through these.

func mustList(t *testing.T, s *Store) []Group {
	t.Helper()
	out, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return out
}

func mustGet(t *testing.T, s *Store, id string) (Group, bool) {
	t.Helper()
	g, ok, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return g, ok
}
