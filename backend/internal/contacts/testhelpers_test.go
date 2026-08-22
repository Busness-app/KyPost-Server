package contacts

import "testing"

// The reader API returns an error because a failed disk re-read must not be
// served as data (see refreshFromDiskLocked). Tests that only care about the
// happy path go through these helpers rather than repeating the check.

func mustList(t *testing.T, s *Store) []Contact {
	t.Helper()
	out, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return out
}

func mustGet(t *testing.T, s *Store, uid string) (Contact, bool) {
	t.Helper()
	c, ok, err := s.Get(uid)
	if err != nil {
		t.Fatalf("Get(%s): %v", uid, err)
	}
	return c, ok
}

func mustGetSelf(t *testing.T, s *Store) (Contact, bool) {
	t.Helper()
	c, ok, err := s.GetSelf()
	if err != nil {
		t.Fatalf("GetSelf: %v", err)
	}
	return c, ok
}

func mustSearch(t *testing.T, s *Store, query string, limit int) []Contact {
	t.Helper()
	out, err := s.Search(query, limit)
	if err != nil {
		t.Fatalf("Search(%q): %v", query, err)
	}
	return out
}

func mustChangedSince(t *testing.T, s *Store, rev int64) ([]Contact, []Contact, int64, bool) {
	t.Helper()
	changed, deleted, cursor, tooOld, err := s.ChangedSince(rev)
	if err != nil {
		t.Fatalf("ChangedSince(%d): %v", rev, err)
	}
	return changed, deleted, cursor, tooOld
}

func mustPGPKeyGeneration(t *testing.T, s *Store) int64 {
	t.Helper()
	gen, err := s.PGPKeyGeneration()
	if err != nil {
		t.Fatalf("PGPKeyGeneration: %v", err)
	}
	return gen
}
