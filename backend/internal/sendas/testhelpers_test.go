package sendas

import "testing"

// The listing readers return an error so a failed disk re-read is never served
// as an alias set. Happy-path tests go through these.

func mustList(t *testing.T, s *Store) []Alias {
	t.Helper()
	out, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return out
}

func mustListVerified(t *testing.T, s *Store) []Alias {
	t.Helper()
	out, err := s.ListVerified()
	if err != nil {
		t.Fatalf("ListVerified: %v", err)
	}
	return out
}

func mustGet(t *testing.T, s *Store, id string) (Alias, bool) {
	t.Helper()
	a, ok, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return a, ok
}

func mustPendingNotExpired(t *testing.T, s *Store) []Alias {
	t.Helper()
	out, err := s.PendingNotExpired()
	if err != nil {
		t.Fatalf("PendingNotExpired: %v", err)
	}
	return out
}
