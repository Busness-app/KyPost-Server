package rules

import "testing"

// Get returns an error so a failed disk re-read is never served as a rule.
func mustGet(t *testing.T, s *Store, id string) (Rule, bool) {
	t.Helper()
	r, ok, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	return r, ok
}
