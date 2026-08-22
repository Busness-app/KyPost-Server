package mailcache

import "testing"

// Snapshot returns an error so a failed disk re-read is never served as a warm
// window. Happy-path tests go through this.
func mustSnapshot(t *testing.T, s *Store, mailboxKey string, limit int) ([]Entry, bool) {
	t.Helper()
	entries, warmed, err := s.Snapshot(mailboxKey, limit)
	if err != nil {
		t.Fatalf("Snapshot(%s, %d): %v", mailboxKey, limit, err)
	}
	return entries, warmed
}
