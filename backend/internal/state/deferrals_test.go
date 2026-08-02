package state

import (
	"testing"
	"time"
)

// The deferral ledger is what bounds a retry. A message left unprocessed holds
// the poll checkpoint below itself, so "retry forever" and "never make
// progress" are the same behaviour — these pin the counting and the clearing
// that turn the first into the second.

func TestRecordDeferralCountsPerMessage(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for want := 1; want <= 3; want++ {
		got, err := s.RecordDeferral("42")
		if err != nil {
			t.Fatalf("RecordDeferral: %v", err)
		}
		if got != want {
			t.Fatalf("RecordDeferral #%d returned %d, want %d", want, got, want)
		}
	}

	// A different message counts separately, or one stuck message would drag
	// every other deferral to the cap with it.
	if got, err := s.RecordDeferral("43"); err != nil || got != 1 {
		t.Fatalf("RecordDeferral(43) = %d, %v; want 1, nil", got, err)
	}
	if got, err := s.DeferralAttempts("42"); err != nil || got != 3 {
		t.Fatalf("DeferralAttempts(42) = %d, %v; want 3, nil", got, err)
	}
	if got, err := s.DeferralAttempts("nonexistent"); err != nil || got != 0 {
		t.Fatalf("DeferralAttempts(nonexistent) = %d, %v; want 0, nil", got, err)
	}
}

// TestRecordProcessedDecisionClearsTheDeferral is the invariant the poller
// relies on instead of clearing the ledger itself: retiring a message and
// forgetting its deferral history are one state change.
//
// Without it, a message that failed twice months ago would start its next
// deferral two attempts closer to being given up on.
func TestRecordProcessedDecisionClearsTheDeferral(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.RecordDeferral("42"); err != nil {
		t.Fatalf("RecordDeferral: %v", err)
	}
	if err := s.RecordProcessedDecision(Decision{MessageID: "42", Status: "applied"}); err != nil {
		t.Fatalf("RecordProcessedDecision: %v", err)
	}

	if got, err := s.DeferralAttempts("42"); err != nil || got != 0 {
		t.Fatalf("DeferralAttempts after retirement = %d, %v; want 0, nil", got, err)
	}
	if seen, err := s.Seen("42"); err != nil || !seen {
		t.Fatalf("Seen after retirement = %v, %v; want true, nil", seen, err)
	}
}

func TestClearDeferralIsIdempotent(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Clearing something never deferred is not an error: the poller clears on
	// paths that do not know whether a deferral was ever opened.
	if err := s.ClearDeferral("never-seen"); err != nil {
		t.Fatalf("ClearDeferral on an absent row: %v", err)
	}
	if _, err := s.RecordDeferral("42"); err != nil {
		t.Fatalf("RecordDeferral: %v", err)
	}
	if err := s.ClearDeferral("42"); err != nil {
		t.Fatalf("ClearDeferral: %v", err)
	}
	if err := s.ClearDeferral("42"); err != nil {
		t.Fatalf("second ClearDeferral: %v", err)
	}
	if got, _ := s.DeferralAttempts("42"); got != 0 {
		t.Fatalf("DeferralAttempts after clear = %d, want 0", got)
	}
}

func TestDeferralStatsReportsCountAndOldest(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	count, oldest, err := s.DeferralStats()
	if err != nil || count != 0 || oldest != "" {
		t.Fatalf("DeferralStats on an empty store = %d, %q, %v; want 0, \"\", nil", count, oldest, err)
	}

	for _, id := range []string{"10", "11", "12"} {
		if _, err := s.RecordDeferral(id); err != nil {
			t.Fatalf("RecordDeferral(%s): %v", id, err)
		}
	}
	// Backdate one so "oldest" is a real answer rather than whichever row the
	// same-second timestamps happened to order first.
	if _, err := s.db.Exec(`UPDATE deferrals SET first_at = ? WHERE message_id = '11'`,
		time.Now().UTC().Add(-3*time.Hour).Unix()); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	count, oldest, err = s.DeferralStats()
	if err != nil {
		t.Fatalf("DeferralStats: %v", err)
	}
	if count != 3 {
		t.Fatalf("DeferralStats count = %d, want 3", count)
	}
	parsed, perr := time.Parse(time.RFC3339, oldest)
	if perr != nil {
		t.Fatalf("oldest %q is not RFC3339: %v", oldest, perr)
	}
	if age := time.Since(parsed); age < 2*time.Hour {
		t.Fatalf("oldest deferral reported as %v old, want the backdated ~3h one", age)
	}
}

// TestCleanupDropsOrphanedDeferrals covers the message a user deleted from the
// mailbox mid-deferral: nothing retries it, nothing retires it, and its row
// would otherwise inflate the deferred count an operator reads as pending work
// for as long as the install lives.
func TestCleanupDropsOrphanedDeferrals(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.RecordDeferral("old"); err != nil {
		t.Fatalf("RecordDeferral: %v", err)
	}
	if _, err := s.RecordDeferral("recent"); err != nil {
		t.Fatalf("RecordDeferral: %v", err)
	}
	if _, err := s.db.Exec(`UPDATE deferrals SET first_at = ? WHERE message_id = 'old'`,
		time.Now().UTC().Add(-40*24*time.Hour).Unix()); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	if err := s.Cleanup(30); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	if got, _ := s.DeferralAttempts("old"); got != 0 {
		t.Fatalf("stale deferral survived cleanup: attempts = %d", got)
	}
	if got, _ := s.DeferralAttempts("recent"); got != 1 {
		t.Fatalf("cleanup dropped a live deferral: attempts = %d, want 1", got)
	}
}
