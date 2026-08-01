package sendas

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	created, err := s.Create("user-1", "Someone@Example.com", "Some One")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create: expected non-empty ID")
	}
	if created.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", created.UserID, "user-1")
	}
	if created.Email != "someone@example.com" {
		t.Errorf("Email = %q, want lowercase-normalized %q", created.Email, "someone@example.com")
	}
	if created.DisplayName != "Some One" {
		t.Errorf("DisplayName = %q, want %q", created.DisplayName, "Some One")
	}
	if created.Status != "pending" {
		t.Errorf("Status = %q, want %q", created.Status, "pending")
	}
	if created.VerificationCode == "" {
		t.Fatal("VerificationCode: expected non-empty")
	}
	if len(created.VerificationCode) != len("kp-")+8 || created.VerificationCode[:3] != "kp-" {
		t.Errorf("VerificationCode = %q, want format kp-XXXXXXXX", created.VerificationCode)
	}
	if created.CreatedAt == "" {
		t.Fatal("CreatedAt: expected non-empty")
	}
	createdAt, err := time.Parse(time.RFC3339, created.CreatedAt)
	if err != nil {
		t.Fatalf("CreatedAt not RFC3339: %v", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, created.ExpiresAt)
	if err != nil {
		t.Fatalf("ExpiresAt not RFC3339: %v", err)
	}
	if diff := expiresAt.Sub(createdAt); diff != 5*time.Minute {
		t.Errorf("ExpiresAt - CreatedAt = %v, want 5m", diff)
	}

	got, ok := s.Get(created.ID)
	if !ok {
		t.Fatal("Get: expected to find record just created")
	}
	if got != created {
		t.Errorf("Get returned %+v, want %+v", got, created)
	}

	if _, ok := s.Get("does-not-exist"); ok {
		t.Error("Get: expected not found for unknown ID")
	}
}

func TestMarkVerifiedIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	created, err := s.Create("user-1", "a@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.MarkVerified(created.ID); err != nil {
		t.Fatalf("MarkVerified (first): %v", err)
	}
	first, _ := s.Get(created.ID)
	if first.Status != "verified" {
		t.Fatalf("Status = %q, want verified", first.Status)
	}
	if first.VerifiedAt == "" {
		t.Fatal("VerifiedAt: expected non-empty after MarkVerified")
	}

	// Calling again on an already-verified record must be a no-op success,
	// not an error (guards against a poller racing a duplicate match).
	if err := s.MarkVerified(created.ID); err != nil {
		t.Fatalf("MarkVerified (second, idempotent call): %v", err)
	}
	second, _ := s.Get(created.ID)
	if second.Status != "verified" {
		t.Fatalf("Status after second call = %q, want verified", second.Status)
	}

	if err := s.MarkVerified("does-not-exist"); err == nil {
		t.Error("MarkVerified: expected error for unknown ID")
	}
}

func TestMarkFailedRejectsNonPending(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	created, err := s.Create("user-1", "a@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.MarkVerified(created.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	// The record is now "verified"; MarkFailed on it must be an error, unlike
	// MarkVerified's idempotent no-op behavior.
	if err := s.MarkFailed(created.ID); err == nil {
		t.Error("MarkFailed: expected error when record is already verified")
	}
	stillVerified, _ := s.Get(created.ID)
	if stillVerified.Status != "verified" {
		t.Errorf("Status = %q, want still verified after rejected MarkFailed", stillVerified.Status)
	}

	// A fresh pending record can be marked failed.
	pending, err := s.Create("user-1", "b@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkFailed(pending.ID); err != nil {
		t.Fatalf("MarkFailed on pending record: %v", err)
	}
	failed, _ := s.Get(pending.ID)
	if failed.Status != "failed" {
		t.Errorf("Status = %q, want failed", failed.Status)
	}
	if failed.FailedAt == "" {
		t.Error("FailedAt: expected non-empty after MarkFailed")
	}

	// Calling MarkFailed again on an already-failed record must also error.
	if err := s.MarkFailed(pending.ID); err == nil {
		t.Error("MarkFailed: expected error when record is already failed")
	}

	if err := s.MarkFailed("does-not-exist"); err == nil {
		t.Error("MarkFailed: expected error for unknown ID")
	}
}

func TestPendingNotExpired(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	freshPending, err := s.Create("user-1", "fresh@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	expiredPending, err := s.Create("user-1", "expired@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	verified, err := s.Create("user-1", "verified@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkVerified(verified.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	failed, err := s.Create("user-1", "failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkFailed(failed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	// Directly manipulate the on-disk record for expiredPending to simulate
	// time having passed, since Create always sets ExpiresAt = now + 5m.
	s.mu.Lock()
	for i := range s.aliases {
		if s.aliases[i].ID == expiredPending.ID {
			s.aliases[i].ExpiresAt = time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatalf("persistLocked: %v", err)
	}
	s.mu.Unlock()

	result := s.PendingNotExpired()

	foundFresh := false
	for _, a := range result {
		if a.ID == freshPending.ID {
			foundFresh = true
		}
		if a.ID == expiredPending.ID {
			t.Error("PendingNotExpired: expired pending record must be excluded")
		}
		if a.ID == verified.ID {
			t.Error("PendingNotExpired: verified record must be excluded")
		}
		if a.ID == failed.ID {
			t.Error("PendingNotExpired: failed record must be excluded")
		}
	}
	if !foundFresh {
		t.Error("PendingNotExpired: fresh pending record must be included")
	}
}

func TestFindVerifiedByEmailCrossInstance(t *testing.T) {
	dir := t.TempDir()

	// s1 simulates the API process: creates and verifies an alias.
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New (s1): %v", err)
	}
	created, err := s1.Create("user-1", "Verified@Example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// s2 simulates the mail-send-time daemon process: opened separately,
	// shares no memory with s1.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (s2): %v", err)
	}

	// Before verification, s2 must not find it (record is still pending).
	// The error is asserted at every call, not discarded: a read failure also
	// reports ok=false, so ignoring it would let this whole test pass against a
	// store that could not read anything at all.
	if _, ok, err := s2.FindVerifiedByEmail("verified@example.com"); ok || err != nil {
		t.Errorf("FindVerifiedByEmail: ok=%v err=%v, want no match and no error for a pending record", ok, err)
	}

	// s1 marks it verified and persists to disk.
	if err := s1.MarkVerified(created.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	// s2 must observe the change made by s1 on its next call, since
	// FindVerifiedByEmail always refreshes from disk first — this is the
	// property the mail-send authorization check depends on.
	found, ok, err := s2.FindVerifiedByEmail("VERIFIED@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("FindVerifiedByEmail: %v", err)
	}
	if !ok {
		t.Fatal("FindVerifiedByEmail: expected to find record verified by a separate Store instance")
	}
	if found.ID != created.ID {
		t.Errorf("found ID = %q, want %q", found.ID, created.ID)
	}

	// A second, unrelated alias in "pending" status must not match even
	// though its email could otherwise be confused.
	if _, err := s1.Create("user-1", "other@example.com", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok, err := s2.FindVerifiedByEmail("other@example.com"); ok || err != nil {
		t.Errorf("FindVerifiedByEmail: ok=%v err=%v, want no match and no error for a pending record", ok, err)
	}

	if _, ok, err := s2.FindVerifiedByEmail("nobody@example.com"); ok || err != nil {
		t.Errorf("FindVerifiedByEmail: ok=%v err=%v, want no match and no error for an unknown email", ok, err)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	created, err := s.Create("user-1", "a@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Delete(created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s.Get(created.ID); ok {
		t.Error("Get: expected record to be gone after Delete")
	}
	if len(s.List()) != 0 {
		t.Errorf("List: expected empty after deleting only record, got %d", len(s.List()))
	}

	if err := s.Delete("does-not-exist"); err == nil {
		t.Error("Delete: expected error for unknown ID")
	}
}

func TestSweepTerminal(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	oldFailed, err := s.Create("user-1", "old-failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkFailed(oldFailed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	recentFailed, err := s.Create("user-1", "recent-failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkFailed(recentFailed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	verified, err := s.Create("user-1", "verified@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkVerified(verified.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	pending, err := s.Create("user-1", "pending@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Backdate oldFailed's FailedAt so it looks old enough to sweep.
	s.mu.Lock()
	for i := range s.aliases {
		if s.aliases[i].ID == oldFailed.ID {
			s.aliases[i].FailedAt = time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatalf("persistLocked: %v", err)
	}
	s.mu.Unlock()

	if err := s.SweepTerminal(1 * time.Hour); err != nil {
		t.Fatalf("SweepTerminal: %v", err)
	}

	if _, ok := s.Get(oldFailed.ID); ok {
		t.Error("SweepTerminal: expected old failed record to be removed")
	}
	if _, ok := s.Get(recentFailed.ID); !ok {
		t.Error("SweepTerminal: recent failed record must be left untouched")
	}
	if _, ok := s.Get(verified.ID); !ok {
		t.Error("SweepTerminal: verified record must never be removed")
	}
	if _, ok := s.Get(pending.ID); !ok {
		t.Error("SweepTerminal: pending record must never be removed")
	}
}

func TestListAndListVerified(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pending, err := s.Create("user-1", "pending@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	verified, err := s.Create("user-1", "verified@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkVerified(verified.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	failed, err := s.Create("user-1", "failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkFailed(failed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	all := s.List()
	if len(all) != 3 {
		t.Fatalf("List: got %d records, want 3", len(all))
	}

	onlyVerified := s.ListVerified()
	if len(onlyVerified) != 1 || onlyVerified[0].ID != verified.ID {
		t.Errorf("ListVerified: got %+v, want only %q", onlyVerified, verified.ID)
	}

	_ = pending
}

// The From-address check on every send goes through here. A swallowed read
// error answered from whatever this process last loaded, so an alias deleted
// from a file that has since become unreadable went on authorizing sends from
// an address the account no longer owns.
func TestFindVerifiedByEmailFailsClosedOnAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	alias, err := s.Create("user-1", "alias@example.com", "Alias")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if _, ok, err := s.FindVerifiedByEmail("alias@example.com"); !ok || err != nil {
		t.Fatalf("FindVerifiedByEmail = %v, %v; want the verified alias", ok, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "send_as_aliases.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	found, ok, err := s.FindVerifiedByEmail("alias@example.com")
	if err == nil {
		t.Fatalf("FindVerifiedByEmail authorized %q from cache after the file went bad", found.Email)
	}
	if ok {
		t.Fatal("FindVerifiedByEmail reported a match alongside an error")
	}
}
