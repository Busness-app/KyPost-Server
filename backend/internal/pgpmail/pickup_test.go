package pgpmail

import (
	"path/filepath"
	"testing"
	"time"
)

func TestPickupStoreCreateAndViewOnce(t *testing.T) {
	dir := t.TempDir()
	store := NewPickupStore(filepath.Join(dir, "pickup"), filepath.Join(dir, "pickup.key"))

	id, err := store.Create("user-1", "bob@example.com", "Hello", "secret body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	subject, body, mode, err := store.View(id)
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if subject != "Hello" || body != "secret body" || mode != "plain" {
		t.Fatalf("unexpected view result: subject=%q body=%q mode=%q", subject, body, mode)
	}

	if _, _, _, err := store.View(id); err != ErrPickupExpired {
		t.Fatalf("expected ErrPickupExpired on second view, got %v", err)
	}
}

func TestPickupStoreViewUnknownID(t *testing.T) {
	dir := t.TempDir()
	store := NewPickupStore(filepath.Join(dir, "pickup"), filepath.Join(dir, "pickup.key"))
	if _, _, _, err := store.View("does-not-exist"); err != ErrPickupNotFound {
		t.Fatalf("expected ErrPickupNotFound, got %v", err)
	}
}

func TestPickupStoreExpiresByTTL(t *testing.T) {
	dir := t.TempDir()
	store := NewPickupStore(filepath.Join(dir, "pickup"), filepath.Join(dir, "pickup.key"))

	id, err := store.Create("user-1", "bob@example.com", "Hello", "secret body", "plain", -time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, _, err := store.View(id); err != ErrPickupExpired {
		t.Fatalf("expected ErrPickupExpired for a record created already-expired, got %v", err)
	}
}

func TestPickupStoreSweepRemovesOldRecords(t *testing.T) {
	dir := t.TempDir()
	baseDir := filepath.Join(dir, "pickup")
	store := NewPickupStore(baseDir, filepath.Join(dir, "pickup.key"))

	id, err := store.Create("user-1", "bob@example.com", "Hello", "secret body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Sweep(0); err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if _, _, _, err := store.View(id); err != ErrPickupNotFound {
		t.Fatalf("expected record swept (not found), got %v", err)
	}
}

// recordPath is the only path sink in the codebase with no lexical guard of its
// own. Every call site HMAC-authenticates the id first, so a traversing id
// cannot currently arrive — but that safety is a property of a different
// package held by five separate callers, and this is cheap.
func TestRecordPathRejectsTraversal(t *testing.T) {
	s := NewPickupStore("/tmp/pickup", "/tmp/key")
	for _, id := range []string{"../../etc/passwd", "..", ".", "", "a/b", `a\b`, "a\x00b"} {
		if got := s.recordPath(id); got != "" {
			t.Errorf("recordPath(%q) = %q, want \"\" — it escapes or names something other than "+
				"one record in baseDir", id, got)
		}
	}
	if got := s.recordPath("valid-id-123"); got == "" {
		t.Fatal("recordPath rejected an ordinary id")
	}
}
