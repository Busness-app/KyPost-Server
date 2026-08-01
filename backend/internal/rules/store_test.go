package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStore_CreateUpdateDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	created, err := s.Upsert(Rule{Name: "Archive newsletters", Enabled: true})
	if err != nil {
		t.Fatalf("Upsert create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected assigned ID")
	}
	if created.Rev == 0 {
		t.Fatal("expected non-zero Rev")
	}
	if created.CreatedAt == "" {
		t.Fatal("expected CreatedAt to be stamped")
	}

	created.Name = "Archive all newsletters"
	updated, err := s.Upsert(created)
	if err != nil {
		t.Fatalf("Upsert update: %v", err)
	}
	if updated.ID != created.ID {
		t.Errorf("update changed ID: %q -> %q", created.ID, updated.ID)
	}
	if updated.Name != "Archive all newsletters" {
		t.Errorf("Name = %q, want %q", updated.Name, "Archive all newsletters")
	}
	if updated.CreatedAt != created.CreatedAt {
		t.Errorf("CreatedAt changed on update: %q -> %q", created.CreatedAt, updated.CreatedAt)
	}
	if updated.Rev == created.Rev {
		t.Error("expected Rev to bump on update")
	}

	got, ok := s.Get(created.ID)
	if !ok || got.Name != "Archive all newsletters" {
		t.Errorf("Get after update = %+v, ok=%v", got, ok)
	}

	removed, err := s.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !removed {
		t.Error("expected Delete to report removal")
	}
	if _, ok := s.Get(created.ID); ok {
		t.Error("expected Get to fail after Delete")
	}

	removedAgain, err := s.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete (already gone): %v", err)
	}
	if removedAgain {
		t.Error("expected second Delete to report false")
	}
}

func TestStore_ListSortedByOrder_CrossInstance(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range []struct {
		name  string
		order int
	}{
		{"first", 0}, {"second", 1}, {"third", 2},
	} {
		if _, err := s1.Upsert(Rule{Name: tc.name, Order: tc.order}); err != nil {
			t.Fatalf("Upsert(%q): %v", tc.name, err)
		}
	}

	// A second Store instance over the same directory must see what the
	// first wrote — the API and poller processes share no memory.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (second instance): %v", err)
	}
	list, _ := s2.List()
	if len(list) != 3 {
		t.Fatalf("List() len = %d, want 3", len(list))
	}
	want := []string{"first", "second", "third"}
	for i, r := range list {
		if r.Name != want[i] {
			t.Errorf("List()[%d].Name = %q, want %q", i, r.Name, want[i])
		}
	}
}

func TestStore_Reorder(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a, err := s.Upsert(Rule{Name: "a"})
	if err != nil {
		t.Fatalf("Upsert a: %v", err)
	}
	b, err := s.Upsert(Rule{Name: "b"})
	if err != nil {
		t.Fatalf("Upsert b: %v", err)
	}
	c, err := s.Upsert(Rule{Name: "c"})
	if err != nil {
		t.Fatalf("Upsert c: %v", err)
	}

	if err := s.Reorder([]string{c.ID, a.ID, b.ID}); err != nil {
		t.Fatalf("Reorder: %v", err)
	}

	list, _ := s.List()
	want := []string{"c", "a", "b"}
	for i, r := range list {
		if r.Name != want[i] {
			t.Errorf("List()[%d].Name = %q, want %q", i, r.Name, want[i])
		}
	}
}

// Rules move, mark as spam and delete. A read failure that returns the last
// good in-memory list keeps applying rules the user may have deleted, against
// real mail, for as long as the file stays unreadable — so List reports it and
// its callers skip evaluation instead.
func TestListFailsClosedOnAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Upsert(Rule{Name: "delete everything", Enabled: true}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if list, err := s.List(); err != nil || len(list) != 1 {
		t.Fatalf("List() = %v, %v; want the seeded rule", list, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "rules.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	list, err := s.List()
	if err == nil {
		t.Fatalf("List() returned %d cached rules and no error after the file went bad", len(list))
	}
	if list != nil {
		t.Fatalf("List() returned rules alongside an error: %v", list)
	}
}
