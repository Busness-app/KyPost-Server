package groups

import "testing"

func TestStore_CreateRenameDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	created, err := s.Upsert(Group{Name: "Family"})
	if err != nil {
		t.Fatalf("Upsert create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected assigned ID")
	}
	if created.Rev == 0 {
		t.Fatal("expected non-zero Rev")
	}

	renamed, err := s.Upsert(Group{ID: created.ID, Name: "Immediate Family"})
	if err != nil {
		t.Fatalf("Upsert rename: %v", err)
	}
	if renamed.ID != created.ID {
		t.Errorf("rename changed ID: %q -> %q", created.ID, renamed.ID)
	}
	if renamed.Name != "Immediate Family" {
		t.Errorf("Name = %q, want %q", renamed.Name, "Immediate Family")
	}
	if renamed.CreatedAt != created.CreatedAt {
		t.Errorf("CreatedAt changed on rename: %q -> %q", created.CreatedAt, renamed.CreatedAt)
	}
	if renamed.Rev == created.Rev {
		t.Error("expected Rev to bump on rename")
	}

	got, ok := mustGet(t, s, created.ID)
	if !ok || got.Name != "Immediate Family" {
		t.Errorf("Get after rename = %+v, ok=%v", got, ok)
	}

	removed, err := s.Delete(created.ID)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !removed {
		t.Error("expected Delete to report removal")
	}
	if _, ok := mustGet(t, s, created.ID); ok {
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

func TestStore_ListSortedByName_CrossInstance(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, name := range []string{"Work", "Book Club", "Family"} {
		if _, err := s1.Upsert(Group{Name: name}); err != nil {
			t.Fatalf("Upsert(%q): %v", name, err)
		}
	}

	// A second Store instance over the same directory must see what the
	// first wrote — the two API/daemon processes share no memory.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (second instance): %v", err)
	}
	list := mustList(t, s2)
	if len(list) != 3 {
		t.Fatalf("List() len = %d, want 3", len(list))
	}
	want := []string{"Book Club", "Family", "Work"}
	for i, g := range list {
		if g.Name != want[i] {
			t.Errorf("List()[%d].Name = %q, want %q", i, g.Name, want[i])
		}
	}
}
