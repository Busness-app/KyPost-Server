package pgpdiscovery

import "testing"

func TestSuppressionsAbsentIsEmpty(t *testing.T) {
	list, err := LoadSuppressions(t.TempDir())
	if err != nil {
		t.Fatalf("LoadSuppressions: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty, got %+v", list)
	}
}

func TestAddListRemoveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := AddSuppression(dir, "Bob@Example.com", ReasonDeleted); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	list, err := LoadSuppressions(dir)
	if err != nil {
		t.Fatalf("LoadSuppressions: %v", err)
	}
	if len(list) != 1 || list[0].Email != "bob@example.com" || list[0].Reason != ReasonDeleted {
		t.Fatalf("unexpected list after add: %+v", list)
	}
	if list[0].SuppressedAt == "" {
		t.Fatalf("expected SuppressedAt to be set")
	}

	removed, err := RemoveSuppression(dir, "bob@example.com")
	if err != nil {
		t.Fatalf("RemoveSuppression: %v", err)
	}
	if !removed {
		t.Fatalf("expected removed=true")
	}
	list, _ = LoadSuppressions(dir)
	if len(list) != 0 {
		t.Fatalf("expected empty after remove, got %+v", list)
	}
}

func TestAddIsIdempotentAndUpdatesReason(t *testing.T) {
	dir := t.TempDir()
	if err := AddSuppression(dir, "carol@example.com", ReasonDeleted); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	if err := AddSuppression(dir, "CAROL@example.com", ReasonExplicit); err != nil {
		t.Fatalf("AddSuppression (re-add): %v", err)
	}
	list, _ := LoadSuppressions(dir)
	if len(list) != 1 {
		t.Fatalf("expected one entry after idempotent re-add, got %+v", list)
	}
	if list[0].Reason != ReasonExplicit {
		t.Fatalf("expected reason updated to %q, got %q", ReasonExplicit, list[0].Reason)
	}
}

func TestRemoveAbsentReturnsFalse(t *testing.T) {
	removed, err := RemoveSuppression(t.TempDir(), "nobody@example.com")
	if err != nil {
		t.Fatalf("RemoveSuppression: %v", err)
	}
	if removed {
		t.Fatalf("expected removed=false for an address that was never suppressed")
	}
}

func TestSuppressedSet(t *testing.T) {
	dir := t.TempDir()
	_ = AddSuppression(dir, "  Dave@Example.com  ", ReasonExplicit)
	set, err := SuppressedSet(dir)
	if err != nil {
		t.Fatalf("SuppressedSet: %v", err)
	}
	if !set["dave@example.com"] {
		t.Fatalf("expected normalized address in set, got %+v", set)
	}
}
