package contacts

import "testing"

func TestSetSelf_MarksAndEnforcesUniqueness(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Upsert(Contact{FormattedName: "Alice"})
	b, _ := s.Upsert(Contact{FormattedName: "Bob"})

	if _, ok := mustGetSelf(t, s); ok {
		t.Fatal("expected no self-contact before SetSelf")
	}

	updated, found, err := s.SetSelf(a.UID, true)
	if err != nil || !found {
		t.Fatalf("SetSelf(a, true): found=%v err=%v", found, err)
	}
	if !updated.IsSelf {
		t.Fatal("expected IsSelf true on returned contact")
	}
	self, ok := mustGetSelf(t, s)
	if !ok || self.UID != a.UID {
		t.Fatalf("GetSelf: ok=%v uid=%q, want %q", ok, self.UID, a.UID)
	}

	// Marking b as self must clear a's flag — at most one self-contact ever.
	if _, found, err := s.SetSelf(b.UID, true); err != nil || !found {
		t.Fatalf("SetSelf(b, true): found=%v err=%v", found, err)
	}
	self, ok = mustGetSelf(t, s)
	if !ok || self.UID != b.UID {
		t.Fatalf("GetSelf after re-marking: ok=%v uid=%q, want %q", ok, self.UID, b.UID)
	}
	refreshedA, _ := mustGet(t, s, a.UID)
	if refreshedA.IsSelf {
		t.Fatal("expected a's IsSelf to be cleared after b was marked self")
	}
	// a's Rev must advance when its IsSelf flag is cleared, so a sync client
	// whose cursor is already past a's old Rev still observes the flip via
	// ChangedSince — not just b's Rev bumping.
	if refreshedA.Rev <= updated.Rev {
		t.Fatalf("expected a's Rev to increase after being cleared: got %d, want > %d", refreshedA.Rev, updated.Rev)
	}
}

func TestSetSelf_UnknownUIDReturnsNotFound(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := s.SetSelf("nope", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false for unknown uid")
	}
}

func TestSetSelf_FalseClearsFlag(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Upsert(Contact{FormattedName: "Alice"})
	if _, _, err := s.SetSelf(a.UID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetSelf(a.UID, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustGetSelf(t, s); ok {
		t.Fatal("expected no self-contact after unmarking")
	}
}

// TestUpsert_PreservesIsSelfAcrossEdits guards the exact bug this feature
// would otherwise reintroduce: the API's contactPayload/toContact() (see
// api/contacts_handlers.go) never carries isSelf, so every normal edit through
// PUT /api/contacts/{id} builds a fresh Contact with IsSelf false. Upsert
// must restore the existing record's IsSelf, the same way it already
// restores CreatedAt, or editing any field of your own contact card would
// silently un-mark it.
func TestUpsert_PreservesIsSelfAcrossEdits(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Upsert(Contact{FormattedName: "Alice"})
	if _, _, err := s.SetSelf(a.UID, true); err != nil {
		t.Fatal(err)
	}
	edited, _ := mustGet(t, s, a.UID)
	edited.Title = "Engineer"
	edited.IsSelf = false // what toContact() would produce on a normal edit
	updated, err := s.Upsert(edited)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.IsSelf {
		t.Fatal("expected Upsert to preserve IsSelf from the existing record")
	}
}

func TestDelete_ClearsIsSelf(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Upsert(Contact{FormattedName: "Alice"})
	if _, _, err := s.SetSelf(a.UID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Delete(a.UID); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustGetSelf(t, s); ok {
		t.Fatal("expected no self-contact after deleting the self-contact")
	}
}
