package contacts

import (
	"testing"
)

func TestSearch_CaseInsensitivity(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := s.Upsert(Contact{FormattedName: "Alice Smith"})
	c2, _ := s.Upsert(Contact{FormattedName: "Bob Jones", Emails: []ContactValue{{Value: "bob@example.com"}}})

	// Search for "alice" should match "Alice Smith"
	results := mustSearch(t, s, "alice", 10)
	if len(results) != 1 || results[0].UID != c1.UID {
		t.Errorf("case-insensitive search for 'alice' failed: got %d results", len(results))
	}

	// Search for "BOB@EXAMPLE.COM" should match email
	results = mustSearch(t, s, "BOB@EXAMPLE.COM", 10)
	if len(results) != 1 || results[0].UID != c2.UID {
		t.Errorf("case-insensitive search for 'BOB@EXAMPLE.COM' failed: got %d results", len(results))
	}
}

func TestSearch_EmptyQueryReturnsEmpty(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Upsert(Contact{FormattedName: "Alice"})

	// Empty string query
	results := mustSearch(t, s, "", 10)
	if len(results) != 0 {
		t.Errorf("empty query should return empty slice, got %d results", len(results))
	}

	// Whitespace-only query
	results = mustSearch(t, s, "   ", 10)
	if len(results) != 0 {
		t.Errorf("whitespace-only query should return empty slice, got %d results", len(results))
	}
}

func TestSearch_NonPositiveLimitReturnsEmpty(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Upsert(Contact{FormattedName: "Alice"})

	// Zero limit
	results := mustSearch(t, s, "alice", 0)
	if len(results) != 0 {
		t.Errorf("zero limit should return empty slice, got %d results", len(results))
	}

	// Negative limit
	results = mustSearch(t, s, "alice", -1)
	if len(results) != 0 {
		t.Errorf("negative limit should return empty slice, got %d results", len(results))
	}
}

func TestSearch_DeletedContactsExcluded(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := s.Upsert(Contact{FormattedName: "Alice"})
	_, _ = s.Upsert(Contact{FormattedName: "Bob"})

	// Delete Alice
	_, _ = s.Delete(c1.UID)

	// Search should only return Bob, not deleted Alice
	results := mustSearch(t, s, "a", 10)
	if len(results) != 0 {
		t.Errorf("deleted contact should be excluded, got %d results", len(results))
	}
}

func TestSearch_RankingOrder(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create contacts with different match types
	// Score 0: FormattedName prefix
	c0, _ := s.Upsert(Contact{
		FormattedName: "Alice Smith",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
	})

	// Score 1: Email prefix
	c1, _ := s.Upsert(Contact{
		FormattedName: "Bob Jones",
		Emails:        []ContactValue{{Value: "alice@example.com"}},
	})

	// Score 2: FormattedName contains
	c2, _ := s.Upsert(Contact{
		FormattedName: "M Alice Baker",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
	})

	// Score 3: GivenName contains
	c3, _ := s.Upsert(Contact{
		GivenName:  "Alice",
		FamilyName: "Brown",
		Emails:     []ContactValue{{Value: "bob@example.com"}},
	})

	// Score 4: Email contains
	c4, _ := s.Upsert(Contact{
		FormattedName: "Bob Smith",
		Emails:        []ContactValue{{Value: "bob@alice.com"}},
	})

	// Search for "alice" - should rank: c0 (score 0), c1 (score 1), c2 (score 2), c3 (score 3), c4 (score 4)
	results := mustSearch(t, s, "alice", 10)
	if len(results) != 5 {
		t.Errorf("expected 5 results, got %d", len(results))
	} else {
		expectedOrder := []string{c0.UID, c1.UID, c2.UID, c3.UID, c4.UID}
		for i, uid := range expectedOrder {
			if results[i].UID != uid {
				t.Errorf("result[%d].UID = %q, want %q", i, results[i].UID, uid)
			}
		}
	}
}

func TestSearch_LimitTruncation(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create 5 contacts matching "alice"
	for i := 0; i < 5; i++ {
		_, _ = s.Upsert(Contact{FormattedName: "Alice " + string(rune('A'+i))})
	}

	// Search with limit 3 should return 3 results
	results := mustSearch(t, s, "alice", 3)
	if len(results) != 3 {
		t.Errorf("limit=3 should return 3 results, got %d", len(results))
	}

	// Search with limit 10 should return 5 results
	results = mustSearch(t, s, "alice", 10)
	if len(results) != 5 {
		t.Errorf("limit=10 should return 5 results, got %d", len(results))
	}
}

func TestSearch_NameVsEmailMatching(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create contacts with names and emails
	c1, _ := s.Upsert(Contact{
		FormattedName: "John Doe",
		Emails:        []ContactValue{{Value: "john@example.com"}},
	})

	c2, _ := s.Upsert(Contact{
		FormattedName: "Jane Doe",
		Emails:        []ContactValue{{Value: "bob@example.com"}},
	})

	c3, _ := s.Upsert(Contact{
		FormattedName: "Bob Smith",
		Emails:        []ContactValue{{Value: "jane@example.com"}},
	})

	// Search for "john" should match c1 (name prefix)
	results := mustSearch(t, s, "john", 10)
	if len(results) != 1 || results[0].UID != c1.UID {
		t.Errorf("search for 'john' should match only c1")
	}

	// Search for "doe" should match c1 and c2 (name contains)
	results = mustSearch(t, s, "doe", 10)
	if len(results) != 2 {
		t.Errorf("search for 'doe' should match 2 results, got %d", len(results))
	}

	// Search for "jane" should match c2 (name) and c3 (email), but c2 should rank higher
	results = mustSearch(t, s, "jane", 10)
	if len(results) != 2 {
		t.Errorf("search for 'jane' should match 2 results, got %d", len(results))
	}
	if results[0].UID != c2.UID {
		t.Errorf("first result should be c2 (name contains), got %q", results[0].UID)
	}
	if results[1].UID != c3.UID {
		t.Errorf("second result should be c3 (email contains), got %q", results[1].UID)
	}
}

func TestSearch_MultipleEmailMatches(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create contact with multiple emails
	c, _ := s.Upsert(Contact{
		FormattedName: "Bob Smith",
		Emails: []ContactValue{
			{Value: "bob@home.com"},
			{Value: "bob@work.com"},
		},
	})

	// Search for "bob@" should match with email prefix (score 1)
	results := mustSearch(t, s, "bob@", 10)
	if len(results) != 1 || results[0].UID != c.UID {
		t.Errorf("email prefix search should match contact")
	}

	// Search for "work" should match email contains (score 4)
	results = mustSearch(t, s, "work", 10)
	if len(results) != 1 || results[0].UID != c.UID {
		t.Errorf("email contains search should match contact")
	}
}

func TestSearch_NoMatches(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	_, _ = s.Upsert(Contact{
		FormattedName: "Alice Smith",
		Emails:        []ContactValue{{Value: "alice@example.com"}},
	})

	// Search for something that doesn't match
	results := mustSearch(t, s, "xyz", 10)
	if len(results) != 0 {
		t.Errorf("no matches should return empty slice, got %d results", len(results))
	}
}

func TestSearch_GivenAndFamilyNameMatching(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Create contact with GivenName and FamilyName but no FormattedName
	c, _ := s.Upsert(Contact{
		GivenName:  "John",
		FamilyName: "Anderson",
	})

	// Search should match GivenName
	results := mustSearch(t, s, "john", 10)
	if len(results) != 1 || results[0].UID != c.UID {
		t.Errorf("search for 'john' should match GivenName")
	}

	// Search should match FamilyName
	results = mustSearch(t, s, "anderson", 10)
	if len(results) != 1 || results[0].UID != c.UID {
		t.Errorf("search for 'anderson' should match FamilyName")
	}

	// Partial matches in FamilyName should work
	results = mustSearch(t, s, "ander", 10)
	if len(results) != 1 || results[0].UID != c.UID {
		t.Errorf("search for 'ander' should match FamilyName contains")
	}
}
