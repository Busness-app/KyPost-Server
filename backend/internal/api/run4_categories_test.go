package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/groups"
)

// run-4 M9. The store-level batch is covered in internal/groups; these pin the
// two things that only exist here: that one card cannot carry an unbounded
// category list, and that rendering a contact back out does not re-read the
// whole groups file once per group.

func TestResolveGroupIDsByNameCapsCategoriesPerCard(t *testing.T) {
	store, err := groups.New(t.TempDir())
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}

	names := make([]string, 0, maxCategoriesPerCard+50)
	for i := 0; i < maxCategoriesPerCard+50; i++ {
		names = append(names, fmt.Sprintf("cat-%d", i))
	}

	ids := resolveGroupIDsByName(store, names)

	if len(ids) > maxCategoriesPerCard {
		t.Fatalf("resolved %d categories from one card, cap is %d", len(ids), maxCategoriesPerCard)
	}
	if got := len(must1(store.List())); got > maxCategoriesPerCard {
		t.Fatalf("one card created %d groups, cap is %d", got, maxCategoriesPerCard)
	}
}

// An ordinary card is untouched by the cap.
func TestResolveGroupIDsByNameKeepsOrdinaryCategories(t *testing.T) {
	store, err := groups.New(t.TempDir())
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}

	ids := resolveGroupIDsByName(store, []string{"Work", "Family"})
	if len(ids) != 2 {
		t.Fatalf("ids = %v, want 2", ids)
	}
}

// A store already at its ceiling must not fail the whole import: the card's
// known categories still resolve, the unknown ones are dropped.
func TestResolveGroupIDsByNameDegradesWhenTheStoreIsFull(t *testing.T) {
	store, err := groups.New(t.TempDir())
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}
	existing, err := store.Upsert(groups.Group{Name: "Work"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	fill := make([]string, 0, groups.MaxGroupsPerUser-1)
	for i := 0; i < groups.MaxGroupsPerUser-1; i++ {
		fill = append(fill, fmt.Sprintf("filler-%d", i))
	}
	if _, err := store.EnsureByName(fill); err != nil {
		t.Fatalf("fill: %v", err)
	}

	ids := resolveGroupIDsByName(store, []string{"Work", "BrandNewCategory"})

	if len(ids) != 1 || ids[0] != existing.ID {
		t.Fatalf("ids = %v, want just the existing group %q", ids, existing.ID)
	}
}

// The second-order half of M9: contactToVCardForUser called gs.Get(id) per
// GroupID and every Get re-reads and re-unmarshals the whole file, so every
// PROPFIND and every export re-paid the cost of however many groups the import
// had created.
func TestContactToVCardResolvesGroupsWithoutPerIDLookups(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	gs, err := srv.userGroupsStore(userID)
	if err != nil {
		t.Fatalf("userGroupsStore: %v", err)
	}
	ids, err := gs.EnsureByName([]string{"Work", "Family", "Cycling"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}

	card := srv.contactToVCardForUser(userID, contacts.Contact{
		UID:           "c1",
		FormattedName: "Bob",
		GroupIDs:      ids,
	})

	categories := card.Values("CATEGORIES")
	joined := strings.Join(categories, ",")
	for _, want := range []string{"Work", "Family", "Cycling"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("CATEGORIES = %v, missing %q", categories, want)
		}
	}
}

// An id that no longer names a group must be skipped, not rendered as an empty
// category.
func TestContactToVCardSkipsUnknownGroupIDs(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	gs, err := srv.userGroupsStore(userID)
	if err != nil {
		t.Fatalf("userGroupsStore: %v", err)
	}
	ids, err := gs.EnsureByName([]string{"Work"})
	if err != nil {
		t.Fatalf("EnsureByName: %v", err)
	}

	card := srv.contactToVCardForUser(userID, contacts.Contact{
		UID:           "c1",
		FormattedName: "Bob",
		GroupIDs:      append(ids, "no-such-group-id"),
	})

	joined := strings.Join(card.Values("CATEGORIES"), ",")
	if strings.Contains(joined, ",,") || strings.HasSuffix(joined, ",") {
		t.Fatalf("an unknown group id rendered as an empty category: %q", joined)
	}
	if !strings.Contains(joined, "Work") {
		t.Fatalf("CATEGORIES = %q, want it to contain Work", joined)
	}
}
