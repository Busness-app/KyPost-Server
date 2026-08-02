package pgpmail

// A pickup record whose link was never delivered must not hold a quota slot.
//
// Creating the record comes first, then minting the link token, then the SMTP
// send that actually tells the recipient anything. When one of those later
// steps fails, the sender is told the send failed — but the record stayed live
// for the full seven-day TTL, counting against maxOutstandingPickupsPerUser for
// a link nobody has and nobody can use. During an SMTP outage a sender retrying
// a handful of messages spends the whole cap on ghosts, and then cannot send
// pickup links at all until the sweeper catches up a week later.
//
// Discard is the compensating delete for exactly that window: the id is known,
// nothing was handed out, so nothing is lost by removing it.

import (
	"errors"
	"testing"
	"time"
)

func TestDiscardFreesTheQuotaSlot(t *testing.T) {
	store := newTestPickupStore(t)

	id, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := store.outstandingForLocked("user-1"); got != 1 {
		t.Fatalf("outstanding after Create = %d, want 1", got)
	}

	if err := store.Discard("user-1", id); err != nil {
		t.Fatalf("Discard: %v", err)
	}
	if got := store.outstandingForLocked("user-1"); got != 0 {
		t.Fatalf("outstanding after Discard = %d, want 0; the slot is still held", got)
	}
}

func TestDiscardedRecordCannotBeViewed(t *testing.T) {
	store := newTestPickupStore(t)

	id, err := store.Create("user-1", "r@example.com", "subject", "body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Discard("user-1", id); err != nil {
		t.Fatalf("Discard: %v", err)
	}

	// Gone, not tombstoned-but-present: nothing was ever delivered, so there is
	// no "already viewed" story to tell about it.
	if _, _, _, err := store.View(id); !errors.Is(err, ErrPickupNotFound) {
		t.Fatalf("View after Discard: err = %v, want ErrPickupNotFound", err)
	}
}

// Discard is only ever called with an id the caller just created. Scoping it to
// the sender keeps a future caller from turning a failed send into a way to
// delete somebody else's outstanding message.
func TestDiscardRefusesAnotherSendersRecord(t *testing.T) {
	store := newTestPickupStore(t)

	id, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := store.Discard("user-2", id); err == nil {
		t.Fatal("Discard removed a record belonging to another sender")
	}
	if got := store.outstandingForLocked("user-1"); got != 1 {
		t.Fatalf("outstanding = %d, want 1; the owner's record was removed anyway", got)
	}
}

// A record that has already been read is not the caller's to reclaim, and its
// slot is already free.
func TestDiscardLeavesAViewedRecordAlone(t *testing.T) {
	store := newTestPickupStore(t)

	id, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, _, err := store.View(id); err != nil {
		t.Fatalf("View: %v", err)
	}

	if err := store.Discard("user-1", id); err != nil {
		t.Fatalf("Discard of a viewed record should be a no-op, got: %v", err)
	}
	// The tombstone must survive, so a second visit to the link still reports
	// "already viewed" rather than the weaker "never existed".
	if _, _, _, err := store.View(id); !errors.Is(err, ErrPickupExpired) {
		t.Fatalf("View after discarding a viewed record: err = %v, want ErrPickupExpired", err)
	}
}

func TestDiscardOfAnUnknownRecordIsNotAnError(t *testing.T) {
	store := newTestPickupStore(t)
	// The send path calls this on a failure that may itself have been the
	// record never landing. Nothing is wrong if it is already gone.
	if err := store.Discard("user-1", "1cb7a3f6-0000-4000-8000-000000000000"); err != nil {
		t.Fatalf("Discard of an unknown id: %v", err)
	}
}
