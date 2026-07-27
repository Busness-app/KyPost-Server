package pgpmail

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newTestPickupStore(t *testing.T) *PickupStore {
	t.Helper()
	dir := t.TempDir()
	return NewPickupStore(filepath.Join(dir, "pickup"), filepath.Join(dir, "pickup.key"))
}

// run-4 LOW-8: ViewClientSealed tombstoned the record and *then* discovered it
// was server-sealed, so a request to the wrong one of the two view routes
// destroyed a perfectly good message and answered 409. View had the mirror-image
// bug for a client-sealed record.
//
// Neither is a disclosure — reaching either route needs a valid token for that
// record — but a one-time message store must not destroy a message on a request
// it is about to refuse. Check the kind first, consume second.

func TestViewClientSealedDoesNotDestroyServerSealedRecord(t *testing.T) {
	store := newTestPickupStore(t)
	id, err := store.Create("user-1", "r@example.com", "Subject", "the body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.ViewClientSealed(id); !errors.Is(err, ErrPickupNotClientSealed) {
		t.Fatalf("ViewClientSealed err = %v, want ErrPickupNotClientSealed", err)
	}

	subject, body, _, err := store.View(id)
	if err != nil {
		t.Fatalf("record was destroyed by the refused call: %v", err)
	}
	if subject != "Subject" || body != "the body" {
		t.Fatalf("unexpected content: subject=%q body=%q", subject, body)
	}
}

func TestViewDoesNotDestroyClientSealedRecord(t *testing.T) {
	store := newTestPickupStore(t)
	sealed := `{"v":1,"iv":"aXY=","ciphertext":"Y3Q="}`
	id, err := store.CreateClientSealed("user-1", "r@example.com", sealed, time.Hour)
	if err != nil {
		t.Fatalf("CreateClientSealed: %v", err)
	}

	if _, _, _, err := store.View(id); !errors.Is(err, ErrPickupClientSealed) {
		t.Fatalf("View err = %v, want ErrPickupClientSealed", err)
	}

	got, err := store.ViewClientSealed(id)
	if err != nil {
		t.Fatalf("record was destroyed by the refused call: %v", err)
	}
	if got != sealed {
		t.Fatalf("sealed blob = %q, want %q", got, sealed)
	}
}

// The refusal must stay a refusal even after the record is legitimately
// consumed — no resurrection, no different answer.
func TestWrongKindAfterConsumeIsStillRefused(t *testing.T) {
	store := newTestPickupStore(t)
	id, err := store.Create("user-1", "r@example.com", "Subject", "the body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, _, err := store.View(id); err != nil {
		t.Fatalf("View: %v", err)
	}
	if _, err := store.ViewClientSealed(id); err == nil {
		t.Fatal("ViewClientSealed succeeded on a consumed record")
	}
}
