package pgpmail

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// run-4 LOW-10: nothing bounded how many pickup records one account could
// create. Each holds a whole message body (the send path allows ~34 MiB of
// decoded attachments), they live on the shared state volume for the full TTL,
// and creating one is an ordinary authenticated send. A user — or a stolen
// session — could fill the volume that every other user's mail cache, contacts
// and sealed private keys are written to, and AtomicWriteFile then fails for
// everyone.
//
// The cap counts only records that are still live. Consumed and expired ones
// are tombstones the sweeper will collect, so they must not hold a slot
// hostage: someone who legitimately sends many pickup links over a week should
// never be told to stop because of messages that have already been read.

func TestCreateRefusesPastTheOutstandingCap(t *testing.T) {
	store := newTestPickupStore(t)

	for i := 0; i < maxOutstandingPickupsPerUser; i++ {
		if _, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	_, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour)
	if !errors.Is(err, ErrPickupQuotaExceeded) {
		t.Fatalf("err = %v, want ErrPickupQuotaExceeded", err)
	}
}

func TestCreateClientSealedRefusesPastTheOutstandingCap(t *testing.T) {
	store := newTestPickupStore(t)
	sealed := `{"v":1,"iv":"aXY=","ciphertext":"Y3Q="}`

	for i := 0; i < maxOutstandingPickupsPerUser; i++ {
		if _, err := store.CreateClientSealed("user-1", "r@example.com", sealed, time.Hour); err != nil {
			t.Fatalf("CreateClientSealed %d: %v", i, err)
		}
	}

	_, err := store.CreateClientSealed("user-1", "r@example.com", sealed, time.Hour)
	if !errors.Is(err, ErrPickupQuotaExceeded) {
		t.Fatalf("err = %v, want ErrPickupQuotaExceeded", err)
	}
}

// The quota is per user. One account exhausting its own allowance must not
// stop anyone else sending — otherwise the cap is itself the denial of service
// it was added to prevent.
func TestPickupQuotaIsPerUser(t *testing.T) {
	store := newTestPickupStore(t)

	for i := 0; i < maxOutstandingPickupsPerUser; i++ {
		if _, err := store.Create("noisy-user", "r@example.com", "s", "b", "plain", time.Hour); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	if _, err := store.Create("quiet-user", "r@example.com", "s", "b", "plain", time.Hour); err != nil {
		t.Fatalf("a second user was blocked by the first user's quota: %v", err)
	}
}

func TestConsumedRecordsDoNotCountAgainstTheQuota(t *testing.T) {
	store := newTestPickupStore(t)

	var ids []string
	for i := 0; i < maxOutstandingPickupsPerUser; i++ {
		id, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour)
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	// The recipient reads one. That slot must come back.
	if _, _, _, err := store.View(ids[0]); err != nil {
		t.Fatalf("View: %v", err)
	}
	if _, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour); err != nil {
		t.Fatalf("a read message still held its slot: %v", err)
	}
}

func TestExpiredRecordsDoNotCountAgainstTheQuota(t *testing.T) {
	store := newTestPickupStore(t)

	for i := 0; i < maxOutstandingPickupsPerUser; i++ {
		if _, err := store.Create("user-1", "r@example.com", "s", "b", "plain", -time.Minute); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	if _, err := store.Create("user-1", "r@example.com", "s", "b", "plain", time.Hour); err != nil {
		t.Fatalf("expired records held their slots: %v", err)
	}
}

// The error reaches an end user through the send path, so it has to say what
// went wrong without naming another account or a filesystem path.
func TestPickupQuotaErrorIsSafeToShow(t *testing.T) {
	msg := ErrPickupQuotaExceeded.Error()
	if !strings.Contains(msg, "pickup") {
		t.Fatalf("error is not self-describing: %q", msg)
	}
}
