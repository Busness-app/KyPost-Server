package pgpmail

import (
	"strings"
	"testing"
	"time"
)

// TestOneUserCannotExhaustTheSharedPickupCeiling pins the relationship between
// the two caps.
//
// maxPickupBytesTotal is a ceiling on the WHOLE pickup directory, and it is
// checked BEFORE the per-user cap — which is denominated in RECORDS, not bytes.
// At 100 records x ~34 MiB a single account may hold ~3.4 GiB, more than the
// 2 GiB shared ceiling, so one user acting entirely inside their own quota
// denies the pickup feature to every other user for the seven-day retention.
//
// For the per-user cap to apportion the shared ceiling it has to be expressed
// in the same unit as the thing it is apportioning.
func TestOneUserCannotExhaustTheSharedPickupCeiling(t *testing.T) {
	if maxPickupBytesPerUser >= maxPickupBytesTotal {
		t.Fatalf("one account may hold %d bytes against a shared ceiling of %d: "+
			"the per-user cap cannot bound the shared resource",
			maxPickupBytesPerUser, maxPickupBytesTotal)
	}
}

// TestPickupRefusesAUserPastTheirOwnByteQuota is the functional half: a sender
// over their byte quota is refused with the per-account error, not the
// shared-storage one, and other users are unaffected.
func TestPickupRefusesAUserPastTheirOwnByteQuota(t *testing.T) {
	dir := t.TempDir()
	store := NewPickupStore(dir, dir+"/pickup.key")

	prev := maxPickupBytesPerUser
	maxPickupBytesPerUser = 64 << 10 // 64 KiB, so a handful of records reaches it
	t.Cleanup(func() { maxPickupBytesPerUser = prev })

	body := strings.Repeat("x", 16<<10)
	var lastErr error
	for i := 0; i < 20; i++ {
		if _, err := store.Create("hog", "bob@example.com", "subject", body, "plain", time.Hour); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("sender was never refused despite passing their byte quota")
	}
	if lastErr != ErrPickupQuotaExceeded {
		t.Fatalf("err = %v, want ErrPickupQuotaExceeded (the sender's own quota, "+
			"not the shared ceiling)", lastErr)
	}

	// A different user must be unaffected.
	if _, err := store.Create("innocent", "carol@example.com", "s", "short", "plain", time.Hour); err != nil {
		t.Fatalf("an unrelated sender was refused: %v", err)
	}
}
