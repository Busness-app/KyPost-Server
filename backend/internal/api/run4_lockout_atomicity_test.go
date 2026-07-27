package api

import (
	"sync"
	"testing"
	"time"
)

// run-4 LOW-6: every lockout and cooldown except mfaPushCooldown was
// check-then-act — allowed() at the top of a handler, record*() much later —
// so concurrent requests all observed "allowed" before any of them recorded,
// and a burst walked straight past the budget. The audit measured roughly 7×
// the login budget and 3.8× the MFA budget that way.
//
// The budget has to be spent at check time. tryAttempt reserves a strike in the
// same critical section that checks for one, and the outcome calls settle it:
// recordSuccess clears the whole entry, cancelAttempt gives the strike back for
// a path that never became a credential check at all.

func TestTryAttemptBoundsAConcurrentBurst(t *testing.T) {
	const budget = 3
	lockout := newFailureLockout(budget, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := lockout.tryAttempt("victim"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted > budget {
		t.Fatalf("admitted %d attempts against a budget of %d", admitted, budget)
	}
	if admitted == 0 {
		t.Fatal("admitted nothing at all")
	}
}

func TestTryAttemptLocksOutAfterTheBudget(t *testing.T) {
	lockout := newFailureLockout(3, time.Minute)

	for i := 0; i < 3; i++ {
		if ok, _ := lockout.tryAttempt("victim"); !ok {
			t.Fatalf("attempt %d was refused inside the budget", i)
		}
	}
	ok, retryAfter := lockout.tryAttempt("victim")
	if ok {
		t.Fatal("a fourth attempt was admitted past a budget of three")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %v, want a positive wait", retryAfter)
	}
}

// A success wipes the slate, so an ordinary user who mistypes twice and then
// gets it right is not one typo away from a lockout next time.
func TestRecordSuccessClearsReservedStrikes(t *testing.T) {
	lockout := newFailureLockout(3, time.Minute)

	lockout.tryAttempt("user")
	lockout.tryAttempt("user")
	lockout.recordSuccess("user")

	for i := 0; i < 3; i++ {
		if ok, _ := lockout.tryAttempt("user"); !ok {
			t.Fatalf("attempt %d refused after a success cleared the history", i)
		}
	}
}

// cancelAttempt exists for paths that reserved a strike and then turned out not
// to be a credential attempt at all — the login handler's "captcha
// verification unavailable" 503 being the case that matters. That is the
// operator's outage, not the user's failure, and counting it would lock out
// every user of the instance for the duration.
func TestCancelAttemptGivesTheStrikeBack(t *testing.T) {
	lockout := newFailureLockout(3, time.Minute)

	for i := 0; i < 10; i++ {
		ok, _ := lockout.tryAttempt("user")
		if !ok {
			t.Fatalf("attempt %d was refused even though every prior one was cancelled", i)
		}
		lockout.cancelAttempt("user")
	}
}

func TestCancelAttemptNeverGoesNegative(t *testing.T) {
	lockout := newFailureLockout(3, time.Minute)

	// Cancelling more than was ever reserved must not create credit that
	// buys extra attempts later.
	lockout.cancelAttempt("user")
	lockout.cancelAttempt("user")
	lockout.tryAttempt("user")
	lockout.cancelAttempt("user")
	lockout.cancelAttempt("user")
	lockout.cancelAttempt("user")

	for i := 0; i < 3; i++ {
		if ok, _ := lockout.tryAttempt("user"); !ok {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if ok, _ := lockout.tryAttempt("user"); ok {
		t.Fatal("over-cancelling bought an extra attempt")
	}
}

// An expired lockout resets, or a locked-out key would stay locked forever.
func TestTryAttemptResetsAfterTheLockoutExpires(t *testing.T) {
	lockout := newFailureLockout(2, 10*time.Millisecond)

	lockout.tryAttempt("user")
	lockout.tryAttempt("user")
	if ok, _ := lockout.tryAttempt("user"); ok {
		t.Fatal("admitted past the budget")
	}

	time.Sleep(20 * time.Millisecond)
	if ok, _ := lockout.tryAttempt("user"); !ok {
		t.Fatal("still locked out after the window expired")
	}
}

// The same TOCTOU, in the send-as cooldown. Two concurrent verification
// requests for one address both saw "allowed" and both mailed the third party.
func TestSendAsCooldownTryConsumeAdmitsOnlyOne(t *testing.T) {
	cooldown := newSendAsVerificationCooldown()

	var wg sync.WaitGroup
	var mu sync.Mutex
	admitted := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := cooldown.tryConsume("user|target@example.com"); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if admitted != 1 {
		t.Fatalf("admitted %d probe sends for one address, want exactly 1", admitted)
	}
}

func TestSendAsCooldownTryConsumeIsPerKey(t *testing.T) {
	cooldown := newSendAsVerificationCooldown()

	if ok, _ := cooldown.tryConsume("user|a@example.com"); !ok {
		t.Fatal("first address refused")
	}
	if ok, _ := cooldown.tryConsume("user|b@example.com"); !ok {
		t.Fatal("a different address was penalised by the first one's cooldown")
	}
}
