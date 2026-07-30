package api

import (
	"sync"
	"testing"
	"time"
)

func TestMfaPushLimiterAllowsBurstThenBlocks(t *testing.T) {
	c := newMfaPushLimiter()
	const userID = "user-1"

	for i := 0; i < mfaPushBurst; i++ {
		ok, retryAfter := c.tryConsume(userID)
		if !ok {
			t.Fatalf("push %d of %d: expected to be allowed within the burst", i+1, mfaPushBurst)
		}
		if retryAfter != 0 {
			t.Fatalf("push %d: retryAfter = %v, want 0 when allowed", i+1, retryAfter)
		}
	}

	ok, retryAfter := c.tryConsume(userID)
	if ok {
		t.Fatalf("expected push %d to be blocked once the burst is spent", mfaPushBurst+1)
	}
	if retryAfter <= 0 || retryAfter > mfaPushWindow {
		t.Fatalf("retryAfter = %v, want a positive duration <= %v", retryAfter, mfaPushWindow)
	}
}

// TestMfaPushLimiterAllowsASecondPushImmediately is the unit-level regression
// test for "after one push, MFA push notifications break". The policy used to be
// one push per window, so the second sign-in attempt got no notification at all.
func TestMfaPushLimiterAllowsASecondPushImmediately(t *testing.T) {
	c := newMfaPushLimiter()
	const userID = "user-retry"

	if ok, _ := c.tryConsume(userID); !ok {
		t.Fatal("expected the first push to be allowed")
	}
	if ok, retryAfter := c.tryConsume(userID); !ok {
		t.Fatalf("a second sign-in attempt must still get a push; blocked for %v", retryAfter)
	}
}

func TestMfaPushLimiterIsPerAccount(t *testing.T) {
	c := newMfaPushLimiter()
	for i := 0; i < mfaPushBurst; i++ {
		c.tryConsume("user-a")
	}

	if ok, _ := c.tryConsume("user-a"); ok {
		t.Fatal("user-a should be throttled after spending its burst")
	}
	if ok, _ := c.tryConsume("user-b"); !ok {
		t.Fatal("user-b's push must not be affected by user-a's throttling")
	}
}

func TestMfaPushLimiterRecoversAsTheWindowSlides(t *testing.T) {
	c := newMfaPushLimiter()
	const userID = "user-2"
	for i := 0; i < mfaPushBurst; i++ {
		c.tryConsume(userID)
	}
	if ok, _ := c.tryConsume(userID); ok {
		t.Fatal("expected the burst to be spent")
	}

	// Age the oldest entry out of the window, leaving the rest inside it: one
	// slot should free up, and exactly one.
	c.mu.Lock()
	c.sent[userID][0] = time.Now().Add(-mfaPushWindow - time.Second)
	c.mu.Unlock()

	if ok, _ := c.tryConsume(userID); !ok {
		t.Fatal("expected a slot to free up once the oldest push left the window")
	}
	if ok, _ := c.tryConsume(userID); ok {
		t.Fatal("only one slot had expired; the burst must not be refilled wholesale")
	}
}

// TestMfaPushLimiterTryConsumeIsAtomicUnderRace fires many concurrent
// tryConsume calls for the same account and asserts exactly mfaPushBurst
// succeed — this is the exact TOCTOU the old separate allowed()+recordSent()
// calls were vulnerable to.
func TestMfaPushLimiterTryConsumeIsAtomicUnderRace(t *testing.T) {
	c := newMfaPushLimiter()
	const userID = "user-race"
	const n = 50

	var wg sync.WaitGroup
	barrier := make(chan struct{})
	results := make([]bool, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier
			ok, _ := c.tryConsume(userID)
			results[idx] = ok
		}(i)
	}
	close(barrier)
	wg.Wait()

	allowedCount := 0
	for _, ok := range results {
		if ok {
			allowedCount++
		}
	}
	if allowedCount != mfaPushBurst {
		t.Fatalf("expected exactly %d of %d concurrent tryConsume calls to succeed, got %d",
			mfaPushBurst, n, allowedCount)
	}
}

func TestMfaPushLimiterSweepDropsIdleAccounts(t *testing.T) {
	c := newMfaPushLimiter()
	c.tryConsume("user-idle")
	c.tryConsume("user-active")

	c.mu.Lock()
	c.sent["user-idle"][0] = time.Now().Add(-mfaPushLimiterSweepMaxAge - time.Minute)
	c.mu.Unlock()

	c.sweep(mfaPushLimiterSweepMaxAge)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.sent["user-idle"]; exists {
		t.Fatal("expected the idle account's entry to be reclaimed")
	}
	if _, exists := c.sent["user-active"]; !exists {
		t.Fatal("an account whose push is still inside the window must survive the sweep")
	}
}
