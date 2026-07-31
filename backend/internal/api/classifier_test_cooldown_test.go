package api

import (
	"testing"
	"time"
)

func TestClassifierTestCooldownBlocksWithinWindow(t *testing.T) {
	c := newCooldown(classifierTestCooldownFor)
	const key = "admin-1"

	ok, retryAfter := c.tryConsume(key)
	if !ok {
		t.Fatal("expected first test request to be allowed")
	}
	if retryAfter != 0 {
		t.Fatalf("retryAfter = %v, want 0 when allowed", retryAfter)
	}

	ok, retryAfter = c.tryConsume(key)
	if ok {
		t.Fatal("expected a second request within the cooldown window to be blocked")
	}
	if retryAfter <= 0 || retryAfter > classifierTestCooldownFor {
		t.Fatalf("retryAfter = %v, want a positive duration <= %v", retryAfter, classifierTestCooldownFor)
	}
}

func TestClassifierTestCooldownIsPerKey(t *testing.T) {
	c := newCooldown(classifierTestCooldownFor)
	c.tryConsume("admin-a")

	if ok, _ := c.tryConsume("admin-a"); ok {
		t.Fatal("admin-a should be in cooldown")
	}
	if ok, _ := c.tryConsume("admin-b"); !ok {
		t.Fatal("admin-b's request must not be affected by admin-a's cooldown")
	}
}

func TestClassifierTestCooldownExpiresAfterWindow(t *testing.T) {
	c := newCooldown(classifierTestCooldownFor)
	const key = "admin-2"
	c.tryConsume(key)
	// Simulate the window having already elapsed.
	c.mu.Lock()
	c.lastSent[key] = time.Now().Add(-classifierTestCooldownFor - time.Second)
	c.mu.Unlock()

	if ok, _ := c.tryConsume(key); !ok {
		t.Fatal("expected request to be allowed again once the cooldown window has elapsed")
	}
}
