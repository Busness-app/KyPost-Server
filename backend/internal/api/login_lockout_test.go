package api

import (
	"testing"
	"time"
)

func TestLoginLockoutLocksAfterThreeFailures(t *testing.T) {
	l := newLoginLockout()
	const user = "alice"

	for i := 0; i < loginMaxFailures; i++ {
		if ok, _ := l.allowed(user); !ok {
			t.Fatalf("attempt %d: expected allowed before lockout threshold", i+1)
		}
		_, _ = l.tryAttempt(user)
	}

	ok, retryAfter := l.allowed(user)
	if ok {
		t.Fatal("expected lockout after loginMaxFailures failures")
	}
	if retryAfter <= 0 || retryAfter > loginLockoutFor {
		t.Fatalf("retryAfter = %v, want a positive duration <= %v", retryAfter, loginLockoutFor)
	}
}

func TestLoginLockoutIsPerUsername(t *testing.T) {
	l := newLoginLockout()
	for i := 0; i < loginMaxFailures; i++ {
		_, _ = l.tryAttempt("alice")
	}
	if ok, _ := l.allowed("alice"); ok {
		t.Fatal("alice should be locked out")
	}
	if ok, _ := l.allowed("bob"); !ok {
		t.Fatal("bob's attempts must not be affected by alice's lockout")
	}
}

func TestLoginLockoutSuccessClearsHistory(t *testing.T) {
	l := newLoginLockout()
	const user = "carol"
	_, _ = l.tryAttempt(user)
	_, _ = l.tryAttempt(user)
	l.recordSuccess(user)

	// A prior success must reset the strike count: two more failures alone
	// (not three) must not trip the lockout.
	_, _ = l.tryAttempt(user)
	_, _ = l.tryAttempt(user)
	if ok, _ := l.allowed(user); !ok {
		t.Fatal("strike count should have been reset by recordSuccess")
	}
}

func TestLoginLockoutExpiresAndResets(t *testing.T) {
	l := newLoginLockout()
	const user = "dave"
	for i := 0; i < loginMaxFailures; i++ {
		_, _ = l.tryAttempt(user)
	}
	if ok, _ := l.allowed(user); ok {
		t.Fatal("expected lockout")
	}

	// Simulate the lockout having already expired.
	l.mu.Lock()
	l.entries[user].lockedUntil = time.Now().Add(-time.Second)
	l.mu.Unlock()

	ok, _ := l.allowed(user)
	if !ok {
		t.Fatal("expired lockout should allow attempts again")
	}

	// And the strike count must have reset, not just the lockout: one more
	// failure alone must not immediately relock it.
	_, _ = l.tryAttempt(user)
	if ok, _ := l.allowed(user); !ok {
		t.Fatal("a single failure after an expired lockout must not relock immediately")
	}
}
