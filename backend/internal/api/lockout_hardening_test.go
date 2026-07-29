package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

func loginAttempt(srv *Server, username, password, remoteAddr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)
	return rec
}

// A lockout must apply only to the (username, client IP) pair that earned it:
// otherwise anyone who knows a username can lock the real owner out at will
// from a different machine.
func TestLoginLockoutScopedToClientIP(t *testing.T) {
	srv := newTestServer(t)

	for i := 0; i < loginMaxFailures; i++ {
		if rec := loginAttempt(srv, "victim", "wrong", "203.0.113.10:40000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := loginAttempt(srv, "victim", "wrong", "203.0.113.10:40000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP after threshold: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec := loginAttempt(srv, "victim", "wrong", "198.51.100.7:40000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("different IP: status = %d, want %d (a lockout earned by one IP must not lock the account for everyone)", rec.Code, http.StatusUnauthorized)
	}
}

func TestFailureLockoutCustomThreshold(t *testing.T) {
	l := newFailureLockout(2, time.Minute)
	_, _ = l.tryAttempt("key")
	if ok, _ := l.allowed("key"); !ok {
		t.Fatal("one failure below a threshold of two must not lock")
	}
	_, _ = l.tryAttempt("key")
	ok, retryAfter := l.allowed("key")
	if ok {
		t.Fatal("expected lockout after reaching the custom threshold")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("retryAfter = %v, want a positive duration <= 1m", retryAfter)
	}
}

func davRequest(srv *Server, username, password, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, davPrefix+"/", nil)
	req.SetBasicAuth(username, password)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

// The DAV surface authenticates with scrypt-verified Basic Auth on every
// request; without a lockout each guess costs the server a full scrypt run
// (CPU DoS) with no cap, unlike the login endpoint.
func TestDAVAuthLockoutAfterRepeatedFailures(t *testing.T) {
	srv := newTestServer(t)

	for i := 0; i < davMaxFailures; i++ {
		if rec := davRequest(srv, "nobody", "guess", "203.0.113.20:40000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := davRequest(srv, "nobody", "guess", "203.0.113.20:40000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP after threshold: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec := davRequest(srv, "nobody", "guess", "198.51.100.9:40000"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("different IP: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestDAVAuthSuccessClearsLockoutHistory(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	u := all[0]
	hash, err := users.HashPassword("dav-app-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{Hash: hash, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	const ip = "203.0.113.30:40000"
	for i := 0; i < davMaxFailures-1; i++ {
		if rec := davRequest(srv, u.Username, "wrong", ip); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d", i+1, rec.Code, http.StatusUnauthorized)
		}
	}
	if rec := davRequest(srv, u.Username, "dav-app-password", ip); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusTooManyRequests {
		t.Fatalf("correct password below threshold: status = %d, want an authenticated response", rec.Code)
	}
	// The success must have reset the strike count: a single further failure
	// alone must not trip the lockout.
	if rec := davRequest(srv, u.Username, "wrong", ip); rec.Code != http.StatusUnauthorized {
		t.Fatalf("failure after success: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestFailureLockoutIsHardBounded is the regression test for a "bound" that
// bounded nothing.
//
// The old sweep deleted entries that were NOT currently locked out. A locked
// entry is what an attacker manufactures deliberately — maxFailures requests
// buys one that survives every subsequent sweep — so the threshold only limited
// the unlocked portion while its comment claimed it bounded the whole map. The
// only real limit was the scrypt cost per attempt, in a different file,
// undocumented.
func TestFailureLockoutIsHardBounded(t *testing.T) {
	l := newFailureLockout(1, 15*time.Minute) // 1 strike => instantly locked

	// Every key here goes straight to locked, which is the adversarial case.
	total := loginLockoutHardCap + 25_000
	for i := range total {
		l.tryAttempt(fmt.Sprintf("victim-%d\x00203.0.113.%d", i, i%256))
	}

	l.mu.Lock()
	size := len(l.entries)
	l.mu.Unlock()

	// The insert in tryAttempt happens after the sweep, so the steady state sits
	// between the low-water mark and the cap.
	if size > loginLockoutHardCap {
		t.Errorf("lockout table holds %d entries after %d all-locking attempts, want at most %d",
			size, total, loginLockoutHardCap)
	}
	if size < loginLockoutLowWater {
		t.Errorf("lockout table trimmed to %d, below the %d low-water mark: it is discarding "+
			"more cooldowns than it needs to", size, loginLockoutLowWater)
	}
}

// TestCrowdedTableDoesNotErasePartialStrikes is the more serious bug the hard-cap
// work uncovered.
//
// The old sweep dropped every entry that was not currently locked — which
// includes entries mid-accumulation at 1-of-3 and 2-of-3 strikes. So an attacker
// who kept the table above the sweep threshold erased everyone's partial
// progress on every attempt, no key ever reached the third strike, and the
// lockout stopped engaging at all. A memory bound that disables the control it
// bounds is worse than no bound.
func TestCrowdedTableDoesNotErasePartialStrikes(t *testing.T) {
	l := newFailureLockout(3, 15*time.Minute)

	// Flood past the sweep threshold with locked entries, the way an attacker
	// would.
	for i := range loginLockoutSweepThreshold + 500 {
		key := fmt.Sprintf("filler-%d", i)
		for range 3 {
			l.tryAttempt(key)
		}
	}
	l.mu.Lock()
	crowded := len(l.entries) >= loginLockoutSweepThreshold
	l.mu.Unlock()
	if !crowded {
		t.Fatalf("test did not achieve a crowded table; sweep behaviour is not being exercised")
	}

	// Now a real key must still be able to accumulate its way to a lockout,
	// with the table crowded the whole time.
	const victim = "real-victim\x00198.51.100.7"
	for i := range 3 {
		if ok, _ := l.tryAttempt(victim); !ok {
			t.Fatalf("attempt %d was refused before the budget was spent", i+1)
		}
	}
	ok, retryAfter := l.tryAttempt(victim)
	if ok {
		t.Fatal("the 4th attempt was allowed: a crowded table erased the victim's partial " +
			"strikes, so the lockout never engaged — this is a lockout bypass by table flooding")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want a positive cooldown", retryAfter)
	}
}

// TestStalePartialStrikesAreForgiven pins the other half of keying the sweep on
// lastSeen: an entry that has been idle longer than the cooldown starts fresh,
// so a single failed attempt today plus two tomorrow is not a lockout.
func TestStalePartialStrikesAreForgiven(t *testing.T) {
	l := newFailureLockout(3, 15*time.Minute)
	const key = "occasional-typo\x00198.51.100.9"

	if ok, _ := l.tryAttempt(key); !ok {
		t.Fatal("first attempt refused")
	}
	// Backdate the entry past the cooldown window.
	l.mu.Lock()
	l.entries[key].lastSeen = time.Now().Add(-16 * time.Minute)
	l.mu.Unlock()

	// Three more attempts must all be allowed: the stale strike is forgiven, so
	// this is a fresh budget of 3, not 2.
	for i := range 3 {
		if ok, _ := l.tryAttempt(key); !ok {
			t.Fatalf("attempt %d refused; a stale partial strike was carried forward", i+1)
		}
	}
	if ok, _ := l.tryAttempt(key); ok {
		t.Error("the budget did not apply after the reset")
	}
}

// TestCrowdedTableSweepIsThrottled guards the cost of the sweep itself.
//
// Both stages are O(n), and the sweep is called from tryAttempt — so a table
// parked above the threshold made every attempt pay a full scan, letting the
// attacker who created the flood also choose how much work each of their
// requests cost.
func TestCrowdedTableSweepIsThrottled(t *testing.T) {
	l := newFailureLockout(1, 15*time.Minute)
	for i := range loginLockoutSweepThreshold + 100 {
		l.tryAttempt(fmt.Sprintf("filler-%d", i))
	}

	l.mu.Lock()
	before := l.lastSweep
	l.mu.Unlock()
	if before.IsZero() {
		t.Fatal("sweep never ran on a crowded table")
	}

	// An immediate follow-up attempt must not re-run the scan.
	l.tryAttempt("another-key")
	l.mu.Lock()
	after := l.lastSweep
	l.mu.Unlock()
	if !after.Equal(before) {
		t.Error("the sweep ran again immediately; it should be throttled by sweepMinInterval")
	}
}
