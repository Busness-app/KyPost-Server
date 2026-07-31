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
	if ok, _ := l.lockedNow("key"); !ok {
		t.Fatal("one failure below a threshold of two must not lock")
	}
	_, _ = l.tryAttempt("key")
	ok, retryAfter := l.lockedNow("key")
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

// TestFailureLockoutIsHardBounded pins the bound AND what it must never trade
// for it.
//
// The table is capped, but a live cooldown is never evicted to make room. The
// previous version made room exactly that way, taking locked entries first — so
// an attacker who wanted more guesses at one account pushed the table past the
// cap with rotating keys and their target's lockout was in the first tranche
// deleted. Fifteen minutes became zero, repeatably. Saturation now sheds new
// keys instead: an outage for callers the table has not seen, never an amnesty
// for one it has.
func TestFailureLockoutIsHardBounded(t *testing.T) {
	l := newFailureLockout(1, 15*time.Minute) // 1 strike => instantly locked

	// A victim, locked out before the flood starts.
	const victim = "victim\x00203.0.113.9"
	l.tryAttempt(victim)
	if ok, _ := l.lockedNow(victim); ok {
		t.Fatal("setup: the victim should be locked out")
	}

	// Every key here goes straight to locked, which is the adversarial case.
	total := loginLockoutHardCap + 25_000
	for i := range total {
		l.tryAttempt(fmt.Sprintf("filler-%d\x00203.0.113.%d", i, i%256))
	}

	l.mu.Lock()
	size := len(l.entries)
	l.mu.Unlock()
	if size > loginLockoutHardCap {
		t.Errorf("lockout table holds %d entries after %d all-locking attempts, want at most %d",
			size, total, loginLockoutHardCap)
	}

	// THE POINT: the flood must not have bought the attacker their victim back.
	if ok, _ := l.lockedNow(victim); ok {
		t.Error("flooding the table past the hard cap forgave a live lockout. " +
			"That is a lockout bypass with a price tag, not a memory bound: an " +
			"attacker who wants more guesses at one account only has to fill the table.")
	}
	if !l.Saturated() {
		t.Error("the table shed keys without recording it; an operator sees 429s on good " +
			"credentials with nothing in the log to explain them")
	}
}

// A saturated table must still serve the keys it already knows. Shedding is for
// keys it has never seen; refusing an existing one would let a flood lock out
// every user who was mid-accumulation.
func TestSaturatedTableStillServesKnownKeys(t *testing.T) {
	l := newFailureLockout(3, 15*time.Minute)

	const known = "known\x00203.0.113.1"
	l.tryAttempt(known) // 1 of 3: known to the table, not locked

	for i := range loginLockoutHardCap + 1_000 {
		l.tryAttempt(fmt.Sprintf("filler-%d", i))
	}

	if ok, _ := l.tryAttempt(known); !ok {
		t.Error("a saturated table refused a key it was already tracking; a flood would " +
			"lock out every user mid-accumulation")
	}
	if ok, _ := l.tryAttempt("brand-new-key"); ok {
		t.Error("a saturated table admitted a brand-new key, so the cap does not hold")
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
