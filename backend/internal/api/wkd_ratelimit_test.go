package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

// fixedClock returns a now() function whose value the caller can advance,
// so refill behavior is testable without sleeping.
func fixedClock(start time.Time) (now func() time.Time, advance func(time.Duration)) {
	t := start
	return func() time.Time { return t }, func(d time.Duration) { t = t.Add(d) }
}

func TestIPRateLimiterAllowsBurstThenBlocks(t *testing.T) {
	l := newIPRateLimiter(3, 1)
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("1.2.3.4"); !ok {
			t.Fatalf("request %d in burst should be allowed", i+1)
		}
	}
	ok, retryAfter := l.allow("1.2.3.4")
	if ok {
		t.Fatal("request past the burst should be blocked")
	}
	if retryAfter <= 0 {
		t.Fatalf("blocked request should report a positive retryAfter, got %v", retryAfter)
	}
}

func TestIPRateLimiterIsPerKey(t *testing.T) {
	l := newIPRateLimiter(1, 1)
	if ok, _ := l.allow("1.1.1.1"); !ok {
		t.Fatal("first key should be allowed")
	}
	if ok, _ := l.allow("1.1.1.1"); ok {
		t.Fatal("first key should now be exhausted")
	}
	// A different client must be unaffected by the first one's exhaustion.
	if ok, _ := l.allow("2.2.2.2"); !ok {
		t.Fatal("second key must not be blocked by the first key's usage")
	}
}

func TestIPRateLimiterRefillsOverTime(t *testing.T) {
	l := newIPRateLimiter(2, 1) // 2 burst, 1 token/sec
	now, advance := fixedClock(time.Now())
	l.now = now

	l.allow("1.2.3.4")
	l.allow("1.2.3.4")
	if ok, _ := l.allow("1.2.3.4"); ok {
		t.Fatal("should be exhausted after burst")
	}

	advance(1100 * time.Millisecond) // ~1 token back
	if ok, _ := l.allow("1.2.3.4"); !ok {
		t.Fatal("a token should have refilled after ~1s")
	}
	if ok, _ := l.allow("1.2.3.4"); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestIPRateLimiterDoesNotExceedBurstOnRefill(t *testing.T) {
	l := newIPRateLimiter(2, 1)
	now, advance := fixedClock(time.Now())
	l.now = now

	l.allow("1.2.3.4")
	advance(1 * time.Hour) // long idle: must cap at burst, not accumulate
	allowed := 0
	for i := 0; i < 10; i++ {
		if ok, _ := l.allow("1.2.3.4"); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("refill must cap at burst (2), allowed %d", allowed)
	}
}

func TestIPRateLimiterSweepsIdleEntries(t *testing.T) {
	l := newIPRateLimiter(1, 1)
	l.sweepThreshold = 4
	now, advance := fixedClock(time.Now())
	l.now = now

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"} {
		l.allow(ip)
	}
	advance(1 * time.Hour) // every bucket refills to full => all sweepable
	l.allow("6.6.6.6")

	l.mu.Lock()
	size := len(l.entries)
	l.mu.Unlock()
	if size > l.sweepThreshold {
		t.Fatalf("entries should have been swept below the threshold, got %d", size)
	}
}

// The WKD endpoint is public and unauthenticated, so it must be rate limited
// per client IP and answer 429 with Retry-After once a client exceeds it.
func TestWKDServingRateLimited(t *testing.T) {
	srv := newTestServer(t)
	srv.wkdLimiter = newIPRateLimiter(2, 1)
	handler := srv.routes()

	path := "/.well-known/openpgpkey/example.com/hu/abc"

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "9.9.9.9:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == 429 {
			t.Fatalf("request %d within burst should not be rate limited", i+1)
		}
	}

	req := httptest.NewRequest("GET", path, nil)
	req.RemoteAddr = "9.9.9.9:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Fatalf("expected 429 past the burst, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 response must carry a Retry-After header")
	}

	// A different client IP must still be served.
	other := httptest.NewRequest("GET", path, nil)
	other.RemoteAddr = "8.8.8.8:1234"
	otherRec := httptest.NewRecorder()
	handler.ServeHTTP(otherRec, other)
	if otherRec.Code == 429 {
		t.Fatal("a different client IP must not be rate limited by another's usage")
	}
}
