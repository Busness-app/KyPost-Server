package classifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newAdmissionTestClient returns a client pointed at srv with warmup already
// satisfied, so tests exercise the admission path rather than model loading.
func newAdmissionTestClient(t *testing.T, srv *httptest.Server, concurrency int, pace time.Duration) *HTTPClient {
	t.Helper()
	c := &HTTPClient{
		baseURL:      srv.URL,
		path:         "/api/generate",
		model:        "test",
		client:       srv.Client(),
		classifySem:  make(chan struct{}, concurrency),
		paceInterval: pace,
	}
	getWarmupState(c.baseURL + c.path + "|" + c.model).ready = true
	t.Cleanup(ResetWarmupState)
	return c
}

// generateStub answers /api/generate with label after holding the request open
// for hold, and records peak concurrency.
func generateStub(hold time.Duration, label string, peak *int64, live *int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(live, 1)
		for {
			old := atomic.LoadInt64(peak)
			if n <= old || atomic.CompareAndSwapInt64(peak, old, n) {
				break
			}
		}
		time.Sleep(hold)
		atomic.AddInt64(live, -1)
		_ = json.NewEncoder(w).Encode(map[string]string{"response": label})
	}))
}

func TestClassifyHonorsTheConcurrencyLimit(t *testing.T) {
	var peak, live int64
	srv := generateStub(40*time.Millisecond, "Primary", &peak, &live)
	defer srv.Close()

	c := newAdmissionTestClient(t, srv, 2, 0)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", ""); err != nil {
				t.Errorf("Classify: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&peak); got > 2 {
		t.Fatalf("peak in-flight generations = %d, want at most the configured 2", got)
	}
	if got := atomic.LoadInt64(&peak); got < 2 {
		t.Fatalf("peak in-flight generations = %d, want 2 — the extra slot is unreachable", got)
	}
}

// TestClassifyDoesNotPaceByDefault is the regression guard on the throughput
// bug: an unconditional 3s gap capped the whole instance at 20 classifications
// a minute regardless of user count or model speed.
func TestClassifyDoesNotPaceByDefault(t *testing.T) {
	var peak, live int64
	srv := generateStub(0, "Primary", &peak, &live)
	defer srv.Close()

	c := newAdmissionTestClient(t, srv, 1, 0)

	start := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", ""); err != nil {
			t.Fatalf("Classify %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("five instant classifications took %s; a fixed inter-request delay is back", elapsed)
	}
}

func TestClassifyPacesWhenConfigured(t *testing.T) {
	var peak, live int64
	srv := generateStub(0, "Primary", &peak, &live)
	defer srv.Close()

	c := newAdmissionTestClient(t, srv, 1, 60*time.Millisecond)

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", ""); err != nil {
			t.Fatalf("Classify %d: %v", i, err)
		}
	}
	// Three requests, two gaps.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("paced run took %s, want at least two 60ms gaps — CLASSIFY_PACE_MS is not honored", elapsed)
	}
}

// TestClassifyAbandonsTheQueueOnContextCancel is why the semaphore is a
// channel and not a Mutex: a caller whose context is already done must not sit
// behind another user's retry backoff.
func TestClassifyAbandonsTheQueueOnContextCancel(t *testing.T) {
	var peak, live int64
	srv := generateStub(500*time.Millisecond, "Primary", &peak, &live)
	defer srv.Close()

	c := newAdmissionTestClient(t, srv, 1, 0)

	blocking := make(chan struct{})
	go func() {
		defer close(blocking)
		_, _ = c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", "")
	}()
	// Let the first request take the only slot.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Classify(ctx, []string{"Primary"}, "a@b.c", "s", "b", ""); err == nil {
		t.Fatal("Classify with a cancelled context returned no error")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("cancelled caller waited %s for the slot; it should abandon the queue", elapsed)
	}
	<-blocking
}

func TestStatsReportsAdmissionDepth(t *testing.T) {
	var peak, live int64
	srv := generateStub(200*time.Millisecond, "Primary", &peak, &live)
	defer srv.Close()

	c := newAdmissionTestClient(t, srv, 1, 0)
	if got := c.Stats(); got.Concurrency != 1 || got.InFlight != 0 || got.Queued != 0 {
		t.Fatalf("idle Stats() = %+v, want concurrency 1 and nothing in flight", got)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", "")
	}()
	go func() {
		_, _ = c.Classify(context.Background(), []string{"Primary"}, "a@b.c", "s", "b", "")
	}()
	time.Sleep(60 * time.Millisecond)

	st := c.Stats()
	if st.InFlight != 1 {
		t.Errorf("Stats().InFlight = %d, want 1", st.InFlight)
	}
	if st.Queued != 1 {
		t.Errorf("Stats().Queued = %d, want 1 — a growing queue is the backlog signal", st.Queued)
	}
	<-done
}
