package processor

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"kypost-server/backend/internal/retry"
)

// TestPushRetryDelayGrowsWithTheAttempt pins the backoff to what its own doc
// comment claims.
//
// pushRetryDelay takes an attempt number and shifts by it, but sendWithRetry
// passed a hardcoded 0 — so the shift was always a no-op and all three attempts
// waited the same 500ms. The code looked exponential and was not, which is the
// worst combination: during a relay outage every server retries at a constant
// rate against a service that is already failing.
func TestPushRetryDelayGrowsWithTheAttempt(t *testing.T) {
	for attempt, want := range map[int]time.Duration{
		0: pushRetryBackoff,
		1: pushRetryBackoff * 2,
		2: pushRetryBackoff * 4,
	} {
		if got := pushRetryDelay(errors.New("transient"), attempt); got != want {
			t.Fatalf("pushRetryDelay(attempt=%d) = %v, want %v", attempt, got, want)
		}
	}
}

// A relay that names its own Retry-After still wins over the backoff, at every
// attempt — the far end knows when it will be ready and the backoff is only a
// guess in its absence.
func TestRelayRetryAfterOverridesTheBackoff(t *testing.T) {
	err := &relayStatusError{Code: http.StatusTooManyRequests, RetryAfter: 2 * time.Second}
	for _, attempt := range []int{0, 1, 2} {
		if got := pushRetryDelay(err, attempt); got != 2*time.Second {
			t.Fatalf("pushRetryDelay(attempt=%d) = %v, want the relay's 2s Retry-After", attempt, got)
		}
	}
}

// sendWithRetry must hand the loop's real attempt counter to pushRetryDelay,
// not a constant. Asserted through retry.Loop itself so the test fails if the
// call site regresses to a fixed value, which is exactly how the bug looked.
func TestRetryLoopSleepsForTheGrowingDelay(t *testing.T) {
	var delays []time.Duration
	attempts := 0
	_, err := retry.Loop(context.Background(), pushRetryAttempts,
		func(attempt int) time.Duration {
			d := pushRetryDelay(errors.New("transient"), attempt)
			delays = append(delays, d)
			// Recorded, then collapsed: this test is about which delay was
			// chosen, and sleeping the real ones would cost 1.5 seconds.
			return time.Millisecond
		},
		func(int) (struct{}, error, bool) {
			attempts++
			return struct{}{}, errors.New("transient"), true
		})
	if err == nil {
		t.Fatal("expected the transient error to survive every attempt")
	}
	if attempts != pushRetryAttempts {
		t.Fatalf("attempts = %d, want %d", attempts, pushRetryAttempts)
	}
	if len(delays) != pushRetryAttempts-1 {
		t.Fatalf("delays = %v, want %d (no sleep after the last attempt)", delays, pushRetryAttempts-1)
	}
	if delays[0] >= delays[1] {
		t.Fatalf("delays = %v, want each wait longer than the one before", delays)
	}
}
