package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// withSaturatedKDF fills every derivation slot and returns a release func. The
// slots stay held until release is called, so anything that asks for one during
// the test must take the shed path.
func withSaturatedKDF(t *testing.T, s *Server) (release func()) {
	t.Helper()
	for i := 0; i < maxConcurrentKDF; i++ {
		s.kdfSem <- struct{}{}
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		for i := 0; i < maxConcurrentKDF; i++ {
			<-s.kdfSem
		}
	}
}

// withShortKDFQueueWait shrinks the queue tolerance so a saturation test does
// not have to wait out the production value.
func withShortKDFQueueWait(t *testing.T, d time.Duration) {
	t.Helper()
	previous := kdfMaxQueueWait
	kdfMaxQueueWait = d
	t.Cleanup(func() { kdfMaxQueueWait = previous })
}

// TestWithKDFSlotShedsRatherThanQueueingForever is the property the whole
// change exists for.
//
// The slot used to be an unbounded blocking channel send. That capped scrypt's
// memory and replaced it with an unbounded backlog: goroutines parked forever,
// each holding a parsed request, draining at four derivations at a time. Neither
// ReadTimeout nor the client hanging up unblocks a channel send, so the work ran
// anyway, minutes later, for callers long gone.
func TestWithKDFSlotShedsRatherThanQueueingForever(t *testing.T) {
	srv := newTestServer(t)
	withShortKDFQueueWait(t, 50*time.Millisecond)
	release := withSaturatedKDF(t, srv)
	defer release()

	ran := false
	start := time.Now()
	err := srv.withKDFSlot(context.Background(), func() { ran = true })
	elapsed := time.Since(start)

	if !errors.Is(err, errKDFBusy) {
		t.Fatalf("got err %v, want errKDFBusy", err)
	}
	if ran {
		t.Error("fn ran despite no slot being available; the shed must not perform the derivation")
	}
	if elapsed > time.Second {
		t.Errorf("waited %v before shedding; the bounded wait is not in effect", elapsed)
	}
}

// TestWithKDFSlotAbandonsOnCancelledContext covers the other half: a client that
// has already disconnected must not be handed a slot ahead of one still waiting,
// and must not cost a derivation.
func TestWithKDFSlotAbandonsOnCancelledContext(t *testing.T) {
	srv := newTestServer(t)
	withShortKDFQueueWait(t, 5*time.Second)
	release := withSaturatedKDF(t, srv)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.withKDFSlot(ctx, func() { t.Error("fn ran for a cancelled caller") }) }()

	// Give the goroutine time to park on the semaphore, then hang up.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got err %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withKDFSlot did not return after its caller's context was cancelled")
	}
}

// TestWithKDFSlotAdmitsWhenCapacityFrees proves the shed is a bound and not a
// blanket refusal: once a slot frees, the next caller runs normally.
func TestWithKDFSlotAdmitsWhenCapacityFrees(t *testing.T) {
	srv := newTestServer(t)
	withShortKDFQueueWait(t, 2*time.Second)
	release := withSaturatedKDF(t, srv)

	var wg sync.WaitGroup
	wg.Add(1)
	ran := false
	var err error
	go func() {
		defer wg.Done()
		err = srv.withKDFSlot(context.Background(), func() { ran = true })
	}()

	time.Sleep(20 * time.Millisecond)
	release()
	wg.Wait()

	if err != nil {
		t.Fatalf("unexpected error once capacity freed: %v", err)
	}
	if !ran {
		t.Error("fn did not run after a slot became available")
	}
}

// TestWithKDFSlotBoundsConcurrentDerivations is the original property, kept:
// shedding must not have loosened the concurrency cap it replaced the queue for.
func TestWithKDFSlotBoundsConcurrentDerivations(t *testing.T) {
	srv := newTestServer(t)
	withShortKDFQueueWait(t, 5*time.Second)

	var mu sync.Mutex
	inFlight, peak := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentKDF*4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = srv.withKDFSlot(context.Background(), func() {
				mu.Lock()
				inFlight++
				if inFlight > peak {
					peak = inFlight
				}
				mu.Unlock()
				time.Sleep(5 * time.Millisecond)
				mu.Lock()
				inFlight--
				mu.Unlock()
			})
		}()
	}
	wg.Wait()

	if peak > maxConcurrentKDF {
		t.Fatalf("observed %d concurrent derivations, cap is %d", peak, maxConcurrentKDF)
	}
}
