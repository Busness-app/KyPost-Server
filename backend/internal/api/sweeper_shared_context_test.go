package api

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestAllSweepersExitOnSharedContextCancel proves that a single, real,
// cancelable context.Context — the kind runServer/runAll thread into all
// three background sweepers (Task 20) instead of context.Background() —
// genuinely stops every one of them: StartPickupSweeper,
// StartCooldownSweeper, and StartVersionMonitor all return
// promptly once that one shared context is canceled.
//
// Before the fix, each sweeper ran on context.Background(), which never
// cancels — so this exact test (cancel the shared context, wait for all
// three goroutines to exit) would hang and time out, which is precisely the
// leaked-goroutine failure mode Task 20 closes.
func TestAllSweepersExitOnSharedContextCancel(t *testing.T) {
	srv := newTestServer(t)
	// StartVersionMonitor runs its checks once before entering the select
	// loop; without this the self-update check would reach the real GitHub API
	// from a unit test.
	serveReleases(t, `[]`)

	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); srv.StartPickupSweeper(ctx) }()
	go func() { defer wg.Done(); srv.StartCooldownSweeper(ctx) }()
	go func() { defer wg.Done(); srv.StartVersionMonitor(ctx) }()

	// Give the goroutines a moment to actually start running (enter their
	// select loops) before cancellation, so this isn't just testing that an
	// already-canceled context is checked once at the top.
	time.Sleep(20 * time.Millisecond)

	cancel()

	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	select {
	case <-allDone:
	case <-time.After(2 * time.Second):
		t.Fatal("expected all three sweeper goroutines to exit after their shared context was canceled, but at least one is still running (leaked goroutine)")
	}
}
