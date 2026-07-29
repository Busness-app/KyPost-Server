package state

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDecisionsSeesAnotherProcessesAppend pins the two-process invariant.
//
// decisions.json is appended to by the DAEMON on every classification and read
// by the API to serve GET /api/decisions. The API caches its *Store for the
// process lifetime, so a Decisions() that only read its in-memory slice served
// a snapshot frozen at the first request and never advanced — the audit view
// showed nothing new until the API process restarted, with no error anywhere.
//
// Two Stores over one directory is exactly the two-process situation.
func TestDecisionsSeesAnotherProcessesAppend(t *testing.T) {
	dir := t.TempDir()

	api, err := New(dir)
	if err != nil {
		t.Fatalf("New(api): %v", err)
	}
	daemon, err := New(dir)
	if err != nil {
		t.Fatalf("New(daemon): %v", err)
	}

	// The API reads once first, which is what populated (and froze) its slice.
	if got := len(api.Decisions(50)); got != 0 {
		t.Fatalf("setup: Decisions() = %d entries, want 0", got)
	}

	if err := daemon.AddDecision(Decision{MessageID: "1", Subject: "written by the daemon", Label: "Primary"}); err != nil {
		t.Fatalf("AddDecision: %v", err)
	}

	got := api.Decisions(50)
	if len(got) != 1 {
		t.Fatalf("Decisions() = %d entries, want 1 — the API is serving a stale in-memory snapshot", len(got))
	}
	if got[0].Subject != "written by the daemon" {
		t.Fatalf("Decisions()[0].Subject = %q, want the daemon's entry", got[0].Subject)
	}
}

func TestAICreditsExhaustedSeesAnotherProcessesWrite(t *testing.T) {
	// Same invariant: the flag is raised by the daemon (which is what talks to
	// the model) and read by the API to surface it in the UI.
	dir := t.TempDir()
	api, err := New(dir)
	if err != nil {
		t.Fatalf("New(api): %v", err)
	}
	daemon, err := New(dir)
	if err != nil {
		t.Fatalf("New(daemon): %v", err)
	}
	if exhausted, _ := api.AICreditsExhausted(); exhausted {
		t.Fatal("setup: flag already set")
	}
	if _, err := daemon.SetAICreditsExhausted(time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("SetAICreditsExhausted: %v", err)
	}
	if exhausted, _ := api.AICreditsExhausted(); !exhausted {
		t.Fatal("AICreditsExhausted() did not see the daemon's write")
	}
}

// TestDecisionsReturnsNewestFirst pins the ordering contract that survived the
// switch away from sorting the whole history on every read.
func TestDecisionsReturnsNewestFirst(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, id := range []string{"oldest", "middle", "newest"} {
		if err := s.AddDecision(Decision{
			MessageID: id,
			AtUTC:     base.Add(time.Duration(i) * time.Hour).Format(time.RFC3339),
		}); err != nil {
			t.Fatalf("AddDecision(%s): %v", id, err)
		}
	}

	all := s.Decisions(0)
	if len(all) != 3 {
		t.Fatalf("Decisions(0) = %d, want 3", len(all))
	}
	for i, want := range []string{"newest", "middle", "oldest"} {
		if all[i].MessageID != want {
			t.Fatalf("Decisions(0)[%d] = %q, want %q", i, all[i].MessageID, want)
		}
	}

	limited := s.Decisions(2)
	if len(limited) != 2 || limited[0].MessageID != "newest" || limited[1].MessageID != "middle" {
		t.Fatalf("Decisions(2) = %+v, want the two newest, newest first", limited)
	}
}

// TestConcurrentMarkProcessedLosesNothing is the property the JSON store could
// not provide. There, every writer read the whole file, mutated in memory and
// wrote the whole file back; an advisory file lock narrowed the window but the
// two processes still each held a full in-memory copy. Here the write touches
// one row inside a transaction, so interleaving is the storage engine's
// problem, not ours.
//
// Two Stores over one directory is the two-process situation.
func TestConcurrentMarkProcessedLosesNothing(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	defer a.Close()
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New(b): %v", err)
	}
	defer b.Close()

	const perWriter = 50
	var wg sync.WaitGroup
	for i, s := range []*Store{a, b} {
		wg.Add(1)
		go func(prefix int, store *Store) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if err := store.MarkProcessed(fmt.Sprintf("w%d-m%d", prefix, j)); err != nil {
					t.Errorf("MarkProcessed: %v", err)
					return
				}
			}
		}(i, s)
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		for j := 0; j < perWriter; j++ {
			id := fmt.Sprintf("w%d-m%d", i, j)
			if !a.Seen(id) {
				t.Fatalf("%s was lost — a concurrent writer overwrote it", id)
			}
		}
	}
}

// TestConcurrentAddDecisionLosesNothing is the same property for the append-only
// audit log, which the daemon writes on every classification while the api
// reads it.
func TestConcurrentAddDecisionLosesNothing(t *testing.T) {
	dir := t.TempDir()
	daemon, err := New(dir)
	if err != nil {
		t.Fatalf("New(daemon): %v", err)
	}
	defer daemon.Close()
	api, err := New(dir)
	if err != nil {
		t.Fatalf("New(api): %v", err)
	}
	defer api.Close()

	const perWriter = 40
	var wg sync.WaitGroup
	for i, s := range []*Store{daemon, api} {
		wg.Add(1)
		go func(prefix int, store *Store) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if err := store.AddDecision(Decision{MessageID: fmt.Sprintf("w%d-m%d", prefix, j)}); err != nil {
					t.Errorf("AddDecision: %v", err)
					return
				}
			}
		}(i, s)
	}
	wg.Wait()

	if got := len(api.Decisions(0)); got != 2*perWriter {
		t.Fatalf("Decisions() = %d, want %d — concurrent appends were lost", got, 2*perWriter)
	}
}

// TestConcurrentPairingCodeConsumedOnce pins single-use redemption against a
// race. Validate-then-delete as two statements would let both callers win.
func TestConcurrentPairingCodeConsumedOnce(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New(a): %v", err)
	}
	defer a.Close()
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New(b): %v", err)
	}
	defer b.Close()

	if err := a.SetDesktopPairingCode("SHARED", time.Hour); err != nil {
		t.Fatalf("SetDesktopPairingCode: %v", err)
	}

	var wins int32
	var wg sync.WaitGroup
	for _, s := range []*Store{a, b} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			ok, err := store.ConsumeDesktopPairingCode("SHARED")
			if err != nil {
				t.Errorf("ConsumeDesktopPairingCode: %v", err)
				return
			}
			if ok {
				atomic.AddInt32(&wins, 1)
			}
		}(s)
	}
	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d callers consumed the same pairing code; it must be redeemable exactly once", wins)
	}
}
