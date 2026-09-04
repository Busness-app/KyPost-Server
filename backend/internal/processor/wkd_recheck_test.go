package processor

import (
	"net"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/wkdpublish"
)

// verifiedDomains is Store.VerifiedDomains with its read error asserted away.
// The subject of every test in this file is which claims the re-check leaves
// verified, not whether the claims file reads — and that error exists so a
// caller cannot mistake a stale cache for a fresh answer, which includes here.
func verifiedDomains(t *testing.T, s *wkdpublish.Store) map[string]bool {
	t.Helper()
	vd, err := s.VerifiedDomains()
	if err != nil {
		t.Fatalf("VerifiedDomains: %v", err)
	}
	return vd
}

// newTestPollerForWKDRecheck builds a minimal *Poller sufficient to exercise
// recheckWKDDomains: a logger, a stateDir, and a wkdStore rooted at that same
// stateDir (recheckWKDDomains uses p.wkdStore directly rather than opening
// its own Store — see R3/wkdpublish.Store's doc comment), mirroring
// newTestPollerForHarvest / newTestPollerForSendAs in this package.
func newTestPollerForWKDRecheck(t *testing.T) *Poller {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	stateDir := t.TempDir()
	wkdStore, err := wkdpublish.New(stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}

	p := &Poller{
		log:      logger,
		stateDir: stateDir,
		wkdStore: wkdStore,
	}
	return p
}

// TestRecheckSuspendsWhenTXTValueWrong covers one definitive-suspend path: a
// successful DNS lookup that resolves but no longer carries the expected
// token value (e.g. the record was edited to something else).
func TestRecheckSuspendsWhenTXTValueWrong(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Seed as verified but last checked well outside recheckWKDInterval, so
	// the ticker's skip-if-recently-checked guard doesn't short-circuit the
	// lookup this test means to exercise.
	if err := store.SetVerified("example.com", true, time.Now().Add(-recheckWKDInterval-time.Hour)); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	wkdpublish.LookupTXT = func(string) ([]string, error) { return []string{"nothing"}, nil }

	p.recheckWKDDomains()

	if verifiedDomains(t, store)["example.com"] {
		t.Fatal("claim should be suspended when the TXT value no longer matches")
	}
}

// TestRecheckSuspendsWhenTXTRecordDeleted covers R1: the primary revocation
// path is an operator DELETING the TXT record entirely, which net.LookupTXT
// reports as an NXDOMAIN/NODATA *net.DNSError with IsNotFound set — not a
// successful empty answer. This must be treated as a definitive "no proof"
// and suspend the claim, exactly like a wrong value does. Before the R1 fix,
// CheckTXT returned this as a plain lookup error, which recheckWKDDomains's
// transient-error branch swallowed without ever suspending the domain — the
// exact action an operator performs to revoke never worked.
func TestRecheckSuspendsWhenTXTRecordDeleted(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now().Add(-recheckWKDInterval-time.Hour)); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "_kypost-wkd.example.com", IsNotFound: true}
	}

	p.recheckWKDDomains()

	if verifiedDomains(t, store)["example.com"] {
		t.Fatal("claim should be suspended after the TXT record was deleted (NXDOMAIN/NODATA)")
	}
}

// TestRecheckReVerifiesWhenTXTReappears covers the re-enable half of the
// lifecycle: a suspended claim whose TXT proof is present again on the next
// check must flip back to verified.
func TestRecheckReVerifiesWhenTXTReappears(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	claim, err := store.Create("example.com")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Seed as suspended (unverified) but last checked well outside
	// recheckWKDInterval, so this recheck is due.
	if err := store.SetVerified("example.com", false, time.Now().Add(-recheckWKDInterval-time.Hour)); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return []string{"kypost-wkd-verify=" + claim.Token}, nil
	}

	p.recheckWKDDomains()

	if !verifiedDomains(t, store)["example.com"] {
		t.Fatal("claim should be re-verified once TXT proof reappears")
	}
}

// TestRecheckSkipsRecentlyCheckedClaims covers the interval-skip path: a
// claim checked well within recheckWKDInterval must not be re-queried, even
// if the stubbed lookup would have flipped it.
func TestRecheckSkipsRecentlyCheckedClaims(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	called := false
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		called = true
		return []string{"nothing"}, nil
	}

	p.recheckWKDDomains()

	if called {
		t.Fatal("a claim checked moments ago must not be re-queried before recheckWKDInterval elapses")
	}
	if !verifiedDomains(t, store)["example.com"] {
		t.Fatal("claim should remain verified since it was skipped")
	}
}

// TestRecheckDoesNotSuspendOnLookupError covers the global constraint: a
// transient DNS/lookup error (here a plain, non-*net.DNSError failure —
// contrast TestRecheckSuspendsWhenTXTRecordDeleted's *net.DNSError with
// IsNotFound, which IS definitive) must never flip a verified claim to
// unverified.
func TestRecheckDoesNotSuspendOnLookupError(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Seed as verified but due for recheck, so recheckWKDDomains actually
	// reaches the CheckTXT call this test means to fail.
	if err := store.SetVerified("example.com", true, time.Now().Add(-recheckWKDInterval-time.Hour)); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	called := false
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		called = true
		return nil, errFakeRawFetch
	}

	p.recheckWKDDomains()

	if !called {
		t.Fatal("test setup bug: lookup was never attempted")
	}
	if !verifiedDomains(t, store)["example.com"] {
		t.Fatal("a lookup error must never suspend a verified claim")
	}
}

// TestRunRechecksWKDDomainsOnStartup covers R2: Run() must invoke
// recheckWKDDomains once before entering its ticker select loop, since
// time.NewTicker only fires after a full interval (12h) elapses — without an
// eager first call, a host that restarts more often than every
// recheckWKDInterval would never run the revocation check at all.
func TestRunRechecksWKDDomainsOnStartup(t *testing.T) {
	p := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Seeded verified and due for recheck (well outside recheckWKDInterval),
	// so a startup call actually reaches CheckTXT.
	if err := store.SetVerified("example.com", true, time.Now().Add(-recheckWKDInterval-time.Hour)); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	defer func() { wkdpublish.LookupTXT = orig }()
	called := make(chan struct{}, 1)
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		select {
		case called <- struct{}{}:
		default:
		}
		return []string{"nothing"}, nil
	}

	go p.Run()
	defer p.Stop()

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("recheckWKDDomains was not invoked at Run() startup")
	}

	// The lookup returning "nothing" (no matching TXT record) must have
	// suspended the claim, proving the startup call ran recheckWKDDomains
	// end-to-end, not just performed some unrelated DNS lookup.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !verifiedDomains(t, store)["example.com"] {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("claim should be suspended after the startup recheck found no TXT proof")
}
