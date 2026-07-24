package processor

import (
	"testing"
	"time"

	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// newTestPollerForWKDRecheck builds a minimal *Poller sufficient to exercise
// recheckWKDDomains: a logger, a stateDir (so userStateDir works), and a real
// users.Store (so p.users.List() resolves) seeded with one active user via
// LoadOrMigrate's fresh-install path, mirroring newTestPollerForHarvest /
// newTestPollerForSendAs in this package.
func newTestPollerForWKDRecheck(t *testing.T) (*Poller, string) {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	usersStore, err := users.LoadOrMigrate(t.TempDir(), "")
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	all, err := usersStore.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected exactly one seeded user, got %d", len(all))
	}
	if !all[0].Active {
		t.Fatalf("seeded user must be Active")
	}

	p := &Poller{
		log:      logger,
		users:    usersStore,
		stateDir: t.TempDir(),
	}
	return p, all[0].ID
}

func TestRecheckSuspendsWhenTXTGone(t *testing.T) {
	p, userID := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.userStateDir(userID))
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

	if store.VerifiedDomains()["example.com"] {
		t.Fatal("claim should be suspended after TXT disappeared")
	}
}

// TestRecheckReVerifiesWhenTXTReappears covers the re-enable half of the
// lifecycle: a suspended claim whose TXT proof is present again on the next
// check must flip back to verified.
func TestRecheckReVerifiesWhenTXTReappears(t *testing.T) {
	p, userID := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.userStateDir(userID))
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

	if !store.VerifiedDomains()["example.com"] {
		t.Fatal("claim should be re-verified once TXT proof reappears")
	}
}

// TestRecheckSkipsRecentlyCheckedClaims covers the interval-skip path: a
// claim checked well within recheckWKDInterval must not be re-queried, even
// if the stubbed lookup would have flipped it.
func TestRecheckSkipsRecentlyCheckedClaims(t *testing.T) {
	p, userID := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.userStateDir(userID))
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
	if !store.VerifiedDomains()["example.com"] {
		t.Fatal("claim should remain verified since it was skipped")
	}
}

// TestRecheckDoesNotSuspendOnLookupError covers the global constraint: a
// transient DNS/lookup error must never flip a verified claim to
// unverified, only a successful lookup that fails to find the token does.
func TestRecheckDoesNotSuspendOnLookupError(t *testing.T) {
	p, userID := newTestPollerForWKDRecheck(t)
	store, err := wkdpublish.New(p.userStateDir(userID))
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
	if !store.VerifiedDomains()["example.com"] {
		t.Fatal("a lookup error must never suspend a verified claim")
	}
}
