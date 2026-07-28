package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/captcha"
)

func TestPoWEscalationStartsCheap(t *testing.T) {
	e := newPowEscalation()
	if got := e.maxNumberFor("1.2.3.4", 5_000, time.Now()); got != 5_000 {
		t.Fatalf("maxNumberFor(clean IP) = %d, want the base 5000 — an honest first login must be nearly free", got)
	}
}

func TestPoWEscalationQuadruplesPerFailure(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	for i, want := range []int{20_000, 80_000, 320_000} {
		e.recordFailure("1.2.3.4", now)
		if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != want {
			t.Errorf("after %d failures: maxNumberFor() = %d, want %d", i+1, got, want)
		}
	}
}

func TestPoWEscalationIsCapped(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	for i := 0; i < 30; i++ {
		e.recordFailure("1.2.3.4", now)
	}
	// Uncapped, this overflows into a challenge nobody can ever solve —
	// which is a denial of service against that IP, not a defence.
	if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != powMaxNumberCeiling {
		t.Fatalf("maxNumberFor() = %d, want the %d ceiling", got, powMaxNumberCeiling)
	}
}

func TestPoWEscalationIsPerIP(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", now)
	e.recordFailure("1.2.3.4", now)
	if got := e.maxNumberFor("5.6.7.8", 5_000, now); got != 5_000 {
		t.Fatalf("an unrelated IP got %d, want the base — one attacker must not slow down everyone", got)
	}
}

func TestPoWEscalationDecays(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", now)
	e.recordFailure("1.2.3.4", now)
	later := now.Add(powEscalationDecay + time.Minute)
	if got := e.maxNumberFor("1.2.3.4", 5_000, later); got != 5_000 {
		t.Fatalf("maxNumberFor() after the decay window = %d, want the base — a shared NAT address must recover", got)
	}
}

func TestPoWEscalationClearedOnSuccess(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", now)
	e.clear("1.2.3.4")
	if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != 5_000 {
		t.Fatalf("maxNumberFor() after a successful login = %d, want the base", got)
	}
}

func TestPoWEscalationSweepDropsDecayedEntries(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", now)
	if got := e.entryCount(); got != 1 {
		t.Fatalf("entryCount() = %d, want 1", got)
	}
	e.sweepExpired(now.Add(powEscalationDecay + time.Minute))
	if got := e.entryCount(); got != 0 {
		t.Fatalf("entryCount() after sweep = %d, want 0", got)
	}
}

func TestPoWEscalationSweepsAtThreshold(t *testing.T) {
	// Any failed login from any address inserts an entry, and nothing about
	// that requires a credential — so an attacker presenting new source
	// addresses grows this map for free. Entries live 15 minutes against a
	// 10-minute ticker, so the ticker alone leaves a wide window; recordFailure
	// must reclaim decayed entries inline once the map crosses sweepThreshold.
	e := newPowEscalation()
	e.sweepThreshold = 4
	now := time.Now()

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		e.recordFailure(ip, now)
	}
	if got := e.entryCount(); got != 4 {
		t.Fatalf("entryCount() = %d, want 4", got)
	}

	// All four have now decayed, and the fifth insertion crosses the (lowered)
	// threshold, so it must sweep before adding its own entry.
	e.recordFailure("5.5.5.5", now.Add(powEscalationDecay+time.Minute))

	if got := e.entryCount(); got != 1 {
		t.Fatalf("entryCount() after the threshold sweep = %d, want 1 (only the new entry)", got)
	}
}

func TestPoWSweeperClearsEscalationWhenPoWIsNotTheProvider(t *testing.T) {
	// Regression tripwire. handleLogin calls powDifficulty.recordFailure on
	// every failed login whatever CAPTCHA_PROVIDER says, but StartPoWSweeper
	// used to return immediately when powVerifier was nil. On a default
	// install — and on every Turnstile/Friendly install — that made this map
	// grow forever from unauthenticated failed logins: remotely triggerable
	// memory growth on installs that never opted into proof-of-work.
	srv := newTestServer(t) // no powVerifier: the default install
	if srv.powVerifier != nil {
		t.Fatal("setup: this test needs pow switched off")
	}

	restore := powSweepInterval
	powSweepInterval = 5 * time.Millisecond
	t.Cleanup(func() { powSweepInterval = restore })

	// Already decayed, so the very first tick should reclaim it.
	srv.powDifficulty.recordFailure("1.2.3.4", time.Now().Add(-powEscalationDecay-time.Minute))
	if got := srv.powDifficulty.entryCount(); got != 1 {
		t.Fatalf("setup: entryCount() = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartPoWSweeper(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.powDifficulty.entryCount() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the escalation map was never swept with pow disabled; it grows without bound on a default install")
}

func TestFailedLoginRaisesTheNextChallengeDifficulty(t *testing.T) {
	srv := newTestServerWithPoW(t)

	first := issueChallenge(t, srv, "9.9.9.9")
	doLoginFrom(t, srv, "9.9.9.9", "admin", "definitely-wrong")
	second := issueChallenge(t, srv, "9.9.9.9")

	if second.MaxNumber <= first.MaxNumber {
		t.Fatalf("maxnumber did not rise after a failed login: %d then %d", first.MaxNumber, second.MaxNumber)
	}
}

// newTestServerWithPoW returns a test server whose challenge endpoint is
// live.
//
// It deliberately leaves captchaVerifier nil, so handleLogin skips the
// captcha gate and reaches the password check these tests are about. Wiring
// the verifier in as well would be more faithful to production and would make
// the tests assert nothing: with no captchaToken in the body, every login
// would 401 at the captcha gate and never record a failure.
//
// That is also the real behaviour worth knowing about — with pow enabled, a
// wrong password only escalates an address if a valid proof-of-work was
// solved first, so nobody can raise a stranger's difficulty for free.
func newTestServerWithPoW(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t)
	v, err := captcha.NewPoWVerifier([]byte("test-hmac-key"), 5_000)
	if err != nil {
		t.Fatalf("NewPoWVerifier: %v", err)
	}
	srv.powVerifier = v
	return srv
}

func issueChallenge(t *testing.T, srv *Server, ip string) captcha.Challenge {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil)
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	srv.handlePoWChallenge(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge request: status %d (%s)", rec.Code, rec.Body.String())
	}
	var ch captcha.Challenge
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	return ch
}

// doLoginFrom posts a login that is expected to fail, from a given IP.
func doLoginFrom(t *testing.T, srv *Server, ip, username, password string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	srv.handleLogin(httptest.NewRecorder(), req)
}
