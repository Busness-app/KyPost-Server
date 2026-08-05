package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
		e.recordFailure("1.2.3.4", "victim", now)
		if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != want {
			t.Errorf("after %d failures: maxNumberFor() = %d, want %d", i+1, got, want)
		}
	}
}

func TestPoWEscalationIsCapped(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	for i := 0; i < 30; i++ {
		e.recordFailure("1.2.3.4", "victim", now)
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
	e.recordFailure("1.2.3.4", "victim", now)
	e.recordFailure("1.2.3.4", "victim", now)
	if got := e.maxNumberFor("5.6.7.8", 5_000, now); got != 5_000 {
		t.Fatalf("an unrelated IP got %d, want the base — one attacker must not slow down everyone", got)
	}
}

func TestPoWEscalationDecays(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", "victim", now)
	e.recordFailure("1.2.3.4", "victim", now)
	later := now.Add(powEscalationDecay + time.Minute)
	if got := e.maxNumberFor("1.2.3.4", 5_000, later); got != 5_000 {
		t.Fatalf("maxNumberFor() after the decay window = %d, want the base — a shared NAT address must recover", got)
	}
}

func TestPoWEscalationClearedOnSuccess(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", "victim", now)
	e.clearAccount("1.2.3.4", "victim")
	if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != 5_000 {
		t.Fatalf("maxNumberFor() after a successful login = %d, want the base", got)
	}
}

func TestPoWEscalationSweepDropsDecayedEntries(t *testing.T) {
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", "victim", now)
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
		e.recordFailure(ip, "victim", now)
	}
	if got := e.entryCount(); got != 4 {
		t.Fatalf("entryCount() = %d, want 4", got)
	}

	// All four have now decayed, and the fifth insertion crosses the (lowered)
	// threshold, so it must sweep before adding its own entry.
	e.recordFailure("5.5.5.5", "victim", now.Add(powEscalationDecay+time.Minute))

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
	srv.powDifficulty.recordFailure("1.2.3.4", "victim", time.Now().Add(-powEscalationDecay-time.Minute))
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

func TestPoWEscalationSuccessForgivesOnlyThatAccount(t *testing.T) {
	// The bug this pins: clear() dropped the whole IP entry, so ANY valid
	// credential reset the difficulty for the address. An attacker holding one
	// ordinary account on the instance could spray guesses at another
	// username, log in as themselves once to reset the price, and repeat — the
	// escalation control cost them one extra request per burst.
	e := newPowEscalation()
	now := time.Now()

	for i := 0; i < 3; i++ {
		e.recordFailure("1.2.3.4", "victim", now)
	}
	escalated := e.maxNumberFor("1.2.3.4", 5_000, now)
	if escalated <= 5_000 {
		t.Fatalf("setup: maxNumberFor() = %d, want escalated above the 5000 base", escalated)
	}

	// The attacker logs in successfully as their own account from the same
	// address. The victim's failures must survive it.
	e.clearAccount("1.2.3.4", "attacker")

	if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != escalated {
		t.Fatalf("maxNumberFor() after an unrelated account succeeded = %d, want %d — "+
			"one credential must not reprice guesses made against a different account", got, escalated)
	}
}

func TestPoWEscalationSuccessForgivesTheAccountThatSucceeded(t *testing.T) {
	// The other half: an honest user who mistyped their own password several
	// times and then got it right must go straight back to the base price.
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", "victim", now)
	e.recordFailure("1.2.3.4", "victim", now)
	e.clearAccount("1.2.3.4", "victim")
	if got := e.maxNumberFor("1.2.3.4", 5_000, now); got != 5_000 {
		t.Fatalf("maxNumberFor() after that account's own successful login = %d, want the base", got)
	}
}

func TestPoWEscalationSumsAcrossAccounts(t *testing.T) {
	// Difficulty must still behave like a flat per-IP counter for the honest
	// case: splitting the tally by account is bookkeeping for clearAccount, not
	// a discount for spraying many usernames from one address.
	e := newPowEscalation()
	now := time.Now()
	e.recordFailure("1.2.3.4", "alice", now)
	e.recordFailure("1.2.3.4", "bob", now)
	e.recordFailure("1.2.3.4", "carol", now)

	flat := newPowEscalation()
	for i := 0; i < 3; i++ {
		flat.recordFailure("5.6.7.8", "alice", now)
	}

	if got, want := e.maxNumberFor("1.2.3.4", 5_000, now), flat.maxNumberFor("5.6.7.8", 5_000, now); got != want {
		t.Fatalf("three failures across three accounts priced at %d, three against one at %d — they must match", got, want)
	}
}

// TestPowEscalationBoundsAccountsPerAddress pins the bound the outer map has
// and the inner one does not.
//
// sweepThreshold guards p.entries, and the check sits inside the !exists branch
// so it only ever runs when a NEW ip arrives. e.byAccount is keyed on a
// caller-supplied username with no cap of its own, so one address rotating
// usernames grows a single entry without limit.
func TestPowEscalationBoundsAccountsPerAddress(t *testing.T) {
	p := newPowEscalation()
	now := time.Now()

	for i := 0; i < maxPowEscalationAccountsPerIP*3; i++ {
		p.recordFailure("198.51.100.7", fmt.Sprintf("victim-%d", i), now)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.entries["198.51.100.7"]
	if e == nil {
		t.Fatal("no entry recorded")
	}
	if len(e.byAccount) > maxPowEscalationAccountsPerIP {
		t.Fatalf("byAccount holds %d accounts for one address, cap is %d",
			len(e.byAccount), maxPowEscalationAccountsPerIP)
	}
}

// TestPowEscalationEntryExpiresDespiteContinuedFailures pins the other half: an
// entry whose expiry is pushed forward on every failure never ages out while an
// attacker keeps working, so the sweep can never reclaim it.
func TestPowEscalationEntryExpiresDespiteContinuedFailures(t *testing.T) {
	p := newPowEscalation()
	start := time.Now()

	p.recordFailure("198.51.100.8", "victim", start)
	// Keep failing, well past the decay window.
	for i := 1; i <= 20; i++ {
		p.recordFailure("198.51.100.8", "victim", start.Add(time.Duration(i)*powEscalationDecay))
	}

	p.sweepExpired(start.Add(25 * powEscalationDecay))

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.entries["198.51.100.8"]; ok {
		t.Fatal("entry survived a sweep 25 decay windows after it was created, " +
			"because every failure pushed its expiry forward")
	}
}
