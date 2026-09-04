package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/captcha"
)

func TestPoWChallengeLimiterAllowsBurstThenRefuses(t *testing.T) {
	l := newPowChallengeLimiter()
	now := time.Now()
	for i := 0; i < powChallengeBurst; i++ {
		if !l.allow("1.2.3.4", now) {
			t.Fatalf("request %d of the burst should be allowed", i+1)
		}
	}
	if l.allow("1.2.3.4", now) {
		t.Fatal("the request after the burst must be refused")
	}
	// A different client is unaffected: the endpoint is unauthenticated, so
	// one noisy IP must not deny service to everyone else.
	if !l.allow("5.6.7.8", now) {
		t.Fatal("a different IP must have its own budget")
	}
	// The window rolls.
	if !l.allow("1.2.3.4", now.Add(powChallengeWindowLen+time.Second)) {
		t.Fatal("the budget must refill after the window")
	}
}

func TestPoWChallengeLimiterSweepDropsStaleWindows(t *testing.T) {
	l := newPowChallengeLimiter()
	now := time.Now()
	l.allow("1.2.3.4", now)
	if got := l.windowCount(); got != 1 {
		t.Fatalf("windowCount() = %d, want 1", got)
	}
	l.sweepExpired(now.Add(powChallengeWindowLen + time.Second))
	if got := l.windowCount(); got != 0 {
		t.Fatalf("windowCount() after sweep = %d, want 0", got)
	}
}

func TestPoWChallengeLimiterSweepsAtThreshold(t *testing.T) {
	// GET /api/auth/pow-challenge is unauthenticated and costs the caller
	// nothing, so an attacker presenting many distinct source IPs can mint
	// one map entry per request. sweepExpired only runs on StartPoWSweeper's
	// 10-minute ticker, so without a second, size-triggered bound the map
	// could grow unbounded between ticks. allow() must reclaim expired
	// windows inline once the map crosses sweepThreshold.
	l := newPowChallengeLimiter()
	l.sweepThreshold = 4
	now := time.Now()

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		l.allow(ip, now)
	}
	if got := l.windowCount(); got != 4 {
		t.Fatalf("windowCount() = %d, want 4", got)
	}

	// All four windows are now stale, and the fifth insertion crosses the
	// (lowered) threshold, so it must trigger an inline sweep before adding
	// its own entry.
	l.allow("5.5.5.5", now.Add(powChallengeWindowLen+time.Second))

	if got := l.windowCount(); got != 1 {
		t.Fatalf("windowCount() after threshold sweep = %d, want 1 (only the new entry)", got)
	}
}

func TestResolvePoWSecretIsStableAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pow.key")
	first := resolvePoWSecret(path, nil)
	second := resolvePoWSecret(path, nil)
	if len(first) == 0 {
		t.Fatal("resolvePoWSecret returned an empty key")
	}
	if string(first) != string(second) {
		t.Fatal("the key must persist: a key that changes per call invalidates every in-flight challenge")
	}
}

func TestResolvePoWSecretPrefersTheEnvironment(t *testing.T) {
	t.Setenv("POW_SECRET", "operator-supplied-key")
	got := resolvePoWSecret(filepath.Join(t.TempDir(), "pow.key"), nil)
	if string(got) != "operator-supplied-key" {
		t.Fatalf("resolvePoWSecret() = %q, want the POW_SECRET value", got)
	}
}

func TestResolvePoWSecretRefusesAWeakEnvKey(t *testing.T) {
	// A short POW_SECRET is recoverable offline from a single issued
	// challenge, and whoever recovers it can mint their own challenge with
	// maxnumber 0 and a far-future expiry — the proof-of-work becomes a
	// silent no-op. Fail closed instead: NewVerifier rejects a nil key, so
	// login answers "captcha misconfigured" until an operator fixes it.
	t.Setenv("POW_SECRET", "changeme")
	if got := resolvePoWSecret(filepath.Join(t.TempDir(), "pow.key"), nil); got != nil {
		t.Fatalf("resolvePoWSecret() = %q, want nil for a %d-byte secret", got, len("changeme"))
	}
}

func TestResolvePoWSecretAcceptsAnEnvKeyAtTheMinimum(t *testing.T) {
	// The boundary is inclusive, so an operator who followed the documented
	// length is not rejected.
	key := "0123456789abcdef" // exactly powSecretMinLen bytes
	t.Setenv("POW_SECRET", key)
	if got := resolvePoWSecret(filepath.Join(t.TempDir(), "pow.key"), nil); string(got) != key {
		t.Fatalf("resolvePoWSecret() = %q, want %q", got, key)
	}
}

func TestResolvePoWSecretFallsBackToAnEphemeralKey(t *testing.T) {
	// A read-only secrets volume must not brick login on an install that
	// opted into pow. Challenges issued before a restart stop verifying,
	// which is a 5-minute annoyance; refusing to authenticate anyone is not.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got := resolvePoWSecret(filepath.Join(blocker, "pow.key"), nil)
	if len(got) != 32 {
		t.Fatalf("len(resolvePoWSecret()) = %d, want a 32-byte ephemeral key", len(got))
	}
}

func TestPoWChallengeEndpointIssuesASignedChallenge(t *testing.T) {
	srv := newTestServer(t)
	v, err := captcha.NewPoWVerifier([]byte("test-key"), 100)
	if err != nil {
		t.Fatalf("NewPoWVerifier: %v", err)
	}
	srv.powVerifier = v

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil)
	req.RemoteAddr = "203.0.113.7:4444"
	srv.handlePoWChallenge(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	// A cached challenge is a replayed challenge.
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var ch captcha.Challenge
	if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if ch.Algorithm != "SHA-256" || ch.Salt == "" || ch.Challenge == "" || ch.Signature == "" {
		t.Fatalf("incomplete challenge: %+v", ch)
	}
	if ch.MaxNumber != 100 {
		t.Errorf("MaxNumber = %d, want 100", ch.MaxNumber)
	}
	// The challenge is bound to the address that asked for it, or an
	// escalated attacker just fetches cheap ones from a clean address.
	if ch.ClientIP != "203.0.113.7" {
		t.Errorf("ClientIP = %q, want the requesting address", ch.ClientIP)
	}
	if ch.Expires <= time.Now().Unix() {
		t.Errorf("Expires = %d, want a future timestamp", ch.Expires)
	}
}

func TestPoWChallengeEndpointIs404WhenPoWIsOff(t *testing.T) {
	srv := newTestServer(t) // no powVerifier: the default install
	rec := httptest.NewRecorder()
	srv.handlePoWChallenge(rec, httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when pow is not the configured provider", rec.Code)
	}
}

func TestPoWChallengeEndpointRateLimitsPerIP(t *testing.T) {
	srv := newTestServer(t)
	v, _ := captcha.NewPoWVerifier([]byte("test-key"), 100)
	srv.powVerifier = v

	// The endpoint is unauthenticated: without a limit it is a free
	// entropy-and-CPU faucet, and it feeds the spent-salt cache.
	var last *httptest.ResponseRecorder
	for i := 0; i < powChallengeBurst+1; i++ {
		last = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil)
		req.RemoteAddr = "9.9.9.9:1234"
		srv.handlePoWChallenge(last, req)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status after the burst = %d, want 429", last.Code)
	}
	if last.Header().Get("Retry-After") == "" {
		t.Error("a 429 should tell the client when to come back")
	}
}

// stubVerifier lets these tests drive handleLogin's captcha branch directly,
// without solving a real challenge.
type stubVerifier struct {
	ok  bool
	err error
}

func (s stubVerifier) Verify(context.Context, string, string) (bool, error) { return s.ok, s.err }

func TestLoginRefundsTheStrikeForAnExpiredChallenge(t *testing.T) {
	srv := newTestServer(t)
	srv.captchaVerifier = stubVerifier{err: captcha.ErrChallengeExpired}

	// Get the bootstrap admin user's actual username
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	adminUsername := all[0].Username

	// A stale tab is a clock, not a credential: three expired tabs must not
	// lock the user out. Loop loginMaxFailures + 1 times to prove the strikes
	// are refunded: if they were not, the final request would lock the account
	// and return 429; if they are refunded, it still returns 401.
	for i := 0; i <= loginMaxFailures; i++ {
		rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": adminUsername, "password": "irrelevant", "captchaToken": "stale"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401 (body %s)", i+1, rec.Code, rec.Body.String())
		}
	}
}

func TestLoginRefundsTheStrikeForAChallengeIssuedToAnotherAddress(t *testing.T) {
	srv := newTestServer(t)
	srv.captchaVerifier = stubVerifier{err: captcha.ErrChallengeWrongClient}

	// Get the bootstrap admin user's actual username
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	adminUsername := all[0].Username

	// A phone handing off between wifi and cellular can do this repeatedly
	// through no fault of its own, so a changed address must never lock an
	// account. Loop loginMaxFailures + 1 times to prove the strikes are
	// refunded: unrefunded, the final request would return 429.
	for i := 0; i <= loginMaxFailures; i++ {
		rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": adminUsername, "password": "irrelevant", "captchaToken": "foreign"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401 (body %s)", i+1, rec.Code, rec.Body.String())
		}
	}
}

func TestLoginSpendsTheStrikeForAWrongSolution(t *testing.T) {
	srv := newTestServer(t)
	srv.captchaVerifier = stubVerifier{ok: false}

	// Get the bootstrap admin user's actual username
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	adminUsername := all[0].Username

	for i := 0; i < loginMaxFailures; i++ {
		rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
			map[string]string{"username": adminUsername, "password": "irrelevant", "captchaToken": "wrong"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}
	// A wrong solution is a failed attempt and costs one, exactly as
	// cancelAttempt's doc comment says.
	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": adminUsername, "password": "irrelevant", "captchaToken": "wrong"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status after %d wrong solutions = %d, want 429", loginMaxFailures, rec.Code)
	}
}

func TestLoginStillReports503WhenAProviderIsDown(t *testing.T) {
	srv := newTestServer(t)
	srv.captchaVerifier = stubVerifier{err: errors.New("siteverify unreachable")}

	// Get the bootstrap admin user's actual username
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	adminUsername := all[0].Username

	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": adminUsername, "password": "irrelevant", "captchaToken": "x"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — the pre-existing outage path must be unchanged", rec.Code)
	}
}
