package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kypost-server/backend/internal/captcha"
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
	srv.handlePoWChallenge(rec, httptest.NewRequest(http.MethodGet, "/api/auth/pow-challenge", nil))
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
