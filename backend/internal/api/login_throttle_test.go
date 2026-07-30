package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/captcha"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// TestCaptchaDefaultsToSelfHostedProofOfWork pins the new default.
//
// Login is unauthenticated and runs scrypt on every attempt by design (see
// equalizeLoginTiming), so an ungated default made the out-of-the-box
// deployment an unauthenticated CPU amplifier. Proof-of-work is the only
// provider that can be on by default: self-hosted, no account with anyone, no
// site key, no secret key, and nothing added to the CSP.
func TestCaptchaDefaultsToSelfHostedProofOfWork(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want captcha.Provider
	}{
		{"unset defaults to pow", "", captcha.ProviderPoW},
		{"whitespace defaults to pow", "   ", captcha.ProviderPoW},
		{"explicit none disables", "none", captcha.ProviderNone},
		{"explicit none is case-insensitive", "NONE", captcha.ProviderNone},
		{"explicit pow stays pow", "pow", captcha.ProviderPoW},
		{"turnstile is honored", "turnstile", captcha.ProviderTurnstile},
		{"friendly is honored", "friendly", captcha.ProviderFriendly},
		// An unrecognized value must NOT silently become "off": NewVerifier
		// rejects it and handleLogin then fails closed.
		{"garbage is passed through to fail closed", "hunter2", captcha.Provider("hunter2")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveCaptchaProvider(c.env); got != c.want {
				t.Errorf("resolveCaptchaProvider(%q) = %q, want %q", c.env, got, c.want)
			}
		})
	}
}

// newTestServerDefaultCaptcha builds a server WITHOUT the shared helper's
// CAPTCHA_PROVIDER=none, so the shipped default is what is under test.
func newTestServerDefaultCaptcha(t *testing.T) *Server {
	t.Helper()
	t.Setenv("CAPTCHA_PROVIDER", "")

	logDir := t.TempDir()
	stateDir := t.TempDir()
	configDir := t.TempDir()
	// Keep the generated PoW HMAC key inside the test's own tempdir.
	t.Setenv("SECRET_DIR", t.TempDir())

	logger, err := logging.New(logDir)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	usersStore, err := users.LoadOrMigrate(configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("users.LoadOrMigrate: %v", err)
	}
	wkdStore, err := wkdpublish.New(stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}
	return NewServer(config.Default(), logger, health.NewService(), usersStore, nil, wkdStore)
}

// TestLoginRequiresProofOfWorkByDefault is the end-to-end half: a correct
// password with no CAPTCHA solution must be refused on a default install.
func TestLoginRequiresProofOfWorkByDefault(t *testing.T) {
	srv := newTestServerDefaultCaptcha(t)
	if srv.captchaProvider != captcha.ProviderPoW {
		t.Fatalf("captchaProvider = %q, want pow", srv.captchaProvider)
	}
	if srv.captchaVerifier == nil {
		t.Fatal("captchaVerifier is nil on a default install: login would run unthrottled")
	}

	u, err := srv.users.Create("pow-subject", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"username": u.Username, "password": "correct-horse-battery-staple"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.5:1234"
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("login succeeded with the correct password but no proof-of-work solution; " +
			"the default CAPTCHA is not being enforced")
	}
	// And the public config endpoint must advertise it, or the frontend renders
	// no widget and nobody can ever log in.
	cfgRec := httptest.NewRecorder()
	srv.handleCaptchaConfig(cfgRec, httptest.NewRequest(http.MethodGet, "/api/auth/captcha-config", nil))
	var cfg struct{ Provider string }
	if err := json.Unmarshal(cfgRec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode captcha-config: %v", err)
	}
	if cfg.Provider != "pow" {
		t.Errorf("captcha-config advertises provider %q, want pow — the login form would render "+
			"no widget while the server requires a solution", cfg.Provider)
	}
}

// TestLoginRateLimitIsInstanceWide is the regression test for the amplifier.
//
// loginLockout is keyed on username+IP, and the username comes out of the
// request body — so a caller who never repeats a username never trips it, while
// every attempt pays scrypt (equalizeLoginTiming, to keep timing from revealing
// whether an account exists). The throttle has to be instance-wide, because a
// per-IP one is defeated by more IPs and the resource being spent (CPU) is
// shared.
func TestLoginRateLimitIsInstanceWide(t *testing.T) {
	withProductionHashCost(t)
	srv := newTestServer(t)

	// Distinct usernames AND distinct source IPs: neither the per-account nor
	// the per-IP lockout can catch this pattern.
	got429 := false
	for i := range loginRateBurst + 40 {
		body, _ := json.Marshal(map[string]string{
			"username": "nobody-" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			"password": "wrong-password-entirely",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = "198.51.100." + string(rune('0'+i%10)) + ":2000"
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429 = true
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 without a Retry-After header")
			}
			break
		}
	}
	if !got429 {
		t.Errorf("made %d login attempts with rotating usernames and IPs without being throttled; "+
			"each one runs scrypt, so this is unbounded unauthenticated CPU", loginRateBurst+40)
	}
}

// TestLoginIPLockoutCatchesRotatingUsernames covers the second new control: one
// address cycling through usernames must eventually be cut off even if it stays
// under the instance-wide rate.
func TestLoginIPLockoutCatchesRotatingUsernames(t *testing.T) {
	srv := newTestServer(t)
	// Take the instance-wide bucket out of the picture so this test is about the
	// per-IP lockout specifically.
	srv.loginRateLimiter = nil
	// And shrink the threshold, in the same spirit and for a blunter reason.
	// Every attempt below runs a full scrypt derivation on purpose -- see
	// equalizeLoginTiming, which makes an unknown username cost what a wrong
	// password costs -- so at the production loginIPMaxFailures of 50 this test
	// paid 55 of them: 84s under -race, the most expensive test in the package.
	// What is under test is that the per-IP counter accumulates across
	// *different* usernames and eventually stops the address, and that a
	// different address is untouched. Neither depends on the threshold's value;
	// 50 is a tuning decision, not behaviour, and asserting it here bought
	// nothing but wall-clock.
	const maxFailures = 4
	srv.loginIPLockout = newFailureLockout(maxFailures, loginIPLockoutFor)

	const ip = "198.51.100.77"
	locked := false
	for i := range maxFailures + 5 {
		body, _ := json.Marshal(map[string]string{
			"username": "victim-" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			"password": "wrong-password-entirely",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = ip + ":3000"
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			locked = true
			break
		}
	}
	if !locked {
		t.Errorf("one address made %d failed attempts against %d different usernames without "+
			"being locked out", maxFailures+5, maxFailures+5)
	}

	// A different address must be unaffected — this must not become a way to
	// lock the whole instance out.
	body, _ := json.Marshal(map[string]string{"username": "someone", "password": "wrong-password-entirely"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.200:3000"
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("an unrelated address was locked out by another address's failures")
	}
}

// TestSuccessfulLoginClearsTheIPBudget makes sure the per-IP lockout does not
// accumulate against a legitimate shared egress (a NAT, an office) that
// occasionally mistypes.
func TestSuccessfulLoginClearsTheIPBudget(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("ip-budget-user", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const ip = "198.51.100.90"
	login := func(password string) int {
		body, _ := json.Marshal(map[string]string{"username": u.Username, "password": password})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.RemoteAddr = ip + ":4000"
		rec := httptest.NewRecorder()
		srv.handleLogin(rec, req)
		return rec.Code
	}

	// A couple of typos, then the real password.
	login("wrong-password-entirely")
	login("wrong-password-entirely")
	if code := login("correct-horse-battery-staple"); code != http.StatusOK {
		t.Fatalf("login with the correct password returned %d, want 200", code)
	}

	srv.loginIPLockout.mu.Lock()
	_, stillTracked := srv.loginIPLockout.entries[ip]
	srv.loginIPLockout.mu.Unlock()
	if stillTracked {
		t.Error("the address still carries failure state after a successful login; a shared " +
			"egress would accumulate its way to a lockout")
	}
}
