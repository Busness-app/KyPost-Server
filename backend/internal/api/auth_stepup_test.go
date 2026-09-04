package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// The Security page hands out key fingerprints, the paired-device list and a
// backup of the PGP private key, and a session cookie says only that somebody
// signed in here once. These cover the endpoint the page asks before it draws:
// the credential AND the second factor, now.

func stepUpRequest(t *testing.T, srv *Server, userID string, body map[string]string) *http.Response {
	t.Helper()
	rec := doJSONAuth(srv, srv.withAuth(srv.handleAuthStepUp), http.MethodPost, "/api/auth/step-up", body, userID)
	return rec.Result()
}

func TestStepUpNeedsTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "gwen", "pw-gwen-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A session alone proves nothing about who is at the keyboard, which is the
	// entire subject of this endpoint.
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an empty body passed step-up: %d", resp.StatusCode)
	}
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": "not-the-password"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong password passed step-up: %d", resp.StatusCode)
	}
	// No TOTP on this account, so the credential is the whole gate and a missing
	// code must not be held against it.
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": "pw-gwen-testpassword"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner could not step up with their own password: %d", resp.StatusCode)
	}
}

func TestStepUpNeedsTheSecondFactorWhenTOTPIsOn(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "hugo", "pw-hugo-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	secret, _ := enrollTOTP(t, srv, u.ID)
	password := "pw-hugo-testpassword"

	// The password alone is what a shoulder-surfer or a password manager left
	// unlocked already gives up; on an account with TOTP it is half the gate.
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the password alone passed step-up on a TOTP account: %d", resp.StatusCode)
	}
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": "000000"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong code passed step-up: %d", resp.StatusCode)
	}

	code := totpCodeForTest(t, secret, time.Now())
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": code}); resp.StatusCode != http.StatusOK {
		t.Fatalf("the owner could not step up with a valid code: %d", resp.StatusCode)
	}

	// The replay guard is per ACCOUNT, not per endpoint: a code spent here is
	// spent everywhere, or a captured one is worth a second use at the login
	// challenge inside the same window.
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": code}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a replayed code passed step-up: %d", resp.StatusCode)
	}
}

func TestStepUpAcceptsARecoveryCodeAndConsumesIt(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "iris", "pw-iris-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, recoveryCodes := enrollTOTP(t, srv, u.ID)
	password := "pw-iris-testpassword"

	// Without this, losing an authenticator is a lockout rather than an
	// inconvenience: login takes a recovery code, and the page that recovery
	// leads to — the one that turns TOTP off — would not.
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": recoveryCodes[0]}); resp.StatusCode != http.StatusOK {
		t.Fatalf("a recovery code was refused at step-up: %d", resp.StatusCode)
	}
	if resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": recoveryCodes[0]}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a recovery code was reusable at step-up: %d", resp.StatusCode)
	}
	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(after.RecoveryCodesHash) != recoveryCodeCount-1 {
		t.Fatalf("recovery codes remaining = %d, want %d", len(after.RecoveryCodesHash), recoveryCodeCount-1)
	}
}

// TestStepUpSecondFactorIsThrottled is run-7 finding F6.
//
// handleAuthStepUp spends one per-account counter twice, once per factor.
// confirmAccountCredential's recordSuccess DELETES the account's entry, so a
// correct credential reset the counter before confirmSecondFactor spent it — and
// the second factor was therefore never throttled at all, however many attempts
// were made. The comment on that throttle ("six digits do not survive one")
// described a control that was not running.
func TestStepUpSecondFactorIsThrottled(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "ivy", "pw-ivy-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	const password = "pw-ivy-testpassword"

	lastCode := 0
	for i := 0; i < mfaMaxFailures+5; i++ {
		// Correct password, wrong second factor — the shape that reset the counter.
		resp := stepUpRequest(t, srv, u.ID, map[string]string{"password": password, "code": "000000"})
		lastCode = resp.StatusCode
		if resp.StatusCode == http.StatusTooManyRequests {
			return // throttled, as it must be
		}
	}
	t.Fatalf("made %d wrong second-factor attempts at /api/auth/step-up with no 429 (last status %d); "+
		"the per-account throttle is being reset by the credential check that runs before it",
		mfaMaxFailures+5, lastCode)
}

// TestStepUpFailuresDoNotDenyTheOwnersSecondFactor pins the separation between
// two throttles that share one counter.
//
// confirmAccountCredentialNoRecord spends s.mfaLockout — the counter that gates
// completion of the sign-in SECOND FACTOR — on a PASSWORD check, and does not
// cancel it when the password is wrong. mfaLockout is keyed on the bare user ID
// (deliberately: login_lockout.go explains that a password holder can mint
// unlimited fresh challenges, so the TOTP code budget must be account-wide or
// six digits are brute-forceable online).
//
// The consequence is that someone holding only a stolen session — no password,
// no second factor — exhausts the owner's TOTP and recovery-code budget from
// their own machine. The control becomes the attack, which is the exact failure
// passwordChangeLockout's comment says it composes the client IP to avoid.
//
// Note the fix is NOT to compose the IP into mfaLockout: that would reopen the
// online brute-force window it is account-wide to close. The two throttles must
// simply stop sharing one counter.
func TestStepUpFailuresDoNotDenyTheOwnersSecondFactor(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "victim", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A session thief burns the step-up budget with wrong passwords.
	for i := 0; i < mfaMaxFailures+2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/step-up", nil)
		rec := httptest.NewRecorder()
		srv.confirmAccountCredentialNoRecord(rec, req, u.ID, "wrong-password", "")
	}

	// The owner's second factor must still be reachable.
	if allowed, _ := srv.mfaLockout.tryAttempt(u.ID); !allowed {
		t.Fatal("a session thief's wrong-password attempts locked the owner out of " +
			"their own sign-in second factor and recovery codes")
	}
}
