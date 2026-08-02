package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
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
