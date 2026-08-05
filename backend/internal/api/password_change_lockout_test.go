package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// changePassword posts a password change as u from the given source address.
func changePassword(t *testing.T, srv *Server, u users.User, ip, oldPassword, newPassword string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"oldPassword": oldPassword,
		"newPassword": newPassword,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", strings.NewReader(string(body)))
	req.RemoteAddr = ip + ":40000"
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}))
	rec := httptest.NewRecorder()
	srv.handleChangePassword(rec, req)
	return rec
}

// TestPasswordChangeLockoutBoundsCurrentCredentialGuessing: a session is not
// proof of the password, so a stolen cookie must not buy unlimited guesses at it
// against an endpoint that answers definitively.
func TestPasswordChangeLockoutBoundsCurrentCredentialGuessing(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "victim", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	const thief = "203.0.113.9"
	for i := 0; i < passwordChangeMaxFailures; i++ {
		rec := changePassword(t, srv, u, thief, "wrong-guess", "new-password-attempt")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, rec.Code)
		}
	}

	rec := changePassword(t, srv, u, thief, "wrong-guess", "new-password-attempt")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: got %d, want 429", passwordChangeMaxFailures, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 carries no Retry-After; a client cannot tell how long to wait")
	}
}

// TestPasswordChangeLockoutIsKeyedOnUserAndAddress keeps the control from
// becoming the attack.
//
// Keyed on the user ID alone, a thief holding a stolen cookie burns the whole
// budget from their own machine and locks the real owner out of changing their
// password — during the incident where changing it is the remedy. The login
// lockout is keyed on username+IP for the same reason.
func TestPasswordChangeLockoutIsKeyedOnUserAndAddress(t *testing.T) {
	srv := newTestServer(t)
	const password = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "victim", password, users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// The thief exhausts their own budget.
	const thief = "203.0.113.9"
	for i := 0; i <= passwordChangeMaxFailures; i++ {
		changePassword(t, srv, u, thief, "wrong-guess", "new-password-attempt")
	}
	if rec := changePassword(t, srv, u, thief, "wrong-guess", "x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("thief should be locked out: got %d, want 429", rec.Code)
	}

	// The owner, from their own address, is unaffected and can still change it.
	rec := changePassword(t, srv, u, "198.51.100.4", password, "a-brand-new-password-1234")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("the real owner was locked out by an attacker's failures from a different address")
	}
	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("owner's change with the correct password: got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestPasswordChangeSuccessClearsTheStrikes covers the settle path: a user who
// mistypes their current password a few times and then gets it right must not
// carry those strikes into their next change.
func TestPasswordChangeSuccessClearsTheStrikes(t *testing.T) {
	srv := newTestServer(t)
	const password = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "fumbler", password, users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	const home = "198.51.100.4"
	for i := 0; i < passwordChangeMaxFailures-1; i++ {
		if rec := changePassword(t, srv, u, home, "typo", "whatever-1234"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, rec.Code)
		}
	}

	next := "a-brand-new-password-1234"
	if rec := changePassword(t, srv, u, home, password, next); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("correct password after near-miss failures: got %d (%s)", rec.Code, rec.Body.String())
	}

	// Fresh budget: another full run of failures must still be allowed to start.
	reloaded, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if rec := changePassword(t, srv, reloaded, home, "typo-again", "whatever-5678"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after a success the strikes should be cleared: got %d, want 401", rec.Code)
	}
}

// TestPasswordChangeOnMustChangeStillRequiresTheCurrentCredential is run-8
// finding F4.
//
// The endpoint used to skip verification entirely for a MustChangePassword
// account that offered no old credential, on the reasoning that "a user handed
// a temporary password may have nothing to prove". The test that pinned that
// branch named the consequence in its own comment — "Inverted, this branch
// turns the endpoint into a password reset for anyone holding a cookie" — and
// the reasoning does not hold: every session on such an account was minted by
// handleLogin or by an MFA completion whose challenge follows a successful
// password login, and the shipped SPA always sends the old credential.
//
// So a request carrying only the NEW credential returned 200: the attacker's
// secret authenticated, the temporary password died, MustChangePassword
// cleared, and revokeAllUserCredentialsExcept evicted the owner. Every
// admin-created and admin-reset account was exposed for its whole forced-change
// window. 2f0e9d9 closed the identical hole on the PGP-rewrap half of the same
// request and left this one.
func TestPasswordChangeOnMustChangeStillRequiresTheCurrentCredential(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "newcomer", "temporary-issued-password", users.RoleUser)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// An admin-set temporary password, which is how a real account arrives at
	// MustChangePassword.
	u, err = srv.users.SetPassword(context.Background(), u.ID, "temporary-issued-password", true)
	if err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !u.MustChangePassword {
		t.Fatal("test setup: MustChangePassword was not set")
	}

	const home = "198.51.100.4"
	rec := changePassword(t, srv, u, home, "", "attacker-chosen-password-9876")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password change offering NO current credential returned %d (%s); "+
			"the endpoint is a password reset for anyone holding a cookie",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	// The temporary password must still work, i.e. nothing was written.
	reloaded, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if !reloaded.MustChangePassword {
		t.Fatal("MustChangePassword was cleared by a request that proved nothing")
	}
	if rec := changePassword(t, srv, reloaded, home, "temporary-issued-password", "the-real-new-password-1234"); rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("the genuine first-login change with the temporary password got %d (%s)",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}
