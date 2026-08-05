package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// regenerateFrom posts a recovery-code regeneration as userID from the given
// source address.
func regenerateFrom(t *testing.T, srv *Server, userID, ip, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/recovery-codes/regenerate", bytes.NewReader(body))
	req.RemoteAddr = ip + ":40000"
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: userID, Username: "victim", Role: users.RoleUser}))
	rec := httptest.NewRecorder()
	srv.handleMFARecoveryCodesRegenerate(rec, req)
	return rec
}

// TestMFALockoutIsScopedToTheClientIP is run-8 finding F12.
//
// requirePasswordConfirm and handleMFAConfirm keyed their re-authentication
// throttle on the bare username, while handleLogin and handleChangePassword
// both compose the client IP — the latter's comment states the rule outright.
// On the account alone, a thief holding a stolen cookie burns the budget from
// their own machine and locks the real owner out of /api/mfa/totp/confirm,
// /totp/disable and /recovery-codes/regenerate for fifteen minutes, renewable
// indefinitely, during the incident where those are the remedy. The control
// becomes the attack.
func TestMFALockoutIsScopedToTheClientIP(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "victim", "correct-horse-battery-staple", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const thief = "203.0.113.9"
	const owner = "198.51.100.4"

	// The thief exhausts the budget from their own address.
	for i := 0; i < loginMaxFailures; i++ {
		if rec := regenerateFrom(t, srv, u.ID, thief, "guess"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d hit the lockout early", i+1)
		}
	}
	if rec := regenerateFrom(t, srv, u.ID, thief, "guess"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the thief was not locked out after %d failures: %d", loginMaxFailures, rec.Code)
	}

	// The owner, from their own machine, must still be able to try. 401 for a
	// wrong password is fine; 429 is the failure this test exists for.
	rec := regenerateFrom(t, srv, u.ID, owner, "also-wrong")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("the real owner was locked out of recovery-code regeneration by failures " +
			"an attacker manufactured from a different address")
	}
}
