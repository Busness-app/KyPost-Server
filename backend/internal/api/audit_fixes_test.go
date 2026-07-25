package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// Finding 1: a paired device must stop authenticating once its owning account
// is deactivated — deactivation is an offboarding/revocation action and the
// device path must honor it just as the session path does.
func TestDeviceAuthRejectedAfterDeactivation(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "revoke-device")

	// Sanity: the device works while the account is active.
	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); !ok {
		t.Fatal("device should authenticate while the account is active")
	}

	if _, err := srv.users.Deactivate(userID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); ok {
		t.Fatal("device must NOT authenticate after the account is deactivated")
	}

	// And an end-to-end withMailAuth-style route must reject it too.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/sync", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d for a deactivated account's device", rec.Code, http.StatusUnauthorized)
	}
}

func deviceRequest(deviceID, deviceSecret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/sync", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	return req
}

// Finding 8: a device id already owned by a DIFFERENT user must be reported as
// a conflict, so registration cannot hijack the global device-index entry for
// a victim's device id (targeted DoS).
func TestForeignDeviceIDIsAConflict(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	victimID := all[0].ID
	victimDeviceID, _ := pairNativeDevice(t, srv, victimID, "victim-device")

	attacker, err := srv.users.Create("attacker", "attacker-pass-123", users.RoleUser)
	if err != nil {
		t.Fatalf("create attacker: %v", err)
	}

	// Test 1: attacker trying to reserve victim's device should fail (conflict).
	if srv.reserveDeviceID(attacker.ID, victimDeviceID) {
		t.Fatal("attacker should fail to reserve a device id owned by the victim")
	}
	// Test 2: victim re-registering their own device should succeed (no conflict).
	if !srv.reserveDeviceID(victimID, victimDeviceID) {
		t.Fatal("the victim should succeed to reserve their own device id")
	}
	// Test 3: attacker trying to reserve an unused device should succeed.
	if !srv.reserveDeviceID(attacker.ID, "brand-new-device-id") {
		t.Fatal("an unused device id should be reserved successfully")
	}
}

// Finding 2: a user flagged MustChangePassword must not be able to use any
// authenticated endpoint except the password-change (and logout) path — the
// flag must be enforced server-side, not merely surfaced to the client.
func TestMustChangePasswordBlocksOtherEndpoints(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("mcp-user", "initial-pass-123", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Create() sets MustChangePassword=true; inject a session directly (not via
	// authRequestAs, which intentionally clears the flag for onboarded tests).
	token := "mcp-session"
	csrf := "mcp-csrf"
	srv.mu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrf}
	srv.mu.Unlock()

	// A normal authenticated endpoint must be refused.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /api/status while MustChangePassword: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// The password-change endpoint must remain reachable so the user can escape.
	body := []byte(`{"oldPassword":"initial-pass-123","newPassword":"a-brand-new-pass-456"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	srv.routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("POST /api/auth/password while MustChangePassword must NOT be blocked; got %d body=%s", rec.Code, rec.Body.String())
	}
}

// Finding 4: second-factor verification must be throttled per account across
// reissued challenges, not only per ephemeral challenge.
func TestMFALockoutIsPerAccountAcrossChallenges(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-abc"
	for i := 0; i < mfaMaxFailures; i++ {
		if ok, _ := srv.mfaLockout.allowed(userID); !ok {
			t.Fatalf("attempt %d: should be allowed before the cap", i+1)
		}
		srv.mfaLockout.recordFailure(userID)
	}
	if ok, _ := srv.mfaLockout.allowed(userID); ok {
		t.Fatal("second-factor attempts must be locked out for the account after the cap, regardless of new challenges")
	}
}
