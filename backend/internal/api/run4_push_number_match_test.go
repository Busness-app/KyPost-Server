package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"kypost-server/backend/internal/users"
)

// pushMFAUser creates a user with TOTP, a paired approver device, and push 2FA
// on — the state in which a number-match challenge is issued.
func pushMFAUser(t *testing.T, srv *Server, name, password, deviceName string) (userID, deviceID, deviceSecret string) {
	t.Helper()
	u, err := srv.users.Create(name, password, users.RoleUser)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret = pairApproverDevice(t, srv, u.ID, deviceName)
	enablePush(t, srv, u.ID)
	return u.ID, deviceID, deviceSecret
}

// run-4 M14 at the HTTP layer. The store-level rules are covered in
// internal/mfa; these pin the parts that only exist here: that the browser is
// told the number, and that the respond endpoint refuses an approval without it.

func TestLoginReturnsMatchDigitsForPushUser(t *testing.T) {
	srv := newTestServer(t)
	pushMFAUser(t, srv, "rowan", "pw-rowan-testpassword", "dev-rowan")

	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "rowan", "password": "pw-rowan-testpassword"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ChallengeID string `json:"challengeId"`
		MatchDigits string `json:"matchDigits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.MatchDigits) != 2 {
		t.Fatalf("matchDigits = %q, want two digits for the browser to display", resp.MatchDigits)
	}

	// And it must be the challenge's real value, or the human is comparing
	// against a number the server will not accept.
	ch, ok := srv.mfaChallenges.Get(resp.ChallengeID)
	if !ok {
		t.Fatal("challenge not found")
	}
	if ch.MatchDigits != resp.MatchDigits {
		t.Fatalf("login showed %q but the challenge holds %q", resp.MatchDigits, ch.MatchDigits)
	}
}

// A TOTP-only user is never sent a push, so there is no number to show and
// nothing should imply otherwise.
func TestLoginOmitsMatchDigitsForTOTPOnlyUser(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("sage", "pw-sage-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}
	enrollTOTP(t, srv, u.ID)

	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "sage", "password": "pw-sage-testpassword"})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := resp["matchDigits"]; present {
		t.Fatalf("a TOTP-only login advertised a match number: %s", rec.Body.String())
	}
}

// The core of M14: valid device credentials are no longer enough to approve.
func TestPushRespondRefusesApprovalWithoutTheNumber(t *testing.T) {
	srv := newTestServer(t)
	_, deviceID, deviceSecret := pushMFAUser(t, srv, "tam", "pw-tam-testpassword", "dev-tam")

	challengeID, _ := loginChallenge(t, srv, "tam", "pw-tam-testpassword")

	rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, true, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "pending" {
		t.Fatal("an approval with no number resolved the challenge")
	}
}

func TestPushRespondRefusesApprovalWithTheWrongNumber(t *testing.T) {
	srv := newTestServer(t)
	_, deviceID, deviceSecret := pushMFAUser(t, srv, "uma", "pw-uma-testpassword", "dev-uma")

	challengeID, _ := loginChallenge(t, srv, "uma", "pw-uma-testpassword")
	ch, ok := srv.mfaChallenges.Get(challengeID)
	if !ok {
		t.Fatal("challenge not found")
	}
	wrong := "00"
	if ch.MatchDigits == wrong {
		wrong = "11"
	}

	rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, true, wrong)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "pending" {
		t.Fatal("a wrong-number approval resolved the challenge")
	}
}

// Denying must never require the number. Someone being MFA-fatigued is looking
// at a challenge they cannot match and needs the safe answer to work.
func TestPushRespondAllowsDenyWithoutTheNumber(t *testing.T) {
	srv := newTestServer(t)
	_, deviceID, deviceSecret := pushMFAUser(t, srv, "vic", "pw-vic-testpassword", "dev-vic")

	challengeID, _ := loginChallenge(t, srv, "vic", "pw-vic-testpassword")

	rec := respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, false, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "denied" {
		t.Fatal("deny without a number did not take effect")
	}
}
