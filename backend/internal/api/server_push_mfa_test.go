package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/users"
)

// pairApproverDevice registers a native device for userID and returns the
// deviceId/deviceSecret credential pair a simulated device presents to
// handlePushRespond via X-Kypost-Device-Id/X-Kypost-Device-Secret. Thin
// wrapper over pairNativeDevice (which already sets MFAApprover: true).
func pairApproverDevice(t *testing.T, srv *Server, userID, deviceID string) (id, secret string) {
	t.Helper()
	return pairNativeDevice(t, srv, userID, deviceID)
}

func TestPushEnableRequiresTOTP(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("nina", "pw-nina-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// No TOTP enrolled: enabling push must be rejected.
	rec := doJSONAuth(srv, srv.withAuth(srv.handleMFAPushEnabled), http.MethodPut,
		"/api/mfa/push/enabled", map[string]bool{"enabled": true}, u.ID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enable without TOTP: status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestPushEnableRequiresDevice(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("omar", "pw-omar-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	// TOTP enrolled but no paired device: still rejected.
	rec := doJSONAuth(srv, srv.withAuth(srv.handleMFAPushEnabled), http.MethodPut,
		"/api/mfa/push/enabled", map[string]bool{"enabled": true}, u.ID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("enable without device: status=%d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestPushEnableAndStatusAndDeviceToggle(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("pia", "pw-pia-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	pairApproverDevice(t, srv, u.ID, "dev-pia")

	enableRec := doJSONAuth(srv, srv.withAuth(srv.handleMFAPushEnabled), http.MethodPut,
		"/api/mfa/push/enabled", map[string]bool{"enabled": true}, u.ID)
	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable: status=%d body=%s", enableRec.Code, enableRec.Body.String())
	}

	statusRec := doJSONAuth(srv, srv.withAuth(srv.handleMFAStatus), http.MethodGet, "/api/mfa/status", nil, u.ID)
	var status struct {
		TOTPEnabled     bool `json:"totpEnabled"`
		PushMFAEnabled  bool `json:"pushMfaEnabled"`
		ApproverDevices []struct {
			DeviceID string `json:"deviceId"`
			Approver bool   `json:"approver"`
		} `json:"approverDevices"`
	}
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !status.PushMFAEnabled || len(status.ApproverDevices) != 1 || !status.ApproverDevices[0].Approver {
		t.Fatalf("status = %+v", status)
	}

	// Toggle the device's approver flag off via the path-scoped endpoint.
	toggleReq := httptest.NewRequest(http.MethodPut, "/api/notifications/native/devices/dev-pia/mfa",
		bytes.NewReader([]byte(`{"approver":false}`)))
	toggleReq.SetPathValue("deviceId", "dev-pia")
	authRequestAs(srv, toggleReq, u.ID)
	toggleRec := httptest.NewRecorder()
	srv.withAuth(srv.handleNativeDeviceMFA)(toggleRec, toggleReq)
	if toggleRec.Code != http.StatusOK {
		t.Fatalf("toggle: status=%d body=%s", toggleRec.Code, toggleRec.Body.String())
	}
	store, _ := srv.userStore(u.ID)
	if d, _ := store.GetNativeDevice("dev-pia"); d.MFAApprover {
		t.Fatalf("expected approver cleared after toggle")
	}
}

// loginChallenge performs a password login and returns the MFA challenge id and
// offered methods (asserting a challenge was issued and no cookie was set).
func loginChallenge(t *testing.T, srv *Server, username, password string) (challengeID string, methods []string) {
	t.Helper()
	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": username, "password": password})
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("expected no session cookie on MFA login, got %+v", cookies)
	}
	var resp struct {
		MFARequired bool     `json:"mfaRequired"`
		ChallengeID string   `json:"challengeId"`
		Methods     []string `json:"methods"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal login: %v", err)
	}
	if !resp.MFARequired || resp.ChallengeID == "" {
		t.Fatalf("expected mfa challenge, got %s", rec.Body.String())
	}
	return resp.ChallengeID, resp.Methods
}

func methodsContain(methods []string, want string) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

// respondPush approves or denies as the paired device would. run-4 M14 made an
// approval carry the number the browser is displaying, so this reads it off the
// live challenge — the real client reads it off the human reading the screen.
func respondPush(srv *Server, challengeID, deviceID, deviceSecret string, approve bool) *httptest.ResponseRecorder {
	matchDigits := ""
	if ch, ok := srv.mfaChallenges.Get(challengeID); ok {
		matchDigits = ch.MatchDigits
	}
	return respondPushWithDigits(srv, challengeID, deviceID, deviceSecret, approve, matchDigits)
}

func respondPushWithDigits(srv *Server, challengeID, deviceID, deviceSecret string, approve bool, matchDigits string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{
		"challengeId": challengeID,
		"approve":     approve,
		"matchDigits": matchDigits,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/push/respond", bytes.NewReader(body))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.handlePushRespond(rec, req)
	return rec
}

func pollPush(srv *Server, challengeID string) string {
	rec := doJSON(srv, srv.handlePushPoll, http.MethodPost, "/api/auth/mfa/push/poll",
		map[string]string{"challengeId": challengeID})
	var resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.Status
}

func enablePush(t *testing.T, srv *Server, userID string) {
	t.Helper()
	rec := doJSONAuth(srv, srv.withAuth(srv.handleMFAPushEnabled), http.MethodPut,
		"/api/mfa/push/enabled", map[string]bool{"enabled": true}, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable push: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPushLoginApproveFlow(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("quinn", "pw-quinn-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret := pairApproverDevice(t, srv, u.ID, "dev-quinn")
	enablePush(t, srv, u.ID)

	challengeID, methods := loginChallenge(t, srv, "quinn", "pw-quinn-testpassword")
	if !methodsContain(methods, "push") || !methodsContain(methods, "totp") {
		t.Fatalf("methods = %v, want both push and totp", methods)
	}
	if pollPush(srv, challengeID) != "pending" {
		t.Fatalf("expected pending before response")
	}

	if rec := respondPush(srv, challengeID, deviceID, deviceSecret, true); rec.Code != http.StatusOK {
		t.Fatalf("respond approve: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "approved" {
		t.Fatalf("expected approved after response")
	}

	finishRec := doJSON(srv, srv.handlePushFinish, http.MethodPost, "/api/auth/mfa/push/finish",
		map[string]string{"challengeId": challengeID})
	if finishRec.Code != http.StatusOK {
		t.Fatalf("finish: status=%d body=%s", finishRec.Code, finishRec.Body.String())
	}
	cookies := finishRec.Result().Cookies()
	if findCookie(cookies, "kypost_session") == nil {
		t.Fatalf("expected session cookie after finish, got %+v", cookies)
	}
}

func TestPushLoginDenyFlow(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("rex", "pw-rex-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret := pairApproverDevice(t, srv, u.ID, "dev-rex")
	enablePush(t, srv, u.ID)

	challengeID, _ := loginChallenge(t, srv, "rex", "pw-rex-testpassword")
	if rec := respondPush(srv, challengeID, deviceID, deviceSecret, false); rec.Code != http.StatusOK {
		t.Fatalf("respond deny: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "denied" {
		t.Fatalf("expected denied")
	}
	finishRec := doJSON(srv, srv.handlePushFinish, http.MethodPost, "/api/auth/mfa/push/finish",
		map[string]string{"challengeId": challengeID})
	if finishRec.Code != http.StatusConflict {
		t.Fatalf("finish after deny: status=%d, want 409", finishRec.Code)
	}
}

func TestPushRespondCrossUserRejected(t *testing.T) {
	srv := newTestServer(t)
	a, err := srv.users.Create("alice", "pw-alice-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create alice: %v", err)
	}
	b, err := srv.users.Create("bob", "pw-bob-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create bob: %v", err)
	}
	enrollTOTP(t, srv, a.ID)
	pairApproverDevice(t, srv, a.ID, "dev-alice")
	enablePush(t, srv, a.ID)
	// Bob's own device + credential.
	deviceB, secretB := pairApproverDevice(t, srv, b.ID, "dev-bob")

	// Alice logs in; Bob's device tries to approve her challenge.
	challengeID, _ := loginChallenge(t, srv, "alice", "pw-alice-testpassword")
	rec := respondPush(srv, challengeID, deviceB, secretB, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-user respond: status=%d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	// Alice's challenge must remain unresolved.
	if pollPush(srv, challengeID) != "pending" {
		t.Fatalf("cross-user attempt must not resolve the challenge")
	}
}

// TestPushRespondRejectedWithoutPushEnabled covers a user who has TOTP 2FA and
// a paired device (MFAApprover=true, the default for ordinary push
// notifications) but has never opted into push as a second factor. Their
// login challenge must not offer "push", and a response from their own paired
// device must be rejected outright — not merely fail at finish time — proving
// ResolvePush never ran and the challenge stays "pending".
func TestPushRespondRejectedWithoutPushEnabled(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("tara", "pw-tara-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret := pairApproverDevice(t, srv, u.ID, "dev-tara")
	// Deliberately do NOT call enablePush: PushMFAEnabled stays false.

	challengeID, methods := loginChallenge(t, srv, "tara", "pw-tara-testpassword")
	if methodsContain(methods, "push") {
		t.Fatalf("methods = %v, want push absent for a push-disabled user", methods)
	}

	rec := respondPush(srv, challengeID, deviceID, deviceSecret, true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("respond without push enabled: status=%d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if status := pollPush(srv, challengeID); status != "pending" {
		t.Fatalf("challenge status = %q, want still pending (ResolvePush must never have run)", status)
	}
}

// TestLoginKeepsPushingForRepeatAttemptsWithinWindow is the regression test for
// "after one push, MFA push notifications break".
//
// The policy used to be one push per five minutes per account, while every login
// attempt mints a fresh challenge id and fresh MatchDigits. So the second
// attempt inside the window returned a challenge that no device had been pushed,
// still advertised "push" as a usable method, and left the browser polling until
// the TTL expired with nothing on the phone. Retrying a sign-in is normal
// behaviour and must produce a real notification.
func TestLoginKeepsPushingForRepeatAttemptsWithinWindow(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("uma", "pw-uma-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	pairApproverDevice(t, srv, u.ID, "dev-uma")
	enablePush(t, srv, u.ID)

	if _, sent := srv.mfaPushLimiter.sent[u.ID]; sent {
		t.Fatal("expected no push recorded before any login")
	}

	first, methods := loginChallenge(t, srv, "uma", "pw-uma-testpassword")
	if !methodsContain(methods, "push") {
		t.Fatalf("methods = %v, want push offered on first login", methods)
	}

	// The whole point: a second attempt moments later still gets a push of its
	// own, for the challenge it actually handed back.
	second, methods := loginChallenge(t, srv, "uma", "pw-uma-testpassword")
	if second == first {
		t.Fatal("expected a distinct challenge id for the second login")
	}
	if !methodsContain(methods, "push") {
		t.Fatalf("methods = %v, want push offered on the second login too", methods)
	}
	if got := len(srv.mfaPushLimiter.sent[u.ID]); got != 2 {
		t.Fatalf("recorded pushes = %d, want 2 (one per attempt)", got)
	}
}

// TestLoginSupersedesTheUnansweredPushChallenge pins the invariant that makes
// the burst cap safe: at most one challenge per account is ever both pushed and
// answerable. Without this, each attempt left another answerable challenge
// behind, so a stream of logins accumulated live approvable prompts — the
// fatigue surface the cap exists to close.
func TestLoginSupersedesTheUnansweredPushChallenge(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("una", "pw-una-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	pairApproverDevice(t, srv, u.ID, "dev-una")
	enablePush(t, srv, u.ID)

	first, _ := loginChallenge(t, srv, "una", "pw-una-testpassword")
	if status, ok := srv.mfaChallenges.PushStatus(first); !ok || status != mfa.PushPending {
		t.Fatalf("first challenge: status=%q ok=%v, want pending and live", status, ok)
	}

	second, _ := loginChallenge(t, srv, "una", "pw-una-testpassword")

	if _, ok := srv.mfaChallenges.PushStatus(first); ok {
		t.Fatal("the unanswered first challenge must be superseded once a newer one is pushed")
	}
	if status, ok := srv.mfaChallenges.PushStatus(second); !ok || status != mfa.PushPending {
		t.Fatalf("second challenge: status=%q ok=%v, want pending and live", status, ok)
	}
}

// TestLoginStopsOfferingPushWhenThrottled covers the other half of the fix: once
// the burst is spent, login must keep working and must NOT advertise a method
// whose notification was suppressed. Advertising it is what produced a browser
// polling a challenge no device could answer.
func TestLoginStopsOfferingPushWhenThrottled(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("ulf", "pw-ulf-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	pairApproverDevice(t, srv, u.ID, "dev-ulf")
	enablePush(t, srv, u.ID)

	for i := 0; i < mfaPushBurst; i++ {
		if _, methods := loginChallenge(t, srv, "ulf", "pw-ulf-testpassword"); !methodsContain(methods, "push") {
			t.Fatalf("login %d: methods = %v, want push within the burst", i+1, methods)
		}
	}

	rec := doJSON(srv, srv.handleLogin, http.MethodPost, "/api/auth/login",
		map[string]string{"username": "ulf", "password": "pw-ulf-testpassword"})
	if rec.Code != http.StatusOK {
		t.Fatalf("throttled login must still succeed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ChallengeID           string   `json:"challengeId"`
		Methods               []string `json:"methods"`
		MatchDigits           string   `json:"matchDigits"`
		PushRetryAfterSeconds int      `json:"pushRetryAfterSeconds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal login: %v", err)
	}
	if resp.ChallengeID == "" {
		t.Fatal("a throttled push must not block challenge creation: TOTP retry has to keep working")
	}
	if !methodsContain(resp.Methods, "totp") {
		t.Fatalf("methods = %v, want totp still offered when push is throttled", resp.Methods)
	}
	if methodsContain(resp.Methods, "push") {
		t.Fatalf("methods = %v, must not offer push for a challenge that was never pushed", resp.Methods)
	}
	if resp.MatchDigits != "" {
		t.Fatal("matchDigits belongs to a push that did not go out; sending it invites a blind approval")
	}
	if resp.PushRetryAfterSeconds <= 0 {
		t.Fatal("expected pushRetryAfterSeconds so the UI can explain where the push option went")
	}
}

// TestPushFinishRejectsAfterAdminClearsMFA is a regression test: an
// already-approved-but-not-yet-finished push challenge must not still mint
// a session after an admin clears the account's MFA in response to a
// suspected compromise — the entire point of that action is to immediately
// cut off access, including any in-flight authentication attempt.
func TestPushFinishRejectsAfterAdminClearsMFA(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("sam", "pw-sam-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret := pairApproverDevice(t, srv, u.ID, "dev-sam")
	enablePush(t, srv, u.ID)

	challengeID, _ := loginChallenge(t, srv, "sam", "pw-sam-testpassword")
	if rec := respondPush(srv, challengeID, deviceID, deviceSecret, true); rec.Code != http.StatusOK {
		t.Fatalf("respond approve: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if pollPush(srv, challengeID) != "approved" {
		t.Fatalf("expected approved after response")
	}

	// Admin clears MFA in response to the suspicious approval.
	clearReq := httptest.NewRequest(http.MethodPost, "/api/users/"+u.ID+"/clear-mfa", nil)
	clearReq.SetPathValue("id", u.ID)
	clearRec := httptest.NewRecorder()
	srv.handleUsersClearMFA(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear-mfa: status=%d body=%s", clearRec.Code, clearRec.Body.String())
	}

	// The already-approved challenge must no longer be redeemable.
	finishRec := doJSON(srv, srv.handlePushFinish, http.MethodPost, "/api/auth/mfa/push/finish",
		map[string]string{"challengeId": challengeID})
	if finishRec.Code != http.StatusUnauthorized {
		t.Fatalf("finish after clear-mfa: status=%d, want 401, body=%s", finishRec.Code, finishRec.Body.String())
	}
	if cookies := finishRec.Result().Cookies(); findCookie(cookies, "kypost_session") != nil {
		t.Fatalf("expected no session cookie minted after clear-mfa, got %+v", cookies)
	}
}

func TestPushFirstResponseWins(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("sam", "pw-sam-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	enrollTOTP(t, srv, u.ID)
	deviceID, deviceSecret := pairApproverDevice(t, srv, u.ID, "dev-sam")
	enablePush(t, srv, u.ID)

	challengeID, _ := loginChallenge(t, srv, "sam", "pw-sam-testpassword")
	if rec := respondPush(srv, challengeID, deviceID, deviceSecret, true); rec.Code != http.StatusOK {
		t.Fatalf("first respond: status=%d body=%s", rec.Code, rec.Body.String())
	}
	// A second response (even from the same device) is rejected, not overwritten.
	second := respondPush(srv, challengeID, deviceID, deviceSecret, false)
	if second.Code != http.StatusConflict {
		t.Fatalf("second respond: status=%d, want 409 (body=%s)", second.Code, second.Body.String())
	}
	if pollPush(srv, challengeID) != "approved" {
		t.Fatalf("status must remain approved after a rejected second response")
	}
}
