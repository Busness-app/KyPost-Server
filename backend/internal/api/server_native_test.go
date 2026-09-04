package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/health"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busness-app/kypost-server/backend/internal/sso"
	"github.com/Busness-app/kypost-server/backend/internal/state"
	"github.com/Busness-app/kypost-server/backend/internal/users"
	"github.com/Busness-app/kypost-server/backend/internal/wkdpublish"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()

	// CAPTCHA off for the shared helper. Proof-of-work is now the DEFAULT
	// provider (see resolveCaptchaProvider), so without this every one of the
	// hundred-odd tests that logs in would have to solve one — testing the PoW
	// implementation over and over instead of the thing it is actually about.
	//
	// The default itself is covered deliberately, in
	// TestCaptchaDefaultsToSelfHostedProofOfWork and
	// TestLoginRequiresProofOfWorkByDefault, which build servers without this.
	t.Setenv("CAPTCHA_PROVIDER", "none")

	logDir := t.TempDir()
	stateDir := t.TempDir()

	logger, err := logging.New(logDir)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() {
		_ = logger.Close()
	})

	configDir := t.TempDir()
	usersStore, err := users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("users.LoadOrMigrate: %v", err)
	}

	// NewServer takes the WKD publish store as a constructor argument (it's
	// shared with the poller process rather than lazily opened per-process —
	// see wkdpublish.Store's doc comment), so it must be built against
	// stateDir up front rather than reassigned after the fact like
	// pickupStore/globalStore below.
	wkdStore, err := wkdpublish.New(stateDir)
	if err != nil {
		t.Fatalf("wkdpublish.New: %v", err)
	}

	srv := NewServer(config.Default(), logger, health.NewService(), usersStore, nil, wkdStore)
	srv.pairingSecret = "test-pairing-secret"
	srv.stateDir = stateDir
	srv.configDir = configDir
	srv.ssoStore = sso.NewStore(configDir)
	srv.totpSecretKeyPath = filepath.Join(configDir, "totp-secret.key")
	srv.pgpPrivateKeyPath = filepath.Join(configDir, "pgp-private-key.key")
	// NewServer wires pickupStore to the process-default /kypost/...
	// paths at construction time, before stateDir above gets overridden, so
	// it must be rebuilt here against the temp dirs or pickup tests would
	// try to write outside the sandbox.
	srv.pickupStore = pgpmail.NewPickupStore(filepath.Join(stateDir, "pickup"), filepath.Join(configDir, "pickup-store.key"))
	// NewServer likewise wires globalStore to the process-default /kypost/...
	// path at construction time, before stateDir above gets overridden — rebuild
	// it against the temp dir so ollama-update-notification tests don't depend
	// on (and fail to write to) the real /kypost/state path.
	globalStore, err := state.New(stateDir)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	srv.globalStore = globalStore
	return srv
}

// testUserStore returns the bootstrap user's per-user state store.
func testUserStore(t *testing.T, s *Server) *state.Store {
	t.Helper()
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	store, err := s.userStore(all[0].ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	return store
}

func authRequest(s *Server, req *http.Request) {
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		panic("authRequest: no test user available")
	}
	token := "session-token"
	csrfToken := "csrf-token"
	s.sessMu.Lock()
	s.sessions[token] = Session{UserID: all[0].ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrfToken}
	s.sessMu.Unlock()
	// Model an onboarded session; the must-change gate (withAuth) has its own
	// dedicated test.
	_, _ = s.users.ClearMustChangePassword(all[0].ID)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", csrfToken)
}

// pairNativeDevice registers a native device for userID directly in that
// user's state store (bypassing the HTTP register handler for test speed),
// hashing a freshly minted raw secret the same way
// handleNotificationNativeRegister does, and warms deviceIndex so
// lookupUserByDevice resolves it without a rescan. Returns the deviceId/
// deviceSecret pair a simulated device presents via
// X-Kypost-Device-Id/X-Kypost-Device-Secret.
func pairNativeDevice(t *testing.T, srv *Server, userID, deviceID string) (id, secret string) {
	t.Helper()
	// A paired device implies an account past first-run. deviceAuthFromRequest
	// refuses a credential whose owner owes a password change, because an admin
	// password reset is the standard response to a compromise and a device
	// credential must not outlive it. The bootstrap admin these fixtures use
	// carries MustChangePassword from birth, and a confined session cannot reach
	// GET /api/notifications/pairing to pair anything — so a device paired to
	// such an account is a state the product cannot actually produce. Clear it
	// here rather than let every device test assert against an unreachable one.
	clearMustChangePassword(t, srv, userID)
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	raw, err := randomToken(24)
	if err != nil {
		t.Fatalf("randomToken: %v", err)
	}
	hash, err := users.HashPassword(context.Background(), raw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := store.UpsertNativeDevice(state.NativeDevice{
		DeviceID:    deviceID,
		Platform:    "android",
		PushToken:   "tok-" + deviceID,
		UserID:      userID,
		MFAApprover: true,
		SecretHash:  hash,
	}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex[deviceID] = userID
	srv.userMu.Unlock()
	return deviceID, raw
}

func setDeviceHeaders(req *http.Request, deviceID, deviceSecret string) {
	req.Header.Set(headerDeviceID, deviceID)
	req.Header.Set(headerDeviceSecret, deviceSecret)
}

func TestNativeRegisterStoresDevice(t *testing.T) {
	srv := newTestServer(t)
	// The subscriber ID is minted from the owning user's store, exactly as
	// the pairing endpoint does, so the register handler can resolve it
	// back to that user.
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	payload := map[string]any{
		"subscriberId": subscriberID,
		"pairingToken": token,
		"deviceToken":  "native-device-token",
		"deviceId":     "device-a",
		"platform":     "ios",
		"deviceName":   "Alice phone",
		"appVersion":   "1.2.3",
	}
	body, _ := json.Marshal(payload)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", bytes.NewReader(body))
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		DeviceID     string `json:"deviceId"`
		DeviceSecret string `json:"deviceSecret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal register response: %v", err)
	}
	if resp.DeviceSecret == "" {
		t.Fatalf("response deviceSecret is empty, want a minted secret")
	}

	devices := store.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].DeviceID != "device-a" {
		t.Fatalf("device id = %q, want %q", devices[0].DeviceID, "device-a")
	}
	if devices[0].Platform != "ios" {
		t.Fatalf("platform = %q, want %q", devices[0].Platform, "ios")
	}
	if devices[0].DeviceName != "Alice phone" {
		t.Fatalf("deviceName = %q, want %q", devices[0].DeviceName, "Alice phone")
	}
	if devices[0].SecretHash == "" || devices[0].SecretHash == resp.DeviceSecret {
		t.Fatalf("stored SecretHash = %q, want a non-empty hash distinct from the raw secret", devices[0].SecretHash)
	}
	if ok, _ := users.VerifyDeviceSecret(context.Background(), devices[0].SecretHash, resp.DeviceSecret); !ok {
		t.Fatalf("stored SecretHash does not verify against the returned deviceSecret")
	}
}

// TestNativeRegisterRejectsReplayedPairingToken is a regression test: a
// captured pairing token/QR code must be redeemable only once, or an
// attacker who observes one (shoulder-surfing, a screen recording, a leaked
// URL) could register an unbounded number of rogue devices within the
// token's validity window, each with full mail sync and push-MFA-approval
// rights.
func TestNativeRegisterRejectsReplayedPairingToken(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"subscriberId": subscriberID,
		"pairingToken": token,
		"deviceToken":  "native-device-token",
		"deviceId":     "device-first",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", bytes.NewReader(body))
	srv.handleNotificationNativeRegister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first registration: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Replay the exact same token with a different device id — this must be
	// rejected even though the device id itself doesn't collide.
	replayBody, _ := json.Marshal(map[string]any{
		"subscriberId": subscriberID,
		"pairingToken": token,
		"deviceToken":  "native-device-token-2",
		"deviceId":     "device-second",
	})
	replayRec := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", bytes.NewReader(replayBody))
	srv.handleNotificationNativeRegister(replayRec, replayReq)
	if replayRec.Code != http.StatusConflict {
		t.Fatalf("replayed registration: status = %d, want 409; body=%s", replayRec.Code, replayRec.Body.String())
	}

	devices := store.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1 (replay must not have registered a second device)", len(devices))
	}
}

// Platform names pass through unchanged (case/whitespace-normalized) so a
// new client isn't silently mislabeled as android; only a truly empty
// platform (legacy clients that omit the field) defaults to android.
func TestNormalizeNativePlatform(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ios", "ios"},
		{"macos", "macos"},
		{" MacOS ", "macos"},
		{"android", "android"},
		{"linux", "linux"},
		{"", "android"},
		{"windows", "windows"},
		{" Windows ", "windows"},
	}
	for _, c := range cases {
		if got := normalizeNativePlatform(c.in); got != c.want {
			t.Errorf("normalizeNativePlatform(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNativeRegisterRejectsInvalidPairingToken(t *testing.T) {
	srv := newTestServer(t)

	payload := map[string]any{
		"subscriberId": "subscriber-1",
		"pairingToken": "bad-token",
		"deviceToken":  "native-device-token",
	}
	body, _ := json.Marshal(payload)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", bytes.NewReader(body))
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestNativeDevicesListAndDelete(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	if err := store.UpsertNativeDevice(state.NativeDevice{
		DeviceID:   "device-b",
		Platform:   "android",
		PushToken:  "token-b",
		SecretHash: "scrypt$16384$8$1$salt$hash",
	}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	listRec := httptest.NewRecorder()
	listReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/devices", nil)
	authRequest(srv, listReq)
	srv.withAuth(srv.handleNotificationNativeDevices).ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", listRec.Code, http.StatusOK)
	}
	var listResp struct {
		Devices []state.NativeDevice `json:"devices"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(listResp.Devices) != 1 {
		t.Fatalf("GET devices len = %d, want 1", len(listResp.Devices))
	}
	if listResp.Devices[0].SecretHash != "" {
		t.Fatalf("decoded SecretHash = %q, want empty (unmarshaled struct)", listResp.Devices[0].SecretHash)
	}
	var rawListResp struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &rawListResp); err != nil {
		t.Fatalf("unmarshal raw list response: %v", err)
	}
	if _, ok := rawListResp.Devices[0]["secretHash"]; ok {
		t.Fatalf("device list response JSON contains a secretHash key, want it fully absent (redacted)")
	}

	delBody := []byte(`{"deviceId":"device-b"}`)
	delRec := httptest.NewRecorder()
	delReq := httptest.NewRequest(http.MethodDelete, "/api/notifications/native/devices", bytes.NewReader(delBody))
	authRequest(srv, delReq)
	srv.withAuth(srv.handleNotificationNativeDevices).ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want %d", delRec.Code, http.StatusOK)
	}

	devices := store.ListNativeDevices()
	if len(devices) != 0 {
		t.Fatalf("len(devices) = %d, want 0", len(devices))
	}
}

func TestNativeDeliveryModeAndPull(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "pull-device")

	// Switch this user to App Pull mode via the authenticated endpoint.
	modeRec := httptest.NewRecorder()
	modeReq := httptest.NewRequest(http.MethodPut, "/api/notifications/native/mode", bytes.NewReader([]byte(`{"mode":"pull"}`)))
	authRequest(srv, modeReq)
	srv.withAuth(srv.handleNotificationNativeMode).ServeHTTP(modeRec, modeReq)
	if modeRec.Code != http.StatusOK {
		t.Fatalf("mode PUT status = %d, want %d; body=%s", modeRec.Code, http.StatusOK, modeRec.Body.String())
	}
	if got := store.NativeDeliveryMode(); got != state.DeliveryModePull {
		t.Fatalf("delivery mode = %q, want %q", got, state.DeliveryModePull)
	}

	// Queue a notification as the poller/test path would.
	if err := store.EnqueuePullNotification(state.PullNotification{Title: "hi", Body: "new mail"}); err != nil {
		t.Fatalf("EnqueuePullNotification: %v", err)
	}

	// The paired device fetches the queue from cursor 0 using its own
	// device credentials.
	pullRec := httptest.NewRecorder()
	pullReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull?after=0", nil)
	setDeviceHeaders(pullReq, deviceID, deviceSecret)
	srv.handleNotificationNativePull(pullRec, pullReq)
	if pullRec.Code != http.StatusOK {
		t.Fatalf("pull status = %d, want %d; body=%s", pullRec.Code, http.StatusOK, pullRec.Body.String())
	}
	var pull struct {
		DeliveryMode  string                   `json:"deliveryMode"`
		Cursor        int64                    `json:"cursor"`
		Notifications []state.PullNotification `json:"notifications"`
	}
	if err := json.Unmarshal(pullRec.Body.Bytes(), &pull); err != nil {
		t.Fatalf("unmarshal pull response: %v", err)
	}
	if len(pull.Notifications) != 1 || pull.Notifications[0].Title != "hi" {
		t.Fatalf("pull notifications = %+v, want one titled 'hi'", pull.Notifications)
	}
	if pull.Cursor != 1 {
		t.Fatalf("cursor = %d, want 1", pull.Cursor)
	}

	// Polling again from the returned cursor yields nothing new.
	pull2Rec := httptest.NewRecorder()
	pull2Req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull?after=1", nil)
	setDeviceHeaders(pull2Req, deviceID, deviceSecret)
	srv.handleNotificationNativePull(pull2Rec, pull2Req)
	var pull2 struct {
		Notifications []state.PullNotification `json:"notifications"`
	}
	if err := json.Unmarshal(pull2Rec.Body.Bytes(), &pull2); err != nil {
		t.Fatalf("unmarshal pull2 response: %v", err)
	}
	if len(pull2.Notifications) != 0 {
		t.Fatalf("pull2 notifications = %d, want 0", len(pull2.Notifications))
	}

	// A wrong device secret is rejected.
	badRec := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(badReq, deviceID, "wrong-secret")
	srv.handleNotificationNativePull(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-secret status = %d, want %d", badRec.Code, http.StatusUnauthorized)
	}

	// Once the device is removed (unpaired), its still-known credentials no
	// longer work — this is the revocation fix this whole change exists for.
	if _, err := store.RemoveNativeDevice(deviceID); err != nil {
		t.Fatalf("RemoveNativeDevice: %v", err)
	}
	revokedRec := httptest.NewRecorder()
	revokedReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(revokedReq, deviceID, deviceSecret)
	srv.handleNotificationNativePull(revokedRec, revokedReq)
	if revokedRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-removal status = %d, want %d", revokedRec.Code, http.StatusUnauthorized)
	}
}

func TestNativeDeregisterRemovesOnlyItself(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "self-device")
	otherID, otherSecret := pairNativeDevice(t, srv, userID, "other-device")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/deregister", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.handleNotificationNativeDeregister(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deregister status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if _, ok := store.GetNativeDevice(deviceID); ok {
		t.Fatalf("device %q still present after self-deregister", deviceID)
	}
	if _, ok := store.GetNativeDevice(otherID); !ok {
		t.Fatalf("unrelated device %q was removed by another device's deregister call", otherID)
	}

	// The now-removed device's credentials no longer authenticate.
	pullRec := httptest.NewRecorder()
	pullReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(pullReq, deviceID, deviceSecret)
	srv.handleNotificationNativePull(pullRec, pullReq)
	if pullRec.Code != http.StatusUnauthorized {
		t.Fatalf("post-deregister pull status = %d, want %d", pullRec.Code, http.StatusUnauthorized)
	}

	// Garbage credentials are rejected without removing anything.
	garbageRec := httptest.NewRecorder()
	garbageReq := httptest.NewRequest(http.MethodPost, "/api/notifications/native/deregister", nil)
	setDeviceHeaders(garbageReq, otherID, "not-the-secret")
	srv.handleNotificationNativeDeregister(garbageRec, garbageReq)
	if garbageRec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage-credential deregister status = %d, want %d", garbageRec.Code, http.StatusUnauthorized)
	}
	if _, ok := store.GetNativeDevice(otherID); !ok {
		t.Fatalf("device %q was removed by a mismatched-secret deregister attempt", otherID)
	}

	// The unrelated device's real credentials still work untouched.
	otherPullRec := httptest.NewRecorder()
	otherPullReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(otherPullReq, otherID, otherSecret)
	srv.handleNotificationNativePull(otherPullRec, otherPullReq)
	if otherPullRec.Code != http.StatusOK {
		t.Fatalf("unrelated device pull status = %d, want %d; body=%s", otherPullRec.Code, http.StatusOK, otherPullRec.Body.String())
	}
}

// clearMustChangePassword takes an account out of the first-run/post-reset
// confinement, so fixtures can model an ordinary established account.
func clearMustChangePassword(t *testing.T, srv *Server, userID string) {
	t.Helper()
	// Tolerate an unknown user: some fixtures pair a device to a synthetic owner
	// id that was never created, to prove cross-user isolation. There is no flag
	// on an account that does not exist.
	u, err := srv.users.Get(userID)
	if err != nil || !u.MustChangePassword {
		return
	}
	if _, err := srv.users.ClearMustChangePassword(userID); err != nil {
		t.Fatalf("clear MustChangePassword: %v", err)
	}
}
