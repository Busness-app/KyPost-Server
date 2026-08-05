package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
)

// newPairedDeviceForTest builds a server with one client-protected user and one
// device paired to it, and returns a function that stamps that device's
// credentials onto a request.
//
// It composes the package's existing fixtures rather than re-deriving them:
// clientProtectedUser for the account (Task 4 needs the identity, because
// WrappedEnvelopes() returns nothing for an account without one) and
// pairNativeDevice/setDeviceHeaders for the credential.
func newPairedDeviceForTest(t *testing.T) (srv *Server, userID, deviceID string, authDevice func(*http.Request)) {
	t.Helper()
	srv = newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, secret := pairNativeDevice(t, srv, u.ID, "enrollment-device")
	return srv, u.ID, id, func(r *http.Request) { setDeviceHeaders(r, id, secret) }
}

// deviceByID reads one device back out of a user's state store.
func deviceByID(t *testing.T, srv *Server, userID, deviceID string) state.NativeDevice {
	t.Helper()
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	d, ok := store.GetNativeDevice(deviceID)
	if !ok {
		t.Fatalf("device %q not found", deviceID)
	}
	return d
}

func TestPublishEnrollmentKeyStoresItForTheCallingDevice(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"BASE64PUBKEY"}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	d := deviceByID(t, srv, userID, deviceID)
	if d.EnrollmentPublicKey != "BASE64PUBKEY" {
		t.Fatalf("key not stored: %+v", d)
	}
	if d.EnrollmentKeyAt == "" {
		t.Fatal("publish time not stamped")
	}
}

// The device id comes from the verified credential, never from the body. A
// device that could name another device's id would be able to overwrite the key
// a browser is about to seal to — which is the substitution attack the whole
// verification code exists to catch, handed over for free.
func TestPublishEnrollmentKeyIgnoresAnyDeviceIdInTheBody(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)

	// A second device on the same account, so "wrote onto the wrong row" is a
	// state the test can actually reach.
	otherID, _ := pairNativeDevice(t, srv, userID, "other-device")

	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"MINE","deviceId":"other-device"}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}

	if got := deviceByID(t, srv, userID, deviceID).EnrollmentPublicKey; got != "MINE" {
		t.Fatalf("the caller's own key was not stored: %q", got)
	}
	if got := deviceByID(t, srv, userID, otherID).EnrollmentPublicKey; got != "" {
		t.Fatalf("a device id in the body reached the write: device %q got key %q", otherID, got)
	}
}

func TestPublishEnrollmentKeyRejectsUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"X"}`))
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an unauthenticated caller published a key")
	}
}

func TestPublishEnrollmentKeyRejectsEmptyKey(t *testing.T) {
	srv, _, _, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"  "}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestDeviceEnvelopeServesOnlyTheCallersOwnSlot(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)

	if _, err := srv.users.SetPGPWrappedEnvelope(userID, users.EnvelopeSlotDevicePrefix+deviceID, `{"v":2,"mine":1}`, ""); err != nil {
		t.Fatalf("seed own slot: %v", err)
	}
	if _, err := srv.users.SetPGPWrappedEnvelope(userID, users.EnvelopeSlotDevicePrefix+"someone-else", `{"v":2,"theirs":1}`, ""); err != nil {
		t.Fatalf("seed other slot: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `mine`) {
		t.Fatalf("did not serve the caller's own envelope: %s", body)
	}
	// The decisive assertion: another device's sealing must not appear, whatever
	// the caller asks for. There is no slot parameter precisely so this cannot vary.
	if strings.Contains(body, `theirs`) {
		t.Fatalf("served another device's envelope: %s", body)
	}
}

// A slot parameter must not exist. If someone adds one later, this fails.
func TestDeviceEnvelopeIgnoresASlotParameter(t *testing.T) {
	srv, userID, _, authDevice := newPairedDeviceForTest(t)
	if _, err := srv.users.SetPGPWrappedEnvelope(userID, users.EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("seed recovery: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope?slot=recovery", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if strings.Contains(rec.Body.String(), `rec`) {
		t.Fatalf("a query parameter reached the slot lookup: %s", rec.Body.String())
	}
}

func TestDeviceEnvelopeIs404WhenNothingSealedYet(t *testing.T) {
	srv, _, _, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// An expired transport copy reads as absent rather than being served, because
// the handler iterates WrappedEnvelopes(), which Task 1 made filter them. That
// filtering is pinned in internal/users (TestDeviceSlotExpires and friends);
// there is no exported write-back on users.Store to force an expiry from here,
// so it is not re-tested at this layer.

func TestDeviceEnvelopeRejectsUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an unauthenticated caller read a device envelope")
	}
}

// newNativeRegisterForTest returns a register function that drives the real
// native-register handler for one device, and can be called repeatedly.
//
// It mints a fresh pairing token per call because native pairing tokens are
// single-use (consumeNativePairingNonce), and it holds deviceToken and platform
// constant so every call merges into the same device row rather than creating a
// new one. extra is spliced into the JSON body — pass `"encryptionEnrolled":true`
// or "" for a body without the field at all.
func newNativeRegisterForTest(t *testing.T) (srv *Server, userID, deviceID string, register func(*testing.T, string) int) {
	t.Helper()
	srv = newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID = all[0].ID
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	deviceID = "enrollment-device"

	// Re-registration under an existing deviceID now requires proof of
	// possession of that device's current secret, so a stolen session cannot
	// rebind a victim's device id (see handleNotificationNativeRegister). A real
	// device always has that secret: it is issued at pairing and used on every
	// subsequent API call. Modelling that here keeps these tests about the
	// merge behaviour rather than about auth.
	secret := ""
	register = func(t *testing.T, extra string) int {
		t.Helper()
		token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
		if err != nil {
			t.Fatalf("createPairingToken: %v", err)
		}
		if extra != "" {
			extra = "," + extra
		}
		body := fmt.Sprintf(
			`{"subscriberId":%q,"pairingToken":%q,"deviceToken":"enrollment-token","deviceId":%q,"platform":"android"%s}`,
			subscriberID, token, deviceID, extra)
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
		if secret != "" {
			req.Header.Set(headerDeviceSecret, secret)
		}
		rec := httptest.NewRecorder()
		srv.handleNotificationNativeRegister(rec, req)
		if rec.Code == http.StatusOK {
			var resp struct {
				DeviceSecret string `json:"deviceSecret"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err == nil && resp.DeviceSecret != "" {
				secret = resp.DeviceSecret
			}
		}
		return rec.Code
	}
	return srv, userID, deviceID, register
}

// The marker must follow the device DOWN as well as up. An app reinstall
// destroys the keystore key, and a marker that only ever turned on would show a
// device as protected when it can no longer read anything.
func TestNativeRegisterCarriesEncryptionEnrolledBothWays(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)

	if code := register(t, `"encryptionEnrolled":true`); code != http.StatusOK {
		t.Fatalf("register true: status %d", code)
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("marker did not turn on")
	}

	if code := register(t, `"encryptionEnrolled":false`); code != http.StatusOK {
		t.Fatalf("register false: status %d", code)
	}
	if deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("marker did not turn back off")
	}
}

// An older client that does not send the field must not be silently marked
// un-enrolled — absent means "no opinion", not "no".
func TestNativeRegisterWithoutTheFieldLeavesTheMarkerAlone(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)
	if code := register(t, `"encryptionEnrolled":true`); code != http.StatusOK {
		t.Fatalf("register true: status %d", code)
	}
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("register without field: status %d", code)
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("an absent field cleared the marker")
	}
}

// Re-registration must not erase a key the device published through the
// enrollment route, which is the store-level carry-forward seen from the
// handler that actually performs the re-registration.
func TestNativeRegisterPreservesAPublishedEnrollmentKey(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("first register: status %d", code)
	}
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if _, err := store.SetNativeDeviceEnrollmentKey(deviceID, "PUBKEY", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("re-register: status %d", code)
	}
	if got := deviceByID(t, srv, userID, deviceID).EnrollmentPublicKey; got != "PUBKEY" {
		t.Fatalf("re-registration erased the published enrollment key: %q", got)
	}
}

// A pairing token proves someone held a live session. It does not prove
// possession of the device being rebound — so a stolen session must not be able
// to point register at a victim's existing deviceId and take it over.
//
// The merge in upsertNativeDeviceTx is what makes this dangerous rather than
// merely rude: it overwrites SecretHash and PushToken while PRESERVING
// MFAApprover and the enrollment columns. The real phone stops authenticating,
// its push is redirected, the attacker inherits its right to approve sign-ins,
// and no new row appears for the user to notice.
func TestNativeRegisterRefusesToRebindADeviceWithoutItsSecret(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("first register: status %d", code)
	}
	original := deviceByID(t, srv, userID, deviceID)

	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	// The attacker holds only a session (enough to mint this token) and the
	// victim's deviceId, which the device list discloses. No device secret.
	body := fmt.Sprintf(
		`{"subscriberId":%q,"pairingToken":%q,"deviceToken":"attacker-endpoint","deviceId":%q,"platform":"android"}`,
		subscriberID, token, deviceID)
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("rebind without the device secret was allowed: status %d", rec.Code)
	}
	after := deviceByID(t, srv, userID, deviceID)
	if after.SecretHash != original.SecretHash {
		t.Error("the real device's secret was replaced")
	}
	if after.PushToken != original.PushToken {
		t.Errorf("push was redirected to %q", after.PushToken)
	}
}

// Refusing a rebind must not burn the single-use pairing token: a legitimate
// device that omits its secret would otherwise send the user back to the QR
// screen. The nonce is consumed only after the re-pair check passes.
func TestARefusedRebindLeavesThePairingTokenUsable(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("first register: status %d", code)
	}
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	post := func(devID string) int {
		body := fmt.Sprintf(
			`{"subscriberId":%q,"pairingToken":%q,"deviceToken":"tok","deviceId":%q,"platform":"android"}`,
			subscriberID, token, devID)
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handleNotificationNativeRegister(rec, req)
		return rec.Code
	}

	if code := post(deviceID); code != http.StatusConflict {
		t.Fatalf("expected the rebind to be refused, got %d", code)
	}
	// The same token must still pair a genuinely new device.
	if code := post("a-brand-new-device"); code != http.StatusOK {
		t.Fatalf("the refused rebind burned the pairing token: status %d", code)
	}
}

// An admin password reset is the standard response to a compromised account,
// and revokeAllUserCredentials purges sessions, devices and the CardDAV
// credential. A native pairing token is none of those — it is a stateless HMAC
// bound to nothing that revocation touches — so one minted BEFORE the reset
// still redeemed after it and minted a working device credential on an account
// the admin believed was secured. The single-use nonce does not help: the token
// is redeemed exactly once, just later than intended.
func TestRevocationInvalidatesAnAlreadyMintedPairingToken(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user: %v", err)
	}
	u := all[0]
	store, err := srv.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	// Warm the index the way a real lookup would, so the test proves the stale
	// entry is evicted rather than that it was never cached.
	if _, ok := srv.lookupUserBySubscriber(subscriberID); !ok {
		t.Fatal("subscriber index did not resolve before revocation")
	}

	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	if err := srv.revokeAllUserCredentials(u); err != nil {
		t.Fatalf("revokeAllUserCredentials: %v", err)
	}

	body := fmt.Sprintf(
		`{"subscriberId":%q,"pairingToken":%q,"deviceToken":"attacker-endpoint","deviceId":"post-reset","platform":"android"}`,
		subscriberID, token)
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("a pairing token minted before revocation still registered a device: %s", rec.Body.String())
	}
}

// MustChangePassword confines a SESSION to the password-change and logout
// routes. A device credential was exempt entirely, so one minted around an
// admin reset kept full mail and contacts access on an account the admin had
// just confined.
func TestDeviceAuthRefusedWhileAPasswordChangeIsOwed(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req)
	if _, _, ok, _ := srv.deviceAuthFromRequest(req); !ok {
		t.Fatal("device credential did not work before the flag was set")
	}

	if _, err := srv.users.SetPassword(context.Background(), userID, "reset-by-admin-password", true); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req2)
	if _, _, ok, _ := srv.deviceAuthFromRequest(req2); ok {
		t.Fatalf("device %q authenticated on an account owing a password change", deviceID)
	}
}

// meterAccountWrite runs in withAuth, withMailAuth and withDAVBasicAuth, but
// withDeviceAuth is an inert marker with no shared middleware to hang it on, so
// commit a8904dd ("meter every auth wrapper") closed three legs and left the
// fourth. A device credential was consequently STRONGER than a session on this
// one axis, while the trust model ranks it weaker.
func TestDeviceAuthMutatingRouteIsMetered(t *testing.T) {
	srv, _, _, authDevice := newPairedDeviceForTest(t)

	throttled := 0
	total := accountWriteBurst + 50
	for i := 0; i < total; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
			strings.NewReader(`{"publicKey":"BASE64PUBKEY"}`))
		authDevice(req)
		rec := httptest.NewRecorder()
		srv.handlePGPPublishEnrollmentKey(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled == 0 {
		t.Fatalf("%d writes on a device credential, none throttled (accountWriteBurst=%d)", total, accountWriteBurst)
	}
}

// ...but the meter must not touch device READS. meterAccountWrite returns true
// immediately for GET, and the device envelope read is on the same credential.
func TestDeviceAuthReadRouteIsNotMetered(t *testing.T) {
	srv, _, _, authDevice := newPairedDeviceForTest(t)

	for i := 0; i < accountWriteBurst+50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
		authDevice(req)
		rec := httptest.NewRecorder()
		srv.handlePGPDeviceEnvelope(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("device read throttled on request %d; reads must not be metered", i+1)
		}
	}
}

// deviceId becomes part of the enrollment code's hash preimage, and three
// independent implementations must produce identical bytes from it. The spec
// mandates UTF-8 and a length prefix but says nothing about normalisation, so a
// non-ASCII id that one implementation normalises differently makes the codes
// never match — surfacing to the user as "the key this server gave the browser
// is not the key on that device", which is indistinguishable from an attack.
func TestRegisterRejectsADeviceIDThatCannotBeHashedPortably(t *testing.T) {
	for _, id := range []string{
		"café-phone",             // non-ASCII: NFC and NFD differ
		"pixeĺ",                 // combining acute, normalises
		"my phone",               // space: breaks the device: slot name
		"emoji-\U0001F4F1",       // outside the BMP
		strings.Repeat("a", 129), // over the slot-id bound
	} {
		if validDeviceID(id) {
			t.Errorf("validDeviceID(%q) = true; that id cannot be hashed portably", id)
		}
	}
	for _, id := range []string{"pixel-7", "device_a", "A.B:C-1", "0123456789abcdef"} {
		if !validDeviceID(id) {
			t.Errorf("validDeviceID(%q) = false; that is an ordinary id", id)
		}
	}
}

// The bound applies to NEW ids only. A device registered before it exists must
// keep working on its next token refresh rather than being stranded, and it
// re-registers through the branch that proves possession of its secret.
func TestAnAlreadyRegisteredDeviceIDIsNotStrandedByTheCharsetBound(t *testing.T) {
	srv, userID, _, _ := newPairedDeviceForTest(t)
	legacyID := "café-phone" // would be refused as a new id

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
		DeviceID: legacyID, Platform: "android", PushToken: "old", UserID: userID, SecretHash: hash,
	}); err != nil {
		t.Fatalf("seed legacy device: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex[legacyID] = userID
	srv.userMu.Unlock()

	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	body := fmt.Sprintf(
		`{"subscriberId":%q,"pairingToken":%q,"deviceToken":"refreshed","deviceId":%q,"platform":"android"}`,
		subscriberID, token, legacyID)
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", strings.NewReader(body))
	req.Header.Set(headerDeviceSecret, raw)
	rec := httptest.NewRecorder()
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a pre-existing device was stranded by the charset bound: status %d, body=%s", rec.Code, rec.Body.String())
	}
}
