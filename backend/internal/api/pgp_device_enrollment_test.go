package api

import (
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
		rec := httptest.NewRecorder()
		srv.handleNotificationNativeRegister(rec, req)
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
