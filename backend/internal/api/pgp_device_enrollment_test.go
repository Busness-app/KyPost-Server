package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/state"
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
