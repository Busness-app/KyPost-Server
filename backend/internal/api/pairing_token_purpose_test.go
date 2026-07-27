package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPairingTokenPurposeMismatchRejected drives the purpose check directly:
// a token minted for one purpose must be rejected by both
// validatePairingToken and parsePairingTokenUserID when checked against a
// different wantPurpose, even though the signature, subject, and expiry are
// all otherwise valid. This is the core security property Task 10 adds —
// without it, a token minted for one flow (e.g. a pickup link mailed in
// plaintext) could be replayed against a different, more sensitive flow
// (e.g. native device pairing).
func TestPairingTokenPurposeMismatchRejected(t *testing.T) {
	srv := newTestServer(t)

	token, _, err := srv.createPairingToken("some-id", pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	if err := srv.validatePairingToken("some-id", token, pairingPurposePickupLink, time.Now()); err != nil {
		t.Fatalf("validatePairingToken with matching purpose should succeed, got: %v", err)
	}

	if err := srv.validatePairingToken("some-id", token, pairingPurposeNativeDevice, time.Now()); err == nil {
		t.Fatalf("validatePairingToken with mismatched purpose should fail, got nil error")
	}
	if err := srv.validatePairingToken("some-id", token, pairingPurposePGPQRKey, time.Now()); err == nil {
		t.Fatalf("validatePairingToken with mismatched purpose should fail, got nil error")
	}

	if _, err := srv.parsePairingTokenUserID(token, pairingPurposePickupLink, time.Now()); err != nil {
		t.Fatalf("parsePairingTokenUserID with matching purpose should succeed, got: %v", err)
	}
	if _, err := srv.parsePairingTokenUserID(token, pairingPurposeNativeDevice, time.Now()); err == nil {
		t.Fatalf("parsePairingTokenUserID with mismatched purpose should fail, got nil error")
	}
}

// TestPickupHandlerRejectsTokenMintedForOtherPurpose proves the cross-purpose
// rejection end-to-end for the pickup flow: a token minted for native device
// pairing (same subject/id, validly signed, unexpired) must not be usable to
// view a pickup record.
func TestPickupHandlerRejectsTokenMintedForOtherPurpose(t *testing.T) {
	srv := newTestServer(t)

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", "Body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Minted for native-device pairing, not pickup — same id, same secret,
	// unexpired.
	wrongPurposeToken, _, err := srv.createPairingToken(id, pairingPurposeNativeDevice, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+wrongPurposeToken, nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (cross-purpose token must be rejected); body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	// The record must still be intact, exactly as for any other rejected
	// token: a real pickup-purpose token can still view it once.
	rightPurposeToken, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	goodReq := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+rightPurposeToken, nil)
	goodRec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(goodRec, goodReq)
	if goodRec.Code != http.StatusOK {
		t.Fatalf("status with correct-purpose token = %d, want %d; body=%s", goodRec.Code, http.StatusOK, goodRec.Body.String())
	}
}

// TestPGPQRKeyRejectsTokenMintedForOtherPurpose proves the cross-purpose
// rejection end-to-end for the PGP QR key-exchange flow: a token minted for
// a pickup link (same subject, validly signed, unexpired) must not be usable
// to fetch a user's PGP key.
func TestPGPQRKeyRejectsTokenMintedForOtherPurpose(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	wrongPurposeToken, _, err := srv.createPairingToken(userID, pairingPurposePickupLink, 2*time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+wrongPurposeToken, nil)
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (cross-purpose token must be rejected); body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestNativeRegisterRejectsTokenMintedForOtherPurpose proves the
// cross-purpose rejection end-to-end for native device pairing: a token
// minted for the PGP QR flow (same subject/subscriber id, validly signed,
// unexpired) must not be usable to register a native push device.
func TestNativeRegisterRejectsTokenMintedForOtherPurpose(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}

	wrongPurposeToken, _, err := srv.createPairingToken(subscriberID, pairingPurposePGPQRKey, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"subscriberId": subscriberID,
		"pairingToken": wrongPurposeToken,
		"deviceToken":  "native-device-token",
		"deviceId":     "device-a",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", jsonBody(body))
	srv.handleNotificationNativeRegister(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (cross-purpose token must be rejected); body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	devices := store.ListNativeDevices()
	if len(devices) != 0 {
		t.Fatalf("len(devices) = %d, want 0 (cross-purpose token must not register a device)", len(devices))
	}
}
