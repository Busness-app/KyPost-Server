package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
)

func TestPGPQRTokenAndKeyRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	id, err := pgpmail.GenerateIdentity("QR Test", "qr-test@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	tokenReq := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/token", nil)
	authRequest(srv, tokenReq)
	tokenRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPQRToken)(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("qr/token: expected 200, got %d: %s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	keyReq := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+tokenResp.Token, nil)
	keyRec := httptest.NewRecorder()
	srv.handlePGPQRKey(keyRec, keyReq)
	if keyRec.Code != http.StatusOK {
		t.Fatalf("qr/key: expected 200, got %d: %s", keyRec.Code, keyRec.Body.String())
	}
	var keyResp struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(keyRec.Body).Decode(&keyResp); err != nil {
		t.Fatalf("decode key response: %v", err)
	}
	if keyResp.Fingerprint != id.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", keyResp.Fingerprint, id.Fingerprint)
	}
}

func TestPGPQRKeyRejectsExpiredToken(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	// createPairingToken clamps ttl<=0 to a 90s default (by design, to avoid
	// accidentally minting dead-on-arrival tokens for its other callers), so
	// it cannot be used to produce an already-expired token here. Build one
	// directly using the same claims+HMAC shape instead.
	claims := pairingTokenClaims{
		Sub:   userID,
		Exp:   time.Now().UTC().Add(-1 * time.Minute).Unix(),
		Nonce: "expired-test-nonce",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(srv.pairingSecret))
	mac.Write(payload)
	sig := mac.Sum(nil)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+token, nil)
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired token, got %d", rec.Code)
	}
}

// TestPGPQREndpointsFailClosedOnUnsetPairingSecret guards against the QR
// endpoints becoming a signing oracle when PAIRING_SECRET is left unset
// (its documented "" default): with an empty HMAC key, anyone can forge a
// validly-signed pairing token themselves, so both endpoints must refuse to
// operate at all rather than accept tokens signed with "".
func TestPGPQREndpointsFailClosedOnUnsetPairingSecret(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = ""

	tokenReq := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/token", nil)
	authRequest(srv, tokenReq)
	tokenRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPQRToken)(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("qr/token with unset pairing secret: expected 503, got %d: %s", tokenRec.Code, tokenRec.Body.String())
	}

	keyReq := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t=anything", nil)
	keyRec := httptest.NewRecorder()
	srv.handlePGPQRKey(keyRec, keyReq)
	if keyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("qr/key with unset pairing secret: expected 503, got %d: %s", keyRec.Code, keyRec.Body.String())
	}
}

// TestPGPQRTokenAcceptsDeviceCredentials drives the endpoint through the
// server's real route table (not a hand-wired middleware call) so it fails
// if GET /api/pgp/qr/token is ever wired back to withAuth instead of
// withMailAuth. kypost-android's "My QR Code" screen has no session cookie —
// its own device pairing credential is all it has — so this endpoint must
// accept it or that screen can never authenticate at all.
func TestPGPQRTokenAcceptsDeviceCredentials(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	id, err := pgpmail.GenerateIdentity("QR Test", "qr-test@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "pgp-qr-device")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/token", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (device auth should reach the handler); body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestPGPQRKeyRejectsTamperedSignature drives the
// subtle.ConstantTimeCompare mismatch branch in parsePairingTokenUserID
// directly: the only prior negative test used an expired-but-validly-signed
// token, which never reaches signature comparison failure. Here the token
// is well-formed and unexpired, but its signature is corrupted, so it must
// still be rejected.
func TestPGPQRKeyRejectsTamperedSignature(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	token, _, err := srv.createPairingToken(userID, pairingPurposePGPQRKey, 2*time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sigBytes[0] ^= 0xFF // flip a byte to invalidate the signature
	tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+tamperedToken, nil)
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered signature, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPGPQRKeyIncludesContactCardWhenSelfContactSet(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	id, err := pgpmail.GenerateIdentity("Card Test", "card-test@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	self, err := store.Upsert(contacts.Contact{
		FormattedName: "Jane Doe",
		Org:           "Acme",
		Emails:        []contacts.ContactValue{{Label: "work", Value: "jane@acme.example"}},
		PhotoRef:      "should-not-leak.jpg",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, _, err := store.SetSelf(self.UID, true); err != nil {
		t.Fatalf("SetSelf: %v", err)
	}

	token, _, err := srv.createPairingToken(userID, pairingPurposePGPQRKey, 2*time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+token, nil)
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ContactCard *pgpQRContactCard `json:"contactCard"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if resp.ContactCard == nil {
		t.Fatalf("expected contactCard in response, body=%s", rec.Body.String())
	}
	if resp.ContactCard.FormattedName != "Jane Doe" || resp.ContactCard.Org != "Acme" {
		t.Fatalf("contactCard = %+v, want fn=Jane Doe org=Acme", resp.ContactCard)
	}
	if len(resp.ContactCard.Emails) != 1 || resp.ContactCard.Emails[0].Value != "jane@acme.example" {
		t.Fatalf("contactCard emails = %+v", resp.ContactCard.Emails)
	}
	if strings.Contains(rec.Body.String(), "should-not-leak.jpg") {
		t.Fatalf("photoRef leaked into contactCard response: %s", rec.Body.String())
	}
}

func TestPGPQRKeyOmitsContactCardWhenNoSelfContact(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	id, err := pgpmail.GenerateIdentity("No Card Test", "no-card-test@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	token, _, err := srv.createPairingToken(userID, pairingPurposePGPQRKey, 2*time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+token, nil)
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "contactCard") {
		t.Fatalf("expected no contactCard field when no self-contact is set, body=%s", rec.Body.String())
	}
}
