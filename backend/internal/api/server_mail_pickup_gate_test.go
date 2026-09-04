package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// newPickupGateServer builds a server with a configured mail account, one
// contact holding a real PGP public key, and one keyless address whose
// discovery is suppressed so the resolver makes no network call.
//
// smtp.example.com is deliberately unroutable: any status other than 502
// proves the request never reached the network.
func newPickupGateServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, _ := srv.users.List()
	userID := all[0].ID

	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host:     "imap.example.com",
		Port:     993,
		Username: "alice@example.com",
		Password: "pw",
		Mailbox:  "INBOX",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}

	key, err := crypto.PGP().KeyGeneration().AddUserId("Bob", "bob@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:        pub,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Without this the resolver runs a real WKD/keyserver lookup for the
	// keyless address and the test depends on the network.
	if err := pgpdiscovery.AddSuppression(srv.userStateDir(userID), "carol@example.com", "test"); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	return srv, userID
}

func sendEncrypted(t *testing.T, srv *Server, allowFallback bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"to":                  "bob@example.com, carol@example.com",
		"subject":             "hi",
		"body":                "hello",
		"encrypt":             true,
		"allowPickupFallback": allowFallback,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleMailSend)(rec, req)
	return rec
}

func TestMailSendRefusesKeylessRecipientWithoutOptIn(t *testing.T) {
	srv, _ := newPickupGateServer(t)
	rec := sendEncrypted(t, srv, false)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		KeylessRecipients       []string `json:"keylessRecipients"`
		PickupFallbackAvailable bool     `json:"pickupFallbackAvailable"`
		ClientSideNeeded        bool     `json:"clientSideNeeded"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v (%s)", err, rec.Body.String())
	}
	if len(got.KeylessRecipients) != 1 || got.KeylessRecipients[0] != "carol@example.com" {
		t.Fatalf("expected carol@example.com listed, got %+v", got.KeylessRecipients)
	}
	if !got.PickupFallbackAvailable {
		t.Fatal("expected pickupFallbackAvailable true")
	}
	// Must not collide with the other 409 shape, which clients discriminate on.
	if got.ClientSideNeeded {
		t.Fatal("keyless refusal must not set clientSideNeeded")
	}
}

// The keyed recipient must not receive anything. A 409 rather than a 502 from
// the unroutable SMTP host is what proves no delivery was attempted, which is
// what makes a confirm-then-resend safe.
func TestMailSendKeylessRefusalHappensBeforeAnySend(t *testing.T) {
	srv, _ := newPickupGateServer(t)
	if rec := sendEncrypted(t, srv, false); rec.Code == http.StatusBadGateway {
		t.Fatalf("refusal must precede SMTP delivery, got 502: %s", rec.Body.String())
	}
}

// Every recipient keyless + opt-in: there is nothing to encrypt, so the send
// becomes pickup-notifications-only. It must not 400 (the dialog would be a
// dead end) and must not panic on deliveries[0].
//
// smtp.example.com is unroutable (see newPickupGateServer), so the pickup
// notification to dave@example.com genuinely cannot be delivered here — and
// since he is the only recipient, that failure is total. The response must
// say so (502) rather than answer 200 for a send that delivered nothing;
// that silent-200 case is exactly the bug this test used to lock in before
// finishMailSend started folding pickup-notification failures into the
// response instead of only logging them.
func TestMailSendWithOnlyKeylessRecipientsAndOptIn(t *testing.T) {
	srv, userID := newPickupGateServer(t)
	if err := pgpdiscovery.AddSuppression(srv.userStateDir(userID), "dave@example.com", "test"); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"to":                  "dave@example.com",
		"subject":             "hi",
		"body":                "hello",
		"encrypt":             true,
		"allowPickupFallback": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleMailSend)(rec, req)

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("opting in must not dead-end in the no-keyed-recipients 400: %s", rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (every pickup notification failed, so nothing was delivered), got %d: %s", rec.Code, rec.Body.String())
	}
}

// The opt-in test above (TestMailSendWithOnlyKeylessRecipientsAndOptIn) only
// covers the all-keyless branch, which skips buildPGPDeliveries entirely —
// that is not the code path a real mixed inbox hits, since most sends have
// at least one recipient with a key. Nothing asserted that a mixed
// keyed/keyless request with allowPickupFallback actually gets past the gate
// into buildPGPDeliveries; an inverted "!req.AllowPickupFallback" check would
// have passed every existing test.
//
// 502 rather than 409 is the success signal here, same idiom as
// TestMailSendKeylessRefusalHappensBeforeAnySend above: smtp.example.com is
// unroutable, so reaching finishMailSend's SMTPDeliver call for bob's
// ciphertext proves the gate let the request through instead of refusing it.
// A 409 would mean the opt-in flag was not honored for the mixed case.
func TestMailSendMixedKeyedKeylessOptInReachesDelivery(t *testing.T) {
	srv, _ := newPickupGateServer(t)
	rec := sendEncrypted(t, srv, true)

	if rec.Code == http.StatusConflict {
		t.Fatalf("opting in on a mixed keyed/keyless send must still not 409, got: %s", rec.Body.String())
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (unroutable smtp host, proving delivery was attempted), got %d: %s", rec.Code, rec.Body.String())
	}
}

// A client-custody account cannot encrypt server-side at all, so naming its
// keyless recipients would answer a question it never got to ask. Clients
// discriminate the two 409s by field, so exactly one must be present.
func TestClientCustody409TakesPrecedenceOverKeyless(t *testing.T) {
	srv, userID := newPickupGateServer(t)
	_, err := srv.users.SetPGPIdentityClientProtected(userID,
		"FPR123", "KID123",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\npub\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"c2FsdA==","iv":"aXY=","ciphertext":"Y3Q="}`,
		"generated", "2026-07-25T00:00:00Z")
	if err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	rec := sendEncrypted(t, srv, false)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		ClientSideNeeded  bool     `json:"clientSideNeeded"`
		KeylessRecipients []string `json:"keylessRecipients"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.ClientSideNeeded {
		t.Fatal("expected clientSideNeeded on a client-custody account")
	}
	if len(got.KeylessRecipients) != 0 {
		t.Fatalf("expected no keylessRecipients alongside clientSideNeeded, got %+v", got.KeylessRecipients)
	}
}

// Mobile needs autoEncryptWhenKeyKnown or the same account auto-encrypts on
// web and silently does not on the phone. Only the read moves to device auth.
//
// This dispatches through srv.routes() rather than calling withMailAuth on
// the handler directly: the thing under test is the route *registration* in
// server.go (GET vs PUT wired to withAuth vs withMailAuth), and calling the
// handler directly would bypass that registration entirely, passing whether
// or not the route change was ever made.
func TestDiscoverySettingsReadableWithDeviceAuth(t *testing.T) {
	srv, userID := newPickupGateServer(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-1")

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/discovery/settings", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a device-authenticated read, got %d: %s", rec.Code, rec.Body.String())
	}
}

// The PUT must stay session-only: a device secret is not a re-verified
// password, and changing discovery policy is a settings write, not a read.
func TestDiscoverySettingsPutRejectsDeviceAuth(t *testing.T) {
	srv, userID := newPickupGateServer(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-1")

	body, _ := json.Marshal(map[string]any{"autoEncryptWhenKeyKnown": true})
	req := httptest.NewRequest(http.MethodPut, "/api/pgp/discovery/settings", bytes.NewReader(body))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a device-authenticated write, got %d: %s", rec.Code, rec.Body.String())
	}
}

// Mobile compose needs to warn about keyless recipients before the user hits
// send. resolve is unavailable to these accounts by design (it 409s for
// anything but client custody), so check is the endpoint, and it has to be
// reachable from a paired device.
//
// This dispatches through srv.routes() rather than calling withMailAuth on
// the handler directly: the thing under test is the route *registration* in
// server.go, and calling the handler directly would bypass that registration
// entirely, passing whether or not the route change was ever made.
func TestRecipientsCheckReadableWithDeviceAuth(t *testing.T) {
	srv, userID := newPickupGateServer(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-1")

	body, _ := json.Marshal(map[string]any{"addresses": []string{"bob@example.com", "carol@example.com"}})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/recipients/check", bytes.NewReader(body))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a device-authenticated check, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "carol@example.com") {
		t.Fatalf("expected every address echoed back, got %s", rec.Body.String())
	}
}
