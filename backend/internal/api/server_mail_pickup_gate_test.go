package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
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
