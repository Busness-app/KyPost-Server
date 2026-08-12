package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/users"
)

// These tests cover the end-to-end PGP contract at the HTTP boundary rather
// than at the Go struct boundary. The original implementation was verified
// only at the struct level, which is why it shipped with the ciphertext
// being dropped at JSON serialization and every key endpoint unreachable
// from a paired device — both invisible to a struct-level check.

func clientProtectedUser(t *testing.T, srv *Server) users.User {
	t.Helper()
	u, err := srv.users.Create(context.Background(), "e2e-tester", "e2e-tester-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := srv.users.SetPGPIdentityClientProtected(
		u.ID, "FPR123", "KID123", "-----BEGIN PGP PUBLIC KEY BLOCK-----\npub\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"c2FsdA==","iv":"aXY=","ciphertext":"Y3Q="}`,
		"generated", "2026-07-25T00:00:00Z")
	if err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return updated
}

// The whole point of client protection is that the server holds nothing it
// can decrypt with. Pin that the stored record has no server-readable key.
func TestClientProtectedIdentityLeavesNoServerReadableKey(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)

	if u.PGPPrivateKeyEnc != "" {
		t.Fatal("server-sealed private key survived a client-protected identity write")
	}
	if u.PGPProtection() != users.PGPProtectionClient {
		t.Fatalf("protection = %q, want %q", u.PGPProtection(), users.PGPProtectionClient)
	}
	if u.HasServerReadableKey() {
		t.Fatal("HasServerReadableKey() is true for a client-protected account")
	}
	// Public() must never leak either private field.
	blob, _ := json.Marshal(u.Public())
	for _, forbidden := range []string{"pgpPrivateKeyEnc", "pgpPrivateKeyWrapped", "ciphertext"} {
		if strings.Contains(string(blob), forbidden) {
			t.Errorf("Public() exposes %q: %s", forbidden, blob)
		}
	}
}

// The bootstrap endpoint is what a cold-starting client calls. It must
// describe the account completely enough that the client never has to guess.
func TestPGPBootstrapDescribesClientProtectedAccount(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["hasIdentity"] != true {
		t.Error("hasIdentity should be true")
	}
	if got["protection"] != "client" {
		t.Errorf("protection = %v, want client", got["protection"])
	}
	if got["unlockRequired"] != true {
		t.Error("unlockRequired should be true: the client cannot read mail until it unwraps the key")
	}
	if got["canDecryptServerSide"] != false {
		t.Error("canDecryptServerSide should be false")
	}
	if got["migrationAvailable"] != false {
		t.Error("a client-protected key has nothing to migrate")
	}
	wrapped, _ := got["wrappedPrivateKey"].(string)
	if !strings.Contains(wrapped, "PBKDF2-SHA256") {
		t.Errorf("wrappedPrivateKey missing or not an envelope: %q", wrapped)
	}
	if got["payloadEndpoint"] != "/api/mail/pgp-payload" {
		t.Errorf("payloadEndpoint = %v", got["payloadEndpoint"])
	}
}

// A legacy account must be told it can still read mail and should migrate,
// not told to prompt for an unlock it has no envelope for.
func TestPGPBootstrapDescribesLegacyAccount(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "legacy-tester", "legacy-tester-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed-envelope", "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)

	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["protection"] != "server" {
		t.Errorf("protection = %v, want server", got["protection"])
	}
	if got["unlockRequired"] != false {
		t.Error("a legacy account has no envelope to unlock")
	}
	if got["migrationAvailable"] != true {
		t.Error("a legacy account should be offered migration")
	}
	if got["wrappedPrivateKey"] != "" {
		t.Error("legacy account must not report a wrapped key")
	}
	// The sealed server-side envelope must never appear in a bootstrap body.
	if strings.Contains(rec.Body.String(), "sealed-envelope") {
		t.Fatalf("bootstrap leaked the server-sealed private key: %s", rec.Body.String())
	}
}

// An account with no key at all must be distinguishable from both modes.
func TestPGPBootstrapWithNoIdentity(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "nokey-tester", "nokey-tester-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)

	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["hasIdentity"] != false {
		t.Error("hasIdentity should be false")
	}
	if got["unlockRequired"] != false || got["migrationAvailable"] != false {
		t.Error("an account with no key must not be prompted to unlock or migrate")
	}
}

// The ciphertext endpoint refuses server-protected accounts: the server
// already decrypted those into the inbox response, so handing back the raw
// payload as well widens exposure for nothing.
// The server-protected 409 is now asserted against a real encrypted message,
// in TestPGPPayloadStillRefusesEncryptedForServerProtectedAccount
// (pgp_client_read_test.go).
//
// This test used to live here and assert the refusal with no message present
// at all, which worked only because the protection gate ran before the handler
// had looked at anything. The gate now runs after the fetch — it has to, since
// whether the refusal applies depends on whether this UID is encrypted or
// merely signed — so "no message" no longer reaches it, and the replacement
// drives the real case instead of a shortcut.

// TestHandlePGPPayloadNarrowsSignerKeysToTheResolvedSender is review round 1
// finding #4: every existing test of the sender-narrowing logic calls
// boundSignerKeysForSender directly, so nothing proved handlePGPPayload
// itself wires content.Sender into senderAddrSpec, narrows signerKeys with
// the result, or emits "sender"/"resolvedSender" in the response. Deleting
// that wiring (reverting to the un-narrowed boundSignerKeys(contactsStore)
// call and dropping the two new response fields) would not fail a single
// test before this one existed.
//
// This drives the real HTTP handler with a fake IMAP client, using the exact
// RFC 5322 comment header from the task's own threat model — Bob's real
// mailbox with Eve's address hidden in a parenthesised comment — to prove
// end to end that only Bob's key reaches the client.
func TestHandlePGPPayloadNarrowsSignerKeysToTheResolvedSender(t *testing.T) {
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	u := clientProtectedUser(t, srv)

	contactsStore, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	bob, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		Emails:         []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:         bob.ArmoredPublicKey,
		PGPKeySource:   "qr",
		PGPKeyVerified: true,
	}); err != nil {
		t.Fatalf("Upsert bob contact: %v", err)
	}
	eve, err := pgpmail.GenerateIdentity("Eve", "eve@evil.example")
	if err != nil {
		t.Fatalf("GenerateIdentity eve: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		Emails:       []contacts.ContactValue{{Value: "eve@evil.example"}},
		PGPKey:       eve.ArmoredPublicKey,
		PGPKeySource: contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert eve contact: %v", err)
	}

	// mailFor/userMailClient only reuses a cached client when the cached
	// updatedAt matches what's on disk (see rules_handlers_test.go) — write a
	// real (if inert) IMAP config payload stamped with the same updatedAt
	// used below so mailFor resolves to the injected fake.
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(u.ID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "e2e-tester@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	rawSender := "Bob Smith (Eve <eve@evil.example>) <bob@example.com>"
	fake := &fakeMailClient{
		bodies: map[int]string{5: ""},
		bodyPGPEncryptedPayload: map[int]string{
			5: "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n",
		},
		bodySender: map[int]string{5: rawSender},
	}
	srv.userMu.Lock()
	srv.userMail[u.ID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/mail/pgp-payload?mailbox=INBOX&messageId=5", nil)
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPPayload)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["sender"] != rawSender {
		t.Errorf("sender = %v, want the raw header %q", got["sender"], rawSender)
	}
	if got["resolvedSender"] != "bob@example.com" {
		t.Errorf("resolvedSender = %v, want bob@example.com — the comment-hidden decoy must not win", got["resolvedSender"])
	}
	signerKeys, ok := got["signerKeys"].([]any)
	if !ok {
		t.Fatalf("signerKeys missing or wrong type: %+v", got["signerKeys"])
	}
	if len(signerKeys) != 1 {
		t.Fatalf("want exactly one signer key bound to bob@example.com, got %d: %+v", len(signerKeys), signerKeys)
	}
	key, ok := signerKeys[0].(map[string]any)
	if !ok {
		t.Fatalf("signerKeys[0] has unexpected shape: %+v", signerKeys[0])
	}
	addresses, _ := key["addresses"].([]any)
	if len(addresses) != 1 || addresses[0] != "bob@example.com" {
		t.Fatalf("signerKeys[0].addresses = %+v, want [bob@example.com]; eve's key must not be offered", addresses)
	}
}

// ---- send-path delivery validation ----------------------------------------

// The header-less shape the browser used to emit. This is the regression
// that matters: the old check accepted it, so the endpoint would have
// relayed messages with no From, To, Subject, or Date.
const headerlessDelivery = "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n" +
	"MIME-Version: 1.0\r\n\r\n" +
	"--b\r\nContent-Type: application/octet-stream\r\n\r\n" +
	"-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----\r\n--b--\r\n"

const wellFormedDelivery = "From: alice@example.com\r\n" +
	"To: bob@example.com\r\n" +
	"Subject: [Encrypted] Email Sent by KyPost\r\n" +
	"Date: Sat, 25 Jul 2026 12:00:00 GMT\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"b\"\r\n\r\n" +
	"--b\r\nContent-Type: application/octet-stream\r\n\r\n" +
	"-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----\r\n--b--\r\n"

func TestValidatePGPMimeDelivery(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{"well formed", wellFormedDelivery, ""},
		{"header-less (the shipped regression)", headerlessDelivery, "missing required header"},
		{"no header block at all", "-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----", "no header block"},
		// text/plain now fails the RFC 3156 shape check before the armor check
		// is reached: this endpoint relays ciphertext, and "the marker appears
		// somewhere in the body" was never evidence of that.
		{"not an encrypted part", "From: alice@example.com\r\nTo: d@e.f\r\nSubject: s\r\nDate: now\r\nContent-Type: text/plain\r\n\r\nhi", "multipart/encrypted"},
		{"encrypted shape but no armor", strings.Replace(wellFormedDelivery, "-----BEGIN PGP MESSAGE-----", "not-armor", 1), "no OpenPGP message"},
		{"From is not the authorized sender", strings.Replace(wellFormedDelivery, "From: alice@example.com", "From: ceo@example.com", 1), "may send as"},
		{
			"missing only Date",
			strings.Replace(wellFormedDelivery, "Date: Sat, 25 Jul 2026 12:00:00 GMT\r\n", "", 1),
			"Date",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePGPMimeDelivery(tc.input, "alice@example.com")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// Header matching is case-insensitive per RFC 5322 §1.2.2.
func TestValidatePGPMimeDeliveryAcceptsLowercaseHeaders(t *testing.T) {
	lowered := strings.ToLower(wellFormedDelivery[:strings.Index(wellFormedDelivery, "\r\n\r\n")]) +
		wellFormedDelivery[strings.Index(wellFormedDelivery, "\r\n\r\n"):]
	if err := validatePGPMimeDelivery(lowered, "alice@example.com"); err != nil {
		t.Fatalf("lowercase headers rejected: %v", err)
	}
}

// The endpoint must reject a malformed delivery before it reaches SMTP,
// rather than relaying it and discovering the problem at the recipient.
func TestHandleMailSendPGPRejectsHeaderlessDelivery(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	// No IMAP config is needed: validation now runs before any config read,
	// so a malformed delivery is rejected without touching SMTP.

	body, _ := json.Marshal(map[string]any{
		"from":    "e2e@example.com",
		"subject": "hi",
		"deliveries": []map[string]any{
			{"recipients": []string{"bob@example.com"}, "ciphertext": headerlessDelivery},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send-pgp", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handleMailSendPGP)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "missing required header") {
		t.Fatalf("unhelpful rejection: %s", rec.Body.String())
	}
}
