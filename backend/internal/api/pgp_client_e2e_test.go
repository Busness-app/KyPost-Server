package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

// These tests cover the end-to-end PGP contract at the HTTP boundary rather
// than at the Go struct boundary. The original implementation was verified
// only at the struct level, which is why it shipped with the ciphertext
// being dropped at JSON serialization and every key endpoint unreachable
// from a paired device — both invisible to a struct-level check.

func clientProtectedUser(t *testing.T, srv *Server) users.User {
	t.Helper()
	u, err := srv.users.Create("e2e-tester", "e2e-tester-testpassword", users.RoleUser)
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
	u, err := srv.users.Create("legacy-tester", "legacy-tester-testpassword", users.RoleUser)
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
	u, err := srv.users.Create("nokey-tester", "nokey-tester-testpassword", users.RoleUser)
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
func TestPGPPayloadRefusesServerProtectedAccount(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("legacy-payload", "legacy-payload-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed", "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/mail/pgp-payload?mailbox=INBOX&messageId=5", nil)
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPPayload)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
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
		{"no pgp payload", "From: a@b.c\r\nTo: d@e.f\r\nSubject: s\r\nDate: now\r\nContent-Type: text/plain\r\n\r\nhi", "no OpenPGP message"},
		{
			"missing only Date",
			strings.Replace(wellFormedDelivery, "Date: Sat, 25 Jul 2026 12:00:00 GMT\r\n", "", 1),
			"Date",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePGPMimeDelivery(tc.input)
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
	if err := validatePGPMimeDelivery(lowered); err != nil {
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
