package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
)

// signedOnlyFixture builds a real RFC 3156 signed message from sender, and
// returns a server whose INBOX holds it at UID 5 along with the signer's
// identity. The user is server-protected (pgpVictimWithIdentity seals the key
// to the server), which is the case the gate used to refuse.
func signedOnlyFixture(t *testing.T) (*Server, string, *pgpmail.Identity) {
	t.Helper()
	userID, _, contactsStore, srv := pgpVictimWithIdentity(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")

	sender, err := pgpmail.GenerateIdentity("Sender", "sender@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity sender: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Sender",
		Emails:        []contacts.ContactValue{{Value: "sender@example.com"}},
		PGPKey:        sender.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert sender contact: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Signed only",
		Body:    "trust me",
		Mode:    "plain",
	}.Build()
	signed, err := pgpmail.SignMIME(plaintext, sender)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}

	// mailFor/userMailClient only reuses a cached client when the cached
	// updatedAt matches what's on disk — write a real (if inert) IMAP config
	// stamped with the same updatedAt so mailFor resolves to the fake.
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "tester@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	fake := &fakeMailClient{
		bodies:                  map[int]string{5: "trust me"},
		bodySender:              map[int]string{5: "Sender <sender@example.com>"},
		bodyPGPSignaturePayload: map[int]string{5: "-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----"},
		rawMessages:             map[int][]byte{5: signed},
	}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()

	return srv, userID, sender
}

func fetchPayload(t *testing.T, srv *Server, userID string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/mail/pgp-payload?mailbox=INBOX&messageId=5", nil)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPPayload)(rec, req)

	got := map[string]any{}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rec, got
}

// A server-protected account must be able to fetch a signed-only payload. The
// 409 exists to stop an account fetching ciphertext the server already
// decrypted for it; a signed-only message has no ciphertext, and its body was
// already in the inbox response. Refusing here would leave server-protected
// accounts with no way to check a signature at all, now that the server does
// not check it for them.
func TestPGPPayloadAllowsSignedOnlyForServerProtectedAccount(t *testing.T) {
	srv, userID, _ := signedOnlyFixture(t)

	rec, got := fetchPayload(t, srv, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got["signedPartBase64"] == "" || got["signedPartBase64"] == nil {
		t.Fatal("expected the verbatim signed part; without it the browser has nothing to verify")
	}
	sig, _ := got["signaturePayload"].(string)
	if !strings.Contains(sig, "-----BEGIN PGP SIGNATURE-----") {
		t.Fatalf("expected a complete armored signature, got %q", sig)
	}
}

// The encrypted path keeps its gate exactly as it was.
func TestPGPPayloadStillRefusesEncryptedForServerProtectedAccount(t *testing.T) {
	srv, userID, _ := signedOnlyFixture(t)

	srv.userMu.Lock()
	srv.userMail[userID].client = &fakeMailClient{
		bodies:                  map[int]string{5: ""},
		bodySender:              map[int]string{5: "Sender <sender@example.com>"},
		bodyPGPEncryptedPayload: map[int]string{5: "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----\n"},
	}
	srv.userMu.Unlock()

	rec, _ := fetchPayload(t, srv, userID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 — a server-protected account must not fetch ciphertext the server already opened", rec.Code)
	}
}

// The bytes served must be the bytes signed. This is the property the whole
// change exists to establish, and the one the old server-side check silently
// failed: it compared a signature against go-imap's decoded body.
func TestPGPPayloadServesVerifiableSignedBytes(t *testing.T) {
	srv, userID, sender := signedOnlyFixture(t)

	_, got := fetchPayload(t, srv, userID)
	encoded, _ := got["signedPartBase64"].(string)
	signedPart, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("signedPartBase64 is not valid base64: %v", err)
	}
	armoredSig, _ := got["signaturePayload"].(string)

	key, err := crypto.NewKeyFromArmored(sender.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("parse signer key: %v", err)
	}
	keyring, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	handle, err := crypto.PGP().Verify().VerificationKeys(keyring).New()
	if err != nil {
		t.Fatalf("verify handle: %v", err)
	}
	result, err := handle.VerifyDetached(signedPart, []byte(armoredSig), crypto.Auto)
	if err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if err := result.SignatureError(); err != nil {
		t.Fatalf("the served bytes are not the bytes that were signed: %v", err)
	}
}
