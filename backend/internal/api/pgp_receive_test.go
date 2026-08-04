package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

// extractArmoredPGPPayload is a test-only helper that pulls the armored
// OpenPGP data part out of a full multipart/encrypted envelope (as
// EncryptMIME produces), mirroring the content-sniffing technique
// pgpDetectPayload uses in production (internal/adapters/imap/client.go) —
// production reaches the same bytes via goimap's own attachment parsing
// rather than this direct MIME walk.
func extractArmoredPGPPayload(t *testing.T, raw []byte) string {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("expected a multipart Content-Type, got %q (%v)", msg.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("ReadAll part: %v", err)
		}
		if crypto.IsPGPMessage(string(body)) {
			return string(body)
		}
	}
	t.Fatal("no armored pgp payload found in encrypted envelope")
	return ""
}

func TestDecryptPGPMessageContentRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	recipient, err := pgpmail.GenerateIdentity("Recipient", "recipient@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := recipient.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, recipient.Fingerprint, recipient.KeyID, recipient.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	sender, err := pgpmail.GenerateIdentity("Sender", "sender@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity sender: %v", err)
	}
	contactsStore, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Sender",
		Emails:        []contacts.ContactValue{{Value: "sender@example.com"}},
		PGPKey:        sender.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert contact: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "sender@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Secret",
		Body:    "meet at dawn",
		Mode:    "plain",
	}.Build()
	encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, sender)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}

	payload := extractArmoredPGPPayload(t, encrypted)
	content := imapadapter.MessageContent{PGPEncryptedPayload: payload}
	result := srv.decryptPGPMessageContent(userID, "sender@example.com", content)

	if result.PGPDecryptError != "" {
		t.Fatalf("unexpected decrypt error: %s", result.PGPDecryptError)
	}
	if result.Body != "meet at dawn" {
		t.Fatalf("body mismatch: got %q", result.Body)
	}
	if result.PGPProtectedSubject != "Secret" {
		t.Fatalf("expected the real subject restored from protected headers, got %q", result.PGPProtectedSubject)
	}
	if !result.PGPVerified {
		t.Fatal("expected signature to verify against the known contact key")
	}
	if result.PGPSignerFingerprint != sender.Fingerprint {
		t.Fatalf("signer fingerprint mismatch: got %s want %s", result.PGPSignerFingerprint, sender.Fingerprint)
	}
}

func TestDecryptPGPMessageContentNoIdentityConfigured(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	content := imapadapter.MessageContent{PGPEncryptedPayload: "-----BEGIN PGP MESSAGE-----\nbogus\n-----END PGP MESSAGE-----"}
	result := srv.decryptPGPMessageContent(userID, "sender@example.com", content)
	if result.PGPDecryptError == "" {
		t.Fatal("expected a decrypt error when no pgp identity is configured")
	}
}

// extractArmoredDetachedSignature is a test-only helper that pulls the
// armored "-----BEGIN PGP SIGNATURE-----...-----END PGP SIGNATURE-----" block
// out of a full multipart/signed envelope (as pgpmail.SignMIME produces),
// mirroring pgpDetectSignature's content-sniffing technique.
func extractArmoredDetachedSignature(t *testing.T, signed []byte) string {
	t.Helper()
	s := string(signed)
	start := strings.Index(s, "-----BEGIN PGP SIGNATURE-----")
	if start == -1 {
		t.Fatal("expected an armored signature block in the signed envelope")
	}
	end := strings.Index(s[start:], "-----END PGP SIGNATURE-----") + len("-----END PGP SIGNATURE-----")
	return s[start : start+end]
}

func TestVerifySignedOnlyMessageContentRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	sender, err := pgpmail.GenerateIdentity("Sender", "sender@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	contactsStore, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Sender",
		Emails:        []contacts.ContactValue{{Value: "sender@example.com"}},
		PGPKey:        sender.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert contact: %v", err)
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
	armoredSig := extractArmoredDetachedSignature(t, signed)

	// The exact bytes VerifyDetached must be given to succeed are the signed
	// MIME part as SignMIME produced it: the Content-Type and
	// Content-Transfer-Encoding header lines plus the body, byte-identical to
	// what buildSignedEnvelope wrapped (see pgpmail.SignMIME/splitMessage).
	// This mirrors the "verification succeeds when the exact signed bytes are
	// available" case; a real goimap-parsed inbox body drops those header
	// lines, which is the documented best-effort gap
	// verifySignedOnlyMessageContent's doc comment describes.
	//
	// The body is base64 because mailmsg.Message.Build emits every body that
	// way. Spelled out structurally — headers, blank line, one wrapped base64
	// line, trailing CRLF — rather than as a transcribed literal, so a change
	// to the framing fails here instead of being absorbed by a hand-copied
	// blob.
	exactSignedContent := "Content-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte("trust me")) + "\r\n"

	t.Run("verifies against the exact signed bytes", func(t *testing.T) {
		content := imapadapter.MessageContent{Body: exactSignedContent, PGPSignaturePayload: armoredSig}
		result := srv.verifySignedOnlyMessageContent(userID, "sender@example.com", content)

		if !result.PGPSigned {
			t.Fatal("expected PGPSigned to be true")
		}
		if result.PGPSignaturePayload != "" {
			t.Fatal("expected PGPSignaturePayload to be cleared after verification")
		}
		if !result.PGPVerified {
			t.Fatal("expected signature to verify against the known contact key")
		}
		if result.PGPSignerFingerprint != sender.Fingerprint {
			t.Fatalf("signer fingerprint mismatch: got %s want %s", result.PGPSignerFingerprint, sender.Fingerprint)
		}
	})

	t.Run("best-effort: a body that doesn't byte-match leaves it unverified, not erroring", func(t *testing.T) {
		content := imapadapter.MessageContent{Body: "trust me", PGPSignaturePayload: armoredSig}
		result := srv.verifySignedOnlyMessageContent(userID, "sender@example.com", content)

		if !result.PGPSigned {
			t.Fatal("expected PGPSigned to stay true even when verification can't confirm the signature")
		}
		if result.PGPVerified {
			t.Fatal("expected PGPVerified to be false when the body doesn't byte-match the signed content")
		}
	})
}

func TestVerifySignedOnlyMessageContentUnknownSigner(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	stranger, err := pgpmail.GenerateIdentity("Stranger", "stranger@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	plaintext := mailmsg.Message{
		From:    "stranger@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Signed only",
		Body:    "trust me",
		Mode:    "plain",
	}.Build()
	signed, err := pgpmail.SignMIME(plaintext, stranger)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}
	armoredSig := extractArmoredDetachedSignature(t, signed)

	content := imapadapter.MessageContent{
		Body:                "Content-Type: text/plain; charset=UTF-8\r\n\r\ntrust me",
		PGPSignaturePayload: armoredSig,
	}
	result := srv.verifySignedOnlyMessageContent(userID, "sender@example.com", content)
	if !result.PGPSigned {
		t.Fatal("expected PGPSigned to be true")
	}
	if result.PGPVerified {
		t.Fatal("expected PGPVerified to be false when the signer isn't a known contact")
	}
}

// TestServerCustodyVerificationIsBoundToSender is run-7 finding F3, the
// server-side remainder of run-4's "signature verified with no key↔sender
// binding".
//
// The run-4 fix was applied to the browser only. This path kept offering
// allKnownPGPKeys — every contact key in the book — to DecryptMIME, which takes
// no address and so reports "some offered key signed this". Any contact key
// therefore verified any From, and PGPVerified drove the same green badge.
func TestServerCustodyVerificationIsBoundToSender(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	recipient, err := pgpmail.GenerateIdentity("Recipient", "recipient@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := recipient.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, recipient.Fingerprint, recipient.KeyID, recipient.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	attacker, aerr := pgpmail.GenerateIdentity("Mallory", "mallory@evil.example")
	if err := aerr; err != nil {
		t.Fatalf("GenerateIdentity attacker: %v", err)
	}
	contactsStore, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	// The attacker's key is in the address book under the attacker's OWN address,
	// which is exactly what the Autocrypt harvest does automatically.
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Mallory",
		Emails:        []contacts.ContactValue{{Value: "mallory@evil.example"}},
		PGPKey:        attacker.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert contact: %v", err)
	}

	// Signed by Mallory, encrypted to the victim, claiming to be from Bob.
	plaintext := mailmsg.Message{
		From:    "bob@example.com",
		To:      []string{"recipient@example.com"},
		Subject: "Wire the money",
		Body:    "account details attached",
		Mode:    "plain",
	}.Build()
	encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, attacker)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}

	content := imapadapter.MessageContent{PGPEncryptedPayload: extractArmoredPGPPayload(t, encrypted)}
	result := srv.decryptPGPMessageContent(userID, "bob@example.com", content)

	if result.PGPDecryptError != "" {
		t.Fatalf("unexpected decrypt error: %s", result.PGPDecryptError)
	}
	if result.PGPVerified {
		t.Fatal("a key held for mallory@evil.example verified a message claiming to be from " +
			"bob@example.com; the badge would read 'signature verified' under a spoofed sender")
	}
}
