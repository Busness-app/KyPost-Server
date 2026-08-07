package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
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

// TestUnreadMessageVerificationUsesSenderBindingAddress is the
// UnreadMessage/server-protected-account counterpart of
// TestOverviewFromEmailSenderBindingAddress (internal/adapters/imap):
// decryptPGPUnreadMessage and verifySignedOnlyUnreadMessage must resolve
// signerKeysForSender from UnreadMessage.SenderBindingAddress, not
// UnreadMessage.Sender. Sender is the (possibly multi-mailbox, possibly
// nondeterministically-rendered) display string; SenderBindingAddress is the
// deterministic, fail-closed twin imapadapter.overviewFromEmail computes via
// singleMailboxSender, and is "" for exactly the multi-mailbox From this test
// simulates.
//
// Sender below is deliberately set to a single, cleanly-parseable address —
// NOT a realistic "Name <a>, Name2 <b>" multi-mailbox rendering. A realistic
// rendering already fails closed inside senderAddrSpec regardless of which
// field a caller reads (see TestSenderAddrSpecMultiAddressFailsClosed: a
// syntactically well-formed multi-address string returns "" on its own), so
// it would pass this test whether or not the fix here regressed. Only a
// single clean address in Sender can distinguish "the call site reads
// SenderBindingAddress" from "the call site still reads Sender" — which is
// the exact thing this fix changed.
func TestUnreadMessageVerificationUsesSenderBindingAddress(t *testing.T) {
	const attackerAddress = "attacker@evil.example"

	setUpAttackerContact := func(t *testing.T, store *contacts.Store) *pgpmail.Identity {
		t.Helper()
		attacker, err := pgpmail.GenerateIdentity("Attacker", attackerAddress)
		if err != nil {
			t.Fatalf("GenerateIdentity: %v", err)
		}
		if _, err := store.Upsert(contacts.Contact{
			FormattedName: "Attacker",
			Emails:        []contacts.ContactValue{{Value: attackerAddress}},
			PGPKey:        attacker.ArmoredPublicKey,
		}); err != nil {
			t.Fatalf("Upsert contact: %v", err)
		}
		return attacker
	}

	t.Run("decryptPGPUnreadMessage", func(t *testing.T) {
		userID, recipient, contactsStore, srv := pgpVictimWithIdentity(t)
		attacker := setUpAttackerContact(t, contactsStore)

		plaintext := mailmsg.Message{
			From:    attackerAddress,
			To:      []string{"recipient@example.com"},
			Subject: "hello",
			Body:    "hello",
			Mode:    "plain",
		}.Build()
		encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, attacker)
		if err != nil {
			t.Fatalf("EncryptMIME: %v", err)
		}

		msg := imapadapter.UnreadMessage{
			// Same address the attacker's key is bound under — if
			// decryptPGPUnreadMessage reads Sender instead of
			// SenderBindingAddress, it verifies.
			Sender:               attackerAddress,
			SenderBindingAddress: "",
			PGPEncryptedPayload:  extractArmoredPGPPayload(t, encrypted),
		}
		result := srv.decryptPGPUnreadMessage(userID, msg)
		if result.PGPDecryptError != "" {
			t.Fatalf("unexpected decrypt error: %s", result.PGPDecryptError)
		}
		if result.PGPVerified {
			t.Fatal("SenderBindingAddress is empty (multi-mailbox fail-closed), but the message verified — " +
				"decryptPGPUnreadMessage is binding against Sender instead of SenderBindingAddress")
		}
	})

	// TestUnreadMessageVerificationUsesSenderBindingAddress's other subtests
	// are all negative (SenderBindingAddress == "" must not verify). None of
	// them notice an implementation that never binds anything at all — e.g.
	// decryptPGPUnreadMessage hardcoding "" instead of reading
	// SenderBindingAddress would pass every one of them. This proves the
	// positive direction: a real SenderBindingAddress must still let a
	// legitimately signed/encrypted message verify.
	t.Run("decryptPGPUnreadMessage verifies when SenderBindingAddress is populated", func(t *testing.T) {
		userID, recipient, contactsStore, srv := pgpVictimWithIdentity(t)
		const senderAddress = "sender@example.com"
		sender, err := pgpmail.GenerateIdentity("Sender", senderAddress)
		if err != nil {
			t.Fatalf("GenerateIdentity: %v", err)
		}
		if _, err := contactsStore.Upsert(contacts.Contact{
			FormattedName: "Sender",
			Emails:        []contacts.ContactValue{{Value: senderAddress}},
			PGPKey:        sender.ArmoredPublicKey,
		}); err != nil {
			t.Fatalf("Upsert contact: %v", err)
		}

		plaintext := mailmsg.Message{
			From:    senderAddress,
			To:      []string{"recipient@example.com"},
			Subject: "hello",
			Body:    "hello",
			Mode:    "plain",
		}.Build()
		encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, sender)
		if err != nil {
			t.Fatalf("EncryptMIME: %v", err)
		}

		msg := imapadapter.UnreadMessage{
			Sender:               "Sender <sender@example.com>",
			SenderBindingAddress: "Sender <sender@example.com>",
			PGPEncryptedPayload:  extractArmoredPGPPayload(t, encrypted),
		}
		result := srv.decryptPGPUnreadMessage(userID, msg)
		if result.PGPDecryptError != "" {
			t.Fatalf("unexpected decrypt error: %s", result.PGPDecryptError)
		}
		if !result.PGPSigned || !result.PGPVerified {
			t.Fatalf("expected a legitimately signed message with a populated SenderBindingAddress to verify, got PGPSigned=%v PGPVerified=%v",
				result.PGPSigned, result.PGPVerified)
		}
	})

	t.Run("verifySignedOnlyUnreadMessage", func(t *testing.T) {
		userID, _, contactsStore, srv := pgpVictimWithIdentity(t)
		attacker := setUpAttackerContact(t, contactsStore)

		plaintext := mailmsg.Message{
			From:    attackerAddress,
			To:      []string{"recipient@example.com"},
			Subject: "Signed only",
			Body:    "trust me",
			Mode:    "plain",
		}.Build()
		signed, err := pgpmail.SignMIME(plaintext, attacker)
		if err != nil {
			t.Fatalf("SignMIME: %v", err)
		}
		armoredSig := extractArmoredDetachedSignature(t, signed)
		// Same exact-bytes requirement TestVerifySignedOnlyMessageContentRoundTrip
		// documents — the signed MIME part as SignMIME produced it.
		exactSignedContent := "Content-Type: text/plain; charset=UTF-8\r\n" +
			"Content-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte("trust me")) + "\r\n"

		msg := imapadapter.UnreadMessage{
			Body:                 exactSignedContent,
			PGPSignaturePayload:  armoredSig,
			Sender:               attackerAddress,
			SenderBindingAddress: "",
		}
		result := srv.verifySignedOnlyUnreadMessage(userID, msg)
		if result.PGPVerified {
			t.Fatal("SenderBindingAddress is empty (multi-mailbox fail-closed), but the signature verified — " +
				"verifySignedOnlyUnreadMessage is binding against Sender instead of SenderBindingAddress")
		}
	})

	// Positive counterpart of the subtest above — see the comment on
	// "decryptPGPUnreadMessage verifies when SenderBindingAddress is
	// populated" for why a purely negative assertion isn't enough here.
	t.Run("verifySignedOnlyUnreadMessage verifies when SenderBindingAddress is populated", func(t *testing.T) {
		userID, _, contactsStore, srv := pgpVictimWithIdentity(t)
		const senderAddress = "sender@example.com"
		sender, err := pgpmail.GenerateIdentity("Sender", senderAddress)
		if err != nil {
			t.Fatalf("GenerateIdentity: %v", err)
		}
		if _, err := contactsStore.Upsert(contacts.Contact{
			FormattedName: "Sender",
			Emails:        []contacts.ContactValue{{Value: senderAddress}},
			PGPKey:        sender.ArmoredPublicKey,
		}); err != nil {
			t.Fatalf("Upsert contact: %v", err)
		}

		plaintext := mailmsg.Message{
			From:    senderAddress,
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
		exactSignedContent := "Content-Type: text/plain; charset=UTF-8\r\n" +
			"Content-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte("trust me")) + "\r\n"

		msg := imapadapter.UnreadMessage{
			Body:                 exactSignedContent,
			PGPSignaturePayload:  armoredSig,
			Sender:               "Sender <sender@example.com>",
			SenderBindingAddress: "Sender <sender@example.com>",
		}
		result := srv.verifySignedOnlyUnreadMessage(userID, msg)
		if !result.PGPSigned || !result.PGPVerified {
			t.Fatalf("expected a legitimately signed message with a populated SenderBindingAddress to verify, got PGPSigned=%v PGPVerified=%v",
				result.PGPSigned, result.PGPVerified)
		}
	})
}

// pgpVictimWithIdentity sets up a test user holding a server-readable identity
// and returns the user id, the identity, and the user's contacts store — the
// four-step preamble every binding test below needs.
func pgpVictimWithIdentity(t *testing.T) (string, *pgpmail.Identity, *contacts.Store, *Server) {
	t.Helper()
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
	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	return userID, recipient, store, srv
}

// TestSecondUserIDDoesNotVerify is run-8 finding F1: the THIRD bypass of the
// same badge, by a third mechanism.
//
// run-7's fix replaced a raw-substring User-ID test with a parsed-email one. It
// changed the comparison and not the trust decision, which still asked "does any
// User ID on any key in the book carry the sender's address". A User ID is
// self-asserted and a key may carry arbitrarily many, so one key with two of
// them defeats it — and this needs no crafted string or packet surgery, just
// GenerateIdentity's own variadic additionalEmails.
//
// The reader here holds Bob's genuine key as well, which is the case that makes
// this more than a nuisance: the attacker's signature won anyway, and the UI
// suppresses the signer fingerprint on exactly the verified path.
func TestSecondUserIDDoesNotVerify(t *testing.T) {
	userID, recipient, contactsStore, srv := pgpVictimWithIdentity(t)

	// One key, two User IDs. The harvest validates it against Mallory's From,
	// matches on the first, and pins it under her own contact.
	attacker, err := pgpmail.GenerateIdentity("Mallory", "mallory@evil.example", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity attacker: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Mallory",
		Emails:        []contacts.ContactValue{{Value: "mallory@evil.example"}},
		PGPKey:        attacker.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert attacker contact: %v", err)
	}

	bob, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	if _, err := contactsStore.Upsert(contacts.Contact{
		FormattedName:  "Bob",
		Emails:         []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:         bob.ArmoredPublicKey,
		PGPKeyVerified: true,
	}); err != nil {
		t.Fatalf("Upsert bob contact: %v", err)
	}

	// Sanity check on the premise: the attacker's key really does carry Bob's
	// address as a User ID, so the old any-UID binding would have offered it.
	if !pgpmail.ArmoredKeyCertifiesAddress(attacker.ArmoredPublicKey, "bob@example.com") {
		t.Fatal("premise broken: the attacker key does not carry bob@example.com as a User ID")
	}

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
		t.Fatalf("a key filed under mallory@evil.example verified a message claiming to be from "+
			"bob@example.com, on the strength of a User ID it wrote for itself (signer %s, real Bob %s)",
			result.PGPSignerFingerprint, bob.Fingerprint)
	}
}

// TestSenderBindingAcceptsADisplayNameFrom is run-8 finding F3: run-7's binding
// was fed imap.Overview.Sender, which is e.From.String() — `Name <addr>`
// whenever a display name is present. Compared against a parsed User-ID email
// that matched nothing, so the candidate set came back empty, DecryptMIME left
// Signed as well as Verified false, and the signature indicator DISAPPEARED for
// legitimately signed mail from any named correspondent.
//
// The bare-From form an attacker chooses was the only one that still went green.
func TestSenderBindingAcceptsADisplayNameFrom(t *testing.T) {
	userID, recipient, contactsStore, srv := pgpVictimWithIdentity(t)

	sender, err := pgpmail.GenerateIdentity("Sender", "sender@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity sender: %v", err)
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

	// Every form go-imap actually emits, including the quoted one a comma in
	// the display name forces.
	for _, from := range []string{
		"sender@example.com",
		"<sender@example.com>",
		"Sender <sender@example.com>",
		"Sender Person <sender@example.com>",
		`"Person, Sender" <sender@example.com>`,
	} {
		t.Run(from, func(t *testing.T) {
			content := imapadapter.MessageContent{PGPEncryptedPayload: payload}
			result := srv.decryptPGPMessageContent(userID, from, content)
			if result.PGPDecryptError != "" {
				t.Fatalf("unexpected decrypt error: %s", result.PGPDecryptError)
			}
			if !result.PGPSigned {
				t.Fatalf("From %q: PGPSigned false — no signer key was offered, so the "+
					"indicator vanishes for legitimately signed mail", from)
			}
			if !result.PGPVerified {
				t.Fatalf("From %q: PGPVerified false for the sender's own key", from)
			}
		})
	}
}

// TestSignerKeysRequireTheContactPin covers the other half of the F1 anchor: a
// key swapped under an existing contact without updating its TOFU pin must not
// inherit that contact's binding. An absent pin is a legacy contact, not a
// mismatch, and stays usable.
func TestSignerKeysRequireTheContactPin(t *testing.T) {
	_, _, contactsStore, _ := pgpVictimWithIdentity(t)

	real, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	swapped, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	created, err := contactsStore.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:        real.ArmoredPublicKey,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got := signerKeysForSender(contactsStore, "bob@example.com"); len(got) != 1 {
		t.Fatalf("pinned key should be offered, got %d keys", len(got))
	}

	// The stored key changes; the pin still names the old one.
	created.PGPKey = swapped.ArmoredPublicKey
	if _, err := contactsStore.Upsert(created); err != nil {
		t.Fatalf("Upsert swapped: %v", err)
	}
	if got := signerKeysForSender(contactsStore, "bob@example.com"); len(got) != 0 {
		t.Fatalf("a key that does not match the contact's pin was offered as a signer (%d keys)", len(got))
	}
}

// Most keys are Autocrypt-harvested. If the wire cannot distinguish them
// from a fingerprint-confirmed key, the client can only show one badge,
// and it would claim identity on evidence that shows only continuity.
func TestBoundSignerKeysCarriesProvenance(t *testing.T) {
	_, _, store, _ := pgpVictimWithIdentity(t)

	key, err := pgpmail.GenerateIdentity("Shared", "shared@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if _, err := store.Upsert(contacts.Contact{
		Emails:            []contacts.ContactValue{{Value: "confirmed@example.com"}},
		PGPKey:            key.ArmoredPublicKey,
		PGPKeyFingerprint: key.Fingerprint,
		PGPKeySource:      "qr",
		PGPKeyVerified:    true,
	}); err != nil {
		t.Fatalf("Upsert confirmed contact: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		Emails:            []contacts.ContactValue{{Value: "harvested@example.com"}},
		PGPKey:            key.ArmoredPublicKey,
		PGPKeyFingerprint: key.Fingerprint,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
		PGPKeyVerified:    false,
	}); err != nil {
		t.Fatalf("Upsert harvested contact: %v", err)
	}

	got := boundSignerKeys(store)

	byAddr := map[string]boundSignerKey{}
	for _, k := range got {
		byAddr[k.Addresses[0]] = k
	}
	if c := byAddr["confirmed@example.com"]; !c.Verified || c.Source != "qr" {
		t.Fatalf("confirmed key lost its provenance: %+v", c)
	}
	if h := byAddr["harvested@example.com"]; h.Verified || h.Source != contacts.PGPSourceAutocrypt {
		t.Fatalf("harvested key misreported: %+v", h)
	}
}

// A key that no longer matches its TOFU pin is the one alarm TOFU exists
// to raise. Dropping the contact made it arrive as "no key bound to this
// sender", which is what an ordinary new correspondent looks like.
func TestBoundSignerKeysMarksPinConflictInsteadOfDropping(t *testing.T) {
	_, _, store, _ := pgpVictimWithIdentity(t)

	key, err := pgpmail.GenerateIdentity("Rotated", "rotated@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if _, err := store.Upsert(contacts.Contact{
		Emails:            []contacts.ContactValue{{Value: "rotated@example.com"}},
		PGPKey:            key.ArmoredPublicKey,
		PGPKeyFingerprint: "0000NOTTHEPINNEDFINGERPRINT0000",
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert rotated contact: %v", err)
	}

	got := boundSignerKeys(store)

	if len(got) != 1 {
		t.Fatalf("want the conflicted contact reported, got %d entries", len(got))
	}
	if !got[0].Conflict {
		t.Fatal("a pin mismatch was not marked as a conflict")
	}
	if got[0].PublicKey != "" {
		t.Fatal("a conflicted key must not ship key material; it can never be trusted to verify")
	}
}

// The client no longer parses From at all, so this narrowing IS the binding.
// A key bound to some OTHER contact must never reach a client that is
// displaying this sender.
func TestBoundSignerKeysForSenderExcludesOtherContacts(t *testing.T) {
	_, _, store, _ := pgpVictimWithIdentity(t)

	bob, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
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
	if _, err := store.Upsert(contacts.Contact{
		Emails:       []contacts.ContactValue{{Value: "eve@evil.example"}},
		PGPKey:       eve.ArmoredPublicKey,
		PGPKeySource: contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert eve contact: %v", err)
	}

	got := boundSignerKeysForSender(store, "bob@example.com")

	if len(got) != 1 {
		t.Fatalf("want only the sender's key, got %d: %+v", len(got), got)
	}
	if got[0].Addresses[0] != "bob@example.com" || !got[0].Verified {
		t.Fatalf("wrong key or lost provenance: %+v", got[0])
	}
}

// The RFC 5322 comment attack, at the layer that now owns the decision.
// Go's mail.ParseAddressList binds the real mailbox; the decoy inside the
// comment must not select Eve's key.
func TestBoundSignerKeysForSenderIgnoresAnAddressHiddenInAComment(t *testing.T) {
	_, _, store, _ := pgpVictimWithIdentity(t)

	bob, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
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
	if _, err := store.Upsert(contacts.Contact{
		Emails:       []contacts.ContactValue{{Value: "eve@evil.example"}},
		PGPKey:       eve.ArmoredPublicKey,
		PGPKeySource: contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert eve contact: %v", err)
	}

	resolved := senderAddrSpec("Bob Smith (Eve <eve@evil.example>) <bob@example.com>")
	got := boundSignerKeysForSender(store, resolved)

	if resolved != "bob@example.com" {
		t.Fatalf("senderAddrSpec bound the decoy: %q", resolved)
	}
	if len(got) != 1 || got[0].Addresses[0] != "bob@example.com" {
		t.Fatalf("comment decoy selected the wrong key: %+v", got)
	}
}

// A conflicted key for THIS sender must still be reported, with no key
// material — it is the only way the client can say the key changed.
// A second contact's conflict must not leak into this sender's result: a
// narrowing that reports every conflicted key regardless of address would
// tell the client "bob's key changed" when it was actually eve's, a false
// TOFU alarm attributed to the wrong party. Review round 1 finding #3 —
// hoisting `if k.Conflict { out = append(out, k); continue }` above the
// address-match loop passed all three original assertions here because there
// was only ever one contact in play.
func TestBoundSignerKeysForSenderStillReportsAConflict(t *testing.T) {
	_, _, store, _ := pgpVictimWithIdentity(t)

	rotated, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		Emails:            []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:            rotated.ArmoredPublicKey,
		PGPKeyFingerprint: "0000NOTTHEPINNEDFINGERPRINT0000",
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert bob contact: %v", err)
	}

	// A second, unrelated contact whose key ALSO conflicts its pin. Its
	// conflict belongs to eve@evil.example and must never appear in a
	// lookup for bob@example.com.
	rotatedEve, err := pgpmail.GenerateIdentity("Eve", "eve@evil.example")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		Emails:            []contacts.ContactValue{{Value: "eve@evil.example"}},
		PGPKey:            rotatedEve.ArmoredPublicKey,
		PGPKeyFingerprint: "1111NOTTHEPINNEDFINGERPRINT1111",
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	}); err != nil {
		t.Fatalf("Upsert eve contact: %v", err)
	}

	got := boundSignerKeysForSender(store, "bob@example.com")

	if len(got) != 1 || !got[0].Conflict {
		t.Fatalf("want a conflict marker, got %+v", got)
	}
	if got[0].Addresses[0] != "bob@example.com" {
		t.Fatalf("a conflict for a different contact leaked into bob's result: %+v", got)
	}
	if got[0].PublicKey != "" {
		t.Fatal("a conflicted key must ship no key material")
	}
}

func TestSenderAddrSpecCorpus(t *testing.T) {
	// corpus lives at repo root testdata/from-corpus.json
	data, err := os.ReadFile("../../../testdata/from-corpus.json")
	if err != nil {
		data, err = os.ReadFile("../../testdata/from-corpus.json")
		if err != nil {
			data, err = os.ReadFile("testdata/from-corpus.json")
			if err != nil {
				t.Fatalf("read from-corpus.json: %v", err)
			}
		}
	}
	// parse the corpus directly to avoid adding a dependency on the corpus shape
	type corpusCase struct {
		Name   string `json:"name"`
		From   string `json:"from"`
		Expect string `json:"expect"`
	}
	var corpus struct {
		Cases []corpusCase `json:"cases"`
	}
	// raw JSON has $comment first — unmarshal with a map to skip it
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal corpus raw: %v", err)
	}
	if err := json.Unmarshal(raw["cases"], &corpus.Cases); err != nil {
		t.Fatalf("unmarshal cases: %v", err)
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := senderAddrSpec(c.From)
			if got != c.Expect {
				t.Fatalf("senderAddrSpec(%q) = %q, want %q", c.From, got, c.Expect)
			}
		})
	}
}

func TestSenderAddrSpecMultiAddressFailsClosed(t *testing.T) {
	if got := senderAddrSpec("eve@evil.example, bob@example.com"); got != "" {
		t.Fatalf("multi-address From must fail closed, got %q", got)
	}
	if got := senderAddrSpec("Bob <bob@example.com>, Eve <eve@evil.example>"); got != "" {
		t.Fatalf("multi-address From with display names must fail closed, got %q", got)
	}
}
