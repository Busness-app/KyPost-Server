package api

import (
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

// A server-custody encrypted send used to store its Sent copy as cleartext:
// finishMailSend rebuilt the message from req.Subject/req.Body and APPENDed
// that. Two things were wrong with it.
//
// The message the recipient got was ciphertext; the copy the sender kept was
// not, so the plaintext and the real subject of every encrypted message sat on
// the IMAP store anyway. And because the web reader derives its "PGP:
// encrypted" badge by sniffing the stored message for a PGP payload
// (imap.pgpEnvelopePayload -> decryptPGPMessageContent), a plaintext copy carries
// no evidence that encryption happened — so the Sent folder rendered an
// encrypted send and a cleartext send identically, with no indicator on either.
//
// The client-custody path already solved both by encrypting the copy to the
// sender's own key in the browser (sentCopyDraft, run4_sent_copy_test.go).
// These tests pin the server-custody equivalent.

// extractArmoredPGPMessage pulls the armored block out of a PGP/MIME message so
// a test can decrypt it, without depending on the MIME walk the receive path
// uses.
func extractArmoredPGPMessage(t *testing.T, raw []byte) string {
	t.Helper()
	const begin = "-----BEGIN PGP MESSAGE-----"
	const end = "-----END PGP MESSAGE-----"
	s := string(raw)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 {
		t.Fatalf("no armored PGP message in:\n%s", s)
	}
	return s[i : j+len(end)]
}

func TestEncryptedSentCopyHidesTheBodyAndSubjectFromTheStore(t *testing.T) {
	alice, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	msg := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Quarterly numbers",
		Body:    "revenue fell 40%",
		Mode:    "plain",
	}.Build()

	copyBytes, err := encryptedSentCopy(msg, alice.ArmoredPublicKey, nil)
	if err != nil {
		t.Fatalf("encryptedSentCopy: %v", err)
	}
	if len(copyBytes) == 0 {
		t.Fatal("no Sent copy was produced for a sender who has a key")
	}
	if strings.Contains(string(copyBytes), "revenue fell 40%") {
		t.Fatal("the body is in the bytes appended to Sent")
	}
	if strings.Contains(string(copyBytes), "Quarterly numbers") {
		t.Fatal("the real subject is in the bytes appended to Sent")
	}
	if !strings.Contains(string(copyBytes), pgpmail.OuterPlaceholderSubject) {
		t.Fatalf("outer subject is not the placeholder:\n%s", copyBytes)
	}
}

// The copy is worth keeping only if the sender can still read it. This is the
// half a "store nothing at all" fix would fail.
func TestEncryptedSentCopyStillOpensWithTheSendersKey(t *testing.T) {
	alice, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	msg := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Quarterly numbers",
		Body:    "revenue fell 40%",
		Mode:    "plain",
	}.Build()

	copyBytes, err := encryptedSentCopy(msg, alice.ArmoredPublicKey, nil)
	if err != nil {
		t.Fatalf("encryptedSentCopy: %v", err)
	}

	result, err := pgpmail.DecryptMIME(extractArmoredPGPMessage(t, copyBytes), alice, nil)
	if err != nil {
		t.Fatalf("the sender cannot decrypt their own Sent copy: %v", err)
	}
	body, _, _, err := pgpmail.ParseContent(result.Content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if !strings.Contains(body, "revenue fell 40%") {
		t.Fatalf("decrypted body lost the message: %q", body)
	}
	subject, ok := pgpmail.ExtractProtectedSubject(result.Content)
	if !ok || subject != "Quarterly numbers" {
		t.Fatalf("protected subject = %q (ok=%v), want the real subject", subject, ok)
	}
}

// Encrypting to recipients does not require a key of your own — handleMailSend
// only insists on one for signing. Such a sender has nothing to encrypt a Sent
// copy to, so there is no copy to make, and the caller falls back to today's
// plaintext one rather than losing the copy entirely.
func TestEncryptedSentCopySkippedWhenTheSenderHasNoKey(t *testing.T) {
	copyBytes, err := encryptedSentCopy([]byte("From: a@b\r\nSubject: x\r\n\r\nbody"), "", nil)
	if err != nil {
		t.Fatalf("encryptedSentCopy: %v", err)
	}
	if copyBytes != nil {
		t.Fatal("a Sent copy was produced with no key to encrypt it to")
	}
}

func TestSentCopyDraftAppendsTheEncryptedCopyVerbatim(t *testing.T) {
	const ciphertext = "From: alice@example.com\r\nSubject: [Encrypted] Email Sent by KyPost\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nx\r\n-----END PGP MESSAGE-----\r\n"

	draft := sentCopyDraftForSend(
		mailRequest{Subject: "Quarterly numbers", Body: "revenue fell 40%", Mode: "plain"},
		[]string{"bob@example.com"}, []string{"carol@example.com"}, []string{"dave@example.com"},
		[]byte(ciphertext),
	)

	if string(draft.Raw) != ciphertext {
		t.Fatalf("the ciphertext was not appended verbatim:\n%s", draft.Raw)
	}
	// Rebuilding from Subject/Body would wrap a complete PGP/MIME message in a
	// fresh envelope, and nothing would decrypt it.
	if draft.Body != "" {
		t.Fatalf("Body should be empty when Raw is set, got %q", draft.Body)
	}
	if draft.Subject == "Quarterly numbers" {
		t.Fatal("the real subject was carried on the draft alongside the ciphertext")
	}
	// Recipients stay in the clear: the Sent listing is unusable without them.
	//
	// These fields serve the PLAINTEXT branch only. SaveSent ignores every one
	// of them once Raw is set (client_append.go), so asserting on them proves
	// nothing about what reaches IMAP for an encrypted copy — see
	// TestEncryptedSentCopyKeepsBCC, which reads the bytes instead.
	if len(draft.To) != 1 || len(draft.CC) != 1 || len(draft.BCC) != 1 {
		t.Fatalf("recipients were dropped: %v / %v / %v", draft.To, draft.CC, draft.BCC)
	}
}

// SaveSent takes draft.Raw verbatim and ignores draft.To/CC/BCC entirely once
// it is set. The blind recipients therefore have to be inside those bytes, and
// they were not: the copy was built by encrypting the DELIVERED message, which
// omits Bcc on purpose so no recipient can see who else received it. The result
// was a Sent folder where encrypted sends silently lost their BCC history while
// plaintext ones kept it.
func TestEncryptedSentCopyKeepsBCC(t *testing.T) {
	alice, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	source := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		CC:      []string{"carol@example.com"},
		BCC:     []string{"dave@example.com"},
		Subject: "Quarterly numbers",
		Body:    "revenue fell 40%",
		Mode:    "plain",
	}.Build()

	copyBytes, err := encryptedSentCopy(source, alice.ArmoredPublicKey, nil)
	if err != nil {
		t.Fatalf("encryptedSentCopy: %v", err)
	}

	headers := string(copyBytes)
	if i := strings.Index(headers, "-----BEGIN PGP MESSAGE-----"); i >= 0 {
		headers = headers[:i]
	}
	if !strings.Contains(headers, "dave@example.com") {
		t.Fatalf("the Sent copy does not record its blind recipient:\n%s", headers)
	}
	if !strings.Contains(headers, "bob@example.com") || !strings.Contains(headers, "carol@example.com") {
		t.Fatalf("the Sent copy lost To or Cc:\n%s", headers)
	}
	// Still a real encrypted copy, not a plaintext one that happens to list
	// everybody.
	if strings.Contains(string(copyBytes), "revenue fell 40%") {
		t.Fatal("the body is in the bytes appended to Sent")
	}
	if strings.Contains(headers, "Quarterly numbers") {
		t.Fatal("the real subject is on the outer envelope")
	}
}

func TestSentCopyDraftKeepsPlaintextWhenThereIsNoEncryptedCopy(t *testing.T) {
	draft := sentCopyDraftForSend(
		mailRequest{Subject: "Lunch", Body: "one o'clock", Mode: "plain"},
		[]string{"bob@example.com"}, nil, nil,
		nil,
	)

	if len(draft.Raw) != 0 {
		t.Fatal("an unencrypted send produced a Raw draft")
	}
	if draft.Subject != "Lunch" || draft.Body != "one o'clock" {
		t.Fatalf("the plaintext copy lost its content: %+v", draft)
	}
}

// Compile-time proof the draft shape is what SaveSent takes.
var _ = func(d imapadapter.DraftMessage) imapadapter.DraftMessage { return d }

// testUserWithServerKey gives the first (admin) user a server-readable PGP
// identity and returns their ID alongside it — the custody mode
// handleMailSend's encrypt path requires, since a client-protected account is
// refused with 409 before any of this runs.
func testUserWithServerKey(t *testing.T, srv *Server) (string, *pgpmail.Identity) {
	t.Helper()
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("users.List: %v (%d users)", err, len(all))
	}
	id := all[0].ID
	identity, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := identity.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(id, "FPR", "KEYID", identity.ArmoredPublicKey, sealed, "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	return id, identity
}

func TestSentCopyForEncryptedSendIsEncryptedToTheAccountKey(t *testing.T) {
	srv := newTestServer(t)
	userID, _ := testUserWithServerKey(t, srv)

	msg := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Quarterly numbers",
		Body:    "revenue fell 40%",
		Mode:    "plain",
	}.Build()

	copyBytes, warning := srv.sentCopyForSend(userID, msg, mailRequest{Encrypt: true, Subject: "Quarterly numbers", Body: "revenue fell 40%"}, nil)

	if len(copyBytes) == 0 {
		t.Fatal("an encrypted send stored a cleartext Sent copy")
	}
	if strings.Contains(string(copyBytes), "revenue fell 40%") {
		t.Fatal("the body is in the bytes appended to Sent")
	}
	if warning != "" {
		t.Fatalf("a successful encrypted copy warned the sender anyway: %q", warning)
	}
}

// The degrade to a plaintext Sent copy must reach the person who ticked
// "encrypt". A log line on the server is not an answer to a user, and the whole
// point of the fallback is that the send still succeeds — so without a warning
// the outcome is indistinguishable from the one they asked for.
func TestSentCopyWarnsWhenItCannotBeEncrypted(t *testing.T) {
	srv := newTestServer(t)

	msg := mailmsg.Message{From: "alice@example.com", To: []string{"bob@example.com"}, Subject: "x", Body: "y", Mode: "plain"}.Build()

	// An account id that does not resolve stands in for the failure modes the
	// caller cannot prevent: an unreadable user store, or a key that will not
	// parse. All of them land on the same branch.
	copyBytes, warning := srv.sentCopyForSend("no-such-user", msg, mailRequest{Encrypt: true}, nil)

	if copyBytes != nil {
		t.Fatal("a copy was produced for an account that could not be read")
	}
	if warning == "" {
		t.Fatal("the Sent copy fell back to plaintext without telling the sender")
	}
	if !strings.Contains(strings.ToLower(warning), "plain text") {
		t.Fatalf("warning does not say what happened: %q", warning)
	}
}

// A sender with no key of their own has not suffered a failure: encrypting to
// recipients never required one. Warning here would cry wolf on every send by
// an account that has never generated a key.
func TestSentCopyDoesNotWarnWhenTheSenderHasNoKey(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("users.List: %v", err)
	}

	msg := mailmsg.Message{From: "alice@example.com", To: []string{"bob@example.com"}, Subject: "x", Body: "y", Mode: "plain"}.Build()

	copyBytes, warning := srv.sentCopyForSend(all[0].ID, msg, mailRequest{Encrypt: true}, nil)

	if copyBytes != nil {
		t.Fatal("a copy was encrypted for an account with no key")
	}
	if warning != "" {
		t.Fatalf("warned about a keyless account, which is not a failure: %q", warning)
	}
}

// An unencrypted send keeps its readable Sent copy. Wrapping it would lock the
// sender out of an outbox they never asked to protect, and would put a "PGP:
// encrypted" badge on a message that went out in the clear — the same
// misreporting in the other direction.
func TestSentCopyForUnencryptedSendIsPlaintext(t *testing.T) {
	srv := newTestServer(t)
	userID, _ := testUserWithServerKey(t, srv)

	msg := mailmsg.Message{From: "alice@example.com", To: []string{"bob@example.com"}, Subject: "Lunch", Body: "one o'clock", Mode: "plain"}.Build()

	if copyBytes, _ := srv.sentCopyForSend(userID, msg, mailRequest{Encrypt: false, Subject: "Lunch", Body: "one o'clock"}, nil); copyBytes != nil {
		t.Fatal("an unencrypted send produced an encrypted Sent copy")
	}
}
