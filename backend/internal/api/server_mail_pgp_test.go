package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

func TestDecodeMailRequestParsesEncryptAndSign(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"to":      "bob@example.com",
		"subject": "hi",
		"body":    "hello",
		"encrypt": true,
		"sign":    true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(body))
	decoded, errMsg, err := decodeMailRequest(req)
	if err != nil {
		t.Fatalf("decodeMailRequest: %v (%s)", err, errMsg)
	}
	if !decoded.Encrypt || !decoded.Sign {
		t.Fatalf("expected Encrypt and Sign both true, got %+v", decoded)
	}
}

func TestFindContactPGPKey(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "Bob@Example.com"}},
		PGPKey:        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	key, ok := findContactPGPKey(store, "bob@example.com")
	if !ok || key == "" {
		t.Fatalf("expected a key for bob@example.com, got ok=%v key=%q", ok, key)
	}

	if _, ok := findContactPGPKey(store, "nobody@example.com"); ok {
		t.Fatal("expected no key for an unknown address")
	}
}

// TestMailSendBlocksSigningWithRevokedIdentity proves the own-identity
// enforcement added in this task: Sign=true must be rejected before any
// network I/O when the sender's own PGP identity is revoked. IMAP/SMTP
// config is written directly (bypassing the network) so the handler gets
// past its precondition checks and reaches the signer-status check; a 400
// response (rather than a 502 from a real send attempt) proves the request
// never reached the network.
func TestMailSendBlocksSigningWithRevokedIdentity(t *testing.T) {
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

	key, err := crypto.PGP().KeyGeneration().AddUserId("Alice", "alice@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := key.GetEntity().Revoke(packet.NoReason, "test revocation", &packet.Config{}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	armored, err := key.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}
	importBody, _ := json.Marshal(map[string]string{
		"armoredPrivateKey": armored,
		"password":          stepUpPassword(t, srv, srv.mustBootstrapUserID(t)),
	})
	importReq := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/import", bytes.NewReader(importBody))
	authRequest(srv, importReq)
	importRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityImport)(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d: %s", importRec.Code, importRec.Body.String())
	}

	sendBody, _ := json.Marshal(map[string]any{
		"to":      "bob@example.com",
		"subject": "hi",
		"body":    "hello",
		"sign":    true,
	})
	sendReq := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(sendBody))
	authRequest(srv, sendReq)
	sendRec := httptest.NewRecorder()
	srv.withAuth(srv.handleMailSend)(sendRec, sendReq)

	if sendRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for signing with a revoked identity, got %d: %s", sendRec.Code, sendRec.Body.String())
	}
}

// TestEncryptSignerOnlyPassesIdentityWhenSignRequested guards against the
// encrypt-implicitly-signs regression: handleMailSend eagerly loads a signer
// identity whenever req.Sign || req.Encrypt is true (so it can also cover
// the sign-only branch and the "signing requires an identity" 400 check),
// but that eagerly loaded identity must never leak into EncryptMIME's signer
// argument unless the caller explicitly asked to sign. Encrypt and Sign are
// independent per-email toggles.
func TestEncryptSignerOnlyPassesIdentityWhenSignRequested(t *testing.T) {
	identity, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	if got := encryptSigner(identity, false); got != nil {
		t.Fatalf("Encrypt=true,Sign=false: expected nil signer even though an identity exists, got %+v", got)
	}
	if got := encryptSigner(identity, true); got != identity {
		t.Fatalf("Encrypt=true,Sign=true: expected the loaded identity to be passed through")
	}
	if got := encryptSigner(nil, true); got != nil {
		t.Fatalf("expected nil to stay nil when no identity was loaded, got %+v", got)
	}
	if got := encryptSigner(nil, false); got != nil {
		t.Fatalf("expected nil to stay nil when no identity was loaded, got %+v", got)
	}
}

// generateArmoredKeyWithLifetime generates a fresh key with the given
// generation time and lifetime in seconds, returning its armored public
// key. A generation time in the past plus a short lifetime yields a key
// that is already expired as of "now" — used to build expired-key test
// fixtures without a static testdata file.
func generateArmoredKeyWithLifetime(t *testing.T, name, email string, generationTime time.Time, lifetimeSeconds int32) string {
	t.Helper()
	key, err := crypto.PGP().KeyGeneration().
		GenerationTime(generationTime.Unix()).
		Lifetime(lifetimeSeconds).
		AddUserId(name, email).
		New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	return armored
}

// generateRevokedArmoredKey generates a fresh key and immediately revokes
// it, returning its armored public key with the revocation signature
// attached — as a real revoked key published to a keyserver would have.
func generateRevokedArmoredKey(t *testing.T, name, email string) string {
	t.Helper()
	key, err := crypto.PGP().KeyGeneration().AddUserId(name, email).New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := key.GetEntity().Revoke(packet.NoReason, "test revocation", &packet.Config{}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	return armored
}

func TestBuildPGPRecipientPlanSplitsToCCFromBCCAndFiltersUnusableKeys(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}

	bobID, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	daveID, err := pgpmail.GenerateIdentity("Dave", "dave@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity dave: %v", err)
	}
	revokedKey := generateRevokedArmoredKey(t, "Revoked", "revoked@example.com")
	expiredKey := generateArmoredKeyWithLifetime(t, "Expired", "expired@example.com", time.Now().Add(-48*time.Hour), 3600)

	for _, c := range []contacts.Contact{
		{FormattedName: "Bob", Emails: []contacts.ContactValue{{Value: "bob@example.com"}}, PGPKey: bobID.ArmoredPublicKey},
		{FormattedName: "Dave", Emails: []contacts.ContactValue{{Value: "dave@example.com"}}, PGPKey: daveID.ArmoredPublicKey},
		{FormattedName: "Revoked", Emails: []contacts.ContactValue{{Value: "revoked@example.com"}}, PGPKey: revokedKey},
		{FormattedName: "Expired", Emails: []contacts.ContactValue{{Value: "expired@example.com"}}, PGPKey: expiredKey},
	} {
		if _, err := store.Upsert(c); err != nil {
			t.Fatalf("Upsert %s: %v", c.FormattedName, err)
		}
	}

	resolver := &keyResolver{store: store, discover: false}
	plan := buildPGPRecipientPlan(
		context.Background(),
		[]string{"bob@example.com"},
		[]string{"revoked@example.com"},
		[]string{"dave@example.com", "expired@example.com", "nokey@example.com"},
		resolver,
	)

	if len(plan.toCCEmails) != 1 || plan.toCCEmails[0] != "bob@example.com" || len(plan.toCCKeys) != 1 || plan.toCCKeys[0] != bobID.ArmoredPublicKey {
		t.Fatalf("expected bob alone in toCCEmails with his key, got emails=%v keys=%d", plan.toCCEmails, len(plan.toCCKeys))
	}
	if len(plan.bccEmails) != 1 || plan.bccEmails[0] != "dave@example.com" || len(plan.bccKeys) != 1 || plan.bccKeys[0] != daveID.ArmoredPublicKey {
		t.Fatalf("expected dave alone in bccEmails with his key, got emails=%v keys=%d", plan.bccEmails, len(plan.bccKeys))
	}
	wantWithoutKey := []string{"revoked@example.com", "expired@example.com", "nokey@example.com"}
	if len(plan.withoutKeyEmails) != len(wantWithoutKey) {
		t.Fatalf("withoutKeyEmails mismatch: got %v want %v", plan.withoutKeyEmails, wantWithoutKey)
	}
	for i, want := range wantWithoutKey {
		if plan.withoutKeyEmails[i] != want {
			t.Fatalf("withoutKeyEmails[%d]: got %q want %q (full: %v)", i, plan.withoutKeyEmails[i], want, plan.withoutKeyEmails)
		}
	}
}

// extractArmoredPGPData is a test-only MIME walker that extracts the
// armored PGP data part from an EncryptMIME envelope. Mirrors pgpmail's own
// (unexported) extractOctetStreamPart test helper — duplicated here since
// api and pgpmail are separate test packages.
func extractArmoredPGPData(t *testing.T, raw []byte) string {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("expected multipart Content-Type, got %q (err=%v)", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			t.Fatal("no application/octet-stream part found")
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		if strings.HasPrefix(part.Header.Get("Content-Type"), "application/octet-stream") {
			data, err := io.ReadAll(part)
			if err != nil {
				t.Fatalf("ReadAll part: %v", err)
			}
			return string(data)
		}
	}
}

// TestBuildPGPDeliveriesIsolatesBCCRecipients is the core regression test
// for the BCC key-ID leak: before this change, To/CC/BCC keys were all
// merged into one shared ciphertext, so any recipient could inspect the
// message's OpenPGP packets and see which BCC'd keys it was also encrypted
// to. This asserts the stronger guarantee buildPGPDeliveries actually
// implements — each BCC recipient gets a wholly separate ciphertext that
// nobody else (not the To/CC recipients, not other BCC recipients) can
// decrypt at all.
func TestBuildPGPDeliveriesIsolatesBCCRecipients(t *testing.T) {
	bob, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}
	carol, err := pgpmail.GenerateIdentity("Carol", "carol@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity carol: %v", err)
	}
	dave, err := pgpmail.GenerateIdentity("Dave", "dave@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity dave: %v", err)
	}
	eve, err := pgpmail.GenerateIdentity("Eve", "eve@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity eve: %v", err)
	}

	plan := pgpRecipientPlan{
		toCCEmails: []string{"bob@example.com", "carol@example.com"},
		toCCKeys:   []string{bob.ArmoredPublicKey, carol.ArmoredPublicKey},
		bccEmails:  []string{"dave@example.com", "eve@example.com"},
		bccKeys:    []string{dave.ArmoredPublicKey, eve.ArmoredPublicKey},
	}
	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com", "carol@example.com"},
		Subject: "Secret",
		Body:    "meet at dawn",
		Mode:    "plain",
	}.Build()

	deliveries, err := buildPGPDeliveries(plaintext, plan, nil)
	if err != nil {
		t.Fatalf("buildPGPDeliveries: %v", err)
	}
	if len(deliveries) != 3 {
		t.Fatalf("expected 3 deliveries (1 shared to/cc + 2 individual bcc), got %d", len(deliveries))
	}

	shared := deliveries[0]
	if len(shared.Recipients) != 2 || shared.Recipients[0] != "bob@example.com" || shared.Recipients[1] != "carol@example.com" {
		t.Fatalf("expected shared delivery to bob+carol, got %v", shared.Recipients)
	}
	sharedArmored := extractArmoredPGPData(t, shared.Ciphertext)
	if _, err := pgpmail.DecryptMIME(sharedArmored, bob, nil); err != nil {
		t.Fatalf("bob should decrypt the shared to/cc ciphertext: %v", err)
	}
	if _, err := pgpmail.DecryptMIME(sharedArmored, carol, nil); err != nil {
		t.Fatalf("carol should decrypt the shared to/cc ciphertext: %v", err)
	}
	if _, err := pgpmail.DecryptMIME(sharedArmored, dave, nil); err == nil {
		t.Fatal("dave (bcc) must not be able to decrypt the shared to/cc ciphertext")
	}

	daveDelivery, eveDelivery := deliveries[1], deliveries[2]
	if len(daveDelivery.Recipients) != 1 || daveDelivery.Recipients[0] != "dave@example.com" {
		t.Fatalf("expected dave's own delivery, got %v", daveDelivery.Recipients)
	}
	if len(eveDelivery.Recipients) != 1 || eveDelivery.Recipients[0] != "eve@example.com" {
		t.Fatalf("expected eve's own delivery, got %v", eveDelivery.Recipients)
	}

	daveArmored := extractArmoredPGPData(t, daveDelivery.Ciphertext)
	if _, err := pgpmail.DecryptMIME(daveArmored, dave, nil); err != nil {
		t.Fatalf("dave should decrypt his own bcc ciphertext: %v", err)
	}
	if _, err := pgpmail.DecryptMIME(daveArmored, eve, nil); err == nil {
		t.Fatal("eve must not be able to decrypt dave's bcc ciphertext")
	}
	if _, err := pgpmail.DecryptMIME(daveArmored, bob, nil); err == nil {
		t.Fatal("bob (to/cc recipient) must not be able to decrypt dave's bcc ciphertext")
	}

	eveArmored := extractArmoredPGPData(t, eveDelivery.Ciphertext)
	if _, err := pgpmail.DecryptMIME(eveArmored, eve, nil); err != nil {
		t.Fatalf("eve should decrypt her own bcc ciphertext: %v", err)
	}
	if _, err := pgpmail.DecryptMIME(eveArmored, dave, nil); err == nil {
		t.Fatal("dave must not be able to decrypt eve's bcc ciphertext")
	}

	// The real subject must never travel in cleartext on any delivery's wire
	// bytes; the outer envelope carries only the placeholder.
	for i, d := range deliveries {
		if bytes.Contains(d.Ciphertext, []byte("Secret")) {
			t.Fatalf("delivery %d leaked the real subject in cleartext", i)
		}
		if !bytes.Contains(d.Ciphertext, []byte("Subject: "+pgpmail.OuterPlaceholderSubject)) {
			t.Fatalf("delivery %d missing the placeholder Subject on the outer envelope", i)
		}
	}
}

func TestBuildPGPDeliveriesBCCOnlyWhenNoToCCHasUsableKey(t *testing.T) {
	dave, err := pgpmail.GenerateIdentity("Dave", "dave@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity dave: %v", err)
	}
	plan := pgpRecipientPlan{
		bccEmails: []string{"dave@example.com"},
		bccKeys:   []string{dave.ArmoredPublicKey},
	}
	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"nokey@example.com"},
		Subject: "Secret",
		Body:    "meet at dawn",
		Mode:    "plain",
	}.Build()

	deliveries, err := buildPGPDeliveries(plaintext, plan, nil)
	if err != nil {
		t.Fatalf("buildPGPDeliveries: %v", err)
	}
	if len(deliveries) != 1 || len(deliveries[0].Recipients) != 1 || deliveries[0].Recipients[0] != "dave@example.com" {
		t.Fatalf("expected exactly one bcc-only delivery to dave, got %+v", deliveries)
	}
}

func TestBuildPGPRecipientPlanDedupesAcrossToCcBccKeepingFirstOccurrence(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	bobID, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:        bobID.ArmoredPublicKey,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// bob@example.com appears in both To and BCC (different case) — must be
	// counted once as a To recipient, never duplicated into bccEmails too.
	resolver := &keyResolver{store: store, discover: false}
	plan := buildPGPRecipientPlan(
		context.Background(),
		[]string{"bob@example.com"},
		nil,
		[]string{"Bob@Example.com"},
		resolver,
	)

	if len(plan.toCCEmails) != 1 || len(plan.bccEmails) != 0 {
		t.Fatalf("expected bob counted once in toCCEmails and not duplicated into bccEmails, got toCC=%v bcc=%v", plan.toCCEmails, plan.bccEmails)
	}
}

func TestDecodeMailRequestParsesAllowPickupFallback(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"to":                  "bob@example.com",
		"subject":             "hi",
		"body":                "hello",
		"encrypt":             true,
		"allowPickupFallback": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(body))
	decoded, errMsg, err := decodeMailRequest(req)
	if err != nil {
		t.Fatalf("decodeMailRequest: %v (%s)", err, errMsg)
	}
	if !decoded.AllowPickupFallback {
		t.Fatalf("expected AllowPickupFallback true, got %+v", decoded)
	}
}

// Absent must mean false. The whole gate depends on it: a flag that defaults
// to the unsafe branch protects nobody who forgets to set it.
func TestDecodeMailRequestDefaultsAllowPickupFallbackFalse(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"to": "bob@example.com", "subject": "hi", "body": "hello", "encrypt": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mail/send", bytes.NewReader(body))
	decoded, _, err := decodeMailRequest(req)
	if err != nil {
		t.Fatalf("decodeMailRequest: %v", err)
	}
	if decoded.AllowPickupFallback {
		t.Fatal("expected AllowPickupFallback to default to false")
	}
}
