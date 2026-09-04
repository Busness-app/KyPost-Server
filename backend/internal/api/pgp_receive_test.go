package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	imapadapter "github.com/Busness-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
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

// TestServerCustodyCiphertextIsNotDecrypted is the property the whole retirement
// is for: an account whose key this server CAN open is nonetheless not read by
// it. The distinction matters — unlike a client-protected account, every
// ingredient for decryption is present here, so nothing but the refusal itself
// stops it.
//
// The message is genuinely encrypted to the account's own key and would have
// decrypted cleanly before. The plaintext must not appear in the result, and the
// error must name the migration rather than reading like breakage.
func TestServerCustodyCiphertextIsNotDecrypted(t *testing.T) {
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
	if _, err := srv.users.SetPGPIdentity(userID, recipient.Fingerprint, recipient.KeyID,
		recipient.ArmoredPublicKey, sealed, "generated", "2026-07-14T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}

	const secret = "the quarterly numbers are attached"
	plaintext := mailmsg.Message{
		From: "bob@example.com", To: []string{"recipient@example.com"},
		Subject: "Numbers", Body: secret, Mode: "plain",
	}.Build()
	encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}

	content := imapadapter.MessageContent{PGPEncryptedPayload: extractArmoredPGPPayload(t, encrypted)}
	result := srv.decryptPGPMessageContent(userID, "bob@example.com", content)

	if strings.Contains(result.Body, secret) {
		t.Fatal("the server decrypted a server-custody message; retiring the mode means it must not")
	}
	if result.PGPDecryptError == "" {
		t.Fatal("expected the refusal to be reported, not a silent empty body")
	}
	if !strings.Contains(result.PGPDecryptError, "export-legacy") {
		t.Fatalf("the refusal must tell the user how to recover the key, got %q", result.PGPDecryptError)
	}
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
	got := must1(boundSignerKeysForSender(contactsStore, "bob@example.com"))
	if len(got) != 1 || got[0].PublicKey != real.ArmoredPublicKey {
		t.Fatalf("pinned key should be offered with its material, got %+v", got)
	}
	if got[0].Conflict {
		t.Fatal("a key matching its own pin must not be reported as a conflict")
	}

	// The stored key changes while the record still carries the OLD pin, which
	// is the only shape this guard catches: applyUpsertLocked re-derives the pin
	// from the incoming key whenever the record arrives without one, so a writer
	// that simply omits the fingerprint self-certifies its substitution. See the
	// run-12 finding on contact key substitution.
	created.PGPKey = swapped.ArmoredPublicKey
	if _, err := contactsStore.Upsert(created); err != nil {
		t.Fatalf("Upsert swapped: %v", err)
	}
	// Unlike the retired signerKeysForSender, which dropped the contact
	// entirely, boundSignerKeys REPORTS the mismatch so the client can say
	// "the key for this sender changed" rather than "no key" — but strips the
	// key material, so nothing can verify against it. Both halves matter: the
	// absent PublicKey is the security property, the Conflict flag is the
	// honest badge.
	got = must1(boundSignerKeysForSender(contactsStore, "bob@example.com"))
	if len(got) != 1 || !got[0].Conflict {
		t.Fatalf("a pin mismatch must be reported as a conflict, got %+v", got)
	}
	if got[0].PublicKey != "" {
		t.Fatal("a key that does not match the contact's pin was handed out as verifiable material")
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

	got := must1(boundSignerKeys(store))

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

	got := must1(boundSignerKeys(store))

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

	got := must1(boundSignerKeysForSender(store, "bob@example.com"))

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
	got := must1(boundSignerKeysForSender(store, resolved))

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

	got := must1(boundSignerKeysForSender(store, "bob@example.com"))

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
