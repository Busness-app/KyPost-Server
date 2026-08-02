package imap

import (
	"strings"
	"testing"

	goimap "github.com/BrianLeishman/go-imap"
	"github.com/jhillyerd/enmime/v2"

	"kypost-server/backend/internal/pgpmail"
)

const armoredCiphertext = "-----BEGIN PGP MESSAGE-----\r\n\r\nhQIMA0\r\n-----END PGP MESSAGE-----"

// goimapAttachmentsFor runs a raw message through the same parse goimap does —
// enmime.ReadEnvelope, then Attachments followed by Inlines — and returns what
// the adapter would actually be handed. Nothing else here can prove the
// detector works on real mail: every other test in this file constructs the
// attachment list by hand, which is exactly the assumption under test.
func goimapAttachmentsFor(t *testing.T, raw []byte) []goimap.Attachment {
	t.Helper()
	env, err := enmime.ReadEnvelope(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("enmime.ReadEnvelope: %v", err)
	}
	var out []goimap.Attachment
	for _, a := range env.Attachments {
		out = append(out, goimap.Attachment{Name: a.FileName, MimeType: a.ContentType, Content: a.Content})
	}
	for _, a := range env.Inlines {
		out = append(out, goimap.Attachment{Name: a.FileName, MimeType: a.ContentType, Content: a.Content})
	}
	return out
}

// The load-bearing test: a real PGP/MIME message, encrypted by this codebase's
// own encoder, parsed the way the IMAP library parses it.
//
// It also pins the surprise that shaped the detector. enmime files the
// ciphertext part under BOTH Attachments and Inlines — it carries an inline
// disposition and a filename — and goimap concatenates the two, so a
// single-part envelope arrives as two identical entries. Any rule of the form
// "an encrypted message has exactly one attachment" is wrong on real mail, and
// one in internal/api was: it meant the attachment listing never looked inside
// genuine encrypted mail, only inside the fake in its own test.
func TestPGPEnvelopePayload_RealPGPMIMEMessage(t *testing.T) {
	identity, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	plain := "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
	encrypted, err := pgpmail.EncryptMIME([]byte(plain), []string{identity.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}

	attachments := goimapAttachmentsFor(t, encrypted)
	if len(attachments) < 2 {
		t.Logf("note: goimap now yields %d part(s) for PGP/MIME, not the 2 this was written against", len(attachments))
	}

	payload := pgpEnvelopePayload(attachments)
	if payload == "" {
		t.Fatalf("a real PGP/MIME message was not recognised as an envelope; parts: %s", describe(attachments))
	}
	if !strings.Contains(payload, "-----BEGIN PGP MESSAGE-----") {
		t.Fatalf("payload is not armored ciphertext: %q", payload)
	}
}

// The false positive the detector exists to prevent: an ordinary message that
// happens to carry an encrypted file. Its attachments are the reader's files
// and must be served as themselves, not decrypted and re-indexed.
func TestPGPEnvelopePayload_EncryptedFileAmongOrdinaryOnes(t *testing.T) {
	attachments := []goimap.Attachment{
		{Name: "archive.pgp", MimeType: "application/octet-stream", Content: []byte(armoredCiphertext)},
		{Name: "report.xlsx", MimeType: "application/vnd.ms-excel", Content: []byte("xls-bytes")},
	}
	if payload := pgpEnvelopePayload(attachments); payload != "" {
		t.Fatal("a message carrying an encrypted file was treated as a PGP/MIME envelope")
	}
}

// Same shape, reversed order — the loop must not accept on the strength of the
// first part it likes.
func TestPGPEnvelopePayload_OrdinaryFileFirst(t *testing.T) {
	attachments := []goimap.Attachment{
		{Name: "report.pdf", MimeType: "application/pdf", Content: []byte("pdf-bytes")},
		{Name: "archive.pgp", MimeType: "application/octet-stream", Content: []byte(armoredCiphertext)},
	}
	if payload := pgpEnvelopePayload(attachments); payload != "" {
		t.Fatal("an ordinary attachment before the ciphertext did not disqualify the message")
	}
}

// A message with attachments but no ciphertext anywhere is not encrypted, even
// when every part is an envelope-compatible type.
func TestPGPEnvelopePayload_NoCiphertext(t *testing.T) {
	attachments := []goimap.Attachment{
		{Name: "blob.bin", MimeType: "application/octet-stream", Content: []byte("not armored")},
	}
	if payload := pgpEnvelopePayload(attachments); payload != "" {
		t.Fatal("a message with no armored part was reported as encrypted")
	}
}

func TestPGPEnvelopePayload_NoAttachments(t *testing.T) {
	if payload := pgpEnvelopePayload(nil); payload != "" {
		t.Fatal("a message with no parts was reported as encrypted")
	}
}

// The RFC 3156 version part is normally invisible to us — enmime files it under
// OtherParts, which goimap drops — but a server that presents it as an
// attachment must not disqualify the message.
func TestPGPEnvelopePayload_VersionPartPresent(t *testing.T) {
	attachments := []goimap.Attachment{
		{MimeType: "application/pgp-encrypted", Content: []byte("Version: 1\r\n")},
		{Name: "encrypted.asc", MimeType: "application/octet-stream", Content: []byte(armoredCiphertext)},
	}
	if payload := pgpEnvelopePayload(attachments); payload == "" {
		t.Fatal("an envelope carrying its version part was rejected")
	}
}

// The duplicate the real parse produces must not confuse the result.
func TestPGPEnvelopePayload_DuplicateCiphertextPart(t *testing.T) {
	part := goimap.Attachment{Name: "encrypted.asc", MimeType: "application/octet-stream", Content: []byte(armoredCiphertext)}
	if payload := pgpEnvelopePayload([]goimap.Attachment{part, part}); payload != armoredCiphertext {
		t.Fatalf("the doubled ciphertext part did not yield the payload: %q", payload)
	}
}

func TestIsPGPEnvelopePartType(t *testing.T) {
	for _, mimeType := range []string{
		"application/octet-stream",
		"application/pgp-encrypted",
		`application/octet-stream; name="encrypted.asc"`,
		"APPLICATION/OCTET-STREAM",
		"", // undeclared: judged on content instead
	} {
		if !IsPGPEnvelopePartType(mimeType) {
			t.Errorf("IsPGPEnvelopePartType(%q) = false, want true", mimeType)
		}
	}
	for _, mimeType := range []string{
		"application/pdf",
		"text/plain",
		"image/png",
		"application/vnd.ms-excel",
		"not a media type",
	} {
		if IsPGPEnvelopePartType(mimeType) {
			t.Errorf("IsPGPEnvelopePartType(%q) = true, want false", mimeType)
		}
	}
}

// IsArmoredPGPMessage is the single definition of "is this ciphertext" — the
// api attachment endpoints call it rather than matching the prefix themselves.
// The prefix guard in front of gopenpgp must not change any verdict: gopenpgp's
// regexp is ^-anchored and also requires the END marker.
func TestIsArmoredPGPMessage(t *testing.T) {
	if !IsArmoredPGPMessage([]byte(armoredCiphertext)) {
		t.Error("a complete armored message was not recognised")
	}
	// Header without a terminator is not a message. The prefix guard alone
	// would have said yes; delegating to gopenpgp is what keeps this false.
	if IsArmoredPGPMessage([]byte("-----BEGIN PGP MESSAGE-----\r\n\r\nhQIMA0\r\n")) {
		t.Error("an unterminated armor block was accepted")
	}
	// Anchored at byte 0, matching gopenpgp. Pinned so the asymmetry that used
	// to exist between this and the api copy cannot come back unnoticed.
	if IsArmoredPGPMessage([]byte("   \r\n" + armoredCiphertext)) {
		t.Error("armor behind leading whitespace was accepted; the check is meant to be anchored")
	}
	if IsArmoredPGPMessage([]byte("just a file")) {
		t.Error("ordinary content was called ciphertext")
	}
	if IsArmoredPGPMessage(nil) {
		t.Error("empty content was called ciphertext")
	}
}

func TestIsPGPVersionPart(t *testing.T) {
	for _, body := range []string{"Version: 1\r\n", "version: 1", "  VERSION: 1  "} {
		if !isPGPVersionPart(goimap.Attachment{Content: []byte(body)}) {
			t.Errorf("version part %q was not recognised", body)
		}
	}
	for _, body := range []string{"", "Ver", "not a version part"} {
		if isPGPVersionPart(goimap.Attachment{Content: []byte(body)}) {
			t.Errorf("%q was treated as the version part", body)
		}
	}
}

func describe(attachments []goimap.Attachment) string {
	parts := make([]string, 0, len(attachments))
	for _, a := range attachments {
		parts = append(parts, a.MimeType+"/"+a.Name)
	}
	return strings.Join(parts, ", ")
}
