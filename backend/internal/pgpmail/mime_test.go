package pgpmail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpautocrypt"
)

// withLoweredMaxInboundMessageBytes temporarily lowers the shared inbound
// size cap so tests can exercise overflow/boundary behavior without
// allocating megabytes of test data, restoring the original value via
// t.Cleanup.
func withLoweredMaxInboundMessageBytes(t *testing.T, limit int64) {
	t.Helper()
	original := mailmsg.MaxInboundMessageBytes
	mailmsg.MaxInboundMessageBytes = limit
	t.Cleanup(func() { mailmsg.MaxInboundMessageBytes = original })
}

// extractOctetStreamPart is a test-only MIME walker that finds the armored
// PGP data part EncryptMIME produces, mirroring the content-sniffing
// technique (crypto.IsPGPMessage) the receive-path integration (Task 7) uses
// against real IMAP-fetched attachments.
func extractOctetStreamPart(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	_, content, err := splitMessage(raw)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}
	_, attachments, err := ParseContent(content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	for _, a := range attachments {
		if crypto.IsPGPMessage(string(a.Content)) {
			return string(a.Content), true
		}
	}
	return "", false
}

func TestEncryptDecryptMIMERoundTrip(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	bob, err := GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity bob: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Secret",
		Body:    "meet at dawn",
		Mode:    "plain",
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{bob.ArmoredPublicKey}, alice)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	if !strings.Contains(string(encrypted), "multipart/encrypted") {
		t.Fatal("expected multipart/encrypted content type in output")
	}
	// The real subject must NOT appear in cleartext anywhere on the wire; the
	// outer Subject is replaced with the fixed placeholder.
	if strings.Contains(string(encrypted), "Secret") {
		t.Fatal("real subject leaked into the encrypted message bytes")
	}
	if !strings.Contains(string(encrypted), "Subject: "+OuterPlaceholderSubject) {
		t.Fatal("expected the placeholder Subject on the outer envelope")
	}

	armoredData, ok := extractOctetStreamPart(t, encrypted)
	if !ok {
		t.Fatal("expected an application/octet-stream data part")
	}

	result, err := DecryptMIME(armoredData, bob, []string{alice.ArmoredPublicKey})
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected signature to verify")
	}
	if result.SignerFingerprint != alice.Fingerprint {
		t.Fatalf("signer fingerprint mismatch: got %s want %s", result.SignerFingerprint, alice.Fingerprint)
	}
	// The real subject is recovered from the decrypted payload's protected
	// headers.
	subject, ok := ExtractProtectedSubject(result.Content)
	if !ok || subject != "Secret" {
		t.Fatalf("ExtractProtectedSubject: got (%q, %v), want (\"Secret\", true)", subject, ok)
	}
	body, attachments, err := ParseContent(result.Content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if body != "meet at dawn" {
		t.Fatalf("body mismatch: got %q", body)
	}
	// The protected-headers wrapper and its legacy-display part must be
	// transparent to ParseContent — no phantom attachment.
	if len(attachments) != 0 {
		t.Fatalf("expected no attachments, got %d", len(attachments))
	}
}

func TestEncryptDecryptMIMEWithAttachment(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"alice@example.com"},
		Subject: "With attachment",
		Body:    "see attached",
		Mode:    "plain",
		Attachments: []mailmsg.Attachment{
			{Name: "note.txt", MimeType: "text/plain", Content: []byte("hello file")},
		},
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{alice.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	armoredData, ok := extractOctetStreamPart(t, encrypted)
	if !ok {
		t.Fatal("expected an application/octet-stream data part")
	}

	result, err := DecryptMIME(armoredData, alice, nil)
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	// EncryptMIME was called with a nil signer above: the resulting
	// ciphertext must not carry an embedded signature. This guards against
	// the encrypt-implicitly-signs regression where a caller's eagerly
	// loaded identity leaked into EncryptMIME's signer argument even when
	// signing wasn't requested.
	if result.Signed {
		t.Fatal("expected unsigned result when EncryptMIME was called with a nil signer")
	}
	body, attachments, err := ParseContent(result.Content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if body != "see attached" {
		t.Fatalf("body mismatch: got %q", body)
	}
	if len(attachments) != 1 || attachments[0].Name != "note.txt" || string(attachments[0].Content) != "hello file" {
		t.Fatalf("unexpected attachments: %+v", attachments)
	}
}

func TestSignMIMEAndVerifyDetached(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Signed only",
		Body:    "trust me",
		Mode:    "plain",
	}.Build()

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}
	if !strings.Contains(string(signed), "multipart/signed") {
		t.Fatal("expected multipart/signed content type in output")
	}

	_, content, err := splitMessage(plaintext)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}
	sigStart := strings.Index(string(signed), "-----BEGIN PGP SIGNATURE-----")
	if sigStart == -1 {
		t.Fatal("expected an armored signature block in the output")
	}
	sigEnd := strings.Index(string(signed)[sigStart:], "-----END PGP SIGNATURE-----") + len("-----END PGP SIGNATURE-----")
	armoredSig := string(signed)[sigStart : sigStart+sigEnd]

	result, err := VerifyDetached(content, armoredSig, []string{alice.ArmoredPublicKey})
	if err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	if !result.Verified {
		t.Fatal("expected signature to verify")
	}
	if result.SignerFingerprint != alice.Fingerprint {
		t.Fatalf("signer fingerprint mismatch: got %s want %s", result.SignerFingerprint, alice.Fingerprint)
	}
}

// TestSignMIMEWithAttachmentPreservesTrailingCRLF is a regression test for a
// bug in buildSignedEnvelope: when content (the signed part) already ends in
// its own "\r\n" — which mailmsg.Message.Build() always produces for
// multipart/mixed messages, since mime/multipart.Writer.Close() terminates
// with "\r\n--boundary--\r\n" — the buggy code skipped writing the boundary
// delimiter's own CRLF, silently truncating 2 bytes off the signed content
// as understood by any real MIME parser (which always strips exactly one
// CRLF as the delimiter separator, not two). That corruption doesn't show up
// by inspecting the produced bytes directly; it only appears once the
// envelope is parsed back through a real mime/multipart.Reader, so this test
// does exactly that instead of just calling VerifyDetached in-process.
func TestSignMIMEWithAttachmentPreservesTrailingCRLF(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Signed with attachment",
		Body:    "see attached",
		Mode:    "plain",
		Attachments: []mailmsg.Attachment{
			{Name: "note.txt", MimeType: "text/plain", Content: []byte("hello file")},
		},
	}.Build()

	_, wantContent, err := splitMessage(plaintext)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}
	if !bytes.HasSuffix(wantContent, []byte("\r\n")) {
		t.Fatalf("test setup invalid: expected signed content to end in its own CRLF (multipart/mixed with attachment), got %q", wantContent[len(wantContent)-20:])
	}

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}

	// Parse the produced envelope's actual wire bytes back through a real
	// net/mail + mime/multipart reader, the same way a real interoperating
	// PGP/MIME client would.
	msg, err := mail.ReadMessage(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("mime.ParseMediaType: %v", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("expected multipart Content-Type, got %q", mediaType)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil {
		t.Fatalf("mr.NextPart (signed content part): %v", err)
	}

	// NextPart parses content's own embedded "Content-Type: ...\r\n\r\n"
	// prefix as this part's MIME headers, since MIME doesn't distinguish
	// "embedded" from "real" headers. Reconstruct the full part bytes from
	// the parsed header plus the remaining body, and compare that
	// reconstruction against content — not part's body alone.
	partBody, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("io.ReadAll(part): %v", err)
	}
	var gotContent bytes.Buffer
	gotContent.WriteString("Content-Type: " + part.Header.Get("Content-Type") + "\r\n\r\n")
	gotContent.Write(partBody)

	if !bytes.Equal(gotContent.Bytes(), wantContent) {
		t.Fatalf("signed content part corrupted by round-trip through a real MIME parser:\n got  %q\n want %q", gotContent.Bytes(), wantContent)
	}
}

// TestDecryptMIMERejectsOversizedArmoredInput exercises the cheap defense-in-
// depth check on the armored input itself, before any decryption is
// attempted — a huge non-PGP string is rejected immediately with
// ErrMessageTooLarge rather than being handed to the OpenPGP parser at all.
// The recipient identity's key material is never touched at this size, so a
// zero-value (non-nil) *Identity stands in fine.
func TestDecryptMIMERejectsOversizedArmoredInput(t *testing.T) {
	withLoweredMaxInboundMessageBytes(t, 10)
	_, err := DecryptMIME(strings.Repeat("a", 11), &Identity{}, nil)
	if !errors.Is(err, mailmsg.ErrMessageTooLarge) {
		t.Fatalf("got %v, want ErrMessageTooLarge", err)
	}
}

// TestDecryptMIMERejectsDecompressionBomb proves the real OOM guard: a
// small, legitimately-encrypted ciphertext whose plaintext decompresses past
// the cap makes decryption fail closed — the oversized plaintext is never
// returned — mirroring the PGP decompression-bomb scenario the plan calls
// out. gopenpgp's default profile compresses with zlib, so a large,
// highly-compressible plaintext produces a ciphertext far smaller than the
// plaintext itself — exactly the shape of a decompression bomb — while
// still being cheap to generate in a test.
//
// Note this does NOT assert errors.Is(err, mailmsg.ErrMessageTooLarge): the
// underlying go-crypto library deliberately genericizes every parsing error
// encountered while reading symmetrically-decrypted data (including the
// MaxDecompressedMessageSize overflow) into an opaque "parsing error" —
// openpgp/errors.HandleSensitiveParsingError does this on purpose, to avoid
// giving an attacker an oracle that distinguishes "ciphertext too large"
// from "ciphertext corrupted/wrong key" before the message is authenticated.
// So for real encrypted messages the specific sentinel is unreachable here;
// what's verified, and what actually matters for OOM safety, is that
// decryption aborts with *an* error instead of materializing the bomb.
func TestDecryptMIMERejectsDecompressionBomb(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	const plaintextSize = 200_000
	plaintext := strings.Repeat("a", plaintextSize)

	recipients, err := crypto.NewKeyRing(nil)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	pubKey, err := crypto.NewKeyFromArmored(alice.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	if err := recipients.AddKey(pubKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	// EncryptMIME itself never requests compression (the default encryption
	// handle leaves Compression at NoCompression), but a third-party sender
	// is under no such obligation — DecryptMIME must handle whatever OpenPGP
	// message structure an attacker sends, compressed or not. Building the
	// ciphertext directly via the lower-level crypto package (bypassing
	// EncryptMIME) with compression explicitly requested simulates exactly
	// that: an attacker-crafted message carrying a compressed packet.
	encHandle, err := crypto.PGP().Encryption().Recipients(recipients).CompressWith(constants.ZLIBCompression).New()
	if err != nil {
		t.Fatalf("build encryption handle: %v", err)
	}
	pgpMessage, err := encHandle.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}
	if len(armored) >= plaintextSize {
		t.Fatalf("test setup invalid: expected compression to shrink the ciphertext well below the %d-byte plaintext, got %d armored bytes", plaintextSize, len(armored))
	}

	withLoweredMaxInboundMessageBytes(t, 1024)
	result, err := DecryptMIME(armored, alice, nil)
	if err == nil {
		t.Fatalf("expected decryption to fail closed on an oversized decompressed payload, got a result with %d content bytes", len(result.Content))
	}
}

// TestDecryptMIMEAcceptsWithinCapDecompressionBomb is the boundary
// companion to the decompression-bomb test above: the same kind of
// ciphertext, but with the cap left high enough to admit the plaintext,
// decrypts normally.
func TestDecryptMIMEAcceptsWithinCapDecompressionBomb(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}

	plaintext := "small and unremarkable"
	recipients, err := crypto.NewKeyRing(nil)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	pubKey, err := crypto.NewKeyFromArmored(alice.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	if err := recipients.AddKey(pubKey); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	encHandle, err := crypto.PGP().Encryption().Recipients(recipients).New()
	if err != nil {
		t.Fatalf("build encryption handle: %v", err)
	}
	pgpMessage, err := encHandle.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}

	result, err := DecryptMIME(armored, alice, nil)
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	if string(result.Content) != plaintext {
		t.Fatalf("got %q, want %q", result.Content, plaintext)
	}
}

// TestParseContentRejectsOversizedContent covers the entry-point guard: a
// content byte slice already larger than the cap is rejected immediately,
// without attempting to parse it as MIME at all.
func TestParseContentRejectsOversizedContent(t *testing.T) {
	withLoweredMaxInboundMessageBytes(t, 10)
	content := []byte("Content-Type: text/plain\r\n\r\n" + strings.Repeat("a", 20))
	_, _, err := ParseContent(content)
	if !errors.Is(err, mailmsg.ErrMessageTooLarge) {
		t.Fatalf("got %v, want ErrMessageTooLarge", err)
	}
}

// TestParseContentAcceptsAtCapBoundary proves the entry-point check is a
// strict "greater than", not "greater than or equal": content sized exactly
// to the (lowered) cap still parses normally.
func TestParseContentAcceptsAtCapBoundary(t *testing.T) {
	body := strings.Repeat("a", 5)
	content := []byte("Content-Type: text/plain\r\n\r\n" + body)
	withLoweredMaxInboundMessageBytes(t, int64(len(content)))

	got, attachments, err := ParseContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != body {
		t.Fatalf("got body %q, want %q", got, body)
	}
	if len(attachments) != 0 {
		t.Fatalf("expected no attachments, got %d", len(attachments))
	}
}

// TestParseContentMultipartRejectsWhenOversized proves the size guard
// applies to the multipart path too, not just the simple single-part path:
// a multipart/mixed content blob larger than the (lowered) cap is rejected
// with ErrMessageTooLarge before any part is parsed.
func TestParseContentMultipartRejectsWhenOversized(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	textPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain"}})
	if err != nil {
		t.Fatalf("CreatePart (text): %v", err)
	}
	if _, err := textPart.Write([]byte("hi")); err != nil {
		t.Fatalf("write text part: %v", err)
	}
	attachmentPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/octet-stream"}})
	if err != nil {
		t.Fatalf("CreatePart (attachment): %v", err)
	}
	if _, err := attachmentPart.Write([]byte(strings.Repeat("a", 5000))); err != nil {
		t.Fatalf("write attachment part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	var content bytes.Buffer
	content.WriteString(`Content-Type: multipart/mixed; boundary=` + w.Boundary() + "\r\n\r\n")
	content.Write(buf.Bytes())

	withLoweredMaxInboundMessageBytes(t, 4096)
	if int64(content.Len()) <= mailmsg.MaxInboundMessageBytes {
		t.Fatalf("test setup invalid: expected overall content (%d bytes) to exceed the lowered cap (%d)", content.Len(), mailmsg.MaxInboundMessageBytes)
	}

	_, _, err = ParseContent(content.Bytes())
	if !errors.Is(err, mailmsg.ErrMessageTooLarge) {
		t.Fatalf("got %v, want ErrMessageTooLarge", err)
	}
}

// TestParseContentMultipartAcceptsWithinCap is the boundary companion to
// TestParseContentMultipartRejectsWhenOversized: the identical multipart
// shape, but with the cap left high enough to admit it, parses out the text
// body and attachment normally — proving the cap doesn't false-positive on
// ordinary multipart content it was never meant to reject.
func TestParseContentMultipartAcceptsWithinCap(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	textPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain"}})
	if err != nil {
		t.Fatalf("CreatePart (text): %v", err)
	}
	if _, err := textPart.Write([]byte("hi")); err != nil {
		t.Fatalf("write text part: %v", err)
	}
	attachmentPart, err := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/octet-stream"}, "Content-Disposition": {`attachment; filename="note.txt"`}})
	if err != nil {
		t.Fatalf("CreatePart (attachment): %v", err)
	}
	if _, err := attachmentPart.Write([]byte("attached data")); err != nil {
		t.Fatalf("write attachment part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	var content bytes.Buffer
	content.WriteString(`Content-Type: multipart/mixed; boundary=` + w.Boundary() + "\r\n\r\n")
	content.Write(buf.Bytes())

	withLoweredMaxInboundMessageBytes(t, int64(content.Len())+1)

	body, attachments, err := ParseContent(content.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != "hi" {
		t.Fatalf("got body %q, want %q", body, "hi")
	}
	if len(attachments) != 1 || string(attachments[0].Content) != "attached data" {
		t.Fatalf("unexpected attachments: %+v", attachments)
	}
}

// TestExtractProtectedSubjectThunderbirdStyle proves interop with the
// protected-headers convention as emitted by Thunderbird/Mutt/K-9: the inner
// Subject sits directly on a single-part content (no multipart wrapper, no
// legacy-display part) and is RFC 2047 encoded-word. ExtractProtectedSubject
// must decode it.
func TestExtractProtectedSubjectThunderbirdStyle(t *testing.T) {
	content := []byte("Subject: =?UTF-8?B?" +
		base64UTF8("Café meeting") +
		"?=\r\n" +
		"Content-Type: text/plain; charset=UTF-8; protected-headers=\"v1\"\r\n" +
		"\r\n" +
		"body text\r\n")

	subject, ok := ExtractProtectedSubject(content)
	if !ok || subject != "Café meeting" {
		t.Fatalf("ExtractProtectedSubject: got (%q, %v), want (\"Café meeting\", true)", subject, ok)
	}

	// And it still renders as a plain body, not swallowed.
	body, attachments, err := ParseContent(content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if strings.TrimSpace(body) != "body text" {
		t.Fatalf("body mismatch: got %q", body)
	}
	if len(attachments) != 0 {
		t.Fatalf("expected no attachments, got %d", len(attachments))
	}
}

// TestExtractProtectedSubjectAbsent proves the fallback signal: content with
// no Subject header returns ok=false, so callers keep the outer envelope
// subject.
func TestExtractProtectedSubjectAbsent(t *testing.T) {
	content := []byte("Content-Type: text/plain\r\n\r\nno subject here")
	if subject, ok := ExtractProtectedSubject(content); ok {
		t.Fatalf("expected ok=false for content without a Subject header, got %q", subject)
	}
}

// TestParseContentNestedMultipartAlternative proves the recursive walk: a
// nested multipart/alternative (the shape Thunderbird produces for HTML mail)
// yields a display body rather than being mis-collected as an opaque
// attachment.
func TestParseContentNestedMultipartAlternative(t *testing.T) {
	var inner bytes.Buffer
	iw := multipart.NewWriter(&inner)
	textPart, _ := iw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain"}})
	_, _ = textPart.Write([]byte("plain body"))
	htmlPart, _ := iw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html"}})
	_, _ = htmlPart.Write([]byte("<p>html body</p>"))
	_ = iw.Close()

	var outer bytes.Buffer
	ow := multipart.NewWriter(&outer)
	altPart, _ := ow.CreatePart(textproto.MIMEHeader{
		"Content-Type": {`multipart/alternative; boundary="` + iw.Boundary() + `"`},
	})
	_, _ = altPart.Write(inner.Bytes())
	_ = ow.Close()

	var content bytes.Buffer
	content.WriteString(`Content-Type: multipart/mixed; boundary=` + ow.Boundary() + "\r\n\r\n")
	content.Write(outer.Bytes())

	body, attachments, err := ParseContent(content.Bytes())
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if body != "plain body" {
		t.Fatalf("expected first text part as body, got %q", body)
	}
	if len(attachments) != 0 {
		t.Fatalf("expected nested multipart to render, not become attachments, got %d", len(attachments))
	}
}

// TestEncryptMIMESanitizesProtectedSubject proves a subject carrying CR/LF
// can't inject headers into the protected wrapper: the injected line never
// appears as its own header.
func TestEncryptMIMESanitizesProtectedSubject(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"alice@example.com"},
		Subject: "safe\r\nBcc: evil@example.com",
		Body:    "hi",
		Mode:    "plain",
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{alice.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	armoredData, ok := extractOctetStreamPart(t, encrypted)
	if !ok {
		t.Fatal("expected an application/octet-stream data part")
	}
	result, err := DecryptMIME(armoredData, alice, nil)
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	if bytes.Contains(result.Content, []byte("\r\nBcc:")) {
		t.Fatalf("subject injection: an injected Bcc header appeared in the protected content:\n%s", result.Content)
	}
	// CR and LF are each flattened to a space, so "safe\r\nBcc:..." becomes
	// "safe  Bcc:..." on one line — no injected header.
	subject, ok := ExtractProtectedSubject(result.Content)
	if !ok || subject != "safe  Bcc: evil@example.com" {
		t.Fatalf("ExtractProtectedSubject: got (%q, %v), want flattened single line", subject, ok)
	}
}

// TestEncryptMIMENoSubject proves an empty subject still gets the outer
// placeholder path only when there's a subject: with no subject, the message
// is encrypted without a protected-headers wrapper and no placeholder is
// forced.
func TestEncryptMIMENoSubject(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	plaintext := mailmsg.Message{
		From: "alice@example.com",
		To:   []string{"alice@example.com"},
		Body: "hi",
		Mode: "plain",
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{alice.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	if strings.Contains(string(encrypted), OuterPlaceholderSubject) {
		t.Fatal("did not expect a placeholder Subject when the message had no subject")
	}
	armoredData, ok := extractOctetStreamPart(t, encrypted)
	if !ok {
		t.Fatal("expected an application/octet-stream data part")
	}
	result, err := DecryptMIME(armoredData, alice, nil)
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	if subject, ok := ExtractProtectedSubject(result.Content); ok {
		t.Fatalf("expected no protected subject for a subjectless message, got %q", subject)
	}
	body, _, err := ParseContent(result.Content)
	if err != nil {
		t.Fatalf("ParseContent: %v", err)
	}
	if strings.TrimSpace(body) != "hi" {
		t.Fatalf("body mismatch: got %q", body)
	}
}

// base64UTF8 is a tiny test helper for building an RFC 2047 B-encoded word.
func base64UTF8(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// TestEncryptMIMEPreservesAutocryptHeader and TestSignMIMEPreservesAutocryptHeader
// prove Task 2 of the outbound-publishing spec: mailmsg.Message.Autocrypt
// (Task 1) must survive PGP/MIME wrapping on the outer, unencrypted envelope
// — never inside the ciphertext, since Autocrypt exists precisely so a
// receiving client can opportunistically pick up the sender's key without
// decrypting anything.
func TestEncryptMIMEPreservesAutocryptHeader(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	plaintext := mailmsg.Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "secret",
		Mode:      "plain",
		Autocrypt: "addr=alice@example.com; keydata=QUJD",
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{alice.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	if !bytes.Contains(encrypted, []byte("\r\nAutocrypt: addr=alice@example.com; keydata=QUJD\r\n")) {
		t.Fatalf("Autocrypt header not on outer envelope:\n%s", encrypted)
	}

	armoredData, ok := extractOctetStreamPart(t, encrypted)
	if !ok {
		t.Fatal("expected an application/octet-stream data part")
	}
	result, err := DecryptMIME(armoredData, alice, nil)
	if err != nil {
		t.Fatalf("DecryptMIME: %v", err)
	}
	if bytes.Contains(result.Content, []byte("Autocrypt")) {
		t.Fatalf("Autocrypt header leaked into the encrypted/decrypted inner content:\n%s", result.Content)
	}
}

func TestSignMIMEPreservesAutocryptHeader(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	plaintext := mailmsg.Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "secret",
		Mode:      "plain",
		Autocrypt: "addr=alice@example.com; keydata=QUJD",
	}.Build()

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}
	if !bytes.Contains(signed, []byte("\r\nAutocrypt: addr=alice@example.com; keydata=QUJD\r\n")) {
		t.Fatalf("Autocrypt header not on signed envelope:\n%s", signed)
	}
}

// longAutocryptTestKeydata returns base64 keydata roughly the size of an
// imported RSA-3072 key (~2487 octets unfolded), matching the size that
// motivated R1: gopenpgp's default curve25519 keys stay under RFC 5322's
// line-length limit with little headroom, but an imported RSA key does not.
func longAutocryptTestKeydata(t *testing.T) (keyBytes []byte, keydataB64 string) {
	t.Helper()
	keyBytes = make([]byte, 1865)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	keydataB64 = base64.StdEncoding.EncodeToString(keyBytes)
	if len(keydataB64) < 2000 {
		t.Fatalf("test setup bug: keydata too short to exercise folding (%d)", len(keydataB64))
	}
	return keyBytes, keydataB64
}

// assertNoOverlongLines fails the test if any \r\n-delimited line in raw
// exceeds the RFC 5322 §2.1.1 / RFC 5321 §4.5.3.1.6 998/1000-octet limits.
func assertNoOverlongLines(t *testing.T, raw []byte) {
	t.Helper()
	for _, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Fatalf("line exceeds 998 octets (%d): %q", len(line), line)
		}
	}
}

// TestEncryptMIMEFoldsLongAutocryptHeader covers R1's "critical subtlety":
// splitMessage reads the outer headers via textproto.ReadMIMEHeader, which
// unfolds mailmsg.Build()'s RFC 5322 folding back into one long value, and
// writeEnvelopeHeaders must re-fold the Autocrypt header when re-emitting it
// on the encrypted envelope — otherwise the fold applied on the plain path
// is silently undone on the encrypt path.
func TestEncryptMIMEFoldsLongAutocryptHeader(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	keyBytes, keydataB64 := longAutocryptTestKeydata(t)
	plaintext := mailmsg.Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "secret",
		Mode:      "plain",
		Autocrypt: "addr=alice@example.com; keydata=" + keydataB64,
	}.Build()

	encrypted, err := EncryptMIME(plaintext, []string{alice.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	assertNoOverlongLines(t, encrypted)

	msg, err := mail.ReadMessage(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	_, gotKeydata, err := pgpautocrypt.ParseAutocryptHeader(msg.Header.Get("Autocrypt"))
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if !bytes.Equal(gotKeydata, keyBytes) {
		t.Fatalf("keydata round-trip mismatch on encrypted envelope")
	}
}

// TestSignMIMEFoldsLongAutocryptHeader is TestEncryptMIMEFoldsLongAutocryptHeader's
// counterpart for the sign-only path (buildSignedEnvelope also goes through
// writeEnvelopeHeaders).
func TestSignMIMEFoldsLongAutocryptHeader(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity alice: %v", err)
	}
	keyBytes, keydataB64 := longAutocryptTestKeydata(t)
	plaintext := mailmsg.Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "secret",
		Mode:      "plain",
		Autocrypt: "addr=alice@example.com; keydata=" + keydataB64,
	}.Build()

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}
	assertNoOverlongLines(t, signed)

	msg, err := mail.ReadMessage(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	_, gotKeydata, err := pgpautocrypt.ParseAutocryptHeader(msg.Header.Get("Autocrypt"))
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if !bytes.Equal(gotKeydata, keyBytes) {
		t.Fatalf("keydata round-trip mismatch on signed envelope")
	}
}
