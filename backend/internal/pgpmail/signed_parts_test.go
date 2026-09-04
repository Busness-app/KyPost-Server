package pgpmail

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"
)

// The signed part ExtractSignedParts returns must be byte-identical to the
// content SignMIME signed. Anything less and verification cannot succeed —
// which is exactly the production bug this function exists to fix, where the
// caller passed go-imap's DECODED body instead.
func TestExtractSignedPartsRoundTripsSignMIME(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	plaintext := mailmsg.Message{
		From:    "alice@example.com",
		To:      []string{"bob@example.com"},
		Subject: "Signed only",
		Body:    "trust me",
		Mode:    "plain",
	}.Build()

	_, wantContent, err := splitMessage(plaintext)
	if err != nil {
		t.Fatalf("splitMessage: %v", err)
	}

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}

	gotPart, gotSig, err := ExtractSignedParts(signed)
	if err != nil {
		t.Fatalf("ExtractSignedParts: %v", err)
	}
	if !bytes.Equal(gotPart, wantContent) {
		t.Fatalf("signed part is not byte-identical to what was signed:\n got %q\nwant %q", gotPart, wantContent)
	}
	if !strings.HasPrefix(gotSig, "-----BEGIN PGP SIGNATURE-----") ||
		!strings.HasSuffix(gotSig, "-----END PGP SIGNATURE-----") {
		t.Fatalf("expected a complete armored signature block, got %q", gotSig)
	}
}

// A multipart/mixed body (message with an attachment) ends in its own CRLF, and
// buildSignedEnvelope has a documented history of losing exactly two bytes
// there. The extractor must cut at the CRLF that belongs to the boundary
// delimiter and not one byte further — see TestSignMIMEWithAttachmentPreservesTrailingCRLF.
func TestExtractSignedPartsPreservesTrailingCRLF(t *testing.T) {
	alice, err := GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
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
		t.Fatal("test setup invalid: expected the signed content to end in its own CRLF")
	}

	signed, err := SignMIME(plaintext, alice)
	if err != nil {
		t.Fatalf("SignMIME: %v", err)
	}

	gotPart, _, err := ExtractSignedParts(signed)
	if err != nil {
		t.Fatalf("ExtractSignedParts: %v", err)
	}
	if !bytes.Equal(gotPart, wantContent) {
		t.Fatalf("trailing CRLF handling is wrong:\n got %q\nwant %q", gotPart, wantContent)
	}
}

func TestExtractSignedPartsRejectsNonSignedMessages(t *testing.T) {
	cases := map[string][]byte{
		"plain text message": []byte("From: a@example.com\r\n" +
			"Content-Type: text/plain\r\n\r\nhello\r\n"),
		"multipart/mixed, not signed": []byte("From: a@example.com\r\n" +
			"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"),
		"multipart/signed with a non-PGP protocol": []byte("From: a@example.com\r\n" +
			"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"),
		"multipart/signed with no signature armor": []byte("From: a@example.com\r\n" +
			"Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"b\"\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
			"--b\r\nContent-Type: application/pgp-signature\r\n\r\nnot armor\r\n--b--\r\n"),
		"multipart/signed with only one part": []byte("From: a@example.com\r\n" +
			"Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=\"b\"\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ExtractSignedParts(raw); !errors.Is(err, ErrNotSignedMessage) {
				t.Fatalf("expected ErrNotSignedMessage, got %v", err)
			}
		})
	}
}
