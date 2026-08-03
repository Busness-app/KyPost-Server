package pgpmail

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	opgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"kypost-server/backend/internal/mailmsg"
)

// envelopeHeaderOrder lists the outer RFC 5322 headers preserved verbatim on a
// PGP/MIME-wrapped message, in the order mailmsg.Message.Build() writes them.
// PGP/MIME wraps only the content (Content-Type + body); OpenPGP does not
// protect routing metadata, so routing and display headers stay outside the
// encrypted/signed part. Autocrypt is here rather than folded into the encrypted
// content because it exists to let a receiving client opportunistically pick up
// the sender's public key without decrypting anything.
var envelopeHeaderOrder = []string{"From", "To", "Cc", "Bcc", "Subject", "Autocrypt"}

// splitMessage separates a raw RFC 5322 message (as produced by
// mailmsg.Message.Build()) into its preserved envelope headers and its inner
// content part (the original Content-Type header plus body, byte-identical
// to the input).
func splitMessage(raw []byte) (envelope textproto.MIMEHeader, content []byte, err error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	header, err := reader.ReadMIMEHeader()
	if err != nil && header == nil {
		return nil, nil, fmt.Errorf("pgpmail: read message headers: %w", err)
	}

	contentType := header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain; charset=UTF-8"
	}

	var body bytes.Buffer
	if _, err := body.ReadFrom(reader.R); err != nil {
		return nil, nil, fmt.Errorf("pgpmail: read message body: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString("Content-Type: " + contentType + "\r\n")
	if transferEncoding := header.Get("Content-Transfer-Encoding"); transferEncoding != "" {
		buf.WriteString("Content-Transfer-Encoding: " + transferEncoding + "\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(body.Bytes())

	return header, buf.Bytes(), nil
}

// writeEnvelopeHeaders re-emits the preserved envelope headers. splitMessage
// read them via textproto.ReadMIMEHeader, which unfolds any RFC 5322 folded
// continuation lines back into a single long value — so the Autocrypt header
// (see mailmsg.FoldHeaderValue) must be re-folded here, or its long base64
// keydata would go back out as one unfolded line exceeding the RFC 5322/5321
// line-length limits, even though mailmsg.Message.Build() folded it
// correctly the first time.
func writeEnvelopeHeaders(w io.Writer, envelope textproto.MIMEHeader) {
	for _, name := range envelopeHeaderOrder {
		v := envelope.Get(name)
		if v == "" {
			continue
		}
		if name == "Autocrypt" {
			v = mailmsg.FoldHeaderValue(v)
		}
		_, _ = io.WriteString(w, name+": "+v+"\r\n")
	}
}

// OuterPlaceholderSubject replaces the real Subject on the unencrypted outer
// envelope of a PGP/MIME-encrypted message. The real subject is instead
// carried inside the encrypted payload via protected headers (protectContent)
// and restored on the receiving side (ExtractProtectedSubject). Also reused
// for the outer subject of pickup notifications so the real subject never
// travels in cleartext.
const OuterPlaceholderSubject = "[Encrypted] Email Sent by KyPost"

// protectContent wraps an inner MIME content part (a Content-Type header line
// plus body, as produced by splitMessage) in a Protected Headers v1 structure —
// the "memoryhole" convention of draft-ietf-lamps-header-protection emitted and
// consumed by Thunderbird, Mutt and K-9. The real subject is copied onto the
// wrapper's own headers (protected-headers="v1") so an aware client shows it,
// and, when non-empty, into a leading text/rfc822-headers "legacy display" part
// so any other client still renders it readably. The original content is nested
// byte-verbatim as the final part.
//
// Scope is deliberately Subject-only (LAMPS baseline). Hand-assembled rather
// than via a mime/multipart.Writer for the same reason as buildSignedEnvelope:
// CreatePart injects its own header separator and would corrupt the
// byte-verbatim nested content.
func protectContent(content []byte, subject string) []byte {
	subject = mailmsg.SanitizeHeaderValue(subject)
	boundary := randomBoundary()

	var msg bytes.Buffer
	if subject != "" {
		msg.WriteString("Subject: " + subject + "\r\n")
	}
	msg.WriteString(`Content-Type: multipart/mixed; boundary="` + boundary + `"; protected-headers="v1"` + "\r\n")
	msg.WriteString("\r\n")

	if subject != "" {
		msg.WriteString("--" + boundary + "\r\n")
		msg.WriteString("Content-Type: text/rfc822-headers; protected-headers=\"v1\"\r\n")
		msg.WriteString("Content-Disposition: inline\r\n")
		msg.WriteString("\r\n")
		msg.WriteString("Subject: " + subject + "\r\n")
		msg.WriteString("\r\n")
	}

	// Per RFC 2046 the CRLF before a boundary delimiter belongs to the
	// delimiter; write it unconditionally after the (possibly multipart)
	// content, mirroring buildSignedEnvelope.
	msg.WriteString("--" + boundary + "\r\n")
	msg.Write(content)
	msg.WriteString("\r\n")
	msg.WriteString("--" + boundary + "--\r\n")
	return msg.Bytes()
}

// ExtractProtectedSubject reads a protected Subject header from a decrypted
// PGP/MIME content part (the bytes returned by DecryptMIME). It accepts both
// KyPost's own protectContent output and Thunderbird/Mutt/K-9 protected-headers
// mail, RFC 2047-decoding an encoded-word subject. The inner Subject is
// sender-authored encrypted data — the same trust level as the body — so it is
// accepted regardless of the protected-headers parameter. ok is false when no
// Subject is present or it decodes to empty, and callers then fall back to the
// outer envelope subject.
func ExtractProtectedSubject(content []byte) (subject string, ok bool) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(content)))
	header, err := reader.ReadMIMEHeader()
	if err != nil && header == nil {
		return "", false
	}
	raw := header.Get("Subject")
	if raw == "" {
		return "", false
	}
	decoded, err := (&mime.WordDecoder{}).DecodeHeader(raw)
	if err != nil {
		decoded = raw
	}
	decoded = mailmsg.SanitizeHeaderValue(decoded)
	if decoded == "" {
		return "", false
	}
	return decoded, true
}

// EncryptMIME wraps a plaintext RFC 5322 message (as produced by
// mailmsg.Message.Build()) in an RFC 3156 multipart/encrypted envelope. The
// message's Content-Type and body become the encrypted payload; From/To/Cc/Bcc
// stay on the outer, unencrypted envelope headers. A Subject is moved into the
// encrypted payload via protected headers and the outer Subject replaced with
// OuterPlaceholderSubject, so the real subject never travels in cleartext. A
// non-nil signer signs the content before encryption, verified in one step by
// DecryptMIME on the way back.
func EncryptMIME(plaintext []byte, recipientArmoredPubKeys []string, signer *Identity) ([]byte, error) {
	if len(recipientArmoredPubKeys) == 0 {
		return nil, errors.New("pgpmail: at least one recipient key required")
	}
	envelope, content, err := splitMessage(plaintext)
	if err != nil {
		return nil, err
	}
	if realSubject := envelope.Get("Subject"); realSubject != "" {
		envelope.Set("Subject", OuterPlaceholderSubject)
		content = protectContent(content, realSubject)
	}

	recipients, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: new recipient keyring: %w", err)
	}
	for _, armored := range recipientArmoredPubKeys {
		key, err := crypto.NewKeyFromArmored(armored)
		if err != nil {
			return nil, fmt.Errorf("pgpmail: parse recipient key: %w", err)
		}
		if err := recipients.AddKey(key); err != nil {
			return nil, fmt.Errorf("pgpmail: add recipient key: %w", err)
		}
	}

	builder := crypto.PGP().Encryption().Recipients(recipients)
	if signer != nil {
		builder = builder.SigningKey(signer.key)
	}
	encHandle, err := builder.New()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build encryption handle: %w", err)
	}
	pgpMessage, err := encHandle.Encrypt(content)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: encrypt: %w", err)
	}
	armored, err := pgpMessage.Armor()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: armor encrypted message: %w", err)
	}

	return buildEncryptedEnvelope(envelope, armored), nil
}

func buildEncryptedEnvelope(envelope textproto.MIMEHeader, armoredEncrypted string) []byte {
	var msg bytes.Buffer
	writeEnvelopeHeaders(&msg, envelope)
	msg.WriteString("MIME-Version: 1.0\r\n")

	w := multipart.NewWriter(&msg)
	msg.WriteString(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=` + w.Boundary() + "\r\n")
	msg.WriteString("\r\n")

	control, _ := w.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/pgp-encrypted"}})
	_, _ = io.WriteString(control, "Version: 1\r\n")

	data, _ := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {`application/octet-stream; name="encrypted.asc"`},
		"Content-Disposition": {`inline; filename="encrypted.asc"`},
	})
	_, _ = io.WriteString(data, armoredEncrypted)

	_ = w.Close()
	return msg.Bytes()
}

// DecryptResult is the outcome of decrypting a PGP/MIME payload: the
// recovered content (a Content-Type header plus body, ready for
// ParseContent) and, when the message was combined sign+encrypt, the
// signature verification outcome.
type DecryptResult struct {
	Content           []byte
	Signed            bool
	Verified          bool
	SignerFingerprint string
}

// DecryptMIME decrypts an armored OpenPGP message (the data part of a
// multipart/encrypted structure) using recipient's private key. If
// signerArmoredPubKeys is non-empty, an inline signature (present when the
// sender combined sign+encrypt) is verified against them.
func DecryptMIME(armoredPGPMessage string, recipient *Identity, signerArmoredPubKeys []string) (*DecryptResult, error) {
	if recipient == nil {
		return nil, errors.New("pgpmail: recipient identity required to decrypt")
	}
	// Defense in depth against a giant armored input even before decryption
	// is attempted — the real decompression-bomb guard is
	// MaxDecompressedMessageSize below, which bounds the *decrypted* output
	// regardless of how small the ciphertext is, but there's no reason to
	// let an absurdly large armored blob through either.
	if int64(len(armoredPGPMessage)) > mailmsg.MaxInboundMessageBytes {
		return nil, mailmsg.ErrMessageTooLarge
	}
	decryptionKeys, err := crypto.NewKeyRing(recipient.key)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build decryption keyring: %w", err)
	}

	// MaxDecompressedMessageSize is gopenpgp's own guard against a PGP
	// decompression bomb: a small ciphertext whose compressed packet expands
	// to gigabytes of plaintext once decrypted. Unlike the read sites in
	// package imap, this is a genuine streaming limit enforced by the
	// underlying go-crypto library while decompressing, not a post-hoc size
	// check — see LimitReader in go-crypto's openpgp/packet/compressed.go.
	builder := crypto.PGP().Decryption().DecryptionKeys(decryptionKeys).MaxDecompressedMessageSize(mailmsg.MaxInboundMessageBytes)
	var verifying bool
	if len(signerArmoredPubKeys) > 0 {
		verifyKeys, err := crypto.NewKeyRing(nil)
		if err != nil {
			return nil, fmt.Errorf("pgpmail: build verification keyring: %w", err)
		}
		for _, armored := range signerArmoredPubKeys {
			key, err := crypto.NewKeyFromArmored(armored)
			if err != nil {
				return nil, fmt.Errorf("pgpmail: parse signer key: %w", err)
			}
			if err := verifyKeys.AddKey(key); err != nil {
				return nil, fmt.Errorf("pgpmail: add signer key: %w", err)
			}
		}
		builder = builder.VerificationKeys(verifyKeys)
		verifying = true
	}

	decHandle, err := builder.New()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build decryption handle: %w", err)
	}
	result, err := decHandle.Decrypt([]byte(armoredPGPMessage), crypto.Auto)
	if err != nil {
		// Best-effort, not the primary guarantee: go-crypto's
		// HandleSensitiveParsingError genericizes every parsing error encountered while
		// reading symmetrically-decrypted data — including a MaxDecompressedMessageSize
		// overflow — into an opaque "parsing error", so an attacker cannot use the error
		// to distinguish "ciphertext too large" from "wrong key" before the message is
		// authenticated. For an ordinary encrypted message a decompression-bomb
		// rejection therefore surfaces as a generic decrypt error, and this branch only
		// catches it on the rarer paths go-crypto does not genericize. Either way
		// decryption fails closed and the oversized plaintext is never returned; see
		// TestDecryptMIMERejectsDecompressionBomb.
		if errors.Is(err, opgperrors.ErrMessageTooLarge) {
			return nil, mailmsg.ErrMessageTooLarge
		}
		return nil, fmt.Errorf("pgpmail: decrypt: %w", err)
	}

	out := &DecryptResult{Content: result.Bytes()}
	if verifying {
		out.Signed = len(result.Signatures) > 0
		out.Verified = out.Signed && result.SignatureError() == nil
		if key := result.SignedByKey(); key != nil {
			out.SignerFingerprint = key.GetFingerprint()
		}
	}
	return out, nil
}

// SignMIME wraps a plaintext RFC 5322 message in an RFC 3156 multipart/
// signed envelope: the message's Content-Type and body, byte-identical,
// alongside a detached OpenPGP signature over those exact bytes.
func SignMIME(plaintext []byte, signer *Identity) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("pgpmail: signer identity required")
	}
	envelope, content, err := splitMessage(plaintext)
	if err != nil {
		return nil, err
	}

	signHandle, err := crypto.PGP().Sign().SigningKey(signer.key).Detached().New()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build sign handle: %w", err)
	}
	signature, err := signHandle.Sign(content, crypto.Armor)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: sign: %w", err)
	}

	return buildSignedEnvelope(envelope, content, string(signature)), nil
}

// buildSignedEnvelope hand-assembles the multipart/signed structure instead of
// using mime/multipart.Writer for the first part: CreatePart always inserts its
// own blank-line header separator, which would corrupt the signed part's bytes
// (content already carries its own embedded Content-Type header line), and those
// bytes on the wire must be byte-identical to what was passed to Sign.
//
// Per RFC 2046 the CRLF immediately before a boundary delimiter belongs to the
// delimiter, not the part body, so it is written after content unconditionally —
// even when content already ends in its own "\r\n". That trailing CRLF is
// signed data, and a compliant parser strips exactly one additional CRLF as the
// delimiter separator, not two.
func buildSignedEnvelope(envelope textproto.MIMEHeader, content []byte, armoredSignature string) []byte {
	boundary := randomBoundary()

	var msg bytes.Buffer
	writeEnvelopeHeaders(&msg, envelope)
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(`Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg="pgp-sha256"; boundary="` + boundary + "\"\r\n")
	msg.WriteString("\r\n")

	msg.WriteString("--" + boundary + "\r\n")
	msg.Write(content)
	msg.WriteString("\r\n")

	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(armoredSignature)
	msg.WriteString("\r\n")

	msg.WriteString("--" + boundary + "--\r\n")
	return msg.Bytes()
}

func randomBoundary() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf("pgpmail-%x", buf)
}

// VerifyResult is the outcome of verifying a standalone detached signature.
type VerifyResult struct {
	Verified          bool
	SignerFingerprint string
}

// VerifyDetached verifies an armored detached signature over data using the
// given signer public keys. Used for best-effort verification of standalone
// (non-encrypted) signed mail fetched via IMAP — see the receive-path task
// and the plan's Global Constraints for why this is best-effort rather than
// exact for third-party mail.
func VerifyDetached(data []byte, armoredSignature string, signerArmoredPubKeys []string) (*VerifyResult, error) {
	if len(signerArmoredPubKeys) == 0 {
		return nil, errors.New("pgpmail: at least one signer key required")
	}
	verifyKeys, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build verification keyring: %w", err)
	}
	for _, armored := range signerArmoredPubKeys {
		key, err := crypto.NewKeyFromArmored(armored)
		if err != nil {
			return nil, fmt.Errorf("pgpmail: parse signer key: %w", err)
		}
		if err := verifyKeys.AddKey(key); err != nil {
			return nil, fmt.Errorf("pgpmail: add signer key: %w", err)
		}
	}
	verifyHandle, err := crypto.PGP().Verify().VerificationKeys(verifyKeys).New()
	if err != nil {
		return nil, fmt.Errorf("pgpmail: build verify handle: %w", err)
	}
	result, err := verifyHandle.VerifyDetached(data, []byte(armoredSignature), crypto.Auto)
	if err != nil {
		return nil, fmt.Errorf("pgpmail: verify detached: %w", err)
	}
	out := &VerifyResult{Verified: result.SignatureError() == nil}
	if key := result.SignedByKey(); key != nil {
		out.SignerFingerprint = key.GetFingerprint()
	}
	return out, nil
}

// maxContentDepth bounds recursion into nested multipart structures so a
// maliciously deep message can't exhaust the stack. Legitimate mail (including
// KyPost's own protected-headers wrapper around a multipart/mixed with
// attachments) nests only a couple of levels.
const maxContentDepth = 8

// bodyMode reports which render mode a part's Content-Type asks for. The caller
// carries it to the client so nothing downstream has to sniff the bytes.
func bodyMode(contentType string) string {
	if mediaType, _, err := mime.ParseMediaType(contentType); err == nil &&
		strings.EqualFold(mediaType, "text/html") {
		return BodyModeHTML
	}
	return BodyModePlain
}

// Body render modes, matching imapadapter's.
const (
	BodyModeHTML  = "html"
	BodyModePlain = "plain"
)

// ParseContent decodes a decrypted PGP/MIME content part (a Content-Type header
// line, a blank line, and a body — either a single text part or a multipart
// structure) into a display body and any attachments. It recurses into nested
// multipart parts, so both KyPost's own protected-headers wrapper and
// third-party senders whose inner structure differs (e.g. Thunderbird's nested
// multipart/alternative) render correctly. text/rfc822-headers parts (the
// protected-headers legacy-display part) are skipped. Anything unrecognized
// degrades gracefully to an attachment rather than erroring, so the message
// still renders.
func ParseContent(content []byte) (body, mode string, attachments []mailmsg.Attachment, err error) {
	if int64(len(content)) > mailmsg.MaxInboundMessageBytes {
		return "", "", nil, mailmsg.ErrMessageTooLarge
	}
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(content)))
	header, err := reader.ReadMIMEHeader()
	if err != nil && header == nil {
		return "", "", nil, fmt.Errorf("pgpmail: read content headers: %w", err)
	}
	rest, err := mailmsg.BoundedRead(reader.R, mailmsg.MaxInboundMessageBytes)
	if err != nil {
		if errors.Is(err, mailmsg.ErrMessageTooLarge) {
			return "", "", nil, err
		}
		return "", "", nil, fmt.Errorf("pgpmail: read content body: %w", err)
	}

	mediaType, params, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		if strings.EqualFold(header.Get("Content-Transfer-Encoding"), "base64") {
			if decoded, decErr := decodeBase64Body(rest); decErr == nil {
				rest = decoded
			}
		}
		return string(rest), bodyMode(header.Get("Content-Type")), nil, nil
	}

	mode = BodyModePlain
	err = parseMultipart(bytes.NewReader(rest), params["boundary"], 0, &body, &mode, &attachments)
	return body, mode, attachments, err
}

// parseMultipart walks the parts of a multipart body, recursing into nested
// multipart parts up to maxContentDepth. The first text/plain, text/html or
// untyped part found (in document order, across nesting) wins as the display
// body; other recognized parts become attachments; text/rfc822-headers parts
// are skipped.
func parseMultipart(r io.Reader, boundary string, depth int, body, mode *string, attachments *[]mailmsg.Attachment) error {
	if depth >= maxContentDepth {
		return nil
	}
	mr := multipart.NewReader(r, boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("pgpmail: read multipart part: %w", err)
		}

		partType := part.Header.Get("Content-Type")
		if mediaType, params, mtErr := mime.ParseMediaType(partType); mtErr == nil &&
			strings.HasPrefix(mediaType, "multipart/") && params["boundary"] != "" {
			if err := parseMultipart(part, params["boundary"], depth+1, body, mode, attachments); err != nil {
				return err
			}
			continue
		}

		partBody, err := mailmsg.BoundedRead(part, mailmsg.MaxInboundMessageBytes)
		if err != nil {
			if errors.Is(err, mailmsg.ErrMessageTooLarge) {
				return err
			}
			return fmt.Errorf("pgpmail: read part body: %w", err)
		}
		if strings.EqualFold(part.Header.Get("Content-Transfer-Encoding"), "base64") {
			if decoded, decErr := decodeBase64Body(partBody); decErr == nil {
				partBody = decoded
			}
		}

		// The protected-headers legacy-display part carries only a human-
		// readable Subject line for non-aware clients; never show it as body
		// or attachment.
		if strings.HasPrefix(partType, "text/rfc822-headers") {
			continue
		}
		// A text part without a filename is a body candidate (or, in a
		// multipart/alternative, an alternative rendering of one): the first
		// wins as the display body and the rest are dropped rather than
		// misfiled as attachments. A text part *with* a filename is a genuine
		// text attachment (e.g. note.txt) and falls through below.
		filename := part.FileName()
		if filename == "" && (strings.HasPrefix(partType, "text/plain") || strings.HasPrefix(partType, "text/html") || partType == "") {
			if *body == "" {
				*body = string(partBody)
				// The winning part's own type decides the render mode. Taken
				// here rather than sniffed later: a text/plain part mentioning
				// "<user@example.com>" is not markup, and rendering it as markup
				// deletes the address.
				*mode = bodyMode(partType)
			}
			continue
		}
		name := filename
		if name == "" {
			name = "attachment"
		}
		*attachments = append(*attachments, mailmsg.Attachment{
			Name:     name,
			MimeType: partType,
			Content:  partBody,
		})
	}
	return nil
}

func decodeBase64Body(body []byte) ([]byte, error) {
	return io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(body)))
}
