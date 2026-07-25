// Package mailmsg builds RFC 5322 messages — single-part text, or
// multipart/mixed when attachments are present — shared by the SMTP send
// path (api.handleMailSend) and the IMAP APPEND path (imap saveMessage) so
// both produce identical MIME.
package mailmsg

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

type Attachment struct {
	Name     string
	MimeType string
	Content  []byte
}

type Message struct {
	From string
	To   []string
	CC   []string
	// BCC is written as a header only for stored copies (drafts / Sent);
	// SMTP callers must leave it empty so recipients stay hidden.
	BCC     []string
	Subject string
	Body    string
	// "plain" (default), "html", or "markup" (sent as text/markdown) —
	// the same values /api/mail/send accepts.
	Mode string
	// Autocrypt, when non-empty, is emitted verbatim as the value of an
	// outer "Autocrypt:" header (RFC-none; see the Autocrypt Level 1 spec).
	// It advertises the sender's own public key. The caller is responsible
	// for its content (addr=<from>; keydata=<base64>); it is placed on the
	// outer, unencrypted envelope so correspondents' clients can harvest it.
	Autocrypt   string
	Attachments []Attachment
}

// ContentType is the text part's Content-Type for the message mode.
func (m Message) ContentType() string {
	switch strings.ToLower(strings.TrimSpace(m.Mode)) {
	case "html":
		return "text/html; charset=UTF-8"
	case "markup":
		return "text/markdown; charset=UTF-8"
	default:
		return "text/plain; charset=UTF-8"
	}
}

// SanitizeHeaderValue flattens CR/LF so user input can't inject headers.
func SanitizeHeaderValue(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
}

// sanitizeHeaderValues sanitizes each element of a string slice.
func sanitizeHeaderValues(values []string) []string {
	result := make([]string, len(values))
	for i, v := range values {
		result[i] = SanitizeHeaderValue(v)
	}
	return result
}

// foldWidth is how many characters of an attribute's value are emitted per
// physical line by FoldHeaderValue. Chosen with generous headroom under both
// the RFC 5322 §2.1.1 998-octet MUST NOT and the RFC 5321 §4.5.3.1.6
// 1000-octet SMTP line cap: even the longest realistic physical line this
// produces (header name + a full attribute prefix + one foldWidth chunk) is
// well under a few hundred octets.
const foldWidth = 72

// FoldHeaderValue folds a structured "name=value; name2=value2; ..." header
// value (the shape the Autocrypt header uses) so that any single attribute
// whose value exceeds foldWidth characters is wrapped across RFC 5322 folded
// continuation lines ("\r\n " — CRLF followed by exactly one space of
// linear whitespace). Attribute names, the "=" separating name from value,
// and the "; " between attributes are never split — only kept together with
// their own attribute's fold breaks — so a receiving parser that splits on
// ";" before stripping whitespace (as pgpautocrypt.ParseAutocryptHeader
// does) still finds each "name=" intact.
//
// This exists because the Autocrypt header's base64 keydata can exceed 900+
// octets for an imported RSA-3072 key (gopenpgp's default curve25519 keys
// stay under the limit with little headroom). Emitted unfolded, that single
// line would violate RFC 5322 and RFC 5321's line-length limits, which can
// cause an MTA to reject the message outright or corrupt it mid base64.
//
// Values that don't look like "name=value" pairs (e.g. a plain Subject) or
// whose attributes are all short pass through unchanged — folding only ever
// engages for an attribute value longer than foldWidth.
func FoldHeaderValue(value string) string {
	parts := strings.Split(value, ";")
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		prefix := ""
		if i > 0 {
			prefix = " "
		}
		if len(trimmed) <= foldWidth {
			parts[i] = prefix + trimmed
			continue
		}
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			parts[i] = prefix + trimmed
			continue
		}
		name, val := trimmed[:eq+1], trimmed[eq+1:]
		var b strings.Builder
		b.WriteString(prefix)
		b.WriteString(name)
		for j := 0; j < len(val); j += foldWidth {
			if j > 0 {
				b.WriteString("\r\n ")
			}
			end := min(j+foldWidth, len(val))
			b.WriteString(val[j:end])
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, ";")
}

// Build renders the complete message bytes.
func (m Message) Build() []byte {
	var msg bytes.Buffer
	msg.WriteString("From: " + SanitizeHeaderValue(m.From) + "\r\n")
	msg.WriteString("To: " + strings.Join(sanitizeHeaderValues(m.To), ", ") + "\r\n")
	if len(m.CC) > 0 {
		msg.WriteString("Cc: " + strings.Join(sanitizeHeaderValues(m.CC), ", ") + "\r\n")
	}
	if len(m.BCC) > 0 {
		msg.WriteString("Bcc: " + strings.Join(sanitizeHeaderValues(m.BCC), ", ") + "\r\n")
	}
	msg.WriteString("Subject: " + SanitizeHeaderValue(m.Subject) + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	if m.Autocrypt != "" {
		msg.WriteString("Autocrypt: " + FoldHeaderValue(SanitizeHeaderValue(m.Autocrypt)) + "\r\n")
	}

	if len(m.Attachments) == 0 {
		msg.WriteString("Content-Type: " + m.ContentType() + "\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(m.Body)
		return msg.Bytes()
	}

	w := multipart.NewWriter(&msg)
	msg.WriteString("Content-Type: multipart/mixed; boundary=" + w.Boundary() + "\r\n")
	msg.WriteString("\r\n")

	text, _ := w.CreatePart(textproto.MIMEHeader{
		"Content-Type": {m.ContentType()},
	})
	_, _ = io.WriteString(text, m.Body)

	for _, a := range m.Attachments {
		contentType := strings.TrimSpace(a.MimeType)
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		name := SanitizeHeaderValue(a.Name)
		if name == "" {
			name = "attachment"
		}
		part, _ := w.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {contentType},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition": {mime.FormatMediaType(
				"attachment", map[string]string{"filename": name},
			)},
		})
		writeBase64Wrapped(part, a.Content)
	}
	_ = w.Close()
	return msg.Bytes()
}

// writeBase64Wrapped writes base64 content in RFC 2045 76-character lines.
func writeBase64Wrapped(dst io.Writer, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	const lineLen = 76
	for start := 0; start < len(encoded); start += lineLen {
		end := min(start+lineLen, len(encoded))
		_, _ = io.WriteString(dst, encoded[start:end])
		_, _ = io.WriteString(dst, "\r\n")
	}
}
