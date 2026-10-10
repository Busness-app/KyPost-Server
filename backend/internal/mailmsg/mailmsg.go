// Package mailmsg builds RFC 5322 messages — single-part text, or
// multipart/mixed when attachments are present — shared by the SMTP send
// path (api.handleMailSend) and the IMAP APPEND path (imap saveMessage) so
// both produce identical MIME.
package mailmsg

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"
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
	// EncodedBody, when set, is RFC 2045 base64 text for Body. It is used by
	// request-facing callers to keep raw compose text out of MIME construction.
	EncodedBody string
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
	// MessageID ("<id@domain>") and Date are filled by Stamp when empty.
	// Stamp once and Build every copy (delivered, Sent) from the result so
	// they share one identity.
	MessageID string
	Date      time.Time
	// InReplyTo and References thread a reply (RFC 5322 §3.6.4). Build emits
	// only well-formed msg-ids from them; see MessageIDs.
	InReplyTo  string
	References []string
}

// Stamp fills an empty Date and Message-ID. The Message-ID domain is the From
// address's domain; an unparseable From gets no Message-ID rather than an
// invented domain.
func (m Message) Stamp() Message {
	if m.Date.IsZero() {
		m.Date = time.Now()
	}
	if m.MessageID == "" {
		if addr, err := mail.ParseAddress(m.From); err == nil {
			if at := strings.LastIndexByte(addr.Address, '@'); at >= 0 {
				m.MessageID = "<" + strings.ToLower(rand.Text()) + "@" + strings.ToLower(addr.Address[at+1:]) + ">"
			}
		}
	}
	return m
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

// msgIDPattern is an RFC 5322 msg-id: "<" left "@" right ">" in printable
// ASCII with no angle brackets. Nothing else in a header value survives.
var msgIDPattern = regexp.MustCompile(`<[\x21-\x3b\x3d\x3f-\x7e]{1,250}@[\x21-\x3b\x3d\x3f-\x7e]{1,250}>`)

// maxReferences bounds a References header; RFC 5322 §3.6.4 allows trimming.
const maxReferences = 20

// MessageIDs extracts the well-formed msg-ids from a header value, dropping
// everything else (comments, whitespace, CR/LF, garbage). The whole value is
// scanned, but only the first id (a thread's root) and the newest
// maxReferences are kept, so memory stays bounded and the newest end of a
// long chain is never lost.
func MessageIDs(value string) []string {
	var out []string
	for {
		loc := msgIDPattern.FindStringIndex(value)
		if loc == nil {
			return out
		}
		out = append(out, value[loc[0]:loc[1]])
		value = value[loc[1]:]
		if len(out) > maxReferences+1 {
			out = append(out[:1], out[2:]...)
		}
	}
}

// capReferences keeps the thread root and the newest ids.
func capReferences(refs []string) []string {
	if len(refs) <= maxReferences {
		return refs
	}
	return append(refs[:1:1], refs[len(refs)-(maxReferences-1):]...)
}

// ReplyThreading derives a reply's In-Reply-To and References from the
// original's Message-ID, References and In-Reply-To header values. It returns
// "" when the original has no single well-formed Message-ID to reply to.
func ReplyThreading(messageID, references, inReplyTo string) (string, []string) {
	ids := MessageIDs(messageID)
	if len(ids) != 1 {
		return "", nil
	}
	refs := MessageIDs(references)
	if len(refs) == 0 {
		if parent := MessageIDs(inReplyTo); len(parent) == 1 {
			refs = parent
		}
	}
	return ids[0], capReferences(append(refs, ids[0]))
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

// FoldEncodedWords restores folding between RFC 2047 words after MIME parsers
// unfold them. Each encoded word stays intact on its own physical line.
func FoldEncodedWords(value string) string {
	return strings.ReplaceAll(value, "?= =?", "?=\r\n =?")
}

// Build renders the complete message bytes.
func (m Message) Build() []byte {
	m = m.Stamp()
	bodyEncoded := m.EncodedBody
	if bodyEncoded == "" {
		bodyEncoded = base64.StdEncoding.EncodeToString([]byte(m.Body))
	}
	var msg bytes.Buffer
	msg.WriteString("From: " + SanitizeHeaderValue(m.From) + "\r\n")
	msg.WriteString("To: " + strings.Join(sanitizeHeaderValues(m.To), ", ") + "\r\n")
	if len(m.CC) > 0 {
		msg.WriteString("Cc: " + strings.Join(sanitizeHeaderValues(m.CC), ", ") + "\r\n")
	}
	if len(m.BCC) > 0 {
		msg.WriteString("Bcc: " + strings.Join(sanitizeHeaderValues(m.BCC), ", ") + "\r\n")
	}
	subject := SanitizeHeaderValue(m.Subject)
	encodedSubject := mime.QEncoding.Encode("utf-8", subject)
	if encodedSubject != subject {
		encodedSubject = FoldEncodedWords(encodedSubject)
	}
	msg.WriteString("Subject: " + encodedSubject + "\r\n")
	msg.WriteString("Date: " + m.Date.UTC().Format(time.RFC1123Z) + "\r\n")
	if id := SanitizeHeaderValue(m.MessageID); id != "" {
		msg.WriteString("Message-ID: " + id + "\r\n")
	}
	if ids := MessageIDs(m.InReplyTo); len(ids) == 1 {
		msg.WriteString("In-Reply-To: " + ids[0] + "\r\n")
	}
	if refs := capReferences(MessageIDs(strings.Join(m.References, " "))); len(refs) > 0 {
		// One msg-id per folded line keeps every line far under 998 octets.
		msg.WriteString("References: " + strings.Join(refs, "\r\n ") + "\r\n")
	}
	msg.WriteString("MIME-Version: 1.0\r\n")
	if m.Autocrypt != "" {
		msg.WriteString("Autocrypt: " + FoldHeaderValue(SanitizeHeaderValue(m.Autocrypt)) + "\r\n")
	}

	if len(m.Attachments) == 0 {
		msg.WriteString("Content-Type: " + m.ContentType() + "\r\n")
		msg.WriteString("Content-Transfer-Encoding: base64\r\n")
		msg.WriteString("\r\n")
		writeWrappedBase64(&msg, bodyEncoded)
		return msg.Bytes()
	}

	w := multipart.NewWriter(&msg)
	msg.WriteString("Content-Type: multipart/mixed; boundary=" + w.Boundary() + "\r\n")
	msg.WriteString("\r\n")

	text, _ := w.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {m.ContentType()},
		"Content-Transfer-Encoding": {"base64"},
	})
	writeWrappedBase64(text, bodyEncoded)

	for _, a := range m.Attachments {
		// Sanitized like every other header value here. mime/multipart writes
		// header values verbatim, so a CRLF in the caller-supplied MIME type
		// injects arbitrary part headers, a premature body break and a forged
		// boundary. This was the one value in Build that reached a header
		// writer with only TrimSpace. Re-parsed as well, so a syntactically
		// broken type falls back rather than being emitted as-is.
		contentType := SanitizeHeaderValue(a.MimeType)
		if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
			contentType = parsed
		} else {
			contentType = ""
		}
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
	writeWrappedBase64(dst, base64.StdEncoding.EncodeToString(data))
}

func writeWrappedBase64(dst io.Writer, encoded string) {
	const lineLen = 76
	for start := 0; start < len(encoded); start += lineLen {
		end := min(start+lineLen, len(encoded))
		_, _ = io.WriteString(dst, encoded[start:end])
		_, _ = io.WriteString(dst, "\r\n")
	}
}
