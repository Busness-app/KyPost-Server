package mailmsg

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/pgpautocrypt"
)

func TestBuildSinglePart(t *testing.T) {
	raw := Message{
		From:    "sender@example.com",
		To:      []string{"a@example.com", "b@example.com"},
		CC:      []string{"c@example.com"},
		Subject: "Hello\r\nX-Injected: nope",
		Body:    "The body",
		Mode:    "html",
	}.Build()

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got := msg.Header.Get("Subject"); got != "Hello  X-Injected: nope" {
		t.Fatalf("Subject = %q; header injection must be flattened", got)
	}
	if got := msg.Header.Get("To"); got != "a@example.com, b@example.com" {
		t.Fatalf("To = %q", got)
	}
	if got := msg.Header.Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if msg.Header.Get("Bcc") != "" {
		t.Fatalf("Bcc header must be absent when BCC is empty")
	}
	body, _ := io.ReadAll(msg.Body)
	decoded, err := decodeBase64Lines(string(body))
	if err != nil || string(decoded) != "The body" {
		t.Fatalf("decoded body = %q (err %v)", decoded, err)
	}
}

func TestContentTypePerMode(t *testing.T) {
	cases := map[string]string{
		"":       "text/plain; charset=UTF-8",
		"plain":  "text/plain; charset=UTF-8",
		"HTML":   "text/html; charset=UTF-8",
		"markup": "text/markdown; charset=UTF-8",
	}
	for mode, want := range cases {
		if got := (Message{Mode: mode}).ContentType(); got != want {
			t.Errorf("ContentType(%q) = %q, want %q", mode, got, want)
		}
	}
}

func TestBuildMultipartRoundTrip(t *testing.T) {
	content := []byte("PDF-ish bytes \x00\x01\x02 that need base64")
	raw := Message{
		From:        "sender@example.com",
		To:          []string{"a@example.com"},
		Subject:     "With attachment",
		Body:        "See attached.",
		Mode:        "plain",
		Attachments: []Attachment{{Name: "report q3.pdf", MimeType: "application/pdf", Content: content}},
	}.Build()

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (err %v), want multipart/mixed", mediaType, err)
	}

	reader := multipart.NewReader(msg.Body, params["boundary"])

	text, err := reader.NextPart()
	if err != nil {
		t.Fatalf("text part: %v", err)
	}
	if got := text.Header.Get("Content-Type"); got != "text/plain; charset=UTF-8" {
		t.Fatalf("text part Content-Type = %q", got)
	}
	if got := text.Header.Get("Content-Transfer-Encoding"); got != "base64" {
		t.Fatalf("text part transfer encoding = %q", got)
	}
	textBody, _ := io.ReadAll(text)
	decodedText, err := decodeBase64Lines(string(textBody))
	if err != nil || string(decodedText) != "See attached." {
		t.Fatalf("decoded text body = %q (err %v)", decodedText, err)
	}

	attachment, err := reader.NextPart()
	if err != nil {
		t.Fatalf("attachment part: %v", err)
	}
	if got := attachment.Header.Get("Content-Type"); got != "application/pdf" {
		t.Fatalf("attachment Content-Type = %q", got)
	}
	if got := attachment.FileName(); got != "report q3.pdf" {
		t.Fatalf("attachment filename = %q", got)
	}
	if got := attachment.Header.Get("Content-Transfer-Encoding"); got != "base64" {
		t.Fatalf("attachment transfer encoding = %q", got)
	}
	// multipart.Reader does not decode base64; do it by hand to prove the
	// round-trip. (Lines are CRLF-wrapped at 76 chars per RFC 2045.)
	encoded, _ := io.ReadAll(attachment)
	decoded, err := decodeBase64Lines(string(encoded))
	if err != nil {
		t.Fatalf("decode attachment: %v", err)
	}
	if string(decoded) != string(content) {
		t.Fatalf("attachment content round-trip failed: got %q", decoded)
	}

	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("expected exactly 2 parts, got extra (err %v)", err)
	}
}

func TestBuildFallsBackForUnnamedUntypedAttachment(t *testing.T) {
	raw := Message{
		From:        "s@example.com",
		To:          []string{"a@example.com"},
		Attachments: []Attachment{{Content: []byte("x")}},
	}.Build()
	text := string(raw)
	if !strings.Contains(text, "application/octet-stream") {
		t.Fatalf("missing octet-stream fallback:\n%s", text)
	}
	if !strings.Contains(text, `filename=attachment`) {
		t.Fatalf("missing filename fallback:\n%s", text)
	}
}

func TestBuildSanitizesToCCBCCHeaders(t *testing.T) {
	raw := Message{
		From:    "sender@example.com",
		To:      []string{"a@example.com", "b\r\nX-Injected-To: evil@example.com"},
		CC:      []string{"c\r\nX-Injected-CC: evil@example.com"},
		BCC:     []string{"d\r\nX-Injected-BCC: evil@example.com"},
		Subject: "Test",
		Body:    "The body",
		Mode:    "plain",
	}.Build()

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	// Verify To header injection is prevented (CR/LF flattened to spaces)
	if got := msg.Header.Get("To"); got != "a@example.com, b  X-Injected-To: evil@example.com" {
		t.Fatalf("To = %q; header injection must be flattened", got)
	}

	// Verify injected headers via To/CC/BCC do not appear
	if got := msg.Header.Get("X-Injected-To"); got != "" {
		t.Fatalf("X-Injected-To header must not exist, got %q", got)
	}

	// Verify CC header injection is prevented
	if got := msg.Header.Get("Cc"); got != "c  X-Injected-CC: evil@example.com" {
		t.Fatalf("Cc = %q; header injection must be flattened", got)
	}

	if got := msg.Header.Get("X-Injected-CC"); got != "" {
		t.Fatalf("X-Injected-CC header must not exist, got %q", got)
	}

	// Verify BCC header injection is prevented
	if got := msg.Header.Get("Bcc"); got != "d  X-Injected-BCC: evil@example.com" {
		t.Fatalf("Bcc = %q; header injection must be flattened", got)
	}

	if got := msg.Header.Get("X-Injected-BCC"); got != "" {
		t.Fatalf("X-Injected-BCC header must not exist, got %q", got)
	}
}

func TestBuildEmitsAutocryptHeader(t *testing.T) {
	m := Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "hello",
		Autocrypt: "addr=alice@example.com; keydata=QUJD",
	}
	out := string(m.Build())
	if !strings.Contains(out, "\r\nAutocrypt: addr=alice@example.com; keydata=QUJD\r\n") {
		t.Fatalf("expected Autocrypt header, got:\n%s", out)
	}
}

func TestBuildOmitsAutocryptWhenEmpty(t *testing.T) {
	m := Message{From: "a@x.com", To: []string{"b@y.com"}, Body: "hi"}
	if strings.Contains(string(m.Build()), "Autocrypt:") {
		t.Fatal("did not expect an Autocrypt header")
	}
}

func decodeBase64Lines(encoded string) ([]byte, error) {
	clean := strings.NewReplacer("\r", "", "\n", "").Replace(encoded)
	return base64.StdEncoding.DecodeString(clean)
}

// TestBuildFoldsLongAutocryptHeader covers R1: an imported RSA-3072 key's
// base64 keydata (~2487 octets unfolded, per the branch review that found
// this) must not be emitted as a single unfolded line, since that would
// exceed the RFC 5322 §2.1.1 998-octet MUST NOT and the RFC 5321 §4.5.3.1.6
// 1000-octet SMTP line cap. It must fold, and the folded value must still
// round-trip through pgpautocrypt.ParseAutocryptHeader (after the folding
// whitespace textproto.ReadMIMEHeader would unfold on receipt) to the
// identical key bytes.
func TestBuildFoldsLongAutocryptHeader(t *testing.T) {
	keyBytes := make([]byte, 1865) // ~2487 base64 octets, an RSA-3072-sized key
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	keydataB64 := base64.StdEncoding.EncodeToString(keyBytes)
	if len(keydataB64) < 2000 {
		t.Fatalf("test setup bug: keydata too short to exercise folding (%d)", len(keydataB64))
	}
	autocrypt := "addr=alice@example.com; prefer-encrypt=mutual; keydata=" + keydataB64

	raw := Message{
		From:      "alice@example.com",
		To:        []string{"bob@example.com"},
		Subject:   "hi",
		Body:      "hello",
		Autocrypt: autocrypt,
	}.Build()

	for _, line := range strings.Split(string(raw), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("line exceeds 998 octets (%d): %q", len(line), line)
		}
	}
	if !bytes.Contains(raw, []byte("Autocrypt: addr=alice@example.com; prefer-encrypt=mutual; keydata=")) {
		t.Fatalf("Autocrypt header prefix not found unfolded:\n%s", raw)
	}
	if !bytes.Contains(raw, []byte("\r\n ")) {
		t.Fatalf("expected at least one RFC 5322 folded continuation line:\n%s", raw)
	}

	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	// net/mail's underlying textproto reader unfolds continuation lines back
	// into a single value with the fold's leading space preserved — the same
	// transformation pgpmail.splitMessage performs on the send path.
	unfolded := msg.Header.Get("Autocrypt")
	if strings.Contains(unfolded, "\r\n") {
		t.Fatalf("expected header to be unfolded by the MIME header reader, got %q", unfolded)
	}

	_, gotKeydata, err := pgpautocrypt.ParseAutocryptHeader(unfolded)
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if !bytes.Equal(gotKeydata, keyBytes) {
		t.Fatalf("keydata round-trip mismatch: got %d bytes, want %d bytes", len(gotKeydata), len(keyBytes))
	}
}

func TestFoldHeaderValueShortValuePassesThrough(t *testing.T) {
	in := "addr=alice@example.com; keydata=QUJD"
	if got := FoldHeaderValue(in); got != in {
		t.Fatalf("FoldHeaderValue(%q) = %q, want unchanged", in, got)
	}
}

func TestFoldHeaderValueNeverSplitsAttributeName(t *testing.T) {
	// A value with no "=" at all (e.g. a plain long Subject) must pass
	// through unfolded rather than being chopped mid-word.
	in := strings.Repeat("nofoldpoints", 20)
	if got := FoldHeaderValue(in); got != in {
		t.Fatalf("FoldHeaderValue without '=' must pass through unchanged, got %q", got)
	}
}
