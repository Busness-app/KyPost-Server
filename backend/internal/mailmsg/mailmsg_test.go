package mailmsg

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
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
	if string(body) != "The body" {
		t.Fatalf("body = %q", body)
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
	textBody, _ := io.ReadAll(text)
	if string(textBody) != "See attached." {
		t.Fatalf("text body = %q", textBody)
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
