package mailmsg

import (
	"strings"
	"testing"
)

// run-4 finding LOW-2: Attachment.MimeType was the only value in Build that
// reached a header writer without SanitizeHeaderValue. Go's mime/multipart
// writes header values verbatim, so CRLF in it injects arbitrary MIME part
// headers, a premature body break, and a forged boundary. Bounded (it lands
// inside the multipart body, and the actor owns the message), but it is the
// one unsanitized sink left in Build.
func TestBuildSanitizesAttachmentMimeType(t *testing.T) {
	msg := Message{
		From:    "sender@example.com",
		To:      []string{"victim@example.com"},
		Subject: "hello",
		Body:    "body",
		Attachments: []Attachment{{
			Name:     "invoice.pdf",
			MimeType: "text/plain\r\nX-Injected: yes\r\n\r\nINJECTED BODY\r\n--X--\r\nX-Trailing: 1",
			Content:  []byte("data"),
		}},
	}

	built := string(msg.Build())

	if strings.Contains(built, "X-Injected") {
		t.Errorf("attachment MimeType injected a header into the message:\n%s", built)
	}
	if strings.Contains(built, "INJECTED BODY") {
		t.Errorf("attachment MimeType injected a body break into the message:\n%s", built)
	}
}

// run-4 finding M11: STARTTLS is attempted only when advertised, and AUTH
// likewise — so an on-path attacker who strips both from the EHLO response
// gets a plaintext session AND never triggers net/smtp's own refusal to send
// credentials unencrypted (that refusal only fires when Auth is called). The
// full message then goes out in the clear while the user is shown success.
//
// Submission must fail closed instead. The unit under test is the decision,
// not the socket: requireSTARTTLS reports whether a session that did not
// negotiate TLS may proceed to DATA.
func TestSubmissionRefusesCleartextWhenStartTLSUnavailable(t *testing.T) {
	if err := requireSTARTTLS(false, false); err == nil {
		t.Fatal("a submission session with no STARTTLS must be refused: " +
			"stripping the capability otherwise downgrades the whole message to cleartext")
	}
	if err := requireSTARTTLS(true, false); err != nil {
		t.Fatalf("a session that negotiated STARTTLS must proceed: %v", err)
	}
	if err := requireSTARTTLS(false, true); err != nil {
		t.Fatalf("an operator who explicitly allowed an insecure relay must proceed: %v", err)
	}
}
