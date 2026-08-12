package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

// A PGP/MIME message carries exactly one MIME attachment — the armored
// ciphertext — and the user's real files are inside it. The attachment
// endpoints once opened server-custody messages to list and serve the files
// within; with server custody retired they serve the outer parts untouched for
// every account, and the browser unwraps.
//
// These tests pin that pass-through. The interesting case is a message this
// server still HOLDS the key for: every ingredient for opening it is present,
// so only the refusal keeps it shut.

// encryptedMessageFake returns a mail client whose message uid=7 is a PGP/MIME
// message encrypted to recipient, wrapping body plus one attachment.
//
// The ciphertext part is listed TWICE, which is the shape ListAttachments
// really sees: enmime files it under both Attachments and Inlines (inline
// disposition plus a filename) and goimap concatenates the two. This fake used
// to supply a single part, and that difference hid a bug — the listing gated on
// "exactly one attachment", so it looked inside encrypted mail here and never
// in production. Pinned upstream by
// imap.TestPGPEnvelopePayload_RealPGPMIMEMessage.
func encryptedMessageFake(t *testing.T, recipient *pgpmail.Identity) *fakeMailClient {
	t.Helper()
	plaintext := mailmsg.Message{
		From:        "alice@example.com",
		To:          []string{"bob@example.com"},
		Subject:     "Quarterly numbers",
		Body:        "see attached",
		Mode:        "plain",
		Attachments: []mailmsg.Attachment{{Name: "report.pdf", MimeType: "application/pdf", Content: []byte("pdf-bytes")}},
	}.Build()

	encrypted, err := pgpmail.EncryptMIME(plaintext, []string{recipient.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	armored := extractArmoredPGPMessage(t, encrypted)

	ciphertextPart := mailmsg.Attachment{Name: "encrypted.asc", MimeType: "application/octet-stream", Content: []byte(armored)}
	return &fakeMailClient{
		attachments: map[int][]mailmsg.Attachment{
			7: {ciphertextPart, ciphertextPart},
		},
	}
}

// ordinaryMessageWithEncryptedFileFake is the case the envelope test exists to
// keep out: an ordinary message that happens to carry an encrypted file. The
// file is the reader's, listed at index 0, and must download as itself.
func ordinaryMessageWithEncryptedFileFake(t *testing.T, recipient *pgpmail.Identity) *fakeMailClient {
	t.Helper()
	inner := mailmsg.Message{
		From: "alice@example.com", To: []string{"bob@example.com"},
		Subject: "secret", Body: "inside the archive", Mode: "plain",
		Attachments: []mailmsg.Attachment{{Name: "inner.txt", MimeType: "text/plain", Content: []byte("inner-bytes")}},
	}.Build()
	encrypted, err := pgpmail.EncryptMIME(inner, []string{recipient.ArmoredPublicKey}, nil)
	if err != nil {
		t.Fatalf("EncryptMIME: %v", err)
	}
	armored := extractArmoredPGPMessage(t, encrypted)

	return &fakeMailClient{
		attachments: map[int][]mailmsg.Attachment{
			7: {
				{Name: "archive.pgp", MimeType: "application/octet-stream", Content: []byte(armored)},
				{Name: "report.xlsx", MimeType: "application/vnd.ms-excel", Content: []byte("xls-bytes")},
			},
		},
	}
}

// Looking inside required opening the user's key, so it went away with server
// custody. What must NOT change is the fallback: the outer parts are served
// untouched, exactly as for a client-protected account, so the browser can do
// the unwrapping. Serving armor the reader has to open themselves is a
// usability cost; serving it only because this server declined to read their
// mail is the point.
func TestServeAttachmentListPassesCiphertextThroughForServerCustody(t *testing.T) {
	srv := newTestServer(t)
	userID, identity := testUserWithServerKey(t, srv)
	fake := encryptedMessageFake(t, identity)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachments?mailbox=Sent&messageId=7", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, AuthContext{UserID: userID}))
	srv.serveAttachmentList(rec, req, fake)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Attachments []imapadapter.AttachmentInfo `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	for _, a := range resp.Attachments {
		if a.Name == "report.pdf" {
			t.Fatalf("the server opened a server-custody message to list its attachments: %+v", resp.Attachments)
		}
	}
}

func TestServeAttachmentDownloadPassesCiphertextThroughForServerCustody(t *testing.T) {
	srv := newTestServer(t)
	userID, identity := testUserWithServerKey(t, srv)
	fake := encryptedMessageFake(t, identity)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachment?mailbox=Sent&messageId=7&index=0", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, AuthContext{UserID: userID}))
	srv.serveAttachmentDownload(rec, req, fake)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() == "pdf-bytes" {
		t.Fatal("the server decrypted a server-custody attachment; retiring the mode means it must not")
	}
	if !strings.Contains(rec.Body.String(), "BEGIN PGP MESSAGE") {
		t.Fatalf("expected the untouched ciphertext part, got %q", rec.Body.String())
	}
}

// No key, no decryption: the outer parts are served untouched, which is what a
// client-protected account's browser expects to receive.
func TestServeAttachmentListPassesCiphertextThroughWithoutAKey(t *testing.T) {
	srv := newTestServer(t)
	identity, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	fake := encryptedMessageFake(t, identity)

	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("users.List: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachments?mailbox=Sent&messageId=7", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, AuthContext{UserID: all[0].ID}))
	srv.serveAttachmentList(rec, req, fake)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Attachments []imapadapter.AttachmentInfo `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Both outer entries pass through — they are the same ciphertext part,
	// listed twice by the MIME parse. Untouched is the point, not deduplicated.
	if len(resp.Attachments) == 0 {
		t.Fatal("no attachments were returned")
	}
	for _, got := range resp.Attachments {
		if got.Name != "encrypted.asc" {
			t.Fatalf("attachments = %+v, want the untouched ciphertext parts", resp.Attachments)
		}
	}
}

// The download path used to decrypt anything whose bytes began with a PGP armor
// header, with no check that the MESSAGE was an envelope. An ordinary message
// carrying archive.pgp therefore had that file replaced by whatever sat at the
// same index inside it — or a 404 — for a file the listing said was there.
func TestServeAttachmentDownloadServesAnEncryptedFileAsItself(t *testing.T) {
	srv := newTestServer(t)
	userID, identity := testUserWithServerKey(t, srv)
	fake := ordinaryMessageWithEncryptedFileFake(t, identity)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachment?mailbox=INBOX&messageId=7&index=0", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, AuthContext{UserID: userID}))
	srv.serveAttachmentDownload(rec, req, fake)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "-----BEGIN PGP MESSAGE-----") {
		t.Fatalf("archive.pgp was replaced by something from inside it: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "filename=archive.pgp") {
		t.Fatalf("Content-Disposition = %q, want the file the reader clicked", got)
	}
}

// The listing side of the same case: the reader's own files, not the contents
// of one of them.
func TestServeAttachmentListLeavesAnEncryptedFileAlone(t *testing.T) {
	srv := newTestServer(t)
	userID, identity := testUserWithServerKey(t, srv)
	fake := ordinaryMessageWithEncryptedFileFake(t, identity)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachments?mailbox=INBOX&messageId=7", nil)
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{}, AuthContext{UserID: userID}))
	srv.serveAttachmentList(rec, req, fake)

	var resp struct {
		Attachments []imapadapter.AttachmentInfo `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Attachments) != 2 {
		t.Fatalf("attachments = %+v, want the message's own two files", resp.Attachments)
	}
	if resp.Attachments[0].Name != "archive.pgp" || resp.Attachments[1].Name != "report.xlsx" {
		t.Fatalf("attachments = %+v, want archive.pgp and report.xlsx", resp.Attachments)
	}
}

func TestLooksLikeEncryptedEnvelope(t *testing.T) {
	octet := func(name string) imapadapter.AttachmentInfo {
		return imapadapter.AttachmentInfo{Name: name, MimeType: "application/octet-stream"}
	}

	// The real shape: the same ciphertext part listed twice.
	if !looksLikeEncryptedEnvelope([]imapadapter.AttachmentInfo{octet("encrypted.asc"), octet("encrypted.asc")}) {
		t.Error("a real PGP/MIME message's doubled ciphertext part was not recognised")
	}
	if !looksLikeEncryptedEnvelope([]imapadapter.AttachmentInfo{octet("encrypted.asc")}) {
		t.Error("a single-part envelope was not recognised")
	}
	if looksLikeEncryptedEnvelope(nil) {
		t.Error("a message with no parts was called an envelope")
	}
	if looksLikeEncryptedEnvelope([]imapadapter.AttachmentInfo{
		octet("archive.pgp"),
		{Name: "report.xlsx", MimeType: "application/vnd.ms-excel"},
	}) {
		t.Error("a message carrying an encrypted file was called an envelope")
	}
}
