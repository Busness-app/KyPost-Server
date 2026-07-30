package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/mailmsg"
)

func attachmentFake() *fakeMailClient {
	return &fakeMailClient{
		attachments: map[int][]mailmsg.Attachment{
			7: {
				{Name: "a.pdf", MimeType: "application/pdf", Content: []byte("pdf-bytes")},
				{Name: "b.png", MimeType: "image/png", Content: []byte("png-bytes")},
			},
		},
	}
}

func TestServeAttachmentList(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachments?mailbox=INBOX&messageId=7", nil)
	srv.serveAttachmentList(rec, req, attachmentFake())

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK          bool                         `json:"ok"`
		Attachments []imapadapter.AttachmentInfo `json:"attachments"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rec.Body.String())
	}
	if !resp.OK || len(resp.Attachments) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	first := resp.Attachments[0]
	if first.Index != 0 || first.Name != "a.pdf" || first.MimeType != "application/pdf" || first.Size != len("pdf-bytes") {
		t.Fatalf("first attachment = %+v", first)
	}
}

func TestServeAttachmentListRejectsBadMessageId(t *testing.T) {
	srv := newTestServer(t)
	for _, id := range []string{"", "abc", "0", "-3"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/mail/attachments?mailbox=INBOX&messageId="+id, nil)
		srv.serveAttachmentList(rec, req, attachmentFake())
		if rec.Code != 400 {
			t.Fatalf("messageId=%q: status = %d, want 400", id, rec.Code)
		}
	}
}

func TestServeAttachmentDownload(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachment?mailbox=INBOX&messageId=7&index=1", nil)
	srv.serveAttachmentDownload(rec, req, attachmentFake())

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "image/png" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, `filename=b.png`) {
		t.Fatalf("Content-Disposition = %q", got)
	}
	if rec.Body.String() != "png-bytes" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestServeAttachmentDownloadErrors(t *testing.T) {
	srv := newTestServer(t)

	// Out-of-range index → 404.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/mail/attachment?mailbox=INBOX&messageId=7&index=9", nil)
	srv.serveAttachmentDownload(rec, req, attachmentFake())
	if rec.Code != 404 {
		t.Fatalf("out-of-range index: status = %d, want 404", rec.Code)
	}

	// Missing/negative index → 400.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/mail/attachment?mailbox=INBOX&messageId=7&index=-1", nil)
	srv.serveAttachmentDownload(rec, req, attachmentFake())
	if rec.Code != 400 {
		t.Fatalf("negative index: status = %d, want 400", rec.Code)
	}

	// IMAP failure → 502.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/mail/attachment?mailbox=INBOX&messageId=7&index=0", nil)
	srv.serveAttachmentDownload(rec, req, &fakeMailClient{attachmentsErr: errors.New("imap down")})
	if rec.Code != 502 {
		t.Fatalf("imap failure: status = %d, want 502", rec.Code)
	}
}

func TestDecodeMailRequestAttachments(t *testing.T) {
	body := `{
		"to": "a@example.com",
		"subject": "s",
		"body": "b",
		"mode": "html",
		"attachments": [
			{"name": "a.txt", "mimeType": "text/plain", "dataBase64": "` +
		base64.StdEncoding.EncodeToString([]byte("hello")) + `"}
		]
	}`
	req, errMsg, err := decodeMailRequest(httptest.NewRequest("POST", "/api/mail/send", strings.NewReader(body)))
	if err != nil {
		t.Fatalf("decode: %v (%s)", err, errMsg)
	}
	if len(req.Attachments) != 1 || string(req.Attachments[0].Content) != "hello" ||
		req.Attachments[0].Name != "a.txt" || req.Attachments[0].MimeType != "text/plain" {
		t.Fatalf("attachments = %+v", req.Attachments)
	}
}

func TestDecodeMailRequestRejectsBadAttachmentBase64(t *testing.T) {
	body := `{"to": "a@example.com", "attachments": [{"name": "a", "dataBase64": "!!not-base64!!"}]}`
	_, errMsg, err := decodeMailRequest(httptest.NewRequest("POST", "/api/mail/send", strings.NewReader(body)))
	if err == nil || errMsg != "invalid attachment encoding" {
		t.Fatalf("err=%v msg=%q, want invalid attachment encoding", err, errMsg)
	}
}

func TestDecodeMailRequestEnforcesAttachmentSizeCap(t *testing.T) {
	// Just over the decoded attachment budget, while the base64 of it still
	// fits inside maxMailRequestBytes — otherwise the raw body limit is what
	// rejects the send and the attachment cap is never consulted. That window
	// is what makes this test about the attachment cap specifically; see
	// TestDecodeMailRequestReportsAnOversizedBodyAsTooLarge for the other side.
	over := maxMailAttachmentBytes + (64 << 10)
	chunk := base64.StdEncoding.EncodeToString(make([]byte, over))
	body := `{"to": "a@example.com", "attachments": [` +
		`{"name": "one", "dataBase64": "` + chunk + `"}]}`
	if int64(len(body)) > maxMailRequestBytes {
		t.Fatalf("test body is %d bytes, over the %d-byte request cap: this would exercise the "+
			"body limit instead of the attachment cap", len(body), maxMailRequestBytes)
	}

	_, errMsg, err := decodeMailRequest(httptest.NewRequest("POST", "/api/mail/send", strings.NewReader(body)))
	if err == nil || !strings.Contains(errMsg, "attachments too large") {
		t.Fatalf("err=%v msg=%q, want attachment size-cap rejection", err, errMsg)
	}
}

// TestDecodeMailRequestReportsAnOversizedBodyAsTooLarge covers the layer above
// the attachment cap.
//
// A body past maxMailRequestBytes used to be truncated by the LimitReader, at
// which point the JSON decoder failed with a syntax error and the user was told
// "invalid request" — for the most common reason a send fails. The size has to
// be named.
func TestDecodeMailRequestReportsAnOversizedBodyAsTooLarge(t *testing.T) {
	chunk := base64.StdEncoding.EncodeToString(make([]byte, maxMailRequestBytes))
	body := `{"to": "a@example.com", "attachments": [` +
		`{"name": "one", "dataBase64": "` + chunk + `"}]}`

	// httptest.NewRequest sets ContentLength from the reader when it can.
	req := httptest.NewRequest("POST", "/api/mail/send", strings.NewReader(body))
	_, errMsg, err := decodeMailRequest(req)
	if err == nil || !strings.Contains(errMsg, "message too large") {
		t.Fatalf("err=%v msg=%q, want a body size rejection naming the limit", err, errMsg)
	}

	// And the same must hold when no Content-Length is declared (chunked), where
	// only the LimitReader can catch it.
	req = httptest.NewRequest("POST", "/api/mail/send", strings.NewReader(body))
	req.ContentLength = -1
	_, errMsg, err = decodeMailRequest(req)
	if err == nil || !strings.Contains(errMsg, "message too large") {
		t.Fatalf("chunked: err=%v msg=%q, want a body size rejection naming the limit", err, errMsg)
	}
}
