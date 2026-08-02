package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// malformedLine is a line that fails to decode as a vCard (the BEGIN value
// isn't "VCARD") but is short enough that go-vcard's decoder consumes it and
// returns a non-EOF error in a single Decode() call, so each occurrence
// drives exactly one iteration of the import loop without ever incrementing
// cardCount. A stream of these is the pathological "malformed non-vCard
// input" the attempts cap exists to bound.
const malformedLine = "BEGIN:NOTAVCARD\r\n"

// driveContactsImport runs req through the (authenticated) import handler and
// returns the recorder, failing the test if the handler doesn't respond within
// timeout. This guards against a regression back to a loop that isn't bounded
// independent of successful parses.
func driveContactsImport(t *testing.T, srv *Server, req *http.Request, timeout time.Duration) *httptest.ResponseRecorder {
	t.Helper()

	authRequest(srv, req)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.withAuth(srv.handleContactsImport)(rec, req)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("handleContactsImport did not return within %s; the malformed-input loop is not properly bounded", timeout)
	}
	return rec
}

// decodeImportResult asserts a 200 and returns the decoded JSON result.
func decodeImportResult(t *testing.T, rec *httptest.ResponseRecorder) importResultForTest {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var result importResultForTest
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal import response: %v; body=%s", err, rec.Body.String())
	}
	return result
}

// runContactsImport POSTs body to the import handler as a raw (non-multipart)
// vCard body — the `curl --data-binary @contacts.vcf` shape.
func runContactsImport(t *testing.T, srv *Server, body string, timeout time.Duration) importResultForTest {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/contacts/import", strings.NewReader(body))
	return decodeImportResult(t, driveContactsImport(t, srv, req, timeout))
}

// multipartImportRequest builds the request the browser actually sends: a
// multipart/form-data body with the vCard text in a "file" part. See
// frontend/src/api/contacts.ts.
func multipartImportRequest(t *testing.T, body string) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "contacts.vcf")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.WriteString(fw, body); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/contacts/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// twoValidCards is a minimal well-formed vCard stream.
const twoValidCards = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:John Doe\r\nEND:VCARD\r\n" +
	"BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Jane Roe\r\nEND:VCARD\r\n"

// importResultForTest mirrors the handler's unexported importResult JSON
// shape so tests can decode the response.
type importResultForTest struct {
	Imported   int      `json:"imported"`
	Skipped    int      `json:"skipped"`
	Errors     []string `json:"errors"`
	ErrorCount int      `json:"errorCount"`
}

// TestHandleContactsImport_MalformedInputTerminatesWithinAttemptsCap proves
// that a stream of entirely malformed (non-vCard) input terminates the
// import loop instead of looping for as long as the request body lasts. The
// input here (50,000 malformed lines) is far larger than any cap on
// successful parses (cardCount never increments for this input at all), so
// before the attempts cap existed nothing would break the loop early.
func TestHandleContactsImport_MalformedInputTerminatesWithinAttemptsCap(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	body := strings.Repeat(malformedLine, 50000)
	result := runContactsImport(t, srv, body, 10*time.Second)

	if result.Imported != 0 {
		t.Fatalf("Imported = %d, want 0 (input never contains a valid card)", result.Imported)
	}
	// The attempts cap (maxCards*2 = 10000) must have kicked in well before
	// all 50,000 malformed lines were consumed.
	if result.ErrorCount >= 50000 {
		t.Fatalf("ErrorCount = %d, want well under 50000 (attempts cap should have stopped the loop early)", result.ErrorCount)
	}
	if result.ErrorCount < 1000 {
		t.Fatalf("ErrorCount = %d, want at least in the low thousands (attempts cap is 10000)", result.ErrorCount)
	}

	foundStopMessage := false
	for _, e := range result.Errors {
		if strings.Contains(e, "too many errors") {
			foundStopMessage = true
		}
	}
	if !foundStopMessage {
		t.Fatalf("expected an error entry noting the attempts cap was hit; got %v", result.Errors)
	}
}

// TestHandleContactsImport_ErrorsCappedButCountPreserved proves that
// result.Errors is capped near 100 entries even when many more errors occur,
// while result.ErrorCount still reports the true total so the truncation is
// communicated rather than silently dropped.
func TestHandleContactsImport_ErrorsCappedButCountPreserved(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	const trueErrorCount = 300 // well above the 100 cap, well below the 10000 attempts cap
	body := strings.Repeat(malformedLine, trueErrorCount)
	result := runContactsImport(t, srv, body, 10*time.Second)

	if len(result.Errors) > 100 {
		t.Fatalf("len(result.Errors) = %d, want <= 100 (capped)", len(result.Errors))
	}
	if len(result.Errors) == trueErrorCount {
		t.Fatalf("len(result.Errors) = %d, expected the slice to be truncated below the true count", len(result.Errors))
	}
	if result.ErrorCount != trueErrorCount {
		t.Fatalf("ErrorCount = %d, want %d (true total must be preserved despite the capped Errors slice)", result.ErrorCount, trueErrorCount)
	}
}

// TestHandleContactsImport_MultipartUploadReportsNoWrapperErrors covers the
// only shape a browser ever sends. The handler used to read the request body
// straight into the vCard decoder, which does not fail on a multipart body —
// it reports "no BEGIN field found" for the boundary and the part headers and
// then decodes every card correctly. So a perfectly good import came back as
// "Imported 2 contacts. (2 errors)", every time, and no test could see it
// because every other case here posts raw vCard text.
//
// ErrorCount must be exactly 0: a clean import reports clean.
func TestHandleContactsImport_MultipartUploadReportsNoWrapperErrors(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	req := multipartImportRequest(t, twoValidCards)
	result := decodeImportResult(t, driveContactsImport(t, srv, req, 10*time.Second))

	if result.Imported != 2 {
		t.Fatalf("Imported = %d, want 2; errors=%v", result.Imported, result.Errors)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("ErrorCount = %d, want 0 — the multipart envelope is being fed to the vCard decoder; errors=%v",
			result.ErrorCount, result.Errors)
	}
}

// TestHandleContactsImport_RawBodyStillAccepted pins the other supported
// shape, so fixing the browser path does not quietly break
// `curl --data-binary @contacts.vcf` against the endpoint README documents.
func TestHandleContactsImport_RawBodyStillAccepted(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	result := runContactsImport(t, srv, twoValidCards, 10*time.Second)

	if result.Imported != 2 {
		t.Fatalf("Imported = %d, want 2; errors=%v", result.Imported, result.Errors)
	}
	if result.ErrorCount != 0 {
		t.Fatalf("ErrorCount = %d, want 0; errors=%v", result.ErrorCount, result.Errors)
	}
}

// TestHandleContactsImport_MultipartWithoutFilePart proves a multipart upload
// naming the wrong part is refused outright rather than silently importing
// nothing and reporting success.
func TestHandleContactsImport_MultipartWithoutFilePart(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("vcard", "contacts.vcf") // not "file"
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := io.WriteString(fw, twoValidCards); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	rec := driveContactsImport(t, srv, req, 10*time.Second)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleContactsImport_OversizedUploadRejected proves an over-limit upload
// is refused with 413 rather than truncated.
//
// io.LimitReader is indistinguishable from a body that simply ended, so an
// oversized import used to be cut off mid-card and reported as a partial
// success: the operator was told the import worked and lost contacts anyway.
// Both wire shapes are checked, because only one of them had a limit that a
// multipart parser could also have enforced.
func TestHandleContactsImport_OversizedUploadRejected(t *testing.T) {
	// One card per repeat, comfortably past the 10 MiB ceiling.
	oversized := strings.Repeat(twoValidCards, (maxContactImportBytes/len(twoValidCards))+512)
	if len(oversized) <= maxContactImportBytes {
		t.Fatalf("test payload is %d bytes, needs to exceed %d", len(oversized), maxContactImportBytes)
	}

	t.Run("raw body", func(t *testing.T) {
		srv := newTestServer(t)
		srv.mustBootstrapUserID(t)

		req := httptest.NewRequest(http.MethodPost, "/api/contacts/import", strings.NewReader(oversized))
		rec := driveContactsImport(t, srv, req, 30*time.Second)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("multipart", func(t *testing.T) {
		srv := newTestServer(t)
		srv.mustBootstrapUserID(t)

		req := multipartImportRequest(t, oversized)
		rec := driveContactsImport(t, srv, req, 30*time.Second)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413; body=%s", rec.Code, rec.Body.String())
		}
	})
}

// TestHandleContactsImport_FullSizeMultipartUploadAccepted pins the envelope
// allowance. The documented limit is on the vCard payload, so a file right at
// the ceiling must still import when the browser wraps it in a form — the
// boundary and part headers are framing, not payload, and charging them
// against the user's budget makes the documented limit unreachable.
func TestHandleContactsImport_FullSizeMultipartUploadAccepted(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)

	// Fill to just under the ceiling with comment lines, then one real card.
	padding := strings.Repeat("NOTE:padding\r\n", (maxContactImportBytes-len(twoValidCards)-1024)/14)
	payload := "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Big Card\r\n" + padding + "END:VCARD\r\n"
	if len(payload) > maxContactImportBytes {
		t.Fatalf("payload is %d bytes, must not exceed the %d ceiling", len(payload), maxContactImportBytes)
	}

	req := multipartImportRequest(t, payload)
	rec := driveContactsImport(t, srv, req, 30*time.Second)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a full-size payload must fit once framing is excluded; body=%s",
			rec.Code, rec.Body.String())
	}
}
