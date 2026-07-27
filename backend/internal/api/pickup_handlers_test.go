package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pickupMux builds a minimal ServeMux with the same route pattern server.go
// registers for the pickup page, so r.PathValue("id") resolves the way it
// would in the real server.
func pickupMux(srv *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pickup/{id}", srv.handlePickup)
	return mux
}

func TestHandlePickupHappyPath(t *testing.T) {
	srv := newTestServer(t)

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Hello <there>", "body & stuff", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "Hello &lt;there&gt;") {
		t.Fatalf("expected HTML-escaped subject in body, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "body &amp; stuff") {
		t.Fatalf("expected HTML-escaped body in body, got: %s", bodyStr)
	}
}

// TestHandlePickupRendersHTMLBodyAsReadableText covers the case that made the
// page useless for most real mail: the compose editor posts `mode: "html"`
// and a body of markup, so escaping that body and dropping it in a <pre>
// showed the recipient the tags themselves rather than the message.
//
// The expectation is the same one pickup-decrypt.js already holds for the
// client-sealed twin of this page: HTML is flattened to readable text, never
// rendered as markup.
func TestHandlePickupRendersHTMLBodyAsReadableText(t *testing.T) {
	srv := newTestServer(t)

	html := `<p>Hello <strong>there</strong>.</p><p>Read <a href="https://example.com/x">the notes</a>.</p>`
	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", html, "html", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	page := rec.Body.String()
	if strings.Contains(page, "&lt;p&gt;") || strings.Contains(page, "&lt;strong&gt;") {
		t.Fatalf("recipient was shown the escaped tags instead of the message: %s", page)
	}
	// Rendered as markup would be just as wrong as showing the tags: this page
	// has no sanitizer and shares an origin with the app.
	if strings.Contains(page, "<strong>") {
		t.Fatalf("sender markup reached the page as live HTML: %s", page)
	}
	// Emphasis survives as the plain-text convention (*bold*) rather than
	// being dropped, and a link keeps its target — text extraction alone
	// would silently discard the href and leave "the notes" pointing nowhere.
	if !strings.Contains(page, "Hello *there*.") {
		t.Fatalf("expected readable text of the message, got: %s", page)
	}
	if !strings.Contains(page, "https://example.com/x") {
		t.Fatalf("expected the link target to survive flattening, got: %s", page)
	}
}

// TestHandlePickupEscapesPlainBody pins the plain-mode path: a body that was
// never HTML must still be escaped, not run through the HTML flattener, or a
// message that merely talks about markup would lose it.
func TestHandlePickupEscapesPlainBody(t *testing.T) {
	srv := newTestServer(t)

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", "use <b> for bold", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "use &lt;b&gt; for bold") {
		t.Fatalf("expected the plain body escaped verbatim, got: %s", rec.Body.String())
	}
}

func TestHandlePickupInvalidTokenNeverConsumesRecord(t *testing.T) {
	srv := newTestServer(t)

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", "Body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t=not-a-real-token", nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	// The record must still be intact: an invalid token must never reach
	// pickupStore.View. Mint a real token now and confirm the record can
	// still be viewed once.
	token, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	subject, body, _, err := srv.pickupStore.View(id)
	if err != nil {
		t.Fatalf("View after bad-token attempt should still succeed, got err: %v", err)
	}
	if subject != "Subject" || body != "Body" {
		t.Fatalf("unexpected record contents: subject=%q body=%q", subject, body)
	}
	_ = token // token minted only to demonstrate a valid one could still be built
}

func TestHandlePickupSecondViewIsGone(t *testing.T) {
	srv := newTestServer(t)

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", "Body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err := srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	mux := pickupMux(srv)

	firstReq := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	firstRec := httptest.NewRecorder()
	mux.ServeHTTP(firstRec, firstReq)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first view status = %d, want %d; body=%s", firstRec.Code, http.StatusOK, firstRec.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	secondRec := httptest.NewRecorder()
	mux.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusGone {
		t.Fatalf("second view status = %d, want %d; body=%s", secondRec.Code, http.StatusGone, secondRec.Body.String())
	}
}

// TestHandlePickupRefusesWhenPairingSecretUnset guards against pickup tokens
// being silently HMAC-signed with a known-empty key: both the page and the
// notification sender must fail closed instead of degrading silently when
// PAIRING_SECRET was never configured.
func TestHandlePickupRefusesWhenPairingSecretUnset(t *testing.T) {
	srv := newTestServer(t)
	srv.pairingSecret = ""

	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", "Subject", "Body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t=anything", nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}

	if err := srv.sendPickupNotification("user-1", "from@example.com", "recipient@example.com", "Subject", "Body", "plain", "smtp.example.com", 587, "smtp.example.com:587", "user", "pass"); err == nil {
		t.Fatalf("sendPickupNotification: expected error when PAIRING_SECRET is unset, got nil")
	}
}

func TestHandlePickupUnknownIDIsGone(t *testing.T) {
	srv := newTestServer(t)

	// Never Create()d: a syntactically valid token for an ID that has no
	// backing record on disk.
	token, _, err := srv.createPairingToken("never-created-id", pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/pickup/never-created-id?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMux(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusGone, rec.Body.String())
	}
}
