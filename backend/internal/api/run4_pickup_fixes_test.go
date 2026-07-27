package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pickupMuxWithOpen registers both halves of the server-sealed pickup flow the
// way server.go does, so PathValue and method matching behave as in production.
func pickupMuxWithOpen(srv *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pickup/{id}", srv.handlePickup)
	mux.HandleFunc("POST /pickup/{id}/open", srv.handlePickupOpen)
	return mux
}

func seedServerSealedPickup(t *testing.T, srv *Server, subject, body, mode string) (id, token string) {
	t.Helper()
	id, err := srv.pickupStore.Create("user-1", "recipient@example.com", subject, body, mode, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token, _, err = srv.createPairingToken(id, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	return id, token
}

// run-4 finding M2: the server-sealed pickup page rendered the message AND
// consumed the record in one plain GET. That is the default for every
// server-custody account and every account with no PGP identity at all, so it
// is the common path, not a corner.
//
// Anything that follows a link in an email therefore reads the whole message
// and leaves the human a permanent 410: enterprise URL-detonation scanners
// (Safe Links, Proofpoint, Mimecast) sitting in the recipient's own mail path
// do exactly this. The client-sealed sibling already defends against it —
// pickup_client_sealed.go consumes on a second call precisely "so a link-
// preview bot that fetches the HTML does not burn the message" — and the
// defense simply was never carried across.
func TestServerSealedPickupPageDoesNotConsumeOnGET(t *testing.T) {
	srv := newTestServer(t)
	id, token := seedServerSealedPickup(t, srv, "Quarterly numbers", "the secret body", "plain")

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMuxWithOpen(srv).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	if strings.Contains(page, "the secret body") {
		t.Fatal("the landing page disclosed the message body to a plain GET")
	}
	if strings.Contains(page, "Quarterly numbers") {
		t.Fatal("the landing page disclosed the subject to a plain GET")
	}

	// The record must still be readable afterwards — that is the whole point.
	subject, body, _, err := srv.pickupStore.View(id)
	if err != nil {
		t.Fatalf("record was consumed by the GET: %v", err)
	}
	if subject != "Quarterly numbers" || body != "the secret body" {
		t.Fatalf("unexpected record content: subject=%q body=%q", subject, body)
	}
}

// A scanner that issues HEAD must not burn the link either. Go's ServeMux
// routes HEAD to a GET-registered pattern, so before the fix HEAD consumed the
// record while Go suppressed the body — destroying the message without even
// disclosing it.
func TestServerSealedPickupHEADDoesNotConsume(t *testing.T) {
	srv := newTestServer(t)
	id, token := seedServerSealedPickup(t, srv, "Subject", "the secret body", "plain")

	req := httptest.NewRequest(http.MethodHead, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	pickupMuxWithOpen(srv).ServeHTTP(rec, req)

	if _, _, _, err := srv.pickupStore.View(id); err != nil {
		t.Fatalf("record was consumed by HEAD: %v", err)
	}
}

func TestServerSealedPickupOpenRevealsAndConsumes(t *testing.T) {
	srv := newTestServer(t)
	id, token := seedServerSealedPickup(t, srv, "Quarterly numbers", "the secret body", "plain")

	mux := pickupMuxWithOpen(srv)
	req := httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/open?t="+token, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	if !strings.Contains(page, "the secret body") {
		t.Fatalf("open did not render the body: %s", page)
	}
	if !strings.Contains(page, "Quarterly numbers") {
		t.Fatalf("open did not render the subject: %s", page)
	}

	// Second open is gone — one-time semantics are preserved, just moved.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/open?t="+token, nil))
	if rec2.Code != http.StatusGone {
		t.Fatalf("second open status = %d, want %d", rec2.Code, http.StatusGone)
	}
}

func TestServerSealedPickupOpenRejectsBadToken(t *testing.T) {
	srv := newTestServer(t)
	id, _ := seedServerSealedPickup(t, srv, "Subject", "the secret body", "plain")

	rec := httptest.NewRecorder()
	pickupMuxWithOpen(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/open?t=forged", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if _, _, _, err := srv.pickupStore.View(id); err != nil {
		t.Fatalf("a forged token consumed the record: %v", err)
	}
}

// Both pickup responses carry the message or a direct route to it, so neither
// belongs in a shared cache or a browser's back-forward cache.
func TestPickupResponsesAreNoStore(t *testing.T) {
	srv := newTestServer(t)
	id, token := seedServerSealedPickup(t, srv, "Subject", "body", "plain")
	mux := pickupMuxWithOpen(srv)

	pageRec := httptest.NewRecorder()
	mux.ServeHTTP(pageRec, httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil))
	if got := pageRec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("landing page Cache-Control = %q, want no-store", got)
	}

	openRec := httptest.NewRecorder()
	mux.ServeHTTP(openRec, httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/open?t="+token, nil))
	if got := openRec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("open response Cache-Control = %q, want no-store", got)
	}
}

// The open page must keep the escaping and HTML-flattening the single-step
// page had — moving consumption must not quietly move the message into a
// renderer that treats sender markup as live.
func TestServerSealedPickupOpenFlattensHTMLAndEscapes(t *testing.T) {
	srv := newTestServer(t)
	id, token := seedServerSealedPickup(t, srv, "Sub <ject>",
		`<p>Hello <strong>there</strong>.</p><script>alert(1)</script>`, "html")

	rec := httptest.NewRecorder()
	pickupMuxWithOpen(srv).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/open?t="+token, nil))

	page := rec.Body.String()
	if strings.Contains(page, "<strong>") || strings.Contains(page, "<script>") {
		t.Fatalf("sender markup survived into the page: %s", page)
	}
	if !strings.Contains(page, "Sub &lt;ject&gt;") {
		t.Fatalf("subject was not escaped: %s", page)
	}
	if !strings.Contains(page, "Hello") {
		t.Fatalf("flattened text is missing: %s", page)
	}
}
