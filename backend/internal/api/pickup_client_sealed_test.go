package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

const sealedBlob = `{"v":1,"iv":"aXZpdml2aXY=","ciphertext":"Y2lwaGVydGV4dA=="}`

func createSealedPickupFor(t *testing.T, srv *Server, userID string) (id, token string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"recipient": "nokey@example.com", "sealed": sealedBlob})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/pickup", bytes.NewReader(body))
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePickupCreate)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	_, after, found := strings.Cut(got.URL, "?t=")
	if !found {
		t.Fatalf("url has no token: %s", got.URL)
	}
	return got.ID, after
}

// The link the server hands back must not contain the key. If it did, the
// server would be emailing itself the means to read what it stores.
func TestSealedPickupURLCarriesNoKey(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)

	body, _ := json.Marshal(map[string]any{"recipient": "nokey@example.com", "sealed": sealedBlob})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/pickup", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePickupCreate)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if strings.Contains(got.URL, "#") {
		t.Fatalf("server-built URL contains a fragment; the key must be appended by the client only: %s", got.URL)
	}
	// Nothing from the sealed blob should be echoed back either.
	if strings.Contains(rec.Body.String(), "Y2lwaGVydGV4dA==") {
		t.Fatalf("create response echoed the ciphertext: %s", rec.Body.String())
	}
}

// The stored record must be opaque: the store has no key for it, and the
// server-side view path must refuse rather than returning garbage.
func TestSealedPickupIsNotServerReadable(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, _ := createSealedPickupFor(t, srv, u.ID)

	if _, _, _, err := srv.pickupStore.View(id); err != pgpmail.ErrPickupClientSealed {
		t.Fatalf("View() on a client-sealed record = %v, want ErrPickupClientSealed", err)
	}
}

// One-time semantics must hold for a blob the server cannot read — marking
// viewed does not require decrypting it.
func TestSealedPickupIsSingleUse(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, token := createSealedPickupFor(t, srv, u.ID)

	fetch := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"/blob?t="+token, nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		srv.handlePickupBlob(rec, req)
		return rec
	}

	first := fetch()
	if first.Code != http.StatusOK {
		t.Fatalf("first fetch: status = %d, body=%s", first.Code, first.Body.String())
	}
	if !strings.Contains(first.Body.String(), "Y2lwaGVydGV4dA==") {
		t.Fatalf("first fetch did not return the sealed blob: %s", first.Body.String())
	}

	second := fetch()
	if second.Code != http.StatusGone {
		t.Fatalf("second fetch: status = %d, want 410", second.Code)
	}
}

func TestSealedPickupRejectsBadToken(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, _ := createSealedPickupFor(t, srv, u.ID)

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"/blob?t=forged", nil)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	srv.handlePickupBlob(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// The page served for a sealed record must contain no message content — only
// the shell and a reference to the decrypt script.
func TestSealedPickupPageContainsNoContent(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, token := createSealedPickupFor(t, srv, u.ID)

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	srv.handlePickup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	if !strings.Contains(page, "/pickup-decrypt.js") {
		t.Fatalf("page does not load the decrypt script: %s", page)
	}
	if strings.Contains(page, "Y2lwaGVydGV4dA==") {
		t.Fatal("page inlined the ciphertext; it must be fetched separately so a preview bot does not burn the link")
	}
	// Rendering the page must not consume the record — link-preview bots
	// fetch HTML, and burning the message before a human reads it would make
	// the feature unusable in practice.
	req2 := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"/blob?t="+token, nil)
	req2.SetPathValue("id", id)
	rec2 := httptest.NewRecorder()
	srv.handlePickupBlob(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("blob fetch after page load: status = %d — the page load consumed the record", rec2.Code)
	}
}

// A server-protected account gains nothing from this path (the server can
// already read its mail), so it is refused rather than half-supported.
func TestSealedPickupRefusesServerProtectedAccount(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "legacy-pickup", "legacy-pickup-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed", "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	body, _ := json.Marshal(map[string]any{"recipient": "nokey@example.com", "sealed": sealedBlob})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/pickup", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePickupCreate)(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// A client bug that ships plaintext should be caught rather than stored.
func TestSealedPickupRejectsUnsealedPayload(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)

	for _, payload := range []string{"just a plain message", `{"subject":"hi","body":"readable"}`, `{"v":2,"iv":"a","ciphertext":"b"}`} {
		body, _ := json.Marshal(map[string]any{"recipient": "nokey@example.com", "sealed": payload})
		req := httptest.NewRequest(http.MethodPost, "/api/pgp/pickup", bytes.NewReader(body))
		authRequestAs(srv, req, u.ID)
		rec := httptest.NewRecorder()
		srv.withMailAuth(srv.handlePickupCreate)(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("payload %q: status = %d, want 400", payload, rec.Code)
		}
	}
}

// A GET must not be able to burn a client-sealed message.
//
// The blob endpoint is the destructive one — it marks the record viewed and
// nothing can hand it back. handlePickupOpen (the server-sealed equivalent)
// already refuses to be a GET for exactly this reason: "it must not be
// reachable by a crawler, a prefetch, a link-preview fetch, or a HEAD probe."
// The client-sealed path was left as a GET that the page's own script fired on
// load, which reintroduced the problem one layer up: any scanner that executes
// page JavaScript consumed the message before a human saw it.
func TestSealedPickupBlobRefusesGET(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, token := createSealedPickupFor(t, srv, u.ID)

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"/blob?t="+token, nil)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("GET returned the blob; a prefetch or scanner can burn the message")
	}

	// And the record must still be readable afterwards — a refused GET that
	// consumed it anyway would be the same bug wearing a 405.
	post := httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/blob?t="+token, nil)
	postRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("after the refused GET, POST status = %d, want %d; the GET consumed the record: %s",
			postRec.Code, http.StatusOK, postRec.Body.String())
	}
	if !strings.Contains(postRec.Body.String(), "Y2lwaGVydGV4dA==") {
		t.Fatalf("POST did not return the sealed blob: %s", postRec.Body.String())
	}
}

// The shell page must not fetch anything on its own. Whatever consumes the
// message has to be behind a control the recipient operates.
func TestSealedPickupPageRequiresAGesture(t *testing.T) {
	srv := newTestServer(t)
	u := clientProtectedUser(t, srv)
	id, token := createSealedPickupFor(t, srv, u.ID)

	req := httptest.NewRequest(http.MethodGet, "/pickup/"+id+"?t="+token, nil)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `id="reveal"`) {
		t.Fatalf("pickup shell page has no reveal control, so the script has nothing to wait for:\n%s", rec.Body.String())
	}

	// Rendering the page must leave the message intact.
	post := httptest.NewRequest(http.MethodPost, "/pickup/"+id+"/blob?t="+token, nil)
	postRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(postRec, post)
	if postRec.Code != http.StatusOK {
		t.Fatalf("rendering the page consumed the record: POST status = %d", postRec.Code)
	}
}
