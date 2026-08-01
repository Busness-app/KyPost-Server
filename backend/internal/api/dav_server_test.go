package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

func davAuthedRequest(ac AuthContext, method, target string, body *bytes.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Content-Type", "text/vcard; charset=utf-8")
	return req.WithContext(context.WithValue(req.Context(), authContextKey{}, ac))
}

func smallVCard(uid string) string {
	return fmt.Sprintf("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:%s\r\nFN:Small Card\r\nEND:VCARD\r\n", uid)
}

// TestHandleCardDAVPutRejectsOversizedBody guards against an unbounded PUT
// body being fully buffered in memory: a request body larger than
// maxContactPhotoBytes must be rejected rather than accepted.
func TestHandleCardDAVPutRejectsOversizedBody(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dave", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	// The oversized payload must live *inside* a vCard property (like a real
	// huge base64 PHOTO would) rather than after END:VCARD — go-vcard's
	// line-based decoder stops reading as soon as it sees END:VCARD, so
	// trailing garbage after a complete card would never actually be read
	// and wouldn't exercise the MaxBytesReader cap at all.
	hugePhoto := "PHOTO:data:image/png;base64," + strings.Repeat("A", maxContactPhotoBytes+1024)
	card := "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:oversized-card\r\nFN:Oversized Card\r\n" +
		hugePhoto + "\r\nEND:VCARD\r\n"
	body := bytes.NewReader([]byte(card))

	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/oversized-card.vcf", body)
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
		t.Fatalf("oversized PUT should have been rejected, got status %d body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := store.Get("oversized-card"); ok {
		t.Fatal("oversized PUT must not have been persisted")
	}
}

// TestHandleCardDAVPutAcceptsNormalBody is the control case: a small vCard
// well under the limit must still succeed, proving the new cap doesn't break
// ordinary CardDAV PUTs.
func TestHandleCardDAVPutAcceptsNormalBody(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "erin", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	body := bytes.NewReader([]byte(smallVCard("normal-card")))
	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/normal-card.vcf", body)
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated && rec.Code != http.StatusNoContent {
		t.Fatalf("normal PUT should have succeeded, got status %d body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := store.Get("normal-card"); !ok {
		t.Fatal("normal PUT should have been persisted")
	}
}
