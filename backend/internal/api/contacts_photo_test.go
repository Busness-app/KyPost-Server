package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
)

// TestContactPhotoGetAcceptsDeviceCredentials drives the endpoint through the
// server's real route table (not a hand-wired middleware call) so it fails
// if GET /api/contacts/{id}/photo is ever wired back to withAuth instead of
// withMailAuth. Mobile clients only have their own device pairing
// credentials, never a session cookie — see Client_Contact_Update.md Part 0.
func TestContactPhotoGetAcceptsDeviceCredentials(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	// A 1x1 transparent PNG, small enough to embed inline.
	png := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
		0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
		0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
		0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
	}
	ref, err := srv.storeContactPhoto(userID, png)
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{FormattedName: "Photo Test", PhotoRef: ref})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "photo-device")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/"+c.UID+"/photo", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (device auth should reach the handler); body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// The photo URL is /api/contacts/{uid}/photo with no cache buster, so an
// immutable response pinned a replaced (or deleted) photo on screen for a
// year — an explicit reload included. Revalidation must stay possible.
func TestContactPhotoGetRevalidates(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-1"

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	ref, err := srv.storeContactPhoto(userID, testPNG(t, 7))
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{FormattedName: "Photo Test", PhotoRef: ref})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.handleContactPhotoGet(rec, httptest.NewRequest(http.MethodGet, "/api/contacts/"+c.UID+"/photo", nil), userID, c)
	if got := rec.Header().Get("Cache-Control"); got != "private, no-cache" {
		t.Fatalf("Cache-Control = %q, want %q", got, "private, no-cache")
	}

	// no-cache is not no-store: the conditional request still gets a 304.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/"+c.UID+"/photo", nil)
	req.Header.Set("If-Modified-Since", rec.Header().Get("Last-Modified"))
	srv.handleContactPhotoGet(rec2, req, userID, c)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("conditional GET status = %d, want %d", rec2.Code, http.StatusNotModified)
	}
}
