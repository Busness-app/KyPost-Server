package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
)

// TestContactsDedupeEndpoint drives POST /api/contacts/dedupe end-to-end: it
// seeds two duplicates (sharing a normalized email) into the caller's store,
// then confirms the handler merges them and reports the survivor + absorbed UID.
func TestContactsDedupeEndpoint(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	a, err := store.Upsert(contacts.Contact{FormattedName: "Sam", Emails: []contacts.ContactValue{{Value: "sam@x.com"}}})
	if err != nil {
		t.Fatalf("Upsert a: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Samuel",
		Emails:        []contacts.ContactValue{{Value: "SAM@x.com"}},
		Phones:        []contacts.ContactValue{{Value: "555-321-0000"}},
	}); err != nil {
		t.Fatalf("Upsert b: %v", err)
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsDedupe), http.MethodPost, "/api/contacts/dedupe", nil, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var report contacts.DedupeReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal report: %v; body=%s", err, rec.Body.String())
	}
	if report.MergedCount != 1 {
		t.Fatalf("MergedCount = %d, want 1; body=%s", report.MergedCount, rec.Body.String())
	}
	if len(report.Groups) != 1 || report.Groups[0].Survivor != a.UID {
		t.Fatalf("groups = %+v, want survivor %q", report.Groups, a.UID)
	}

	live := must1(store.List())
	if len(live) != 1 {
		t.Fatalf("live contacts = %d, want 1 after merge", len(live))
	}
	if len(live[0].Phones) != 1 {
		t.Errorf("survivor should have absorbed the phone: %+v", live[0])
	}
}

// TestContactsDedupeAcceptsDeviceCredentials drives the endpoint through the
// server's real route table (not a hand-wired middleware call) so it fails
// if /api/contacts/dedupe is ever wired to withAuth instead of withMailAuth.
// Mobile clients only have their own device pairing credentials, never a
// session cookie — see Mobile_Contacts_DEDupe.md Part 0.
func TestContactsDedupeAcceptsDeviceCredentials(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "dedupe-device")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/dedupe", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (device auth should reach the handler); body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// mustBootstrapUserID returns the ID of the server's bootstrap user.
func (s *Server) mustBootstrapUserID(t *testing.T) string {
	t.Helper()
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no bootstrap user: %v", err)
	}
	return all[0].ID
}
