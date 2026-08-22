package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
)

func TestHandleContactSelf_SetsFlagAndReturnsUpdatedContact(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	a, err := store.Upsert(contacts.Contact{FormattedName: "Alice"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	body, _ := json.Marshal(map[string]bool{"self": true})
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/"+a.UID+"/self", bytes.NewReader(body))
	req.SetPathValue("id", a.UID)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactSelf)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var updated contacts.Contact
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if !updated.IsSelf {
		t.Fatalf("expected isSelf true in response, got %+v", updated)
	}

	self, ok := must2(store.GetSelf())
	if !ok || self.UID != a.UID {
		t.Fatalf("GetSelf: ok=%v uid=%q, want %q", ok, self.UID, a.UID)
	}
}

func TestHandleContactSelf_UnknownIDReturns404(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(map[string]bool{"self": true})
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/nope/self", bytes.NewReader(body))
	req.SetPathValue("id", "nope")
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactSelf)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

// TestContactSelfEndpointRoutesThroughRealMux drives the endpoint through
// the server's real route table (not a hand-wired middleware call) so it
// fails if the route registration in server.go is ever dropped — same
// pattern as TestContactsDedupeAcceptsDeviceCredentials.
func TestContactSelfEndpointRoutesThroughRealMux(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	a, err := store.Upsert(contacts.Contact{FormattedName: "Alice"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	body, _ := json.Marshal(map[string]bool{"self": true})
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/"+a.UID+"/self", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (route should reach the handler); body=%s", rec.Code, rec.Body.String())
	}
}
