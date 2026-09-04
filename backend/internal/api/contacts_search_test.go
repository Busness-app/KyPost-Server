package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestContactsSearchRequiresAuth confirms GET /api/contacts/search is gated
// by withAuth (session cookie only) — no session, no results.
func TestContactsSearchRequiresAuth(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/search?q=sam", nil)
	srv.withAuth(srv.handleContactsSearch).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestContactsSearchRequiresQuery confirms a missing/blank q param is
// rejected with 400 before ever touching the store.
func TestContactsSearchRequiresQuery(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	cases := []string{"", "%20%20%20"}
	for _, q := range cases {
		rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsSearch), http.MethodGet, "/api/contacts/search?q="+q, nil, userID)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("q=%q: status = %d, want %d; body=%s", q, rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	}
}

// TestContactsSearchReturnsMatch drives a valid search end-to-end and
// confirms the seeded contact comes back in the response.
func TestContactsSearchReturnsMatch(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	created, err := store.Upsert(contacts.Contact{
		FormattedName: "Samantha Lee",
		Emails:        []contacts.ContactValue{{Value: "sam@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsSearch), http.MethodGet, "/api/contacts/search?q=sam", nil, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Contacts []contacts.Contact `json:"contacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Contacts) != 1 || resp.Contacts[0].UID != created.UID {
		t.Fatalf("contacts = %+v, want single result with UID %q", resp.Contacts, created.UID)
	}
}

// TestContactsSearchLimitClamped confirms a requested limit above the cap is
// clamped to contactsSearchMaxLimit, not passed through verbatim to the store.
func TestContactsSearchLimitClamped(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	for i := 0; i < 30; i++ {
		if _, err := store.Upsert(contacts.Contact{FormattedName: "Match Contact"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsSearch), http.MethodGet, "/api/contacts/search?q=match&limit=1000", nil, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Contacts []contacts.Contact `json:"contacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Contacts) != contactsSearchMaxLimit {
		t.Fatalf("len(contacts) = %d, want %d (clamped)", len(resp.Contacts), contactsSearchMaxLimit)
	}
}

// TestContactsSearchLimitInvalidFallsBackToDefault confirms that limit
// values which aren't a positive integer (zero, negative, or non-numeric)
// silently fall back to contactsSearchDefaultLimit rather than being
// rejected or treated as "no limit". This is the current, intentional
// behavior of handleContactsSearch's `parsed > 0` guard — documented here
// so a future change to that guard is a deliberate decision, not a
// regression.
func TestContactsSearchLimitInvalidFallsBackToDefault(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := store.Upsert(contacts.Contact{FormattedName: "Match Contact"}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	cases := []string{"0", "-5", "abc"}
	for _, limit := range cases {
		rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsSearch), http.MethodGet, "/api/contacts/search?q=match&limit="+limit, nil, userID)
		if rec.Code != http.StatusOK {
			t.Fatalf("limit=%q: status = %d, want %d; body=%s", limit, rec.Code, http.StatusOK, rec.Body.String())
		}

		var resp struct {
			Contacts []contacts.Contact `json:"contacts"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("limit=%q: unmarshal: %v; body=%s", limit, err, rec.Body.String())
		}
		if len(resp.Contacts) != contactsSearchDefaultLimit {
			t.Fatalf("limit=%q: len(contacts) = %d, want %d (default fallback)", limit, len(resp.Contacts), contactsSearchDefaultLimit)
		}
	}
}

// TestContactsSearchScopedToCaller confirms the handler resolves the store
// via contactsFor(r) — i.e. per-user scoping — by seeding a second user with
// a matching contact and confirming the first user's search doesn't see it.
func TestContactsSearchScopedToCaller(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	other, err := srv.users.Create(context.Background(), "other", "pw-other-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create other user: %v", err)
	}
	otherStore, err := srv.userContactsStore(other.ID)
	if err != nil {
		t.Fatalf("userContactsStore(other): %v", err)
	}
	if _, err := otherStore.Upsert(contacts.Contact{FormattedName: "Sammy Other"}); err != nil {
		t.Fatalf("Upsert other: %v", err)
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handleContactsSearch), http.MethodGet, "/api/contacts/search?q=sammy", nil, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp struct {
		Contacts []contacts.Contact `json:"contacts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Contacts) != 0 {
		t.Fatalf("contacts = %+v, want none (other user's contact must not leak)", resp.Contacts)
	}
}
