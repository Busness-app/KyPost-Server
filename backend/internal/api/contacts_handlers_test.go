package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
)

func TestDeletingDiscoveryCreatedContactSuppresses(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName:    "Ivy",
		Emails:           []contacts.ContactValue{{Value: "ivy@example.com"}},
		DiscoveryCreated: true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/contacts/"+c.UID, nil)
	req.SetPathValue("id", c.UID)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactByID)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	set, err := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if err != nil {
		t.Fatalf("SuppressedSet: %v", err)
	}
	if !set["ivy@example.com"] {
		t.Fatalf("expected ivy@example.com to be suppressed after deleting its discovery-created contact")
	}
}

func TestDeletingNormalContactDoesNotSuppress(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName: "Jon",
		Emails:        []contacts.ContactValue{{Value: "jon@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/contacts/"+c.UID, nil)
	req.SetPathValue("id", c.UID)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactByID)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if set["jon@example.com"] {
		t.Fatalf("did not expect a normal contact's deletion to suppress discovery")
	}
}
