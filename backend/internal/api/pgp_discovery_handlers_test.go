package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

type discoverySettingsResp struct {
	AutoEncryptWhenKeyKnown bool `json:"autoEncryptWhenKeyKnown"`
	StoreDiscoveredKeys     bool `json:"storeDiscoveredKeys"`
}

func TestDiscoverySettingsRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	putRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodPut,
		"/api/pgp/discovery/settings",
		map[string]bool{"autoEncryptWhenKeyKnown": true, "storeDiscoveredKeys": false}, userID)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", putRec.Code, putRec.Body.String())
	}
	var putResp discoverySettingsResp
	if err := json.NewDecoder(putRec.Body).Decode(&putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if !putResp.AutoEncryptWhenKeyKnown || putResp.StoreDiscoveredKeys {
		t.Fatalf("PUT response mismatch: %+v", putResp)
	}

	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodGet,
		"/api/pgp/discovery/settings", nil, userID)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var getResp discoverySettingsResp
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if !getResp.AutoEncryptWhenKeyKnown || getResp.StoreDiscoveredKeys {
		t.Fatalf("GET response mismatch: %+v", getResp)
	}
}

func TestDiscoverySettingsDefaultsBeforePut(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodGet,
		"/api/pgp/discovery/settings", nil, userID)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var getResp discoverySettingsResp
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if getResp.AutoEncryptWhenKeyKnown || !getResp.StoreDiscoveredKeys {
		t.Fatalf("expected defaults {false,true}, got %+v", getResp)
	}
}

func TestSuppressionsListAndClear(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	if err := pgpdiscovery.AddSuppression(srv.userStateDir(userID), "kim@example.com", pgpdiscovery.ReasonDeleted); err != nil {
		t.Fatalf("seed AddSuppression: %v", err)
	}

	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySuppressions), http.MethodGet,
		"/api/pgp/discovery/suppressions", nil, userID)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET list: expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var listResp struct {
		Suppressions []pgpdiscovery.Suppression `json:"suppressions"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Suppressions) != 1 || listResp.Suppressions[0].Email != "kim@example.com" {
		t.Fatalf("unexpected list: %+v", listResp.Suppressions)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/discovery/suppressions/kim%40example.com", nil)
	delReq.SetPathValue("email", "kim@example.com")
	authRequestAs(srv, delReq, userID)
	delRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPDiscoverySuppressionByEmail)(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d: %s", delRec.Code, delRec.Body.String())
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if set["kim@example.com"] {
		t.Fatalf("expected kim@example.com cleared after DELETE")
	}
}

func TestUnsuppressAbsentReturns404(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/discovery/suppressions/ghost%40example.com", nil)
	delReq.SetPathValue("email", "ghost@example.com")
	authRequestAs(srv, delReq, userID)
	delRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPDiscoverySuppressionByEmail)(delRec, delReq)
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an address that was never suppressed, got %d", delRec.Code)
	}
}

func TestSuppressContactClearsKeyAndSuppresses(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	id, err := pgpmail.GenerateIdentity("Lee", "lee@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName:     "Lee",
		Emails:            []contacts.ContactValue{{Value: "lee@example.com"}},
		PGPKey:            id.ArmoredPublicKey,
		PGPKeyFingerprint: id.Fingerprint,
		PGPKeySource:      contacts.PGPSourceWKD,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySuppressContact), http.MethodPost,
		"/api/pgp/discovery/suppress-contact", map[string]string{"contactUID": c.UID}, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("suppress-contact: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated contacts.Contact
	if err := json.NewDecoder(rec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated contact: %v", err)
	}
	if updated.PGPKey != "" || updated.PGPKeyFingerprint != "" || updated.PGPKeySource != "" || updated.PGPKeyVerified {
		t.Fatalf("expected key fields cleared, got %+v", updated)
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if !set["lee@example.com"] {
		t.Fatalf("expected lee@example.com suppressed after explicit action")
	}
}
