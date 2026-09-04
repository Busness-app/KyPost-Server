package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
)

type discoverySettingsResp struct {
	AutoEncryptWhenKeyKnown bool `json:"autoEncryptWhenKeyKnown"`
	StoreDiscoveredKeys     bool `json:"storeDiscoveredKeys"`
	AdvertiseAutocrypt      bool `json:"advertiseAutocrypt"`
	PublishWKD              bool `json:"publishWKD"`
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

// TestDiscoverySettingsPutOmittingFieldsKeepsOnByDefaultValues covers R3: a
// PUT body omitting storeDiscoveredKeys/advertiseAutocrypt (e.g. a stale
// client built before the field existed) must not silently persist them as
// false — the mirror image of the bug pgpdiscovery.Load was fixed for.
func TestDiscoverySettingsPutOmittingFieldsKeepsOnByDefaultValues(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	// First PUT explicitly turns advertiseAutocrypt off, to prove a later
	// omission preserves whatever is currently stored (not just the default).
	putRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodPut,
		"/api/pgp/discovery/settings",
		map[string]bool{"advertiseAutocrypt": false}, userID)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", putRec.Code, putRec.Body.String())
	}
	var putResp discoverySettingsResp
	if err := json.NewDecoder(putRec.Body).Decode(&putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putResp.AdvertiseAutocrypt {
		t.Fatalf("expected advertiseAutocrypt=false after explicit PUT, got %+v", putResp)
	}
	if !putResp.StoreDiscoveredKeys {
		t.Fatalf("storeDiscoveredKeys was omitted from this PUT and must keep its on-by-default value, got %+v", putResp)
	}

	// Second PUT omits advertiseAutocrypt entirely — a stale client sending
	// only autoEncryptWhenKeyKnown must not flip advertiseAutocrypt back on
	// (it was just explicitly turned off) nor touch storeDiscoveredKeys.
	putRec2 := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodPut,
		"/api/pgp/discovery/settings",
		map[string]bool{"autoEncryptWhenKeyKnown": true}, userID)
	if putRec2.Code != http.StatusOK {
		t.Fatalf("PUT 2: expected 200, got %d: %s", putRec2.Code, putRec2.Body.String())
	}
	var putResp2 discoverySettingsResp
	if err := json.NewDecoder(putRec2.Body).Decode(&putResp2); err != nil {
		t.Fatalf("decode PUT 2 response: %v", err)
	}
	if putResp2.AdvertiseAutocrypt {
		t.Fatalf("advertiseAutocrypt was omitted from PUT 2 and must keep its stored value (false), got %+v", putResp2)
	}
	if !putResp2.StoreDiscoveredKeys {
		t.Fatalf("storeDiscoveredKeys was omitted from PUT 2 and must keep its on-by-default value, got %+v", putResp2)
	}
	if !putResp2.AutoEncryptWhenKeyKnown {
		t.Fatalf("autoEncryptWhenKeyKnown was explicitly set true in PUT 2, got %+v", putResp2)
	}

	// Confirm it persisted, not just reflected in the response.
	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodGet,
		"/api/pgp/discovery/settings", nil, userID)
	var getResp discoverySettingsResp
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if getResp.AdvertiseAutocrypt || !getResp.StoreDiscoveredKeys || !getResp.AutoEncryptWhenKeyKnown {
		t.Fatalf("persisted settings mismatch: %+v", getResp)
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
	if !getResp.PublishWKD {
		t.Fatalf("expected publishWKD to default to true, got %+v", getResp)
	}
}

// TestDiscoverySettingsPutPublishWKDExplicitFalseAndOmissionKeepsCurrent
// covers the PUT handler's merge behavior for the new PublishWKD field: an
// explicit false must take effect, and a later PUT that omits the field must
// not silently flip it back on (the same nil-means-keep-current contract as
// storeDiscoveredKeys/advertiseAutocrypt).
func TestDiscoverySettingsPutPublishWKDExplicitFalseAndOmissionKeepsCurrent(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	putRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodPut,
		"/api/pgp/discovery/settings",
		map[string]bool{"publishWKD": false}, userID)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: expected 200, got %d: %s", putRec.Code, putRec.Body.String())
	}
	var putResp discoverySettingsResp
	if err := json.NewDecoder(putRec.Body).Decode(&putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putResp.PublishWKD {
		t.Fatalf("expected publishWKD=false after explicit PUT, got %+v", putResp)
	}

	// Omitting publishWKD on a later PUT must keep it false, not reset to
	// the on-by-default value.
	putRec2 := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodPut,
		"/api/pgp/discovery/settings",
		map[string]bool{"autoEncryptWhenKeyKnown": true}, userID)
	if putRec2.Code != http.StatusOK {
		t.Fatalf("PUT 2: expected 200, got %d: %s", putRec2.Code, putRec2.Body.String())
	}
	var putResp2 discoverySettingsResp
	if err := json.NewDecoder(putRec2.Body).Decode(&putResp2); err != nil {
		t.Fatalf("decode PUT 2 response: %v", err)
	}
	if putResp2.PublishWKD {
		t.Fatalf("publishWKD was omitted from PUT 2 and must keep its stored value (false), got %+v", putResp2)
	}

	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySettings), http.MethodGet,
		"/api/pgp/discovery/settings", nil, userID)
	var getResp discoverySettingsResp
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if getResp.PublishWKD {
		t.Fatalf("persisted publishWKD mismatch: %+v", getResp)
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
