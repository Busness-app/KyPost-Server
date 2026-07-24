package api

import (
	"encoding/json"
	"net/http"
	"testing"
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
