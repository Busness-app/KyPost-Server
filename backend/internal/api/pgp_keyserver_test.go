package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpmail"
)

func TestKeyserverLookupReturnsKey(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Carol", "carol@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(id.ArmoredPublicKey))
	}))
	defer srv.Close()
	old := keyserverBaseURL
	keyserverBaseURL = srv.URL
	defer func() { keyserverBaseURL = old }()

	armored, fp, err := keyserverLookup(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("keyserverLookup: %v", err)
	}
	if fp == "" || !strings.Contains(armored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("unexpected result fp=%q", fp)
	}
}

func TestPGPKeyserverLookupSuccess(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Keyserver Test", "keyserver-test@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vks/v1/by-email/keyserver-test@example.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		_, _ = w.Write([]byte(id.ArmoredPublicKey))
	}))
	defer ts.Close()

	original := keyserverBaseURL
	keyserverBaseURL = ts.URL
	defer func() { keyserverBaseURL = original }()

	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/keyserver/lookup?email=keyserver-test@example.com", nil)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPKeyserverLookup)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Fingerprint string `json:"fingerprint"`
		Revoked     bool   `json:"revoked"`
		Expired     bool   `json:"expired"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Fingerprint != id.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", resp.Fingerprint, id.Fingerprint)
	}
	if resp.Revoked || resp.Expired {
		t.Fatalf("expected a freshly generated key to be neither revoked nor expired, got %+v", resp)
	}
}

func TestPGPKeyserverLookupNotFound(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	original := keyserverBaseURL
	keyserverBaseURL = ts.URL
	defer func() { keyserverBaseURL = original }()

	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/keyserver/lookup?email=nobody@example.com", nil)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPKeyserverLookup)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestPGPRecipientsCheck(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID
	contactsStore, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	hasKeyID, err := pgpmail.GenerateIdentity("Has Key", "haskey@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	revokedKey := generateRevokedArmoredKey(t, "Revoked", "revoked@example.com")
	for _, c := range []contacts.Contact{
		{FormattedName: "Has Key", Emails: []contacts.ContactValue{{Value: "haskey@example.com"}}, PGPKey: hasKeyID.ArmoredPublicKey},
		{FormattedName: "Revoked", Emails: []contacts.ContactValue{{Value: "revoked@example.com"}}, PGPKey: revokedKey},
	} {
		if _, err := contactsStore.Upsert(c); err != nil {
			t.Fatalf("Upsert %s: %v", c.FormattedName, err)
		}
	}

	body, _ := json.Marshal(map[string]any{"addresses": []string{"haskey@example.com", "revoked@example.com", "nokey@example.com"}})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/recipients/check", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPRecipientsCheck)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Results []struct {
			Address string `json:"address"`
			HasKey  bool   `json:"hasKey"`
			Revoked bool   `json:"revoked"`
			Expired bool   `json:"expired"`
		} `json:"results"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}
	if !resp.Results[0].HasKey || resp.Results[0].Revoked || resp.Results[0].Expired {
		t.Fatalf("haskey@example.com: expected a usable key, got %+v", resp.Results[0])
	}
	if resp.Results[1].HasKey || !resp.Results[1].Revoked {
		t.Fatalf("revoked@example.com: expected hasKey=false, revoked=true, got %+v", resp.Results[1])
	}
	if resp.Results[2].HasKey || resp.Results[2].Revoked || resp.Results[2].Expired {
		t.Fatalf("nokey@example.com: expected no key at all, got %+v", resp.Results[2])
	}
}
