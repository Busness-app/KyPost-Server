package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"kypost-server/backend/internal/pgpmail"
)

// POST /api/pgp/identity/client must answer with the SAME identity shape as
// every other endpoint that returns one (generate, import, GET
// /api/pgp/identity): fingerprint/keyId/publicKey/source/createdAt.
//
// It used to write users.Public instead, whose PGP fields are named
// pgpFingerprint/pgpKeyId and which carries no public key at all. The browser
// stores this response as the page's current identity, so after generating or
// migrating to a client-held key the fingerprint it held was undefined — and
// "Download recovery backup" died on `fingerprint.slice(0, 8)` before the file
// or its one-time secret ever reached the user.
func TestClientIdentityResponseMatchesTheIdentityShape(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)

	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/client", map[string]string{
		"publicKey": id.ArmoredPublicKey,
		"wrapped":   `{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"c2FsdA==","iv":"aXY=","ciphertext":"Y3Q="}`,
		"source":    "generated",
		"password":  password,
	}, srv.handlePGPIdentityClient)
	if rec.Code != http.StatusOK {
		t.Fatalf("client identity: status %d; body=%s", rec.Code, rec.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	for field, want := range map[string]string{
		"fingerprint": id.Fingerprint,
		"keyId":       id.KeyID,
		"publicKey":   id.ArmoredPublicKey,
		"source":      "generated",
	} {
		if got[field] != want {
			t.Errorf("%s = %v, want %v", field, got[field], want)
		}
	}
	if s, _ := got["createdAt"].(string); s == "" {
		t.Errorf("createdAt is empty: %s", rec.Body.String())
	}

	// The GET is the contract this has to match; compare them field by field
	// so a future change to one shape cannot silently diverge from the other.
	getRec := pgpRequest(t, srv, http.MethodGet, "/api/pgp/identity", nil, srv.handlePGPIdentity)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get identity: status %d; body=%s", getRec.Code, getRec.Body.String())
	}
	var fromGet map[string]any
	if err := json.Unmarshal(getRec.Body.Bytes(), &fromGet); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	for _, field := range []string{"fingerprint", "keyId", "publicKey", "source", "createdAt"} {
		if got[field] != fromGet[field] {
			t.Errorf("%s: POST returned %v, GET returned %v", field, got[field], fromGet[field])
		}
	}
}
