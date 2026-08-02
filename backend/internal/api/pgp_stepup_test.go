package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/pgpmail"
)

// Replacing or destroying a PGP identity used to need nothing but a session
// cookie. A session is a bearer token and everything else it authorises expires
// with it; a replaced published key does not. It goes out through WKD and
// Autocrypt, so every future correspondent encrypts to the attacker's key, and
// the effect outlives the session that caused it. Deleting the identity is not
// undoable at all — mail already encrypted to that key stays unreadable.

// stepUpPassword sets a known account password on the test user so a step-up
// can actually be performed, and returns it.
func stepUpPassword(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	const password = "correct-horse-battery-staple"
	if _, err := srv.users.SetPassword(context.Background(), userID, password, false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	return password
}

// giveUserAnIdentity installs a server-custody identity directly, so a test can
// start from "this account has something to lose".
func giveUserAnIdentity(t *testing.T, srv *Server, userID string) {
	t.Helper()
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(srv.pgpPrivateKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := srv.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
}

func pgpRequest(t *testing.T, srv *Server, method, path string, body map[string]string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(handler)(rec, req)
	return rec
}

func TestPGPIdentityDeleteRequiresTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	giveUserAnIdentity(t, srv, userID)

	// Session alone: refused.
	rec := pgpRequest(t, srv, http.MethodDelete, "/api/pgp/identity", nil, srv.handlePGPIdentity)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session alone deleted the identity: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil || u.PGPFingerprint == "" {
		t.Fatal("the identity was destroyed by a request that was refused")
	}

	// Wrong password: refused.
	rec = pgpRequest(t, srv, http.MethodDelete, "/api/pgp/identity",
		map[string]string{"password": "not-the-password"}, srv.handlePGPIdentity)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password deleted the identity: %d", rec.Code)
	}

	// Correct password: allowed.
	rec = pgpRequest(t, srv, http.MethodDelete, "/api/pgp/identity",
		map[string]string{"password": password}, srv.handlePGPIdentity)
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not delete their own identity: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil || u.PGPFingerprint != "" {
		t.Fatal("the identity survived a confirmed delete")
	}
}

func TestPGPClientIdentityReplacementRequiresTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	giveUserAnIdentity(t, srv, userID)

	attacker, err := pgpmail.GenerateIdentity("Mallory", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	before, err := srv.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}

	body := map[string]string{
		"publicKey": attacker.ArmoredPublicKey,
		"wrapped":   `{"v":1,"blob":"opaque"}`,
		"source":    "generated",
	}
	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/client", body, srv.handlePGPIdentityClient)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a stolen session replaced the published key: %d %s", rec.Code, rec.Body.String())
	}
	after, err := srv.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	if after.PGPFingerprint != before.PGPFingerprint {
		t.Fatal("the published key was replaced by a request that was refused")
	}

	body["password"] = password
	rec = pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/client", body, srv.handlePGPIdentityClient)
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not replace their own key: %d %s", rec.Code, rec.Body.String())
	}
}

// The rewrap endpoint takes an envelope the server cannot open by design, so it
// cannot check that the blob contains the right key — or any key. Overwriting
// it with rubbish strands every message ever encrypted to that identity, which
// is why a session is not enough for it either.
func TestPGPRewrapRequiresTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	// Client-protected, since rewrap refuses an account whose key the server
	// still holds.
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(userID, id.Fingerprint, id.KeyID,
		id.ArmoredPublicKey, `{"v":1,"blob":"original"}`, "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}

	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/rewrap",
		map[string]string{"wrapped": `{"v":1,"blob":"rubbish"}`}, srv.handlePGPRewrapKey)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session alone rewrapped the private key: %d %s", rec.Code, rec.Body.String())
	}

	rec = pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/rewrap",
		map[string]string{"wrapped": `{"v":1,"blob":"legitimate"}`, "password": password}, srv.handlePGPRewrapKey)
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not rewrap their own key: %d %s", rec.Code, rec.Body.String())
	}
}

// First-time setup is deliberately NOT gated. An account with no identity has
// no key to redirect and none to strand, so a credential prompt there protects
// nothing and would land in the middle of onboarding.
func TestFirstPGPIdentityNeedsNoStepUp(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	stepUpPassword(t, srv, userID)

	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/client", map[string]string{
		"publicKey": id.ArmoredPublicKey,
		"wrapped":   `{"v":1,"blob":"opaque"}`,
		"source":    "generated",
	}, srv.handlePGPIdentityClient)

	if rec.Code != http.StatusOK {
		t.Fatalf("first-time PGP setup demanded a password: %d %s", rec.Code, rec.Body.String())
	}
}
