package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// keyUserIDEmails returns the sorted, lowercased User ID emails of an
// armored key — the set WKD serving and Autocrypt advertising match a mail
// address against before they will use the key for that address.
func keyUserIDEmails(t *testing.T, armored string) []string {
	t.Helper()
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("parse armored key: %v", err)
	}
	var out []string
	for _, uid := range key.GetEntity().Identities {
		out = append(out, strings.ToLower(uid.UserId.Email))
	}
	sort.Strings(out)
	return out
}

// seedClientIdentity stores an end-to-end identity for userID the way the
// browser does, so tests that need an account to HAVE a key do not have to go
// through a server-custody path that no longer exists.
func seedClientIdentity(t *testing.T, srv *Server, userID, armoredPublicKey string) string {
	t.Helper()
	key, err := crypto.NewKeyFromArmored(armoredPublicKey)
	if err != nil {
		t.Fatalf("parse armored key: %v", err)
	}
	fingerprint := strings.ToUpper(key.GetFingerprint())
	if _, err := srv.users.SetPGPIdentityClientProtected(userID, fingerprint,
		key.GetHexKeyID(), armoredPublicKey, `{"v":1}`, "generated", "test"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return fingerprint
}

// TestPGPIdentityGenerateAndImportRefuseServerCustody pins the retirement of
// server-held keys at its source. These two endpoints were the only way to
// create a private key this server could open, so as long as they refuse, no
// account can newly enter server custody however old the client is.
//
// They answer 400 rather than 404 deliberately: an older client that still
// posts here must be told what to do instead, and a 404 would reach the user
// as "server unreachable".
func TestPGPIdentityGenerateAndImportRefuseServerCustody(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")
	password := stepUpPassword(t, srv, userID)

	for _, tc := range []struct {
		name    string
		path    string
		handler http.HandlerFunc
		body    map[string]string
	}{
		{"generate", "/api/pgp/identity/generate", srv.handlePGPIdentityGenerate,
			map[string]string{"password": password}},
		{"import", "/api/pgp/identity/import", srv.handlePGPIdentityImport,
			map[string]string{"armoredPrivateKey": "irrelevant", "password": password}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			authRequest(srv, req)
			rec := httptest.NewRecorder()
			srv.withAuth(tc.handler)(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "/api/pgp/identity/client") {
				t.Fatalf("refusal must name the endpoint to use instead, got %q", rec.Body.String())
			}
			// The refusal has to be a refusal, not a rename: nothing may be
			// stored. Otherwise the endpoint still mints server-custody keys
			// and merely reports failure.
			u, err := srv.users.Get(userID)
			if err != nil {
				t.Fatalf("users.Get: %v", err)
			}
			if u.PGPFingerprint != "" || u.PGPPrivateKeyEnc != "" {
				t.Fatalf("refused request still stored key material: fingerprint=%q enc=%d bytes",
					u.PGPFingerprint, len(u.PGPPrivateKeyEnc))
			}
		})
	}
}

// TestSuggestedKeyUserIDsCarriesVerifiedSendAsAliases covers the invariant that
// used to be enforced by the server's own key generator: the key must carry the
// account address plus every VERIFIED send-as alias as a User ID, and must not
// carry a merely pending one. WKD serving (validateDiscoveredKey) and Autocrypt
// (buildAutocryptHeader) both discard a key that does not carry the address in
// question, so a key missing an alias User ID is silently unusable for it.
//
// The browser generates the key now, so this is the address list the server
// hands it via /api/pgp/bootstrap. Getting this list wrong has exactly the
// consequence it always had; only the component that consumes it changed.
func TestSuggestedKeyUserIDsCarriesVerifiedSendAsAliases(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")

	store, err := srv.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	verified, err := store.Create(userID, "alice@other.example", "")
	if err != nil {
		t.Fatalf("Create verified alias: %v", err)
	}
	if err := store.MarkVerified(verified.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	if _, err := store.Create(userID, "alice@pending.example", ""); err != nil {
		t.Fatalf("Create pending alias: %v", err)
	}

	got := append([]string{}, srv.suggestedKeyUserIDs(userID)...)
	for i := range got {
		got[i] = strings.ToLower(got[i])
	}
	sort.Strings(got)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("suggested user IDs: got %v want %v", got, want)
	}
}

// TestPGPIdentityGetThenDelete covers the lifecycle that survives server-custody
// retirement. The identity is seeded the way the browser installs one.
func TestPGPIdentityGetThenDelete(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)

	key, err := crypto.PGP().KeyGeneration().AddUserId("Alice", "alice@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	fingerprint := seedClientIdentity(t, srv, userID, pub)

	if got := keyUserIDEmails(t, pub); !slices.Equal(got, []string{"alice@example.com"}) {
		t.Fatalf("seeded key user IDs: got %v", got)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/pgp/identity", nil)
	authRequest(srv, getReq)
	getRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentity)(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var getResp pgpIdentityResponse
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if getResp.Fingerprint != fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", getResp.Fingerprint, fingerprint)
	}
	if getResp.Revoked || getResp.Expired {
		t.Fatalf("expected a fresh identity to be neither revoked nor expired, got %+v", getResp)
	}

	// Deleting an existing identity is step-up gated (pgp_stepup.go).
	delBody, _ := json.Marshal(map[string]string{"password": password})
	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/identity", bytes.NewReader(delBody))
	authRequest(srv, delReq)
	delRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentity)(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete: expected 200, got %d: %s", delRec.Code, delRec.Body.String())
	}

	getReq2 := httptest.NewRequest(http.MethodGet, "/api/pgp/identity", nil)
	authRequest(srv, getReq2)
	getRec2 := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentity)(getRec2, getReq2)
	if getRec2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", getRec2.Code)
	}
}

// TestPGPIdentityGetReportsRevoked keeps the revocation reporting that the
// import test used to cover: a revoked key must be reported as revoked, so the
// UI can say so rather than letting the user discover it on a failed send.
// Unlike before, the key arrives through the client path.
func TestPGPIdentityGetReportsRevoked(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	key, err := crypto.PGP().KeyGeneration().AddUserId("Revoked", "revoked@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := key.GetEntity().Revoke(packet.NoReason, "test revocation", &packet.Config{}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	pub, err := key.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("GetArmoredPublicKey: %v", err)
	}
	seedClientIdentity(t, srv, userID, pub)

	getReq := httptest.NewRequest(http.MethodGet, "/api/pgp/identity", nil)
	authRequest(srv, getReq)
	getRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentity)(getRec, getReq)
	var getResp pgpIdentityResponse
	if err := json.NewDecoder(getRec.Body).Decode(&getResp); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if !getResp.Revoked {
		t.Fatalf("expected revoked=true on GET response, got %+v", getResp)
	}
}
