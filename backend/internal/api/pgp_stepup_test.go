package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busness-app/kypost-server/backend/internal/users"
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

// The envelope-slot endpoints (pgp_client_keys.go) mint or destroy an
// additional sealing of the private key, so PUT and DELETE need the same
// standard as rewrap: a stolen session must not be able to plant an
// envelope the server cannot validate, and deleting a sealing that cannot be
// re-minted without the unwrapped key is not undoable. GET is unaffected —
// see docs/E2E_PGP.md.
func TestPGPPutEnvelopeSlotRequiresTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(userID, id.Fingerprint, id.KeyID,
		id.ArmoredPublicKey, `{"v":1,"blob":"original"}`, "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}

	putReq := func(body map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPut, "/api/pgp/identity/envelope/recovery", bytes.NewReader(raw))
		req.SetPathValue("slot", "recovery")
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		srv.withAuth(srv.handlePGPPutEnvelopeSlot)(rec, req)
		return rec
	}

	// Session alone: refused.
	rec := putReq(map[string]string{"envelope": `{"v":1,"blob":"recovery"}`})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session alone installed a wrapped-envelope slot: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil {
		t.Fatalf("users.Get: %v", err)
	} else if len(u.WrappedEnvelopes()) != 1 {
		t.Fatalf("a refused PUT still installed a slot: %+v", u.WrappedEnvelopes())
	}

	// Wrong password: refused.
	rec = putReq(map[string]string{"envelope": `{"v":1,"blob":"recovery"}`, "password": "not-the-password"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password installed a wrapped-envelope slot: %d", rec.Code)
	}

	// Correct password: allowed.
	rec = putReq(map[string]string{"envelope": `{"v":1,"blob":"recovery"}`, "password": password})
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not install their own recovery slot: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil {
		t.Fatalf("users.Get: %v", err)
	} else if len(u.WrappedEnvelopes()) != 2 {
		t.Fatalf("a confirmed PUT did not install the slot: %+v", u.WrappedEnvelopes())
	}
}

// DeletePGPWrappedEnvelope needs no client-protected identity (unlike Set),
// so this test uses SetPGPWrappedEnvelope directly to seed the slot rather
// than going through the client-identity setup above.
func TestPGPDeleteEnvelopeSlotRequiresTheAccountPassword(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(userID, id.Fingerprint, id.KeyID,
		id.ArmoredPublicKey, `{"v":1,"blob":"original"}`, "generated", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	if _, err := srv.users.SetPGPWrappedEnvelope(userID, "recovery", `{"v":1,"blob":"rec"}`, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope (fixture): %v", err)
	}

	delReq := func(body *bytes.Reader) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodDelete, "/api/pgp/identity/envelope/recovery", body)
		req.SetPathValue("slot", "recovery")
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		srv.withAuth(srv.handlePGPDeleteEnvelopeSlot)(rec, req)
		return rec
	}

	// A body-less request must fail closed (refused), not silently skip the
	// step-up check because there was nothing to decode.
	rec := delReq(bytes.NewReader(nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("a body-less DELETE destroyed a wrapped-envelope slot: %d", rec.Code)
	}
	if u, err := srv.users.Get(userID); err != nil {
		t.Fatalf("users.Get: %v", err)
	} else if len(u.WrappedEnvelopes()) != 2 {
		t.Fatalf("a refused DELETE still removed a slot: %+v", u.WrappedEnvelopes())
	}

	// Session with an empty credential: refused.
	raw, _ := json.Marshal(map[string]string{})
	rec = delReq(bytes.NewReader(raw))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session alone destroyed a wrapped-envelope slot: %d %s", rec.Code, rec.Body.String())
	}

	// Wrong password: refused.
	raw, _ = json.Marshal(map[string]string{"password": "not-the-password"})
	rec = delReq(bytes.NewReader(raw))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong password destroyed a wrapped-envelope slot: %d", rec.Code)
	}

	// Correct password: allowed.
	raw, _ = json.Marshal(map[string]string{"password": password})
	rec = delReq(bytes.NewReader(raw))
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not delete their own recovery slot: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil {
		t.Fatalf("users.Get: %v", err)
	} else if len(u.WrappedEnvelopes()) != 1 {
		t.Fatalf("a confirmed DELETE did not remove the slot: %+v", u.WrappedEnvelopes())
	}
}

// TestFirstPGPIdentityNeedsStepUp is run-8 finding F6, and reverses what this
// test used to assert.
//
// The carve-out was "an account with no identity yet has nothing to lose". That
// is true of the asset the operation destroys and false of the asset it
// CREATES. A hijacked session could install an attacker-held key as the
// victim's published identity with no credential of any kind; PublishWKD and
// AdvertiseAutocrypt both default true, so the victim's own outbound mail then
// advertises it and correspondents encrypt to it. A five-minute hijack bought a
// permanent published-key substitution that outlives the session — the exact
// durability the same file cites to justify gating identity replacement.
//
// The onboarding cost it was avoiding does not exist: every client-custody path
// already holds the password, because it wraps the private key with it.
func TestFirstPGPIdentityNeedsStepUp(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)

	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	install := func(body map[string]string) *httptest.ResponseRecorder {
		return pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/client", body, srv.handlePGPIdentityClient)
	}

	rec := install(map[string]string{
		"publicKey": id.ArmoredPublicKey,
		"wrapped":   `{"v":1,"blob":"opaque"}`,
		"source":    "generated",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a session alone published a PGP identity for this account: %d %s", rec.Code, rec.Body.String())
	}
	if u, err := srv.users.Get(userID); err != nil {
		t.Fatalf("users.Get: %v", err)
	} else if u.PGPFingerprint != "" {
		t.Fatalf("an unconfirmed request installed a published key: %s", u.PGPFingerprint)
	}

	rec = install(map[string]string{
		"publicKey": id.ArmoredPublicKey,
		"wrapped":   `{"v":1,"blob":"opaque"}`,
		"source":    "generated",
		"password":  password,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the owner could not set up their own first identity: %d %s", rec.Code, rec.Body.String())
	}
}

// TestFirstLoginExemptionDoesNotCoverTheEnvelope is run-7 finding F7.
//
// POST /api/auth/password used to skip credential verification entirely when
// MustChangePassword was set and no old credential was offered, which let a
// hijacked session overwrite PGPPrivateKeyWrapped — irreversible, and
// unvalidatable by a server that cannot open the envelope.
//
// run-8 F4 then removed the exemption outright, so the credential half is
// refused on the same terms. This test keeps both halves: the unproven request
// is rejected AND writes nothing, and the genuine first-login change still
// works when the temporary password is presented.
func TestFirstLoginExemptionDoesNotCoverTheEnvelope(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "jules", "pw-jules-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(
		u.ID, "FPR", "KID", "PUB", `{"v":2,"ciphertext":"VICTIM"}`, "generated", "2026-08-04T00:00:00Z",
	); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	// Exactly the post-admin-reset state: a live session, MustChangePassword set.
	if _, err := srv.users.SetPassword(context.Background(), u.ID, "temporary-password-xyz", true); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// NOT doJSONAuth: it clears MustChangePassword to model an onboarded session,
	// which is precisely the state under test here.
	rec := changePasswordAs(t, srv, u.ID, map[string]any{
		"newAuthSecret":   strings.Repeat("a", 64),
		"newLoginSalt":    base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
		"newIterations":   600000,
		"rewrappedPgpKey": `{"v":2,"ciphertext":"ATTACKER"}`,
	})
	if rec.Code == http.StatusOK {
		t.Fatal("an unverified request overwrote the client-sealed PGP envelope; the " +
			"MustChangePassword exemption must not extend to key material")
	}

	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.PGPPrivateKeyWrapped != `{"v":2,"ciphertext":"VICTIM"}` {
		t.Fatalf("the envelope was replaced without any credential being proved: %q", after.PGPPrivateKeyWrapped)
	}

	// A credential-only change with NO old credential is now refused too — run-8
	// F4. It was a password reset for anyone holding a cookie.
	rec = changePasswordAs(t, srv, u.ID, map[string]any{
		"newAuthSecret": strings.Repeat("b", 64),
		"newLoginSalt":  base64.StdEncoding.EncodeToString([]byte("fedcba9876543210")),
		"newIterations": 600000,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a password change proving nothing returned %d (%s)", rec.Code, rec.Body.String())
	}

	// Presenting the temporary password, it works.
	rec = changePasswordAs(t, srv, u.ID, map[string]any{
		"oldPassword":   "temporary-password-xyz",
		"newAuthSecret": strings.Repeat("b", 64),
		"newLoginSalt":  base64.StdEncoding.EncodeToString([]byte("fedcba9876543210")),
		"newIterations": 600000,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("the ordinary first-login password change was broken: %d (%s)", rec.Code, rec.Body.String())
	}
}

// changePasswordAs posts to handleChangePassword with an auth context injected
// directly, preserving MustChangePassword — unlike doJSONAuth, which clears it.
func changePasswordAs(t *testing.T, srv *Server, userID string, payload map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:5000"
	u, err := srv.users.Get(userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	req = req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}))
	rec := httptest.NewRecorder()
	srv.handleChangePassword(rec, req)
	return rec
}
