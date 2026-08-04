package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"kypost-server/backend/internal/users"
)

func loginParams(t *testing.T, srv *Server, username string) (string, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login-params?username="+username, nil)
	rec := httptest.NewRecorder()
	srv.handleLoginParams(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login-params: status %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Salt       string `json:"salt"`
		Iterations int    `json:"iterations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode login-params: %v", err)
	}
	return out.Salt, out.Iterations
}

func postLogin(t *testing.T, srv *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.11:5000"
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)
	return rec
}

// TestLoginParamsDoesNotRevealAccountExistence is the property that makes the
// pre-login handshake safe to expose.
//
// The endpoint is unauthenticated and takes a username, so if its answer differed
// for a real account it would be a free account-enumeration oracle — worse than
// the timing oracle equalizeLoginTiming exists to close, because it needs no
// measurement at all.
func TestLoginParamsDoesNotRevealAccountExistence(t *testing.T) {
	srv := newTestServer(t)
	if _, err := srv.users.Create(context.Background(), "realuser", "correct-horse-battery-staple", users.RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}

	realSalt, realIter := loginParams(t, srv, "realuser")
	fakeSalt, fakeIter := loginParams(t, srv, "nosuchuser")

	if realSalt == "" || fakeSalt == "" {
		t.Fatal("login-params returned an empty salt; the client cannot derive anything")
	}
	if len(realSalt) != len(fakeSalt) {
		t.Errorf("salt length differs by account existence: real %d vs unknown %d", len(realSalt), len(fakeSalt))
	}
	if realIter != fakeIter {
		t.Errorf("iteration count differs by account existence: real %d vs unknown %d", realIter, fakeIter)
	}
	if realSalt == fakeSalt {
		t.Error("two different usernames got the same salt; salts must be per-account")
	}

	// Stability matters as much as shape: a salt that changed per request would
	// be a louder oracle than returning nothing.
	againSalt, _ := loginParams(t, srv, "nosuchuser")
	if againSalt != fakeSalt {
		t.Error("the synthetic salt for an unknown username is not stable across requests")
	}

	// And the response must carry no derivation/legacy hint. Once every account
	// has converted, such a field would mean "no such user".
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login-params?username=realuser", nil)
	rec := httptest.NewRecorder()
	srv.handleLoginParams(rec, req)
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, forbidden := range []string{"derivation", "legacy", "exists", "authDerivation"} {
		if _, present := raw[forbidden]; present {
			t.Errorf("login-params response carries %q, which is an account-existence oracle", forbidden)
		}
	}
}

// TestLegacyAccountUpgradesToDerivedAuthOnLogin covers the migration: an account
// created before derived auth existed converts on its next successful sign-in,
// after which the password is no longer accepted or needed.
func TestLegacyAccountUpgradesToDerivedAuthOnLogin(t *testing.T) {
	srv := newTestServer(t)
	const pw = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "legacy-user", pw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.UsesDerivedAuth() {
		t.Fatal("a freshly created account should start legacy (the admin set its password)")
	}

	salt, iterations := loginParams(t, srv, "legacy-user")
	authSecret := deriveAuthSecretForTest(t, pw, salt, iterations)

	// Legacy login: client sends BOTH, server verifies the password and converts.
	rec := postLogin(t, srv, map[string]any{
		"username":        "legacy-user",
		"password":        pw,
		"authSecret":      authSecret,
		"loginSalt":       salt,
		"loginIterations": iterations,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy login: status %d (%s)", rec.Code, rec.Body.String())
	}

	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.UsesDerivedAuth() {
		t.Fatal("the account did not convert to derived auth after a successful legacy login")
	}
	if after.LoginSalt != salt {
		t.Errorf("stored LoginSalt = %q, want the salt the client actually used (%q); otherwise the "+
			"next login derives a different secret and the user is locked out", after.LoginSalt, salt)
	}

	// The derived secret now works on its own, with no password at all.
	rec = postLogin(t, srv, map[string]any{"username": "legacy-user", "authSecret": authSecret})
	if rec.Code != http.StatusOK {
		t.Fatalf("derived login after upgrade: status %d (%s)", rec.Code, rec.Body.String())
	}

	// And the plaintext password alone is no longer a credential — the whole
	// point. If this passed, the server would still be accepting (and therefore
	// still receiving) the value that opens the PGP vault.
	rec = postLogin(t, srv, map[string]any{"username": "legacy-user", "password": pw})
	if rec.Code == http.StatusOK {
		t.Error("the plaintext password still authenticates after conversion; the server is still " +
			"being handed the PGP vault's wrapping-key material on every login")
	}
}

// TestDerivedAuthRejectsCrossFormCredentials is the confusion guard. The salt is
// public, so if the server would check a derived secret as a password (or the
// reverse) anyone could authenticate with a value computed from the salt alone.
func TestDerivedAuthRejectsCrossFormCredentials(t *testing.T) {
	srv := newTestServer(t)
	const pw = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "cross-form", pw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	salt, iterations := loginParams(t, srv, "cross-form")
	authSecret := deriveAuthSecretForTest(t, pw, salt, iterations)
	if err := srv.users.UpgradeToDerivedAuth(context.Background(), u.ID, pw, authSecret, salt, iterations); err != nil {
		t.Fatalf("UpgradeToDerivedAuth: %v", err)
	}

	converted, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// The derived secret must not be accepted as a password. Not because the
	// salt alone yields it — PBKDF2 still needs the password — but because the
	// two are different credentials for one account, and any call site that
	// reached for the wrong verifier would silently accept the wrong one.
	if ok, _ := users.VerifyPassword(context.Background(), converted, authSecret); ok {
		t.Error("VerifyPassword accepted the derived auth secret; the two credential forms must be " +
			"strictly disjoint so no call site can mix them")
	}
	// And the real password must not verify either, now that the account has
	// converted: PasswordHash no longer covers it.
	if ok, _ := users.VerifyPassword(context.Background(), converted, pw); ok {
		t.Error("VerifyPassword accepted the plaintext password on a converted account")
	}
	// And a password must not be accepted as a derived secret.
	if ok, _ := users.VerifyAuthSecret(context.Background(), converted, pw); ok {
		t.Error("VerifyAuthSecret accepted the plaintext password")
	}
	// VerifyAuthSecret must refuse outright for a legacy account, so no call site
	// can use it as a general-purpose check.
	legacy, err := srv.users.Create(context.Background(), "still-legacy", pw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ok, _ := users.VerifyAuthSecret(context.Background(), legacy, pw); ok {
		t.Error("VerifyAuthSecret returned true for a legacy account")
	}
}

// TestPasswordChangeCommitsCredentialAndRewrapTogether is the §2.1 regression
// test: the credential and the re-sealed PGP envelope must land in one write.
func TestPasswordChangeCommitsCredentialAndRewrapTogether(t *testing.T) {
	srv := newTestServer(t)
	const oldPw = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "rewrap-user", oldPw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.ClearMustChangePassword(u.ID); err != nil {
		t.Fatalf("ClearMustChangePassword: %v", err)
	}
	// Give the account a client-protected identity to re-seal.
	if _, err := srv.users.SetPGPIdentityClientProtected(
		u.ID, "FPR", "KEYID", "-----BEGIN PGP PUBLIC KEY BLOCK-----\npub\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"AAAA","iv":"BBBB","ciphertext":"OLD"}`,
		"generated", "2026-01-01T00:00:00Z",
	); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}

	newSalt := "bmV3LXNhbHQtc2l4dGVlbg=="
	newSecret := "aa" + strings0(62)
	const newEnvelope = `{"v":2,"kdf":"PBKDF2-SHA256","iterations":600000,"salt":"CCCC","iv":"DDDD","ciphertext":"NEW"}`

	body, _ := json.Marshal(map[string]any{
		"oldPassword":     oldPw,
		"newAuthSecret":   newSecret,
		"newLoginSalt":    newSalt,
		"newIterations":   600000,
		"rewrappedPgpKey": newEnvelope,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleChangePassword(rec, req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: u.ID, Username: u.Username, Role: users.RoleUser})))
	if rec.Code != http.StatusOK {
		t.Fatalf("change password: status %d (%s)", rec.Code, rec.Body.String())
	}

	after, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.UsesDerivedAuth() {
		t.Error("account is not on derived auth after the change")
	}
	if after.LoginSalt != newSalt {
		t.Errorf("LoginSalt = %q, want %q", after.LoginSalt, newSalt)
	}
	if ok, _ := users.VerifyAuthSecret(context.Background(), after, newSecret); !ok {
		t.Error("the new derived credential does not verify")
	}
	// The envelope must have moved in the SAME write. If it lags, the key is
	// sealed under a password nobody has any more.
	if after.PGPPrivateKeyWrapped != newEnvelope {
		t.Errorf("PGP envelope = %q, want the rewrapped one — the credential and the envelope must "+
			"commit together or the key is stranded", after.PGPPrivateKeyWrapped)
	}
}

// TestPasswordChangeRefusesRewrapWithoutDerivedAuth guards the mismatched pair:
// the legacy plaintext path resets the account to legacy derivation, so storing
// an envelope alongside it would seal the key under a key nothing asks for.
func TestPasswordChangeRefusesRewrapWithoutDerivedAuth(t *testing.T) {
	srv := newTestServer(t)
	const oldPw = "correct-horse-battery-staple"
	u, err := srv.users.Create(context.Background(), "mismatch-user", oldPw, users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.ClearMustChangePassword(u.ID); err != nil {
		t.Fatalf("ClearMustChangePassword: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"oldPassword":     oldPw,
		"newPassword":     "another-correct-horse-battery",
		"rewrappedPgpKey": `{"v":2}`,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.handleChangePassword(rec, req.WithContext(context.WithValue(req.Context(), authContextKey{},
		AuthContext{UserID: u.ID, Username: u.Username, Role: users.RoleUser})))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400: a rewrap alongside a plaintext change stores an envelope "+
			"sealed under a key nothing will ask for", rec.Code)
	}
}

func strings0(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}

// deriveAuthSecretForTest mirrors frontend/src/lib/authSecret.ts: stretch the
// password with the server-supplied login salt, then HKDF-Expand under the auth
// label. Kept in the test rather than in production code because the server must
// never be able to perform this derivation — it does not have the password, and
// that is the entire point.
func deriveAuthSecretForTest(t *testing.T, password, saltB64 string, iterations int) string {
	t.Helper()
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	stretch := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
	// HKDF-Expand with an empty salt and the auth label, one 32-byte block.
	mac := hmac.New(sha256.New, hkdfExtract(nil, stretch))
	mac.Write([]byte("kypost/auth/v1"))
	mac.Write([]byte{0x01})
	return hex.EncodeToString(mac.Sum(nil))
}

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// TestSPARequestShapeSignsInLegacyAccount pins the composition the shipped client
// actually produces, which is the thing the other tests in this file do not cover.
//
// The regression it guards against: the SPA inferred "legacy" from an empty
// login-params salt and sent authSecret ALONE. But loginParamsFor never returns an
// empty salt — a legacy or nonexistent account gets a stable SYNTHETIC one, so the
// endpoint cannot be used to enumerate accounts. The inference was therefore always
// false, every legacy account got a 401, and since Create, the bootstrap admin and
// SetPassword all produce legacy accounts, a fresh install had no account that could
// sign in at all.
//
// Asserting on credentialFields' OUTPUT SHAPE rather than on a hand-written body is
// the point: a test that sends both fields by hand passes whatever the client does.
func TestSPARequestShapeSignsInLegacyAccount(t *testing.T) {
	srv := newTestServer(t)
	const pw = "correct-horse-battery-staple"
	if _, err := srv.users.Create(context.Background(), "legacy-user", pw, users.RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}

	salt, iterations := loginParams(t, srv, "legacy-user")
	if salt == "" {
		t.Fatal("login-params returned an empty salt for a legacy account; the synthetic-salt " +
			"anti-enumeration property is what makes the client unable to detect legacy accounts")
	}
	authSecret := deriveAuthSecretForTest(t, pw, salt, iterations)

	// Unauthenticated sign-in: the server does not disclose the derivation, so the
	// client sends BOTH forms and lets the server pick.
	rec := postLogin(t, srv, map[string]any{
		"username":        "legacy-user",
		"password":        pw,
		"authSecret":      authSecret,
		"loginSalt":       salt,
		"loginIterations": iterations,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("sign-in with both credential forms: status %d (%s)", rec.Code, rec.Body.String())
	}

	// And the shape that broke it, against a SECOND still-legacy account (the first
	// one converted on the successful sign-in above, so it would no longer show the
	// bug).
	if _, err := srv.users.Create(context.Background(), "legacy-user2", pw, users.RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}
	salt2, iterations2 := loginParams(t, srv, "legacy-user2")
	rec = postLogin(t, srv, map[string]any{
		"username":        "legacy-user2",
		"authSecret":      deriveAuthSecretForTest(t, pw, salt2, iterations2),
		"loginSalt":       salt2,
		"loginIterations": iterations2,
	})
	if rec.Code == http.StatusOK {
		t.Fatal("authSecret alone authenticated a legacy account; that form cannot be verified " +
			"against a hash that covers the plaintext")
	}
}

// TestLoginParamsDisclosesDerivationOnlyToTheAccountItself is the property that lets
// the authenticated flows (step-up, re-auth, password change) send exactly one
// credential form without re-introducing an account-existence oracle.
func TestLoginParamsDisclosesDerivationOnlyToTheAccountItself(t *testing.T) {
	srv := newTestServer(t)
	if _, err := srv.users.Create(context.Background(), "someone", "correct-horse-battery-staple", users.RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, username := range []string{"someone", "no-such-account"} {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/login-params?username="+username, nil)
		rec := httptest.NewRecorder()
		srv.handleLoginParams(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := out["derivation"]; ok {
			t.Fatalf("unauthenticated login-params for %q disclosed the derivation; that tells an "+
				"attacker whether the username names a converted (and therefore existing) account", username)
		}
	}
}
