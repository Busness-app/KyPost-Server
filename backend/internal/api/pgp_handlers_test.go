package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// TestPGPIdentityGenerateCarriesVerifiedSendAsAliases covers generating a
// key AFTER aliases already exist: the account address plus every verified
// send-as alias must land on the key as User IDs, or the key can never be
// served over WKD (or advertised via Autocrypt) for those aliases. A still-
// pending alias is not the user's proven address yet, so it must be left
// off.
func TestPGPIdentityGenerateCarriesVerifiedSendAsAliases(t *testing.T) {
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

	genReq := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/generate", nil)
	authRequest(srv, genReq)
	genRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityGenerate)(genRec, genReq)
	if genRec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200, got %d: %s", genRec.Code, genRec.Body.String())
	}
	var genResp pgpIdentityResponse
	if err := json.NewDecoder(genRec.Body).Decode(&genResp); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}

	got := keyUserIDEmails(t, genResp.PublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("generated key user IDs: got %v want %v", got, want)
	}
}

func TestPGPIdentityGenerateThenGetThenDelete(t *testing.T) {
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, _ := srv.users.List()
	userID := all[0].ID
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}

	genReq := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/generate", nil)
	authRequest(srv, genReq)
	genRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityGenerate)(genRec, genReq)
	if genRec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200, got %d: %s", genRec.Code, genRec.Body.String())
	}
	var genResp pgpIdentityResponse
	if err := json.NewDecoder(genRec.Body).Decode(&genResp); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}
	if genResp.Fingerprint == "" || genResp.PublicKey == "" || genResp.Source != "generated" {
		t.Fatalf("unexpected generate response: %+v", genResp)
	}
	if genResp.Revoked || genResp.Expired {
		t.Fatalf("expected a freshly generated identity to be neither revoked nor expired, got %+v", genResp)
	}
	pubKey, err := crypto.NewKeyFromArmored(genResp.PublicKey)
	if err != nil {
		t.Fatalf("parse generated public key: %v", err)
	}
	foundMailIdentity := false
	for _, identity := range pubKey.GetEntity().Identities {
		if identity.UserId.Email == "alice@example.com" {
			foundMailIdentity = true
		}
	}
	if !foundMailIdentity {
		t.Fatalf("expected generated key's UID email to be the configured mail address, got identities: %+v", pubKey.GetEntity().Identities)
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
	if getResp.Fingerprint != genResp.Fingerprint {
		t.Fatalf("fingerprint mismatch: got %s want %s", getResp.Fingerprint, genResp.Fingerprint)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/identity", nil)
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

func TestPGPIdentityImportWithPassphrase(t *testing.T) {
	srv := newTestServer(t)

	keyGen := crypto.PGP().KeyGeneration().AddUserId("Import Test", "import-test@example.com").New()
	key, err := keyGen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	locked, err := crypto.PGP().LockKey(key, []byte("s3cret"))
	if err != nil {
		t.Fatalf("LockKey: %v", err)
	}
	armoredLocked, err := locked.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"armoredPrivateKey": armoredLocked,
		"passphrase":        "s3cret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/import", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityImport)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp pgpIdentityResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.Fingerprint != key.GetFingerprint() || resp.Source != "imported" {
		t.Fatalf("unexpected import response: %+v", resp)
	}

	badBody, _ := json.Marshal(map[string]string{
		"armoredPrivateKey": armoredLocked,
		"passphrase":        "wrong",
	})
	badReq := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/import", bytes.NewReader(badBody))
	authRequest(srv, badReq)
	badRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityImport)(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong passphrase, got %d", badRec.Code)
	}
}

func TestPGPIdentityImportRevokedKeyReportsRevoked(t *testing.T) {
	srv := newTestServer(t)

	key, err := crypto.PGP().KeyGeneration().AddUserId("Revoked", "revoked@example.com").New().GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := key.GetEntity().Revoke(packet.NoReason, "test revocation", &packet.Config{}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	armored, err := key.Armor()
	if err != nil {
		t.Fatalf("Armor: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"armoredPrivateKey": armored})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/import", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityImport)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var importResp pgpIdentityResponse
	if err := json.NewDecoder(rec.Body).Decode(&importResp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if !importResp.Revoked {
		t.Fatalf("expected revoked=true on import response, got %+v", importResp)
	}

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
