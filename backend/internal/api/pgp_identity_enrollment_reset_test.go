package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/pgpmail"
)

// configureMailFor satisfies the generate handler's precondition that the
// account has a mail address to bind the generated key's User ID to.
func configureMailFor(t *testing.T, srv *Server, userID string) {
	t.Helper()
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
}

// Writing or clearing the PGP identity must reset every device's enrollment
// state, for the same reason users.Store clears PGPWrappedEnvelopes on those
// same writes: every non-password slot seals the OLD key.
//
// Three identity writers clear envelopes, so there are three call sites and
// three tests. They are written out rather than folded into one table because
// the failure being guarded against is a fourth writer arriving and only some
// call sites being updated — the reset is enforced nowhere but the call sites,
// exactly like the envelope clear it mirrors.

// enrollDeviceFor pairs a device to userID and marks it fully enrolled.
func enrollDeviceFor(t *testing.T, srv *Server, userID, deviceID string) {
	t.Helper()
	pairNativeDevice(t, srv, userID, deviceID)
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if _, err := store.SetNativeDeviceEnrollmentKey(deviceID, "PUBKEY", "2026-08-05T00:00:00Z"); err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if err := store.SetNativeDeviceEncryptionEnrolled(deviceID, true); err != nil {
		t.Fatalf("SetNativeDeviceEncryptionEnrolled: %v", err)
	}
}

func assertEnrollmentCleared(t *testing.T, srv *Server, userID, deviceID string) {
	t.Helper()
	d := deviceByID(t, srv, userID, deviceID)
	if d.EncryptionEnrolled {
		t.Fatalf("device still reports enrolled after the identity changed: %+v", d)
	}
	if d.EnrollmentPublicKey != "" || d.EnrollmentKeyAt != "" {
		t.Fatalf("a key published for the superseded identity survived: %+v", d)
	}
}

// Call site 1: storePGPIdentity, reached by generate and import.
func TestGeneratingAnIdentityClearsDeviceEnrollment(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	configureMailFor(t, srv, userID)
	enrollDeviceFor(t, srv, userID, "dev-1")

	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/generate",
		map[string]string{"password": password}, srv.handlePGPIdentityGenerate)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: status %d; body=%s", rec.Code, rec.Body.String())
	}

	assertEnrollmentCleared(t, srv, userID, "dev-1")
}

// Call site 2: handlePGPIdentityClient. This is the one that matters most —
// device enrollment exists only for client-protected accounts.
func TestStoringAClientProtectedIdentityClearsDeviceEnrollment(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	enrollDeviceFor(t, srv, userID, "dev-1")

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

	assertEnrollmentCleared(t, srv, userID, "dev-1")
}

// Call site 3: DELETE /api/pgp/identity.
func TestClearingTheIdentityClearsDeviceEnrollment(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	giveUserAnIdentity(t, srv, userID)
	// Enroll after the identity exists, so the DELETE is what this observes.
	enrollDeviceFor(t, srv, userID, "dev-1")

	rec := pgpRequest(t, srv, http.MethodDelete, "/api/pgp/identity",
		map[string]string{"password": password}, srv.handlePGPIdentity)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete identity: status %d; body=%s", rec.Code, rec.Body.String())
	}

	assertEnrollmentCleared(t, srv, userID, "dev-1")
}

// The reset must not take the pairing with it. A user who rotates their key
// still expects push and sync to work on every paired device afterwards.
func TestIdentityChangeKeepsDevicesPaired(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	password := stepUpPassword(t, srv, userID)
	configureMailFor(t, srv, userID)
	enrollDeviceFor(t, srv, userID, "dev-1")

	rec := pgpRequest(t, srv, http.MethodPost, "/api/pgp/identity/generate",
		map[string]string{"password": password}, srv.handlePGPIdentityGenerate)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: status %d; body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("the identity change unpaired a device: %+v", devices)
	}
	if devices[0].PushToken == "" {
		t.Fatalf("the identity change damaged the pairing: %+v", devices[0])
	}
	if !devices[0].MFAApprover {
		t.Fatal("the identity change cleared the push-MFA approver flag, which it does not govern")
	}
}
