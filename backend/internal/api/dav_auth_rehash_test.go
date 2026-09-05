package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestDAVAppPasswordRehashesOnSuccessfulVerify plants a legacy scrypt hash in
// the CardDAV app-password file, exactly as an account created before the
// Argon2id migration still has on disk, and proves a successful Basic Auth
// verify upgrades it in place: the account's next sync attempt should not pay
// scrypt forever just because this file's format predates the switch.
//
// No t.Parallel(): this package writes users.hashCostN/hashParams from
// TestMain and withProductionHashCost, both unsynchronized package variables —
// see TestNoTestInThisPackageCallsParallel.
func TestDAVAppPasswordRehashesOnSuccessfulVerify(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dav-rehash", "dav-rehash-user-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	const appPassword = "app-specific-password-1234"
	legacy, err := users.LegacyScryptHashForTest(context.Background(), appPassword)
	if err != nil {
		t.Fatalf("LegacyScryptHashForTest: %v", err)
	}
	if !strings.HasPrefix(legacy, "scrypt$") {
		t.Fatalf("fixture hash = %q, want a scrypt$ prefix", legacy)
	}
	if err := srv.writeDAVPassword(u.ID, davPasswordFile{
		Hash:      legacy,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("writeDAVPassword: %v", err)
	}

	reached := false
	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest("PROPFIND", davPrefix+"/dav-rehash/", nil)
	req.SetBasicAuth(u.Username, appPassword)
	req.RemoteAddr = "203.0.113.10:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("request did not reach the handler; got %d", rec.Code)
	}

	f, exists, err := srv.readDAVPassword(u.ID)
	if err != nil {
		t.Fatalf("readDAVPassword: %v", err)
	}
	if !exists {
		t.Fatal("carddav password file disappeared after a successful verify")
	}
	if !strings.HasPrefix(f.Hash, "$argon2id$") {
		t.Fatalf("stored hash = %q, want it upgraded to $argon2id$ after a successful verify", f.Hash)
	}
	if users.NeedsRehash(f.Hash) {
		t.Error("the upgraded hash still reports as needing a rehash")
	}
	ok, err := users.VerifySecretHash(context.Background(), f.Hash, appPassword)
	if err != nil {
		t.Fatalf("VerifySecretHash: %v", err)
	}
	if !ok {
		t.Fatal("the app password no longer verifies against its upgraded hash")
	}
}
