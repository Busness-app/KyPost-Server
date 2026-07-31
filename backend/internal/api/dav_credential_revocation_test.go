package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// Clearing the map is only half of revocation. A request that read the
// credential file just before revokeAllUserCredentials deleted it is still
// verifying scrypt when the clear lands, and its put arrives afterwards — which
// re-admitted a credential that no longer exists for a full davCredentialTTL.
// The generation snapshot taken before the read is what makes that put a no-op.
func TestDAVCredentialPutIsDroppedWhenRevocationRacesIt(t *testing.T) {
	cache := newDAVCredentialCache()

	// The in-flight verifier snapshots the generation, then reads/verifies.
	gen := cache.currentGeneration()

	// Revocation happens while that verification is in flight.
	cache.invalidateUser("dav-user")

	// The verifier now finishes and tries to cache what it verified.
	cache.put(gen, "dav-user", "app-password", AuthContext{UserID: "u1", Username: "dav-user"})

	if _, ok := cache.get("dav-user", "app-password"); ok {
		t.Fatal("a credential verified before revocation was cached after it")
	}
}

// The guard must not cost the cache its purpose: an uncontended verification
// still caches, so a syncing client pays scrypt once rather than per PROPFIND.
func TestDAVCredentialPutSucceedsWithoutRevocation(t *testing.T) {
	cache := newDAVCredentialCache()

	gen := cache.currentGeneration()
	cache.put(gen, "dav-user", "app-password", AuthContext{UserID: "u1", Username: "dav-user"})

	ac, ok := cache.get("dav-user", "app-password")
	if !ok {
		t.Fatal("an uncontended verification was not cached")
	}
	if ac.UserID != "u1" {
		t.Fatalf("cached UserID = %q, want %q", ac.UserID, "u1")
	}
}

// End to end over the middleware: once revokeAllUserCredentials has run, the
// deleted app password must be refused on the very next request, whatever the
// cache holds — the account stays Active through a password reset, so the
// Active re-check on a cache hit does not cover this.
func TestDAVPasswordRefusedImmediatelyAfterRevocation(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("dav-revoke", "dav-user-password-long", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A verification that is in flight across the revocation below.
	inFlightGen := srv.davCredentials.currentGeneration()
	srv.davCredentials.put(inFlightGen, u.Username, "app-password",
		AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role})

	// An admin resets the password: the account stays active, the CardDAV
	// credential is deleted, and the cache is invalidated.
	srv.revokeAllUserCredentials(u)

	// The in-flight verifier finishes and lands its put after the revocation.
	srv.davCredentials.put(inFlightGen, u.Username, "app-password",
		AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role})

	reached := false
	handler := srv.withDAVBasicAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest("PROPFIND", davPrefix+"/dav-revoke/", nil)
	req.SetBasicAuth(u.Username, "app-password")
	req.RemoteAddr = "203.0.113.9:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if reached {
		t.Fatal("a revoked CardDAV credential reached the handler through the cache")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}
