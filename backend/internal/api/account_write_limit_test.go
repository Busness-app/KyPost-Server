package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestMutatingRoutesAreMeteredPerAccount is run-8 finding F5's general half.
//
// users.Store rewrites users.json WHOLE — marshal plus two fsyncs — under a
// process mutex and a cross-process file lock, on every account mutation, and
// every authenticated request reads that same file through currentUser. One
// session looping POST /api/mfa/totp/setup drove 335 rewrites/s on real disk
// and took a DIFFERENT user's Get() from 1.58M/s to 6,770/s at 1 KiB and to
// 11/s at 4 MiB.
//
// Eliding no-op writes is the cheaper fix and is applied where it can be. It
// cannot apply to TOTP setup, which mints a fresh secret per call and so
// genuinely changes the file every time — hence a meter at the wrapper, where
// the next such route inherits it.
func TestMutatingRoutesAreMeteredPerAccount(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.withAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Freeze the bucket's clock. The burst is 90 and it refills at 10/s, so
	// spending it takes ~100 ms of headroom — which a -race build on a loaded
	// CI runner does not have. Without this the 91st request sometimes finds a
	// token that refilled while the loop was still running, and the test fails
	// on the machine rather than on the code. Same idiom as
	// TestBucketDebtIsFloored.
	frozen := time.Now()
	srv.accountWriteLimiter.now = func() time.Time { return frozen }

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec.Code
	}

	// The burst is spent without complaint: real sessions do write in bursts.
	for i := 0; i < accountWriteBurst; i++ {
		if code := post(); code != http.StatusNoContent {
			t.Fatalf("request %d within the burst got %d, want 204", i+1, code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
	authRequest(srv, req)
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("past the burst: got %d, want 429 — a session can drive whole-file "+
			"users.json rewrites without bound", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on the 429")
	}

	// Reading is not metered. The cost this bounds is the WRITE, and throttling
	// an inbox poll would be a regression dressed as a fix.
	for i := 0; i < accountWriteBurst+10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/pgp/identity", nil)
		authRequest(srv, req)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("GET %d was throttled (%d); reads must not be metered", i+1, rec.Code)
		}
	}
}

// A second account must be unaffected by the first one's spending: the meter is
// keyed on the acting user, so it bounds a runaway session rather than becoming
// a way for one account to deny service to another.
func TestAccountWriteMeterIsPerAccount(t *testing.T) {
	srv := newTestServer(t)
	handler := srv.withAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	other, err := srv.users.Create(context.Background(), "second-account", "pw-second-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < accountWriteBurst+5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
		authRequest(srv, req)
		handler(httptest.NewRecorder(), req)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/mfa/totp/setup", nil)
	authRequestAs(srv, req, other.ID)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("a second account got %d after the first exhausted its budget", rec.Code)
	}
}
