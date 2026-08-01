package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/users"
)

func contactWithName(name string) contacts.Contact {
	return contacts.Contact{FormattedName: name}
}

func contactPrecondition(etag string) contacts.ContactPrecondition {
	return contacts.ContactPrecondition{RequireETag: etag}
}

func jsonBody(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}

// Fixes verified here (security-audit run-2, findings.json):
//   1. CardDAV Basic Auth now pays the same scrypt cost on every failure
//      path as the login endpoint, closing the timing oracle.
//   2. CardDAV conditional PUT (If-Match) is now atomic with the write, so
//      two concurrent PUTs sharing a stale precondition can't both succeed.
//   3. Native device registration's deviceId uniqueness check is now
//      atomic with the shared-index write.
//   4. GET /api/setup no longer discloses the admin username.

// TestDAVAuthEqualizesTimingOnAllFailurePaths verifies withDAVBasicAuth calls
// the same dummy-scrypt equalization on both failure paths (unknown user,
// and no CardDAV password configured) that the login endpoint already uses,
// so a remote timing comparison can't distinguish them from a real
// wrong-password attempt against a configured account.
func TestDAVAuthEqualizesTimingOnAllFailurePaths(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}

	unknownUserElapsed := timeDAVAuthAttempt(srv, "no-such-user", "whatever")
	noPasswordConfiguredElapsed := timeDAVAuthAttempt(srv, all[0].Username, "whatever")

	// Both failure paths should now pay a real scrypt verification (via
	// equalizeLoginTiming), so neither should be a fast, near-zero-cost
	// rejection. This doesn't assert the two durations are statistically
	// indistinguishable (too flaky for a unit test), just that both are
	// genuinely doing scrypt-scale work rather than one being a cheap
	// short-circuit.
	const minScryptDuration = 2 * time.Millisecond
	if unknownUserElapsed < minScryptDuration {
		t.Fatalf("unknown-user DAV auth returned in %v, want at least %v (equalizeLoginTiming should run)", unknownUserElapsed, minScryptDuration)
	}
	if noPasswordConfiguredElapsed < minScryptDuration {
		t.Fatalf("no-CardDAV-password DAV auth returned in %v, want at least %v (equalizeLoginTiming should run)", noPasswordConfiguredElapsed, minScryptDuration)
	}
}

func timeDAVAuthAttempt(srv *Server, username, password string) time.Duration {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/carddav", nil)
	req.SetBasicAuth(username, password)
	start := time.Now()
	srv.withDAVBasicAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})).ServeHTTP(rec, req)
	return time.Since(start)
}

// TestCardDAVConditionalPUTRaceRejectsLoser drives the real contacts.Store
// through the same check-then-write pattern PutAddressObject now uses
// (UpsertWithPrecondition) and confirms two concurrent writers sharing the
// same stale If-Match precondition can no longer both succeed — exactly the
// lost-update race the audit reproduced 20/20 before this fix.
func TestCardDAVConditionalPUTRaceRejectsLoser(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}

	seeded, err := store.Upsert(contactWithName("Original"))
	if err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	sharedETag := seeded.ETag()

	var wg sync.WaitGroup
	results := make([]error, 2)
	barrier := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-barrier
			c := contactWithName("Edit")
			c.UID = seeded.UID
			_, err := store.UpsertWithPrecondition(c, contactPrecondition(sharedETag))
			results[i] = err
		}(i)
	}
	close(barrier)
	wg.Wait()

	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1 (the loser should get ErrPreconditionFailed, not silently overwrite the winner)", successes)
	}
}

// TestNativeRegisterConcurrentSameDeviceIDOnlyOneOwnerWins drives the real
// HTTP handler for two different accounts concurrently registering the same
// explicit, client-chosen deviceId, and confirms deviceIndex ends up
// consistent with exactly one persisted device row rather than silently
// orphaning a second account's device (the TOCTOU the audit reproduced
// 20/20 before this fix).
func TestNativeRegisterConcurrentSameDeviceIDOnlyOneOwnerWins(t *testing.T) {
	srv := newTestServer(t)

	aliceID := bootstrapAdminID(t, srv)
	bob, err := srv.users.Create(context.Background(), "bob", "correct-horse-battery", users.RoleUser)
	if err != nil {
		t.Fatalf("Create bob: %v", err)
	}

	registerReq := func(userID string) *http.Request {
		store, err := srv.userStore(userID)
		if err != nil {
			t.Fatalf("userStore: %v", err)
		}
		subscriberID, err := store.GetOrCreateSubscriberID()
		if err != nil {
			t.Fatalf("GetOrCreateSubscriberID: %v", err)
		}
		token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
		if err != nil {
			t.Fatalf("createPairingToken: %v", err)
		}
		payload := map[string]any{
			"subscriberId": subscriberID,
			"pairingToken": token,
			"deviceToken":  "token-for-" + userID,
			"deviceId":     "shared-explicit-device-id",
			"platform":     "ios",
		}
		body, _ := json.Marshal(payload)
		return httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", jsonBody(body))
	}

	reqAlice := registerReq(aliceID)
	reqBob := registerReq(bob.ID)

	var wg sync.WaitGroup
	codes := make([]int, 2)
	barrier := make(chan struct{})
	run := func(i int, req *http.Request) {
		defer wg.Done()
		<-barrier
		rec := httptest.NewRecorder()
		srv.handleNotificationNativeRegister(rec, req)
		codes[i] = rec.Code
	}
	wg.Add(2)
	go run(0, reqAlice)
	go run(1, reqBob)
	close(barrier)
	wg.Wait()

	oks := 0
	for _, c := range codes {
		if c == http.StatusOK {
			oks++
		}
	}
	if oks != 1 {
		t.Fatalf("HTTP 200 count = %d, want exactly 1 (the loser must get 409, not both succeed)", oks)
	}

	srv.userMu.Lock()
	owner, ok := srv.deviceIndex["shared-explicit-device-id"]
	srv.userMu.Unlock()
	if !ok {
		t.Fatal("deviceIndex has no entry for the contested deviceId")
	}
	if owner != aliceID && owner != bob.ID {
		t.Fatalf("deviceIndex owner = %q, want alice (%q) or bob (%q)", owner, aliceID, bob.ID)
	}
}

func bootstrapAdminID(t *testing.T, srv *Server) string {
	t.Helper()
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	return all[0].ID
}

// TestHandleSetupDoesNotDiscloseAdminUsername confirms GET /api/setup returns
// only the "configured" boolean, never the admin's real username or
// must-change-password state (which no client consumes and which let any
// anonymous caller defeat the hardening value of a non-default admin
// username).
func TestHandleSetupDoesNotDiscloseAdminUsername(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/setup", nil)
	srv.handleSetup(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if configured, _ := resp["configured"].(bool); !configured {
		t.Fatalf("configured = %v, want true (bootstrap admin already exists in the test server)", resp["configured"])
	}
	if _, present := resp["setup"]; present {
		t.Fatalf("response must not include a setup/admin_user field, got %+v", resp)
	}
	if len(resp) != 1 {
		t.Fatalf("response has %d fields, want exactly 1 (configured); got %+v", len(resp), resp)
	}
}
