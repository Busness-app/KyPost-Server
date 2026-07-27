package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kypost-server/backend/internal/users"
)

// run-4 finding H5: the two JSON rule write paths call rules.ValidateMatchShape,
// but the Sieve editor's PUT did not — so a sub-1MiB script could store a match
// tree three orders of magnitude past the 300-condition cap. Each :regex leaf is
// recompiled per message inside the poller's uninterruptible evaluation, and the
// poller holds a size-1 semaphore across every user, so one such rule stops mail
// processing for the whole instance.
func TestSieveEditorEnforcesMatchShapeCap(t *testing.T) {
	srv := newTestServer(t)

	createBody, _ := json.Marshal(map[string]any{
		"name":    "seed",
		"enabled": true,
		"match": map[string]any{
			"op":         "allof",
			"conditions": []map[string]any{{"field": "from", "comparator": "contains", "value": "x"}},
		},
		"actions": []map[string]any{{"type": "addflag", "value": "X"}},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader(createBody))
	authRequest(srv, createReq)
	createRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("seed rule create status = %d, body=%s", createRec.Code, createRec.Body.String())
	}
	var created rulePayload
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	// One header test whose field list repeats far past the cap. This is well
	// under the 1 MiB body limit the handler already enforces.
	fields := strings.TrimSuffix(strings.Repeat(`"to",`, 5000), ",")
	script := fmt.Sprintf("if header :contains [%s] \"zz\" {\n  addflag \"X\";\n}\n", fields)
	body, _ := json.Marshal(map[string]string{"script": script})

	req := httptest.NewRequest(http.MethodPut, "/api/rules/"+created.ID+"/sieve", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("sieve PUT with 5000 conditions: status = %d, want %d — the Sieve path must apply the same width cap as the JSON paths",
			rec.Code, http.StatusBadRequest)
	}
}

// run-4 finding H9: handleLogin was the only unauthenticated JSON decode in the
// codebase without a byte limit, and it ran before the lockout and captcha
// checks — so an unauthenticated caller controlled the server's allocation.
// A measured 700 MiB body drove RSS to 3.9 GB.
func TestLoginRejectsOversizedBody(t *testing.T) {
	srv := newTestServer(t)

	huge := strings.Repeat("A", 256*1024)
	body, _ := json.Marshal(map[string]string{"username": "someone", "password": huge})

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.50:40000"
	rec := httptest.NewRecorder()
	srv.handleLogin(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized login body: status = %d, want %d — the body must be bounded before it is buffered",
			rec.Code, http.StatusBadRequest)
	}
}

// run-4 finding M4: every admin recovery path calls revokeAllUserCredentials,
// whose doc says it cuts off "every way this account can currently
// authenticate". The user's own password change only revoked sessions, so a
// device secret minted from a stolen session survived the victim's only
// self-service remediation — and every device is registered MFAApprover=true,
// so it also kept a standing second factor.
func TestPasswordChangeRevokesPairedDevices(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "attacker-device")
	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); !ok {
		t.Fatal("precondition: paired device should authenticate before the password change")
	}

	body, _ := json.Marshal(map[string]string{
		"oldPassword": "session-tester-testpassword",
		"newPassword": "an-entirely-new-passphrase",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change status = %d, body=%s", rec.Code, rec.Body.String())
	}

	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); ok {
		t.Fatal("paired device still authenticates after the account password was changed; " +
			"a password change must revoke every credential, not just sessions")
	}
}

// run-4 finding M15: isLastActiveAdmin was evaluated outside the store's
// flock-protected mutation, so two concurrent deactivations each saw one other
// active admin and both proceeded. There is no delete-user endpoint and
// LoadOrMigrate only mints an admin when users.json is absent, so zero admins
// means editing the volume by hand.
// Each attempt races two admins deactivating each other. Pre-fix this lands on
// zero admins readily; post-fix the invariant holds on every attempt, so the
// assertion is deterministic once the check moves inside the write lock.
func TestConcurrentDeactivationCannotRemoveLastAdmin(t *testing.T) {
	for attempt := 0; attempt < 25; attempt++ {
		srv := newTestServer(t)

		all, err := srv.users.List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		var adminA users.User
		for _, u := range all {
			if u.Role == users.RoleAdmin && u.Active {
				adminA = u
				break
			}
		}
		if adminA.ID == "" {
			t.Fatal("precondition: expected a seeded active admin")
		}
		adminB, err := srv.users.Create("second-admin", "second-admin-testpassword", users.RoleAdmin)
		if err != nil {
			t.Fatalf("Create second admin: %v", err)
		}

		// A deactivates B and B deactivates A, concurrently: each observes one
		// other active admin and, without the invariant inside the lock, both
		// are permitted.
		targets := []struct{ actor, target string }{
			{adminA.ID, adminB.ID},
			{adminB.ID, adminA.ID},
		}
		var wg sync.WaitGroup
		for _, pair := range targets {
			wg.Add(1)
			go func(actor, target string) {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodPost, "/api/users/"+target+"/deactivate", nil)
				authRequestAs(srv, req, actor)
				srv.routes().ServeHTTP(httptest.NewRecorder(), req)
			}(pair.actor, pair.target)
		}
		wg.Wait()

		after, err := srv.users.List()
		if err != nil {
			t.Fatalf("List after: %v", err)
		}
		remaining := 0
		for _, u := range after {
			if u.Role == users.RoleAdmin && u.Active {
				remaining++
			}
		}
		if remaining == 0 {
			t.Fatalf("attempt %d: concurrent deactivations removed every active admin; the "+
				"last-admin invariant must be evaluated inside the same lock as the write", attempt)
		}
	}
}

// run-4 finding LOW-4: the device lockout is keyed on the attacker-supplied
// device id alone, on routes that need no authentication, so anyone who learns
// a device id can keep it locked out indefinitely. handleLogin deliberately
// keys on username+clientIP for exactly this reason; the reasoning was not
// carried over.
func TestDeviceLockoutScopedToClientIP(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "victim-device")

	for i := 0; i < deviceMaxFailures; i++ {
		req := deviceRequest(deviceID, "wrong-secret")
		req.RemoteAddr = "203.0.113.99:40000"
		srv.deviceAuthFromRequest(req)
	}

	attacker := deviceRequest(deviceID, deviceSecret)
	attacker.RemoteAddr = "203.0.113.99:40000"
	if _, _, ok, _ := srv.deviceAuthFromRequest(attacker); ok {
		t.Fatal("precondition: the abusing IP should be locked out")
	}

	owner := deviceRequest(deviceID, deviceSecret)
	owner.RemoteAddr = "198.51.100.20:40000"
	if _, _, ok, _ := srv.deviceAuthFromRequest(owner); !ok {
		t.Fatal("the real device is locked out from its own IP because another IP burned the " +
			"attempt budget; the lockout must be scoped to (deviceID, clientIP)")
	}
}
