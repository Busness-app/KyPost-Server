package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
		// "keyword", not the Sieve verb "addflag": this is the JSON action
		// vocabulary (see rules.Action), and rules.ValidateRule now rejects a
		// type the engine cannot execute rather than storing it to fail on
		// every matching message.
		"actions": []map[string]any{{"type": "keyword", "value": "X"}},
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
		adminB, err := srv.users.Create(context.Background(), "second-admin", "second-admin-testpassword", users.RoleAdmin)
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

// run-4 finding H9 (second half): the http.Server was constructed with no
// timeouts at all, so a header-drip connection is held indefinitely. Go's zero
// values mean "no limit", which net/http's own docs warn about, and the
// shipped compose file publishes the port directly with no reverse proxy in
// front to absorb it.
func TestHTTPServerHasTimeouts(t *testing.T) {
	srv := newTestServer(t)
	srv.Prepare()
	if srv.httpServer.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is unset: a slow-header connection can be held open forever")
	}
	if srv.httpServer.ReadTimeout <= 0 {
		t.Error("ReadTimeout is unset")
	}
	if srv.httpServer.IdleTimeout <= 0 {
		t.Error("IdleTimeout is unset")
	}
}

// run-4 finding LOW-3: contactPayload documents PhotoRef as read-only but
// copies it straight into the stored record, and it is the value
// userContactPhotoPath joins onto the photo directory. filepath.Base blocks
// traversal, but ".." survives it and resolves to the user's own state
// directory, which http.ServeFile will then render. The containment is
// accidental; the field should not be client-settable at all.
func TestContactPhotoRefIsNotClientSettable(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	body, _ := json.Marshal(map[string]any{
		"fn":       "Mallory",
		"photoRef": "..",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/contacts", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create contact status = %d, body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	for _, c := range store.List() {
		if c.PhotoRef != "" {
			t.Fatalf("client-supplied photoRef %q was stored; the server owns this field", c.PhotoRef)
		}
	}
}

// run-4 finding H1: handleMailSendPGP called resolveMailFrom — the function
// that enforces "this From is a verified send-as alias" — and discarded its
// headerFrom return, keeping only envelopeFrom. The delivery bytes are relayed
// verbatim, so the From the recipient sees was entirely caller-chosen, and the
// only gate checked that a few header names appeared as substrings and that
// the armor marker appeared *anywhere* (an HTML comment satisfies it). On a
// shared organizational smarthost the result is DKIM-aligned spoofing, and a
// paired device — explicitly denied send-as management — could do it.
func TestPGPDeliveryFromMustMatchAuthorizedSender(t *testing.T) {
	authorized := "alice@example.com"

	spoofed := "From: CEO <ceo@example.com>\r\n" +
		"To: victim@example.com\r\n" +
		"Reply-To: attacker@evil.test\r\n" +
		"Subject: Wire transfer approval\r\n" +
		"Date: Sat, 26 Jul 2026 10:00:00 +0000\r\n" +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=b\r\n" +
		"\r\n" +
		"-----BEGIN PGP MESSAGE-----\r\nx\r\n-----END PGP MESSAGE-----\r\n"
	if err := validatePGPMimeDelivery(spoofed, authorized); err == nil {
		t.Error("a delivery whose From is not the authorized sender was accepted; " +
			"the relayed headers must be bound to what resolveMailFrom authorized")
	}

	cleartext := "From: " + authorized + "\r\n" +
		"To: victim@example.com\r\n" +
		"Subject: hello\r\n" +
		"Date: Sat, 26 Jul 2026 10:00:00 +0000\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		"<html><body>plain text<!-- -----BEGIN PGP MESSAGE----- --></body></html>\r\n"
	if err := validatePGPMimeDelivery(cleartext, authorized); err == nil {
		t.Error("a cleartext text/html body with the armor marker hidden in a comment was " +
			"accepted; the endpoint must require a real RFC 3156 encrypted part")
	}

	good := "From: " + authorized + "\r\n" +
		"To: victim@example.com\r\n" +
		"Subject: hello\r\n" +
		"Date: Sat, 26 Jul 2026 10:00:00 +0000\r\n" +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=b\r\n" +
		"\r\n" +
		"-----BEGIN PGP MESSAGE-----\r\nx\r\n-----END PGP MESSAGE-----\r\n"
	if err := validatePGPMimeDelivery(good, authorized); err != nil {
		t.Errorf("a well-formed delivery from the authorized sender was rejected: %v", err)
	}

	dupFrom := "From: " + authorized + "\r\n" + good
	if err := validatePGPMimeDelivery(dupFrom, authorized); err == nil {
		t.Error("a delivery carrying two From headers was accepted; which one the receiving " +
			"MTA honors is not ours to guess")
	}
}

// run-4 finding H4: identity/client and identity/rewrap are withMailAuth, so a
// device secret reached them — and they replace the account's public key or
// clear PGPPrivateKeyEnc outright. server.go's own routing comment says a
// device secret "is not that password" and must not be exchangeable for the
// key; the endpoint that *reads* a key is gated on a re-verified password
// while the two that destroy one were not.
func TestDeviceCannotReplaceOrDestroyPGPIdentity(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "attacker-device")

	rewrap, _ := json.Marshal(map[string]string{"wrapped": "GARBAGE-NOT-AN-ENVELOPE"})
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/rewrap", bytes.NewReader(rewrap))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("a paired device rewrapped (and thereby destroyed) the account's private key")
	}

	client, _ := json.Marshal(map[string]string{"publicKey": "not-a-key", "wrapped": "x"})
	req2 := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/client", bytes.NewReader(client))
	setDeviceHeaders(req2, deviceID, deviceSecret)
	rec2 := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Error("a paired device replaced the account's PGP identity")
	}
}

// The envelope-slot endpoints (write/read/delete a non-password sealing of
// the private key) are withAuth like the two routes above, and for the same
// reason: a device secret must not be able to mint a sealing of the account
// key. That is the enforcement point the planned passphrase-only account
// tier depends on — if a paired device could add an envelope slot, that tier
// would be unenforceable. Exercised through the full router (not the bare
// handler) so a route-registration slip (withMailAuth instead of withAuth)
// would be caught here too.
func TestDeviceCannotReachEnvelopeSlotRoutes(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	deviceID, deviceSecret := pairNativeDevice(t, srv, u.ID, "attacker-device")

	put := httptest.NewRequest(http.MethodPut, "/api/pgp/identity/envelope/recovery",
		strings.NewReader(`{"envelope":"x"}`))
	setDeviceHeaders(put, deviceID, deviceSecret)
	putRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(putRec, put)
	if putRec.Code == http.StatusOK {
		t.Error("a paired device wrote a wrapped-envelope slot")
	}

	get := httptest.NewRequest(http.MethodGet, "/api/pgp/identity/envelope/recovery", nil)
	setDeviceHeaders(get, deviceID, deviceSecret)
	getRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(getRec, get)
	if getRec.Code == http.StatusOK {
		t.Error("a paired device read a wrapped-envelope slot")
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/pgp/identity/envelope/recovery", nil)
	setDeviceHeaders(del, deviceID, deviceSecret)
	delRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(delRec, del)
	if delRec.Code == http.StatusOK {
		t.Error("a paired device deleted a wrapped-envelope slot")
	}
}

// run-4 finding H8: the "use my saved config" fallback was evaluated per
// field, so a caller supplying only a host got the victim's stored username
// and password sent to it. GET /api/imap/config deliberately never returns the
// password; this was the one path that handed it out, and it is the same
// credential used for SMTP, surviving every KyPost-side revocation.
func TestIMAPTestRefusesPartialCredentialOverride(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	body, _ := json.Marshal(map[string]any{
		"host":     "mail.attacker.test",
		"port":     993,
		"username": "",
		"password": "",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/imap/test", bytes.NewReader(body))
	authRequestAs(srv, req, u.ID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("host-only override: status = %d, want %d — supplying a destination without "+
			"credentials must not pair the caller's host with the stored password",
			rec.Code, http.StatusBadRequest)
	}
}

// run-4 finding H6: the web-push subscription endpoint accepted any endpoint
// string with only a non-empty check — no scheme check, no netguard screening
// — while the sibling UnifiedPush path validates all of that. The stored
// endpoint is then POSTed to by the poller, so an authenticated user could
// aim the server at internal addresses (with POST /api/notifications/test as
// a three-state oracle) and, because webpush-go defaults to a zero-timeout
// client with context.Background(), a tarpit endpoint blocked the poll tick
// forever — halting mail processing for every user on the instance.
func TestWebPushSubscriptionEndpointIsScreened(t *testing.T) {
	srv, u := newTestServerWithUser(t)

	for _, endpoint := range []string{
		"http://169.254.169.254/latest/meta-data",
		"http://127.0.0.1:11434/api/pull",
		"http://10.0.0.5/internal",
		"ftp://example.com/x",
	} {
		body, _ := json.Marshal(map[string]any{
			"endpoint": endpoint,
			"keys":     map[string]string{"p256dh": "BParkedPublicKeyValue", "auth": "c2VjcmV0MTIzNDU2Nzg"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/subscriptions", bytes.NewReader(body))
		authRequestAs(srv, req, u.ID)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("endpoint %q: status = %d, want %d — a push endpoint must be screened the "+
				"same way the UnifiedPush endpoint already is", endpoint, rec.Code, http.StatusBadRequest)
		}
	}
}

// run-4 finding H2: POST /api/imap/config stores payload.Username after only a
// non-empty check — no connection, no challenge — and publishableAddressesAt,
// whose own comment calls it "the anti-impersonation gate at serve time", then
// treats that self-declared string as a proven address alongside genuinely
// verified send-as aliases. On an instance whose admin has DNS-verified the
// organization's domain, any ordinary user could therefore have their public
// key served over WKD as any colleague's address — silent key substitution for
// every correspondent who uses WKD discovery.
func TestUnverifiedIMAPAddressIsNotPublishable(t *testing.T) {
	srv, u := newTestServerWithUser(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")

	// Stored exactly as the handler stores it: no connection is attempted and
	// no ownership challenge is issued, so this string is entirely
	// self-declared.
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(u.ID), srv.imapConfigKeyPath, imapConfigPayload{
		Host:     "imap.attacker.test",
		Port:     993,
		Username: "ceo@example.com",
		Password: "anything",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}

	full, err := srv.users.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := srv.publishableAddressesAt(full, "example.com"); len(got) != 0 {
		t.Fatalf("publishableAddressesAt returned %v for a merely self-declared IMAP username; "+
			"an address must be proven before this gate honors it", got)
	}
}
