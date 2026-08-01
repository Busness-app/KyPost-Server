package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
)

// run-4 hardening notes 2, 3, 4 and 11.

// ---- note 11: unregistered /api/* falls through to the SPA ------------------

// A client calling an endpoint that does not exist got 200 and a page of HTML,
// because the "/" catch-all serves index.html for anything the mux did not
// match. Every API client then has to guess whether it received data or the
// app shell, and a typo in a path looks like success.
func TestUnknownAPIPathReturns404JSON(t *testing.T) {
	srv := newTestServer(t)

	for _, path := range []string{"/api/does-not-exist", "/api/mail/nope", "/api/"} {
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404; body=%s", path, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "<html") || strings.Contains(rec.Body.String(), "<!doctype") {
			t.Fatalf("%s: served the SPA shell instead of an API error: %s", path, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("%s: Content-Type = %q, want JSON", path, ct)
		}
	}
}

// Non-API paths must still reach the SPA, or deep links stop working.
func TestNonAPIPathsStillReachTheFrontend(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/read", nil))

	// No frontend is built in the test environment, so the handler's own
	// "assets not found" 404 is the tell that it got there — what matters is
	// that it is NOT the API JSON refusal.
	if strings.Contains(rec.Body.String(), "unknown api endpoint") {
		t.Fatalf("/read was treated as an API path: %s", rec.Body.String())
	}
}

// ---- note 3: DELETE evicts another user's device-index entry ----------------

// The index eviction ran unconditionally, even when the removal reported that
// the device was not this user's. One user could therefore DELETE with another
// user's deviceId and evict their mapping. It self-heals on the next rescan,
// but it should never happen.
func TestDeleteDeviceDoesNotEvictAnotherUsersIndexEntry(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no bootstrap user: %v", err)
	}
	owner := all[0]
	attacker, err := srv.users.Create(context.Background(), "evictor", "evictor-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ownerStore, err := srv.userStore(owner.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if err := ownerStore.UpsertNativeDevice(state.NativeDevice{DeviceID: "victim-device", Platform: "android"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex["victim-device"] = owner.ID
	srv.userMu.Unlock()

	body, _ := json.Marshal(map[string]string{"deviceId": "victim-device"})
	req := httptest.NewRequest(http.MethodDelete, "/api/notifications/native/devices", bytes.NewReader(body))
	authRequestAs(srv, req, attacker.ID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleNotificationNativeDevices)(rec, req)

	srv.userMu.Lock()
	stillMapped := srv.deviceIndex["victim-device"]
	srv.userMu.Unlock()
	if stillMapped != owner.ID {
		t.Fatalf("another user's DELETE evicted the index entry (now %q, want %q)", stillMapped, owner.ID)
	}
}

// The owner deleting their own device must still evict it, or a stale mapping
// keeps the ID reserved.
func TestDeleteDeviceEvictsTheOwnersOwnIndexEntry(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	owner := all[0]

	ownerStore, err := srv.userStore(owner.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if err := ownerStore.UpsertNativeDevice(state.NativeDevice{DeviceID: "my-device", Platform: "android"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	srv.userMu.Lock()
	srv.deviceIndex["my-device"] = owner.ID
	srv.userMu.Unlock()

	body, _ := json.Marshal(map[string]string{"deviceId": "my-device"})
	req := httptest.NewRequest(http.MethodDelete, "/api/notifications/native/devices", bytes.NewReader(body))
	authRequestAs(srv, req, owner.ID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleNotificationNativeDevices)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	srv.userMu.Lock()
	_, present := srv.deviceIndex["my-device"]
	srv.userMu.Unlock()
	if present {
		t.Fatal("the owner's own delete left the index entry behind")
	}
}

// ---- note 2: desktop pairing leaks the code and never rate-limits -----------

// The pairing code is a credential the moment a redeem handler exists. It was
// persisted verbatim in state.json by RecordDesktopPairingAttempt, and its
// first 32 bits were logged under the label "code_hash" — which it was not.
func TestDesktopPairingDoesNotPersistTheRawCode(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	owner := all[0]

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/notifications/desktop/pair", nil)
	authRequestAs(srv, req, owner.ID)
	srv.withAuth(srv.handleDesktopPair)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		PairingCode string `json:"pairingCode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.PairingCode == "" {
		t.Fatalf("no pairing code issued: %s", rec.Body.String())
	}

	store, err := srv.userStore(owner.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	for _, attempt := range store.ListDesktopPairingAttempts() {
		if strings.Contains(attempt.Code, resp.PairingCode) {
			t.Fatal("the raw pairing code was persisted in the attempt log")
		}
	}
}

// The limiter counted only failed attempts, and the sole caller records a
// success, so failedCount was always zero and the cap never applied. What is
// worth limiting here is issuance.
func TestDesktopPairingLimitsIssuance(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	owner := all[0]

	issue := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/notifications/desktop/pair", nil)
		authRequestAs(srv, req, owner.ID)
		srv.withAuth(srv.handleDesktopPair)(rec, req)
		return rec.Code
	}

	issued := 0
	for i := 0; i < 40; i++ {
		if issue() == http.StatusOK {
			issued++
		}
	}
	if issued > state.MaxDesktopPairingCodesPerHour {
		t.Fatalf("issued %d codes against a cap of %d", issued, state.MaxDesktopPairingCodesPerHour)
	}
	if issued == 0 {
		t.Fatal("issued nothing at all")
	}
}

// ---- note 4: the QR key token is replayable and over-discloses -------------

// The endpoint exists to hand over a PUBLIC KEY. It also returned the owner's
// whole self-contact card — phone numbers, postal addresses, birthday, notes —
// to anyone holding a 2-minute unauthenticated URL.
func TestQRKeyResponseOmitsTheSensitiveContactFields(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	owner := all[0]

	store, err := srv.userContactsStore(owner.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	self, err := store.Upsert(contacts.Contact{
		FormattedName: "Alice Example",
		Org:           "Example Ltd",
		Emails:        []contacts.ContactValue{{Value: "alice@example.com"}},
		Phones:        []contacts.ContactValue{{Value: "+1-555-0100"}},
		Addresses:     []contacts.ContactAddress{{Street: "1 Secret Lane", City: "Springfield"}},
		Notes:         "home alone on Tuesdays",
		Birthday:      "1990-04-01",
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, _, err := store.SetSelf(self.UID, true); err != nil {
		t.Fatalf("SetSelf: %v", err)
	}

	body := qrKeyBody(t, srv, owner.ID)
	for _, secret := range []string{"555-0100", "Secret Lane", "Springfield", "home alone", "1990-04-01"} {
		if strings.Contains(body, secret) {
			t.Fatalf("QR key response disclosed %q:\n%s", secret, body)
		}
	}
	// What a key exchange legitimately needs must survive.
	for _, wanted := range []string{"Alice Example", "alice@example.com"} {
		if !strings.Contains(body, wanted) {
			t.Fatalf("QR key response dropped %q, which the scanning device needs:\n%s", wanted, body)
		}
	}
}

// A 2-minute window is not a substitute for single use: anyone who observes
// the URL inside it can replay it.
func TestQRKeyTokenIsSingleUse(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	owner := all[0]
	seedQRIdentity(t, srv, owner.ID)

	token := mintQRToken(t, srv, owner.ID)

	first := fetchQRKey(srv, token)
	if first.Code != http.StatusOK {
		t.Fatalf("first fetch: status = %d; body=%s", first.Code, first.Body.String())
	}
	second := fetchQRKey(srv, token)
	if second.Code == http.StatusOK {
		t.Fatalf("the token was replayable; second fetch returned 200:\n%s", second.Body.String())
	}
}

func seedQRIdentity(t *testing.T, srv *Server, userID string) {
	t.Helper()
	if _, err := srv.users.SetPGPIdentity(userID, "FPRQR", "KIDQR",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\npub\n-----END PGP PUBLIC KEY BLOCK-----",
		"sealed", "generated", "2026-07-28T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
}

func mintQRToken(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/qr/token", nil)
	authRequestAs(srv, req, userID)
	srv.withAuth(srv.handlePGPQRToken)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint token: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return resp.Token
}

func fetchQRKey(srv *Server, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.handlePGPQRKey(rec, httptest.NewRequest(http.MethodGet, "/api/pgp/qr/key?t="+token, nil))
	return rec
}

func qrKeyBody(t *testing.T, srv *Server, userID string) string {
	t.Helper()
	seedQRIdentity(t, srv, userID)
	rec := fetchQRKey(srv, mintQRToken(t, srv, userID))
	if rec.Code != http.StatusOK {
		t.Fatalf("qr key: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
