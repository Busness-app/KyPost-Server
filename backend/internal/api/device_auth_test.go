package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

func TestDeviceCredentialsFromRequest_Headers(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)
	req.Header.Set(headerDeviceID, "device-1")
	req.Header.Set(headerDeviceSecret, "secret-1")

	id, secret := deviceCredentialsFromRequest(req)
	if id != "device-1" {
		t.Fatalf("deviceID = %q, want %q", id, "device-1")
	}
	if secret != "secret-1" {
		t.Fatalf("deviceSecret = %q, want %q", secret, "secret-1")
	}
}

func TestDeviceCredentialsFromRequest_MissingHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)

	id, secret := deviceCredentialsFromRequest(req)
	if id != "" || secret != "" {
		t.Fatalf("deviceID=%q deviceSecret=%q, want both empty", id, secret)
	}
}

func TestDeviceCredentialsFromRequest_NoQueryParamFallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/inbox?device=device-2&secret=secret-2", nil)

	id, secret := deviceCredentialsFromRequest(req)
	if id != "" || secret != "" {
		t.Fatalf("deviceID=%q deviceSecret=%q, want both empty (query params are not accepted)", id, secret)
	}
}

func TestDeviceAuthFromRequest_ValidCredentials(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-x")

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)

	gotUserID, device, ok, _ := srv.deviceAuthFromRequest(req)
	if !ok {
		t.Fatalf("deviceAuthFromRequest ok = false, want true")
	}
	if gotUserID != userID {
		t.Fatalf("userID = %q, want %q", gotUserID, userID)
	}
	if device.DeviceID != deviceID {
		t.Fatalf("device.DeviceID = %q, want %q", device.DeviceID, deviceID)
	}
}

func TestDeviceAuthFromRequest_WrongSecret(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	deviceID, _ := pairNativeDevice(t, srv, all[0].ID, "device-y")

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, "not-the-real-secret")

	if _, _, ok, _ := srv.deviceAuthFromRequest(req); ok {
		t.Fatalf("deviceAuthFromRequest ok = true, want false for a wrong secret")
	}
}

func TestDeviceAuthFromRequest_UnknownDevice(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, "never-registered", "whatever")

	if _, _, ok, _ := srv.deviceAuthFromRequest(req); ok {
		t.Fatalf("deviceAuthFromRequest ok = true, want false for an unknown device")
	}
}

// TestDeviceAuthFromRequest_RemovedDeviceIsRejected is the core regression
// test for this fix: previously a device's shared account-wide credential
// kept working forever, so removing it from the paired-devices list (e.g.
// via the web UI) did not actually revoke its access. With per-device
// secrets, auth resolves through store.GetNativeDevice, so removing the row
// must reject the device's still-known credentials immediately.
func TestDeviceAuthFromRequest_RemovedDeviceIsRejected(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-z")

	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	if _, _, ok, _ := srv.deviceAuthFromRequest(req); !ok {
		t.Fatalf("deviceAuthFromRequest ok = false before removal, want true")
	}

	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	if _, err := store.RemoveNativeDevice(deviceID); err != nil {
		t.Fatalf("RemoveNativeDevice: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req2, deviceID, deviceSecret)
	if _, _, ok, _ := srv.deviceAuthFromRequest(req2); ok {
		t.Fatalf("deviceAuthFromRequest ok = true after removal, want false (revocation must be immediate)")
	}
}

func TestDeviceAuthFromRequest_CrossUserIsolation(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	otherUserID := userID + "-other"

	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-owned")
	otherDeviceID, _ := pairNativeDevice(t, srv, otherUserID, "device-elsewhere")

	// Device A's real credentials must resolve to its own owner, never the
	// other account.
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	gotUserID, _, ok, _ := srv.deviceAuthFromRequest(req)
	if !ok || gotUserID != userID {
		t.Fatalf("deviceAuthFromRequest = (%q, ok=%v), want (%q, true)", gotUserID, ok, userID)
	}

	// Device A's secret does not authenticate as device B's ID.
	crossReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(crossReq, otherDeviceID, deviceSecret)
	if _, _, ok, _ := srv.deviceAuthFromRequest(crossReq); ok {
		t.Fatalf("deviceAuthFromRequest ok = true using device A's secret against device B's id, want false")
	}
}

// TestDeviceAuthFromRequest_LocksOutAfterMaxFailures proves the brute-force
// guard on the expensive-scrypt device-secret check: once a given deviceID
// has racked up deviceMaxFailures wrong-secret attempts, the very next
// attempt is rejected as locked out (retryAfter > 0) even with the correct
// secret, until the lockout expires.
func TestDeviceAuthFromRequest_LocksOutAfterMaxFailures(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-lockout")

	wrongReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
		setDeviceHeaders(req, deviceID, "definitely-not-the-secret")
		return req
	}

	for i := 0; i < deviceMaxFailures; i++ {
		if _, _, ok, retryAfter := srv.deviceAuthFromRequest(wrongReq()); ok || retryAfter > 0 {
			t.Fatalf("attempt %d: ok=%v retryAfter=%v, want ok=false retryAfter=0 (not yet locked out)", i+1, ok, retryAfter)
		}
	}

	// The deviceID is now locked out: even the CORRECT secret must be
	// rejected without being checked, distinctly from a bad-credentials 401.
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	_, _, ok, retryAfter := srv.deviceAuthFromRequest(req)
	if ok {
		t.Fatal("deviceAuthFromRequest ok = true for a locked-out device, want false")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %v, want > 0 once locked out", retryAfter)
	}
}

// TestDeviceAuthFromRequest_LockoutIsPerDevice proves the lockout is scoped
// to the individual deviceID, not shared globally or by client IP: driving
// one device into lockout must not affect a different, well-behaved device
// (including one belonging to the same account, since deviceID — not
// clientIP or userID — is the lockout key).
func TestDeviceAuthFromRequest_LockoutIsPerDevice(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	lockedDeviceID, _ := pairNativeDevice(t, srv, userID, "device-locked")
	otherDeviceID, otherSecret := pairNativeDevice(t, srv, userID, "device-fine")

	for i := 0; i < deviceMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
		setDeviceHeaders(req, lockedDeviceID, "wrong-secret")
		srv.deviceAuthFromRequest(req)
	}
	if _, _, ok, retryAfter := srv.deviceAuthFromRequest(deviceRequest(lockedDeviceID, "wrong-secret")); ok || retryAfter <= 0 {
		t.Fatalf("expected device-locked to be locked out: ok=%v retryAfter=%v", ok, retryAfter)
	}

	// The other device, never having failed, must authenticate normally.
	otherReq := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(otherReq, otherDeviceID, otherSecret)
	gotUserID, _, ok, retryAfter := srv.deviceAuthFromRequest(otherReq)
	if !ok || retryAfter != 0 {
		t.Fatalf("unrelated device must not be affected by another device's lockout: ok=%v retryAfter=%v", ok, retryAfter)
	}
	if gotUserID != userID {
		t.Fatalf("userID = %q, want %q", gotUserID, userID)
	}
}

// TestDeviceAuthFromRequest_LockoutClearsAfterExpiry proves the lockout is
// time-bounded rather than permanent. failureLockout has no injectable clock
// (see login_lockout.go), so — as a whitebox test in the same package — this
// reaches directly into the lockout's internal entry to simulate elapsed
// time instead of sleeping deviceLockoutFor (15 real minutes) in a test.
func TestDeviceAuthFromRequest_LockoutClearsAfterExpiry(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-expiring")

	for i := 0; i < deviceMaxFailures; i++ {
		srv.deviceAuthFromRequest(deviceRequest(deviceID, "wrong-secret"))
	}
	if _, _, ok, retryAfter := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); ok || retryAfter <= 0 {
		t.Fatalf("expected device to be locked out before simulating expiry: ok=%v retryAfter=%v", ok, retryAfter)
	}

	// Simulate deviceLockoutFor having elapsed by rewinding the entry's
	// lockedUntil into the past, exactly as if real time had passed.
	// The lockout is keyed on (deviceID, clientIP) — see deviceLockoutKey.
	lockKey := srv.deviceLockoutKey(deviceID, deviceRequest(deviceID, deviceSecret))
	srv.deviceLockout.mu.Lock()
	entry, exists := srv.deviceLockout.entries[lockKey]
	if !exists {
		srv.deviceLockout.mu.Unlock()
		t.Fatal("expected a lockout entry for deviceID after failures were recorded")
	}
	entry.lockedUntil = time.Now().Add(-time.Second)
	srv.deviceLockout.mu.Unlock()

	gotUserID, _, ok, retryAfter := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret))
	if !ok || retryAfter != 0 {
		t.Fatalf("expected the device to authenticate again once the lockout window elapsed: ok=%v retryAfter=%v", ok, retryAfter)
	}
	if gotUserID != userID {
		t.Fatalf("userID = %q, want %q", gotUserID, userID)
	}
}

// TestDeviceAuthFromRequest_LockoutHTTP429 is the end-to-end proof that a
// locked-out device gets a 429 with Retry-After from an actual handler route,
// not just from deviceAuthFromRequest in isolation.
func TestDeviceAuthFromRequest_LockoutHTTP429(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, _ := pairNativeDevice(t, srv, userID, "device-http-lockout")

	for i := 0; i < deviceMaxFailures; i++ {
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, deviceRequest(deviceID, "wrong-secret"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d before lockout", i+1, rec.Code, http.StatusUnauthorized)
		}
	}

	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, deviceRequest(deviceID, "wrong-secret"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d once locked out", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on the 429 response")
	}
}

// TestResolveMailAuthContext_LockoutIs429 exercises the resolveMailAuthContext
// / withMailAuth path specifically (as opposed to the direct
// deviceAuthFromRequest call sites already covered above): resolveMailAuthContext
// has no http.ResponseWriter of its own, so it must signal a locked-out device
// via the mailLockedOutError sentinel, and withMailAuth must translate that
// into a 429 with Retry-After rather than the ordinary 401.
func TestResolveMailAuthContext_LockoutIs429(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, _ := pairNativeDevice(t, srv, userID, "device-mail-lockout")

	mailReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)
		setDeviceHeaders(req, deviceID, "wrong-secret")
		return req
	}

	for i := 0; i < deviceMaxFailures; i++ {
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, mailReq())
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want %d before lockout", i+1, rec.Code, http.StatusUnauthorized)
		}
	}

	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, mailReq())
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("GET /api/inbox status = %d, want %d once the device is locked out", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on the 429 response")
	}
}

// TestUnknownDeviceIdsNeverEnterTheLockoutTable is run-8 finding F2 (HIGH).
//
// deviceAuthFromRequest used to spend a lockout strike on the caller-supplied
// X-Kypost-Device-Id BEFORE resolving whether any such device exists.
// tryAttempt inserts unknown keys, and at loginLockoutHardCap it sheds the NEW
// key rather than evicting an old one — deliberately, because for the login
// table a genuine caller already holds a resident entry. On the device path
// that premise does not hold: recordSuccess DELETES the entry on every
// success, so a healthy paired device is always a new key. 50,000 anonymous
// requests with invented device ids (245 ms, no credential of any kind) filled
// the table, and every real device then got 429 on mail sync, contacts sync
// and push-MFA approval — presenting the correct secret, from an unrelated
// address.
//
// Resolving the device first means only a real, currently-paired id can
// occupy a slot.
func TestUnknownDeviceIdsNeverEnterTheLockoutTable(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "device-flood-victim")

	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
		setDeviceHeaders(req, "flood-"+strconv.Itoa(i), "x")
		if _, _, ok, _ := srv.deviceAuthFromRequest(req); ok {
			t.Fatalf("flood request %d authenticated", i)
		}
	}

	srv.deviceLockout.mu.Lock()
	resident := len(srv.deviceLockout.entries)
	srv.deviceLockout.mu.Unlock()
	if resident != 0 {
		t.Fatalf("%d lockout entries after 200 invented device ids; an unauthenticated "+
			"caller can size this table, and at loginLockoutHardCap it sheds every real device", resident)
	}

	// And the genuine device is unaffected, which is the harm the flood caused.
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	if _, _, ok, retryAfter := srv.deviceAuthFromRequest(req); !ok || retryAfter > 0 {
		t.Fatalf("genuine device: ok=%v retryAfter=%v, want ok=true retryAfter=0", ok, retryAfter)
	}
}

// TestOverlongDeviceCredentialsAreRejected is F2's memory variant. The entry
// COUNT was capped; the key BYTES were not, and sweepIfCrowdedLocked returns
// immediately below loginLockoutSweepThreshold so sub-threshold entries are
// never reclaimed. Go's 1 MiB DefaultMaxHeaderBytes is a total per-connection
// budget with no per-header limit, so a 1,024,000-byte device id is accepted
// and ~9,999 of them hold 9.76 GiB against the compose file's mem_limit of 8g.
//
// maxDeviceTextLen is the same cap handleNativeRegister applies when a device
// id is stored, so anything longer could never have been registered.
func TestOverlongDeviceCredentialsAreRejected(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, strings.Repeat("a", maxDeviceTextLen+1), "secret")
	if id, secret := deviceCredentialsFromRequest(req); id != "" || secret != "" {
		t.Fatalf("an over-length device id was accepted: len(id)=%d", len(id))
	}

	req = httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, "device-1", strings.Repeat("b", maxDeviceSecretLen+1))
	if id, secret := deviceCredentialsFromRequest(req); id != "" || secret != "" {
		t.Fatalf("an over-length device secret was accepted: len(secret)=%d", len(secret))
	}

	// A device id at the registration cap still works.
	req = httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, strings.Repeat("a", maxDeviceTextLen), "secret")
	if id, _ := deviceCredentialsFromRequest(req); len(id) != maxDeviceTextLen {
		t.Fatalf("a device id at the registration cap was rejected (len=%d)", len(id))
	}
}

// TestServerCapsHeaderBytes pins the MaxHeaderBytes that closes F2's OOM at
// the transport rather than at one handler. net/http's zero value means the
// 1 MiB default, so this must be set explicitly.
func TestServerCapsHeaderBytes(t *testing.T) {
	srv := newTestServer(t)
	srv.Prepare()
	if srv.httpServer.MaxHeaderBytes == 0 {
		t.Fatal("MaxHeaderBytes is unset, so net/http applies its 1 MiB default — a single " +
			"request may carry a 1,024,000-byte header value")
	}
	if srv.httpServer.MaxHeaderBytes > 128<<10 {
		t.Fatalf("MaxHeaderBytes = %d, larger than any legitimate request here", srv.httpServer.MaxHeaderBytes)
	}
}

// holdEveryKDFSlot fills the process-wide derivation semaphore for the rest of
// the test, so the next scrypt verification sheds with users.ErrKDFBusy instead
// of running. Same mechanism as users' own withSaturatedKDF; that one writes to
// the unexported slot channel, so from here the slots are held through the
// exported users.WithKDFSlot. The queue tolerance is shrunk once the slots are
// held, so a shed costs milliseconds rather than the production two seconds.
func holdEveryKDFSlot(t *testing.T) {
	t.Helper()
	release := make(chan struct{})
	holding := make(chan struct{}, users.MaxConcurrentKDF)
	var wg sync.WaitGroup
	for i := 0; i < users.MaxConcurrentKDF; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := users.WithKDFSlot(context.Background(), func(context.Context) {
				holding <- struct{}{}
				<-release
			})
			if err != nil {
				t.Errorf("could not take a derivation slot to saturate: %v", err)
				holding <- struct{}{}
			}
		}()
	}
	for i := 0; i < users.MaxConcurrentKDF; i++ {
		<-holding
	}
	previousWait := users.KDFMaxQueueWait
	users.KDFMaxQueueWait = 50 * time.Millisecond
	t.Cleanup(func() {
		users.KDFMaxQueueWait = previousWait
		close(release)
		wg.Wait()
	})
}

// TestDeviceAuthKDFBusyIsBusyNotBadCredentials is F-01-4.
//
// A device paired before HashDeviceSecret holds an scrypt secret hash, so
// verifying it takes a derivation slot and can be SHED. The shed branch
// returned like a wrong secret: the strike tryAttempt had just reserved was
// spent, and retryAfter=0 made writeDeviceAuthFailure answer 401 "invalid
// device credentials". That is the failure users.ErrKDFBusy exists to prevent
// — a load spike reported as a dead credential, and four of them locking the
// phone out for deviceLockoutFor while its secret was never once examined.
func TestDeviceAuthKDFBusyIsBusyNotBadCredentials(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	deviceID, deviceSecret := pairNativeDevice(t, srv, all[0].ID, "device-kdf-shed")

	holdEveryKDFSlot(t)

	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, deviceRequest(deviceID, deviceSecret))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: a shed derivation is the server being out of "+
			"capacity, not the device's credentials being wrong", rec.Code, http.StatusServiceUnavailable)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 503, so a client knows when to come back")
	}

	lockKey := srv.deviceLockoutKey(deviceID, deviceRequest(deviceID, deviceSecret))
	srv.deviceLockout.mu.Lock()
	entry, tracked := srv.deviceLockout.entries[lockKey]
	failures := 0
	if tracked {
		failures = entry.failures
	}
	srv.deviceLockout.mu.Unlock()
	if failures != 0 {
		t.Fatalf("the shed attempt spent %d lockout strike(s); no credential was examined, "+
			"so deviceMaxFailures shed requests would lock a valid device out", failures)
	}
}

// The withMailAuth wrapper renders the same shed itself, through
// mailLockedOutError, rather than through writeDeviceAuthFailure — and mail
// sync is the request a phone makes constantly, so it is the one most likely to
// meet a saturated queue. It must not answer 429 "too many failed attempts"
// either: nothing was attempted.
func TestMailAuthKDFBusyIsBusyNotLockedOut(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	deviceID, deviceSecret := pairNativeDevice(t, srv, all[0].ID, "device-kdf-shed-mail")

	holdEveryKDFSlot(t)

	req := httptest.NewRequest(http.MethodGet, "/api/inbox", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected a Retry-After header on the 503, so a client knows when to come back")
	}
}
