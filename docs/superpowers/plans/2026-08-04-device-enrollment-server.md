# Device Enrollment (2a, server side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the server everything a paired device and a browser need to complete an enrollment ceremony — the device's enrollment public key, a device-scoped read of the envelope sealed for it, and an expiring transport copy.

**Architecture:** `NativeDevice` gains the device's enrollment public key and a self-reported "can I still decrypt" marker, following the `MFAApprover` precedent for fields older rows decode as absent. Two new device-authenticated routes let a device publish its public key and fetch the one envelope sealed for it — never any other slot. The transport envelope itself reuses Change 1's `device:<id>` slot, now with an expiry so the server stops holding a payload whose journey is over.

**Tech Stack:** Go, stdlib `net/http` with `mux.HandleFunc`, SQLite-backed state store, JSON user store, table-driven `testing` tests with no mocking framework.

**Scope:** Server only (2a). The browser ceremony (2b) and the Android client (2c) are separate plans written against this wire format. Nothing here is user-visible on its own.

**Spec:** `docs/superpowers/specs/2026-08-04-device-enrollment-design.md`.

## Global Constraints

- Read the DOX chain before editing: root `AGENTS.md`, then `backend/AGENTS.md`. Run a DOX pass after.
- Ponytail rules: reuse before adding, prefer the standard library, no unrequested abstractions, shortest working diff.
- **The server never derives the verification code.** It is computed by the device from its own keystore key and by the browser from what it was served; the server is the party the check defends against. No code-derivation logic belongs in this plan.
- **The server never interprets an envelope.** Opaque string, bounded by length only.
- **A device may publish a public key and read what was sealed for it. Only a session may mint or destroy a sealing.** The `PUT`/`DELETE` envelope routes stay `s.withAuth` + step-up, untouched by this plan.
- The device-scoped read takes **no slot parameter**. The slot name is built from the authenticated device record.
- Transport-copy TTL is **7 days**, matching the pickup-link retention window. One named constant.
- Tests use `t.TempDir()` + `LoadOrMigrate` (users) or the state store's test helpers; no mocking framework.
- Run `gofmt`. Do not background test runs; use narrow `-run` filters.

## File Structure

| File | Responsibility |
|---|---|
| `backend/internal/users/users.go` | `WrappedEnvelope.ExpiresAt`, expiry filtering in `WrappedEnvelopes()`, TTL stamping in `SetPGPWrappedEnvelope` |
| `backend/internal/users/multi_envelope_test.go` | Task 1 tests (append) |
| `backend/internal/state/store.go` | `NativeDevice` enrollment fields, column migration, `SetNativeDeviceEnrollmentKey` |
| `backend/internal/state/device_enrollment_test.go` (new) | Task 2 tests |
| `backend/internal/api/pgp_device_enrollment.go` (new) | The two device-authenticated handlers |
| `backend/internal/api/pgp_device_enrollment_test.go` (new) | Tasks 3-4 tests |
| `backend/internal/api/server.go` | Two route registrations |
| `backend/internal/api/server_notifications.go` | `encryptionEnrolled` on the native register request |

---

### Task 1: Transport copies expire

**Files:**
- Modify: `backend/internal/users/users.go` (the `WrappedEnvelope` type; `WrappedEnvelopes()`; `SetPGPWrappedEnvelope`)
- Test: `backend/internal/users/multi_envelope_test.go` (append)

**Interfaces:**
- Consumes: existing `WrappedEnvelope{Slot, Envelope, AddedAt}`, `EnvelopeSlotDevicePrefix`, `maxWrappedEnvelopeSlots`.
- Produces: `WrappedEnvelope.ExpiresAt string`; `users.DeviceEnvelopeTTL` (a `time.Duration`); `SetPGPWrappedEnvelope` now stamps `ExpiresAt` on `device:` slots; `WrappedEnvelopes()` omits expired entries.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/users/multi_envelope_test.go`. Merge `time` into the file's existing import block; a second `import (...)` after a declaration will not compile.

```go
// A device: slot is a payload in flight, not a record. Once the device has
// fetched and re-sealed it locally the server's copy is dead weight, and the
// device cannot delete it (no session). Expiry is how it goes away.
func TestDeviceSlotExpires(t *testing.T) {
	store, id := newClientProtectedUser(t)
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	if _, err := store.SetPGPWrappedEnvelope(id, "device:abc", `{"v":2,"dev":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.WrappedEnvelopes()) != 2 {
		t.Fatalf("fresh device slot should be visible: %+v", got.WrappedEnvelopes())
	}
	// ExpiresAt must be stamped automatically — a caller is not trusted to remember.
	if got.PGPWrappedEnvelopes[0].ExpiresAt == "" {
		t.Fatal("SetPGPWrappedEnvelope did not stamp ExpiresAt on a device slot")
	}

	// Force it into the past and it must disappear from the synthesised view.
	got.PGPWrappedEnvelopes[0].ExpiresAt = past
	if _, err := store.SetPGPWrappedEnvelope(id, "device:abc", `{"v":2,"dev":1}`, ""); err != nil {
		t.Fatalf("re-set: %v", err)
	}
	expired := User{
		PGPPrivateKeyWrapped: `{"v":2,"pw":true}`,
		PGPWrappedEnvelopes:  []WrappedEnvelope{{Slot: "device:abc", Envelope: "x", ExpiresAt: past}},
	}
	if slots := expired.WrappedEnvelopes(); len(slots) != 1 || slots[0].Slot != EnvelopeSlotPassword {
		t.Fatalf("expired device slot still visible: %+v", slots)
	}
}

// The recovery slot is a durable sealing, not cargo. It must never expire.
func TestRecoverySlotDoesNotExpire(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if got.PGPWrappedEnvelopes[0].ExpiresAt != "" {
		t.Fatalf("recovery slot was given an expiry: %q", got.PGPWrappedEnvelopes[0].ExpiresAt)
	}
}

// An expired slot must not consume cap headroom — otherwise a device that
// enrolled and went quiet permanently costs the user a slot.
func TestExpiredSlotsDoNotCountTowardTheCap(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	u := User{PGPPrivateKeyWrapped: `{"v":2,"pw":true}`}
	for i := 0; i < maxWrappedEnvelopeSlots+5; i++ {
		u.PGPWrappedEnvelopes = append(u.PGPWrappedEnvelopes, WrappedEnvelope{
			Slot: EnvelopeSlotDevicePrefix + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			Envelope: "x", ExpiresAt: past,
		})
	}
	if n := len(u.WrappedEnvelopes()); n != 1 {
		t.Fatalf("expired slots leaked into the synthesised view: %d entries", n)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/users/ -run 'TestDeviceSlotExpires|TestRecoverySlotDoesNotExpire|TestExpiredSlots' -v`
Expected: FAIL — compile error, `ExpiresAt` is not a field of `WrappedEnvelope`.

- [ ] **Step 3: Write minimal implementation**

Add the field to `WrappedEnvelope`:

```go
	// ExpiresAt is set only on device: slots, which carry a payload in flight
	// rather than a durable sealing. The device that the envelope is for cannot
	// delete it — deletion needs a session and the ceremony's last step runs on
	// the device — so an expiry is how the server stops holding a copy whose
	// journey is over. Empty means "never", which is right for password and
	// recovery slots.
	ExpiresAt string `json:"expiresAt,omitempty"`
```

Add the TTL constant beside `maxWrappedEnvelopeSlots`:

```go
// DeviceEnvelopeTTL bounds how long the server keeps a device: transport copy.
// Seven days matches the pickup-link retention window rather than introducing a
// third number; if one moves, both should. It is generous on purpose — enrolling
// at pairing completes in seconds, and this window only matters when the device
// is offline during a deferred enrollment. A device that misses it re-runs the
// ceremony; nothing is lost but the ceremony.
const DeviceEnvelopeTTL = 7 * 24 * time.Hour
```

In `SetPGPWrappedEnvelope`, compute the expiry once before the mutate closure and assign it in both the replace and append branches:

```go
	expiresAt := ""
	if strings.HasPrefix(slot, EnvelopeSlotDevicePrefix) {
		expiresAt = time.Now().UTC().Add(DeviceEnvelopeTTL).Format(time.RFC3339)
	}
```

Set `u.PGPWrappedEnvelopes[i].ExpiresAt = expiresAt` in the replace branch and `ExpiresAt: expiresAt` in the appended literal.

Filter in `WrappedEnvelopes()`, replacing the `continue` guard's block with:

```go
	for _, e := range u.PGPWrappedEnvelopes {
		if e.Slot == EnvelopeSlotPassword || e.expired() {
			continue
		}
		out = append(out, e)
	}
```

And the predicate:

```go
// expired reports whether this envelope's TTL has passed. An unparseable
// ExpiresAt counts as expired: a timestamp the server cannot read is not
// evidence that a payload is still wanted, and failing closed here costs a
// re-run of the ceremony rather than leaving a blob around indefinitely.
func (e WrappedEnvelope) expired() bool {
	if e.ExpiresAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.ExpiresAt)
	if err != nil {
		return true
	}
	return time.Now().UTC().After(t)
}
```

Finally, in `SetPGPWrappedEnvelope`'s cap check, count only live entries so an expired slot frees headroom:

```go
		live := 0
		for _, e := range u.PGPWrappedEnvelopes {
			if !e.expired() {
				live++
			}
		}
		if live >= maxWrappedEnvelopeSlots {
			return ErrTooManyEnvelopeSlots
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/users/ -run 'Envelope|WrappedEnvelope|Expire' -v`
Expected: PASS, including the pre-existing Change 1 tests.

- [ ] **Step 5: Verify the tests bite**

Remove the `e.expired()` clause from `WrappedEnvelopes()`, re-run, confirm `TestDeviceSlotExpires` and `TestExpiredSlotsDoNotCountTowardTheCap` fail. Restore. Then blank the `expiresAt` assignment in `SetPGPWrappedEnvelope`, confirm `TestDeviceSlotExpires` fails on the stamp assertion. Restore. Record both transcripts in the report.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/users/users.go backend/internal/users/multi_envelope_test.go
git commit -m "feat(pgp): expire device transport envelopes after seven days"
```

---

### Task 2: The device's enrollment key and enrollment marker

**Files:**
- Modify: `backend/internal/state/store.go` (`NativeDevice` :67-93; `scanDevice` :854; `insertDevice` :863; `upsertNativeDeviceTx` :939; the schema migration)
- Test: `backend/internal/state/device_enrollment_test.go` (create)

**Interfaces:**
- Consumes: `NativeDevice`, `UpsertNativeDevice`, `ListNativeDevicesStrict`.
- Produces: `NativeDevice.EnrollmentPublicKey string`, `.EnrollmentKeyAt string`, `.EncryptionEnrolled bool`; `(*Store).SetNativeDeviceEnrollmentKey(deviceID, publicKey, at string) (NativeDevice, error)`; `(*Store).SetNativeDeviceEncryptionEnrolled(deviceID string, enrolled bool) error`.

- [ ] **Step 1: Write the failing test**

Create `backend/internal/state/device_enrollment_test.go`. Use the same store-construction helper the package's existing device tests use — find it with `grep -n "func newTestStore\|func testStore" backend/internal/state/*_test.go` and reuse it rather than writing another.

```go
package state

import "testing"

func TestSetNativeDeviceEnrollmentKeyRoundTrips(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.UpsertNativeDevice(NativeDevice{DeviceID: "dev-1", Platform: "android", PushToken: "tok"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	got, err := store.SetNativeDeviceEnrollmentKey("dev-1", "BASE64PUBKEY", "2026-08-04T00:00:00Z")
	if err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if got.EnrollmentPublicKey != "BASE64PUBKEY" || got.EnrollmentKeyAt != "2026-08-04T00:00:00Z" {
		t.Fatalf("not persisted on the returned record: %+v", got)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("ListNativeDevicesStrict: %v", err)
	}
	if len(devices) != 1 || devices[0].EnrollmentPublicKey != "BASE64PUBKEY" {
		t.Fatalf("not persisted through a reload: %+v", devices)
	}
	// The pairing secret must never ride along into an API response.
	if devices[0].Redacted().SecretHash != "" {
		t.Fatal("Redacted() no longer clears SecretHash")
	}
}

func TestSetNativeDeviceEnrollmentKeyUnknownDevice(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := store.SetNativeDeviceEnrollmentKey("nope", "K", "2026-08-04T00:00:00Z"); err == nil {
		t.Fatal("publishing a key for an unknown device silently succeeded")
	}
}

// The marker is device-reported, so it must be able to go BOTH ways: an app
// reinstall destroys the keystore key, and a marker that only ever turns on
// would tell the user a device is protected when it can no longer read anything.
func TestEncryptionEnrolledMarkerClearsAgain(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.UpsertNativeDevice(NativeDevice{DeviceID: "dev-1", Platform: "android", PushToken: "tok"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	if err := store.SetNativeDeviceEncryptionEnrolled("dev-1", true); err != nil {
		t.Fatalf("set true: %v", err)
	}
	devices, _ := store.ListNativeDevicesStrict()
	if !devices[0].EncryptionEnrolled {
		t.Fatal("marker did not turn on")
	}
	if err := store.SetNativeDeviceEncryptionEnrolled("dev-1", false); err != nil {
		t.Fatalf("set false: %v", err)
	}
	devices, _ = store.ListNativeDevicesStrict()
	if devices[0].EncryptionEnrolled {
		t.Fatal("marker could not be turned back off")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/state/ -run 'EnrollmentKey|EncryptionEnrolled' -v`
Expected: FAIL — compile error, the fields and methods do not exist.

- [ ] **Step 3: Write minimal implementation**

Add to `NativeDevice`, after `MFAApprover` so the graceful-default reasoning sits together:

```go
	// EnrollmentPublicKey is this device's EC P-256 public key for encrypted-mail
	// enrollment, published by the device under its own pairing credential. A
	// public key is not a capability: it lets a browser seal TO this device and
	// confers nothing by itself, which is why a device may publish its own while
	// only a session may mint the sealing. Devices paired before this existed
	// decode as empty, meaning "not enrolled and cannot be" until they publish.
	EnrollmentPublicKey string `json:"enrollmentPublicKey,omitempty"`
	EnrollmentKeyAt     string `json:"enrollmentKeyAt,omitempty"`
	// EncryptionEnrolled is DEVICE-REPORTED: whether the device can still open
	// its local envelope. It is not a record of what the browser did, because
	// those diverge — reinstalling the app destroys the keystore key, as does a
	// biometric-enrollment change on some configurations. A marker that only ever
	// turned on would tell the user a device is protected when it can read
	// nothing, so the device restates it on every registration call.
	EncryptionEnrolled bool `json:"encryptionEnrolled"`
```

Add three columns to the devices table migration, mirroring how `mfa_approver` was added (find it with `grep -n "mfa_approver" backend/internal/state/store.go` and follow that pattern exactly, including its `ALTER TABLE`-if-missing form). Extend `scanDevice` and `insertDevice` to carry them, in the same column order.

Then the two setters, following `SetNativeDeviceMFAApprover`'s shape (`grep -n "func (s \*Store) SetNativeDeviceMFAApprover" -A 20`):

```go
// SetNativeDeviceEnrollmentKey records a device's enrollment public key. It
// refuses an unknown device rather than creating one: a device publishes under
// its pairing credential, so the record must already exist, and an insert here
// would mean a credential minted a device row.
func (s *Store) SetNativeDeviceEnrollmentKey(deviceID, publicKey, at string) (NativeDevice, error) {
	// Mirror SetNativeDeviceMFAApprover: locate, mutate, persist, return the
	// updated record; return an error when the device is absent.
}

// SetNativeDeviceEncryptionEnrolled records the device's own answer to "can I
// still decrypt". Both directions must work — see EncryptionEnrolled.
func (s *Store) SetNativeDeviceEncryptionEnrolled(deviceID string, enrolled bool) error {
	// Same shape, without the returned record.
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/state/ -v`
Expected: PASS, including the package's pre-existing device tests — the column addition must not disturb them.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/state/store.go backend/internal/state/device_enrollment_test.go
git commit -m "feat(pgp): store a device's enrollment key and self-reported state"
```

---

### Task 3: A device publishes its enrollment public key

**Files:**
- Create: `backend/internal/api/pgp_device_enrollment.go`
- Modify: `backend/internal/api/server.go` (register beside the other `/api/pgp/` routes)
- Test: `backend/internal/api/pgp_device_enrollment_test.go` (create)

**Interfaces:**
- Consumes: `SetNativeDeviceEnrollmentKey` (Task 2). **Verified helper names — use these exactly:**
  - `s.deviceAuthFromRequest(r) (userID string, device state.NativeDevice, ok bool, retryAfter time.Duration)` — `device_auth.go:60`. Returns the **verified** device record. Note `retryAfter` is a `time.Duration`.
  - `writeDeviceAuthFailure(w, retryAfter)` — the existing failure writer, used at `push_mfa_handlers.go:386`.
  - `s.userStore(ownerID)` — the per-user state-store accessor (`device_auth.go:73`). **Not** `userStateStore`.
  - `store.GetNativeDevice(deviceID)` — device lookup on that store.
- Produces: `POST /api/pgp/device/enrollment-key`, handler `handlePGPPublishEnrollmentKey`.

**Test fixtures: there is no paired-device helper in this package.** `device_auth_test.go:12-13` stamps credentials inline with `req.Header.Set(headerDeviceID, …)` / `req.Header.Set(headerDeviceSecret, …)`. Write one helper in your new test file — `newPairedDeviceForTest(t) (srv *Server, userID, deviceID string, authDevice func(*http.Request))` — that creates a user, registers a device with a known secret, and returns a stamping function. Tasks 4 and 5 reuse it, so give it that exact signature. Do not name it `clientProtectedUser`; that name is already taken in `pgp_client_e2e_test.go` with a different signature.

Write two more small helpers in the same file, used by Tasks 4 and 5:

- `seedClientProtectedIdentity(t *testing.T, srv *Server, userID string)` — calls `srv.users.SetPGPIdentityClientProtected(userID, "FPR", "KID", <armored pub>, `{"v":2,"pw":true}`, "generated", "2026-08-04T00:00:00Z")`. Task 4 needs it because `WrappedEnvelopes()` returns nothing for an account with no identity.
- `deviceByID(t *testing.T, srv *Server, userID, deviceID string) state.NativeDevice` — `srv.userStore(userID)` then `GetNativeDevice(deviceID)`, failing the test if absent.

- [ ] **Step 1: Write the failing test**

Create `backend/internal/api/pgp_device_enrollment_test.go`. Find how existing tests build a paired-device request with valid credentials — `grep -n "deviceAuthFromRequest\|X-Kypost-Device-Id" backend/internal/api/*_test.go` — and reuse that helper rather than hand-rolling headers.

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublishEnrollmentKeyStoresItForTheCallingDevice(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"BASE64PUBKEY"}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	store, err := srv.userStore(userID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if devices[0].EnrollmentPublicKey != "BASE64PUBKEY" {
		t.Fatalf("key not stored: %+v", devices[0])
	}
	if devices[0].EnrollmentKeyAt == "" {
		t.Fatal("publish time not stamped")
	}
}

// The device id comes from the verified credential, never from the body. A
// device that could name another device's id would be able to overwrite the key
// a browser is about to seal to — which is the substitution attack the whole
// verification code exists to catch, handed over for free.
func TestPublishEnrollmentKeyIgnoresAnyDeviceIdInTheBody(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"MINE","deviceId":"some-other-device"}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	store, _ := srv.userStore(userID)
	devices, _ := store.ListNativeDevicesStrict()
	for _, d := range devices {
		if d.DeviceID != deviceID && d.EnrollmentPublicKey != "" {
			t.Fatalf("wrote a key onto device %q", d.DeviceID)
		}
	}
}

func TestPublishEnrollmentKeyRejectsUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"X"}`))
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an unauthenticated caller published a key")
	}
}

func TestPublishEnrollmentKeyRejectsEmptyKey(t *testing.T) {
	srv, _, authDevice := newPairedDeviceForTest(t)
	req := httptest.NewRequest(http.MethodPost, "/api/pgp/device/enrollment-key",
		strings.NewReader(`{"publicKey":"  "}`))
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPPublishEnrollmentKey(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
```

If no `newPairedDeviceForTest` helper exists in this package, write one in this file that registers a device and returns a function stamping valid credential headers onto a request — and say so in your report.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestPublishEnrollmentKey -v`
Expected: FAIL — `handlePGPPublishEnrollmentKey` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `backend/internal/api/pgp_device_enrollment.go`:

```go
package api

// Device-authenticated halves of the enrollment ceremony. Both resolve the
// caller through deviceAuthFromRequest, which returns the VERIFIED device
// record, so neither ever reads an identity out of the request.
//
// These are deliberately not withAuth and not withMailAuth. withMailAuth would
// admit a session, which has no device to scope to; withAuth would exclude the
// device entirely. See docs/superpowers/specs/2026-08-04-device-enrollment-design.md.

// maxEnrollmentPublicKeyBytes bounds the published key. An uncompressed P-256
// point is 65 bytes raw and a few hundred base64-wrapped in any sane encoding;
// this leaves generous headroom while keeping an unbounded string out of the
// device table.
const maxEnrollmentPublicKeyBytes = 4 << 10

func (s *Server) handlePGPPublishEnrollmentKey(w http.ResponseWriter, r *http.Request) {
	_, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter) // reuse whatever push_mfa_handlers.go does here
		return
	}
	var req struct {
		PublicKey string `json:"publicKey"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxEnrollmentPublicKeyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	publicKey := strings.TrimSpace(req.PublicKey)
	if publicKey == "" {
		http.Error(w, "publicKey is required", http.StatusBadRequest)
		return
	}
	store, err := s.userStore(device.UserID)
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	// device.DeviceID, never anything from the body.
	if _, err := store.SetNativeDeviceEnrollmentKey(device.DeviceID, publicKey,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		http.Error(w, "could not store the enrollment key", http.StatusInternalServerError)
		return
	}
	s.logger.Info("pgp enrollment key published", "user_id", device.UserID, "device_id", device.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

Match the exact names of the device-auth failure writer and the per-user state accessor to what `push_mfa_handlers.go` already uses; do not invent new ones.

Register in `server.go`, with the other `/api/pgp/` routes:

```go
	mux.HandleFunc("POST /api/pgp/device/enrollment-key", s.handlePGPPublishEnrollmentKey)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/api/ -run TestPublishEnrollmentKey -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/api/pgp_device_enrollment.go backend/internal/api/pgp_device_enrollment_test.go backend/internal/api/server.go
git commit -m "feat(pgp): let a paired device publish its enrollment public key"
```

---

### Task 4: A device reads the envelope sealed for it

This is the route the spec calls out as a gap in Change 1: all three envelope routes are session-only, so a device cannot fetch what was sealed for it and the ceremony cannot complete.

**Files:**
- Modify: `backend/internal/api/pgp_device_enrollment.go` (append), `backend/internal/api/server.go`
- Test: `backend/internal/api/pgp_device_enrollment_test.go` (append)

**Interfaces:**
- Consumes: `deviceAuthFromRequest`; `(User).WrappedEnvelopes()`; `EnvelopeSlotDevicePrefix`.
- Produces: `GET /api/pgp/device/envelope`, handler `handlePGPDeviceEnvelope`, returning `{"slot":"device:<id>","envelope":"..."}`.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/api/pgp_device_enrollment_test.go`:

```go
func TestDeviceEnvelopeServesOnlyTheCallersOwnSlot(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	seedClientProtectedIdentity(t, srv, userID)

	if _, err := srv.users.SetPGPWrappedEnvelope(userID, "device:"+deviceID, `{"v":2,"mine":1}`, ""); err != nil {
		t.Fatalf("seed own slot: %v", err)
	}
	if _, err := srv.users.SetPGPWrappedEnvelope(userID, "device:someone-else", `{"v":2,"theirs":1}`, ""); err != nil {
		t.Fatalf("seed other slot: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"mine":1`) {
		t.Fatalf("did not serve the caller's own envelope: %s", body)
	}
	// The decisive assertion: another device's sealing must not appear, whatever
	// the caller asks for. There is no slot parameter precisely so this cannot vary.
	if strings.Contains(body, `"theirs":1`) {
		t.Fatalf("served another device's envelope: %s", body)
	}
}

// A slot parameter must not exist. If someone adds one later, this fails.
func TestDeviceEnvelopeIgnoresASlotParameter(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	seedClientProtectedIdentity(t, srv, userID)
	if _, err := srv.users.SetPGPWrappedEnvelope(userID, users.EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("seed recovery: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope?slot=recovery", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if strings.Contains(rec.Body.String(), `"rec":1`) {
		t.Fatalf("a query parameter reached the slot lookup: %s", rec.Body.String())
	}
}

func TestDeviceEnvelopeIs404WhenNothingSealedYet(t *testing.T) {
	srv, userID, deviceID, authDevice := newPairedDeviceForTest(t)
	seedClientProtectedIdentity(t, srv, userID)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	authDevice(req)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestDeviceEnvelopeRejectsUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/device/envelope", nil)
	rec := httptest.NewRecorder()
	srv.handlePGPDeviceEnvelope(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("an unauthenticated caller read a device envelope")
	}
}
```

Replace `users.EnvelopeSlotRecovery` with `users.EnvelopeSlotRecovery` and add the `users` import if the file does not already have it.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestDeviceEnvelope -v`
Expected: FAIL — `handlePGPDeviceEnvelope` undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `backend/internal/api/pgp_device_enrollment.go`:

```go
// handlePGPDeviceEnvelope serves the ONE envelope sealed for the calling device.
//
// It takes no slot parameter, by design. The general GET on
// /api/pgp/identity/envelope/{slot} stays session-only because a device asking
// for another device's sealing — or for the password slot — is exactly what
// that rule withholds. Here the slot name is built from the verified device
// record, so there is no input to abuse.
//
// Serving this one envelope to this one device is safe: it is sealed to a key
// whose private half is non-extractable from that device's secure element, so
// no other caller gains anything by obtaining it.
func (s *Server) handlePGPDeviceEnvelope(w http.ResponseWriter, r *http.Request) {
	_, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	u, err := s.users.Get(device.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	slot := users.EnvelopeSlotDevicePrefix + device.DeviceID
	for _, e := range u.WrappedEnvelopes() {
		if e.Slot == slot {
			writeJSON(w, http.StatusOK, map[string]any{"slot": e.Slot, "envelope": e.Envelope})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "no envelope sealed for this device"})
}
```

`WrappedEnvelopes()` already omits expired entries (Task 1), so an expired transport copy correctly reads as 404 rather than being served.

Register in `server.go`:

```go
	mux.HandleFunc("GET /api/pgp/device/envelope", s.handlePGPDeviceEnvelope)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/api/ -run 'TestDeviceEnvelope|TestPublishEnrollmentKey' -v`
Expected: PASS, 8 tests.

- [ ] **Step 5: Verify the isolation assertion bites**

Change the handler to loop without the `e.Slot == slot` comparison (return the first envelope it sees). Confirm `TestDeviceEnvelopeServesOnlyTheCallersOwnSlot` fails on the `"theirs":1` assertion. Restore. Record the transcript — this is the assertion the route's safety rests on.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/api/pgp_device_enrollment.go backend/internal/api/pgp_device_enrollment_test.go backend/internal/api/server.go
git commit -m "feat(pgp): let a device read the envelope sealed for it"
```

---

### Task 5: The device reports whether it can still decrypt

**Files:**
- Modify: `backend/internal/api/server_notifications.go` (`nativeRegisterRequest` :373-382 and `handleNotificationNativeRegister` :384)
- Test: `backend/internal/api/pgp_device_enrollment_test.go` (append)

**Interfaces:**
- Consumes: `SetNativeDeviceEncryptionEnrolled` (Task 2).
- Produces: `encryptionEnrolled` (optional bool) on the native register request.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/api/pgp_device_enrollment_test.go`. Build the register request exactly as the package's existing native-register tests do — `grep -n "handleNotificationNativeRegister" backend/internal/api/*_test.go`.

```go
// The marker must follow the device DOWN as well as up. An app reinstall
// destroys the keystore key, and a marker that only ever turned on would show a
// device as protected when it can no longer read anything.
func TestNativeRegisterCarriesEncryptionEnrolledBothWays(t *testing.T) {
	srv, userID, deviceID, register := newNativeRegisterForTest(t)

	if code := register(t, `"encryptionEnrolled":true`); code != http.StatusOK {
		t.Fatalf("register true: status %d", code)
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("marker did not turn on")
	}

	if code := register(t, `"encryptionEnrolled":false`); code != http.StatusOK {
		t.Fatalf("register false: status %d", code)
	}
	if deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("marker did not turn back off")
	}
}

// An older client that does not send the field must not be silently marked
// un-enrolled — absent means "no opinion", not "no".
func TestNativeRegisterWithoutTheFieldLeavesTheMarkerAlone(t *testing.T) {
	srv, deviceID, register := newNativeRegisterForTest(t)
	if code := register(t, `"encryptionEnrolled":true`); code != http.StatusOK {
		t.Fatalf("register true: status %d", code)
	}
	if code := register(t, ""); code != http.StatusOK {
		t.Fatalf("register without field: status %d", code)
	}
	if !deviceByID(t, srv, userID, deviceID).EncryptionEnrolled {
		t.Fatal("an absent field cleared the marker")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestNativeRegister -v`
Expected: FAIL — the field is not parsed, so the marker never turns on.

- [ ] **Step 3: Write minimal implementation**

Add to `nativeRegisterRequest`, using a pointer so absent is distinguishable from `false`:

```go
	// EncryptionEnrolled is the device's own answer to "can I still open my
	// enrollment envelope". A POINTER because absent and false mean different
	// things: an older client that does not send it has no opinion and must not
	// have the marker cleared out from under it, while a client that sends false
	// is reporting that its keystore key is gone.
	EncryptionEnrolled *bool `json:"encryptionEnrolled,omitempty"`
```

In `handleNotificationNativeRegister`, after the device row is upserted:

```go
	if req.EncryptionEnrolled != nil {
		if err := store.SetNativeDeviceEncryptionEnrolled(deviceID, *req.EncryptionEnrolled); err != nil {
			// Not fatal to registration: push must keep working even if the
			// enrollment marker cannot be written.
			s.logger.Warn("could not record device encryption state", "device_id", deviceID, "error", err.Error())
		}
	}
```

Use whatever local variable already holds the resolved device id and per-user store in that handler.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && go test ./internal/api/ -run TestNativeRegister -v`
Expected: PASS, both tests plus the pre-existing native-register tests.

- [ ] **Step 5: Full suite and DOX pass**

Run: `cd backend && go build ./... && go vet ./... && gofmt -l . && go test ./...`
Expected: all clean.

Then update `docs/E2E_PGP.md`'s endpoint list with the two new device-authenticated routes, noting that they are device-auth-only and why — that file is where this repo documents PGP routes (`backend/AGENTS.md` documents none of them). Add a bullet to `backend/AGENTS.md` only if the enrollment fields change a contract it already states.

- [ ] **Step 6: Commit**

```bash
git add backend/internal/api/server_notifications.go backend/internal/api/pgp_device_enrollment_test.go docs/E2E_PGP.md
git commit -m "feat(pgp): let a device report whether it can still decrypt"
```

---

## Follow-on work, not in this plan

- **2b (browser).** Device list with the enrolled indicator, the code entry field, local comparison, ECDH seal, `PUT` to `device:<id>`. The browser must refuse to seal on mismatch — that refusal is the entire security of the ceremony.
- **2c (Android).** Keystore/StrongBox keypair, publish, code display, fetch, local re-seal, the pairing-screen indicator rendered from local ground truth.
- **The verification code algorithm** is specified in the design doc and implemented only in 2b and 2c. The server never derives it.
- **Revocation copy.** "Remove device" must say it stops future sealings and does not erase what that device already holds — see the design doc's revocation section.
