package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/users"
)

// Finding 1: a paired device must stop authenticating once its owning account
// is deactivated — deactivation is an offboarding/revocation action and the
// device path must honor it just as the session path does.
func TestDeviceAuthRejectedAfterDeactivation(t *testing.T) {
	srv := newTestServer(t)
	// A dedicated non-admin account: the store now refuses to deactivate the
	// last active admin (see users.guardNotLastActiveAdmin), and the seeded
	// admin this test used to borrow is exactly that. The subject here is the
	// device path honoring deactivation, not the admin-count invariant.
	owner, err := srv.users.Create("deactivation-subject", "deactivation-subject-pass", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	userID := owner.ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "revoke-device")

	// Sanity: the device works while the account is active.
	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); !ok {
		t.Fatal("device should authenticate while the account is active")
	}

	if _, err := srv.users.Deactivate(userID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	if _, _, ok, _ := srv.deviceAuthFromRequest(deviceRequest(deviceID, deviceSecret)); ok {
		t.Fatal("device must NOT authenticate after the account is deactivated")
	}

	// And an end-to-end withMailAuth-style route must reject it too.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/sync", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d for a deactivated account's device", rec.Code, http.StatusUnauthorized)
	}
}

func deviceRequest(deviceID, deviceSecret string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/contacts/sync", nil)
	setDeviceHeaders(req, deviceID, deviceSecret)
	return req
}

// Finding 8: a device id already owned by a DIFFERENT user must be reported as
// a conflict, so registration cannot hijack the global device-index entry for
// a victim's device id (targeted DoS).
func TestForeignDeviceIDIsAConflict(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	victimID := all[0].ID
	victimDeviceID, _ := pairNativeDevice(t, srv, victimID, "victim-device")

	attacker, err := srv.users.Create("attacker", "attacker-pass-123", users.RoleUser)
	if err != nil {
		t.Fatalf("create attacker: %v", err)
	}

	// Test 1: attacker trying to reserve victim's device should fail (conflict).
	if _, ok := srv.reserveDeviceID(attacker.ID, victimDeviceID); ok {
		t.Fatal("attacker should fail to reserve a device id owned by the victim")
	}
	// Test 2: victim re-registering their own device should succeed (no conflict).
	victimRes, ok := srv.reserveDeviceID(victimID, victimDeviceID)
	if !ok {
		t.Fatal("the victim should succeed to reserve their own device id")
	}
	victimRes.Release()
	// Test 3: attacker trying to reserve an unused device should succeed.
	attackerRes, ok := srv.reserveDeviceID(attacker.ID, "brand-new-device-id")
	if !ok {
		t.Fatal("an unused device id should be reserved successfully")
	}
	attackerRes.Release()
}

// A registration that fails after reserving must not leave the id claimed.
//
// A leaked reservation is permanent: nothing sweeps an index entry the owner
// still holds, reserveDeviceID refuses the id to everyone afterwards, and every
// auth attempt against it burns a deviceLockout strike, because the owner lookup
// succeeds and only then finds no device. One transient SQLite error during
// re-pairing used to brick that phone until the process restarted.
func TestFailedRegistrationReleasesItsDeviceIDReservation(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	ownerID := all[0].ID

	res, ok := srv.reserveDeviceID(ownerID, "device-that-never-persists")
	if !ok {
		t.Fatal("reserve should succeed for an unused id")
	}
	res.Release() // the handler's deferred release, on a path that never committed

	srv.userMu.Lock()
	_, stillIndexed := srv.deviceIndex["device-that-never-persists"]
	inFlight := srv.deviceReserving["device-that-never-persists"]
	srv.userMu.Unlock()
	if stillIndexed {
		t.Fatal("a released reservation left the device id claimed; it is now unregisterable forever")
	}
	if inFlight != 0 {
		t.Fatalf("in-flight count = %d after release, want 0", inFlight)
	}

	// And the id is registerable again, by anyone.
	if _, ok := srv.reserveDeviceID(ownerID, "device-that-never-persists"); !ok {
		t.Fatal("the id should be reservable again after a released reservation")
	}
}

// Commit must win over the handler's deferred Release, which runs after it.
func TestCommitSurvivesTheDeferredRelease(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	ownerID := all[0].ID

	res, ok := srv.reserveDeviceID(ownerID, "committed-device")
	if !ok {
		t.Fatal("reserve should succeed")
	}
	res.Commit("committed-device")
	res.Release() // the deferred call, arriving after the commit

	srv.userMu.Lock()
	owner, indexed := srv.deviceIndex["committed-device"]
	srv.userMu.Unlock()
	if !indexed || owner != ownerID {
		t.Fatal("the deferred Release undid a committed registration")
	}
}

// A merged registration (upsert folded it into an existing row) must release the
// id the request asked for while indexing the one it actually landed under.
func TestCommitReleasesTheRequestedIDWhenTheUpsertMerged(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	ownerID := all[0].ID

	res, ok := srv.reserveDeviceID(ownerID, "requested-id")
	if !ok {
		t.Fatal("reserve should succeed")
	}
	res.Commit("actual-id-from-the-merge")
	res.Release()

	srv.userMu.Lock()
	_, requestedStillHeld := srv.deviceIndex["requested-id"]
	_, actualIndexed := srv.deviceIndex["actual-id-from-the-merge"]
	srv.userMu.Unlock()
	if requestedStillHeld {
		t.Fatal("the merged-away id is still claimed and can never be registered again")
	}
	if !actualIndexed {
		t.Fatal("the id the device actually landed under was not indexed")
	}
}

// deviceIndex was the one bounded map in this package with no sweeper. Residue
// there is not inert: it makes an id unregisterable and turns every attempt
// against it into a lockout strike.
func TestSweepDeviceIndexDropsResidueButKeepsLiveAndInFlight(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	ownerID := all[0].ID
	liveDeviceID, _ := pairNativeDevice(t, srv, ownerID, "live-device")

	// Residue: an entry with no device row behind it, e.g. one the daemon
	// removed as stale in the other process.
	srv.userMu.Lock()
	srv.deviceIndex["orphan-device"] = ownerID
	srv.userMu.Unlock()

	// In flight: reserved, not yet persisted. The sweep decides by looking at
	// disk, so without the exemption this is exactly what it would delete.
	inFlight, ok := srv.reserveDeviceID(ownerID, "in-flight-device")
	if !ok {
		t.Fatal("reserve should succeed")
	}
	defer inFlight.Release()

	if removed := srv.sweepDeviceIndex(); removed != 1 {
		t.Fatalf("removed = %d, want 1 (only the orphan)", removed)
	}

	srv.userMu.Lock()
	defer srv.userMu.Unlock()
	if _, ok := srv.deviceIndex["orphan-device"]; ok {
		t.Fatal("residue survived the sweep")
	}
	if _, ok := srv.deviceIndex[liveDeviceID]; !ok {
		t.Fatal("the sweep dropped a device that is on disk; it now costs a lockout strike per request")
	}
	if _, ok := srv.deviceIndex["in-flight-device"]; !ok {
		t.Fatal("the sweep dropped an in-flight reservation, reopening the concurrent-registration hijack")
	}
}

// Finding 2: a user flagged MustChangePassword must not be able to use any
// authenticated endpoint except the password-change (and logout) path — the
// flag must be enforced server-side, not merely surfaced to the client.
func TestMustChangePasswordBlocksOtherEndpoints(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("mcp-user", "initial-pass-123", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Create() sets MustChangePassword=true; inject a session directly (not via
	// authRequestAs, which intentionally clears the flag for onboarded tests).
	token := "mcp-session"
	csrf := "mcp-csrf"
	srv.sessMu.Lock()
	srv.sessions[token] = Session{UserID: u.ID, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrf}
	srv.sessMu.Unlock()

	// A normal authenticated endpoint must be refused.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /api/status while MustChangePassword: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// The password-change endpoint must remain reachable so the user can escape.
	body := []byte(`{"oldPassword":"initial-pass-123","newPassword":"a-brand-new-pass-456"}`)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	srv.routes().ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("POST /api/auth/password while MustChangePassword must NOT be blocked; got %d body=%s", rec.Code, rec.Body.String())
	}
}

// Finding 4: second-factor verification must be throttled per account across
// reissued challenges, not only per ephemeral challenge.
func TestMFALockoutIsPerAccountAcrossChallenges(t *testing.T) {
	srv := newTestServer(t)
	const userID = "user-abc"
	for i := 0; i < mfaMaxFailures; i++ {
		if ok, _ := srv.mfaLockout.lockedNow(userID); !ok {
			t.Fatalf("attempt %d: should be allowed before the cap", i+1)
		}
		_, _ = srv.mfaLockout.tryAttempt(userID)
	}
	if ok, _ := srv.mfaLockout.lockedNow(userID); ok {
		t.Fatal("second-factor attempts must be locked out for the account after the cap, regardless of new challenges")
	}
}

// TestMailUploadLimitsAreInternallyConsistent pins the relationship between the
// request-body cap and the attachment budget.
//
// These were two independently hand-picked numbers: a 25 MiB decoded attachment
// budget under a 40 MiB request cap. Attachments travel base64-encoded inside
// the JSON body (4/3 expansion), so 25 MiB of attachment needs ~33.3 MiB of
// body before any JSON scaffolding — meaning a send near the advertised
// attachment limit failed on the request cap instead, reporting the wrong limit
// at the wrong layer.
func TestMailUploadLimitsAreInternallyConsistent(t *testing.T) {
	// The user-facing upload cap.
	if maxMailRequestBytes != 25<<20 {
		t.Errorf("maxMailRequestBytes = %d, want %d (25 MiB)", maxMailRequestBytes, 25<<20)
	}

	// The attachment budget must be reachable: base64 of a maximum-size
	// attachment set, plus the reserved overhead, must fit inside the body cap.
	encoded := int64(maxMailAttachmentBytes) * 4 / 3
	if encoded+mailRequestOverheadBytes > maxMailRequestBytes {
		t.Errorf("a full %d-byte attachment set base64-encodes to %d bytes, which with %d bytes of "+
			"overhead exceeds the %d-byte request cap — the attachment limit is unreachable",
			maxMailAttachmentBytes, encoded, mailRequestOverheadBytes, maxMailRequestBytes)
	}

	// And it must not be pointlessly small either: within a MiB of the most that
	// could fit, or we are refusing uploads the cap would allow.
	if maxMailRequestBytes-(encoded+mailRequestOverheadBytes) > 1<<20 {
		t.Errorf("attachment budget %d wastes %d bytes of the request cap",
			maxMailAttachmentBytes, maxMailRequestBytes-(encoded+mailRequestOverheadBytes))
	}
}

// TestUploadRoutesGetAnExtendedReadDeadline guards the pairing of the 25 MiB
// body cap with a read deadline that can actually accommodate it.
//
// http.Server's ReadTimeout covers the body, so at 60 s a 25 MiB upload
// requires a sustained 3.5 Mbit/s — which mobile and DSL uplinks do not
// provide. The routes that accept an upload must therefore extend it.
func TestUploadRoutesGetAnExtendedReadDeadline(t *testing.T) {
	if uploadReadDeadline < 5*time.Minute {
		t.Errorf("uploadReadDeadline = %v, too short for a %d-byte upload on a slow uplink",
			uploadReadDeadline, maxMailRequestBytes)
	}

	// A 25 MiB body must be transferable inside the deadline at a rate a phone
	// on cellular can actually sustain (~1 Mbit/s).
	const slowUplinkBytesPerSec = 1_000_000 / 8
	needed := time.Duration(maxMailRequestBytes/slowUplinkBytesPerSec) * time.Second
	if uploadReadDeadline < needed {
		t.Errorf("uploadReadDeadline = %v but a %d-byte upload at 1 Mbit/s needs %v",
			uploadReadDeadline, maxMailRequestBytes, needed)
	}
}
