package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
)

// Headers a paired native client presents on every ongoing request (mail
// sync, contacts sync, App Pull, push-MFA-approve, self-deregister) to prove
// it is a specific device that is still in the account's NativeDevices list.
// Each device has its own secret minted at registration time — there is no
// account-wide shared secret and no legacy query-param fallback.
const (
	headerDeviceID     = "X-Kypost-Device-Id"
	headerDeviceSecret = "X-Kypost-Device-Secret"
)

func deviceCredentialsFromRequest(r *http.Request) (deviceID, deviceSecret string) {
	return strings.TrimSpace(r.Header.Get(headerDeviceID)), r.Header.Get(headerDeviceSecret)
}

// deviceLockoutKey scopes the device brute-force lockout to (deviceID,
// clientIP) rather than deviceID alone.
//
// The routes that authenticate this way — /api/notifications/native/pull and
// /deregister — carry no other credential, so a bare deviceID key let anyone
// who learned a device id keep that device permanently locked out of mail
// sync, contacts sync and push-MFA approval by burning its strike budget from
// anywhere. handleLogin keys on username+clientIP for exactly this reason; the
// reasoning simply had not been carried over here.
//
// One definition, used by the auth path and by the tests that inspect the
// lockout map, so the two cannot drift.
func (s *Server) deviceLockoutKey(deviceID string, r *http.Request) string {
	return deviceID + "\x00" + clientIP(r)
}

// deviceAuthFromRequest resolves and authenticates the paired device calling
// r: it extracts deviceId/deviceSecret from headers, finds which user owns
// deviceId, loads that user's live NativeDevice record by ID, and verifies
// deviceSecret against the stored SecretHash. ok=false covers missing
// headers, an unknown device, a wrong secret, and a deviceId that once
// existed but has since been removed (unpaired) — that last case is what
// makes removing a device an immediate, real revocation.
//
// retryAfter is nonzero exactly when deviceID is currently locked out after
// deviceMaxFailures failed attempts (see s.deviceLockout); callers must
// distinguish this ("come back later") from an ordinary ok=false ("bad
// credentials") and answer 429 rather than 401 — see writeDeviceAuthFailure.
// Every failure branch below that follows a lockout check pays (or would pay,
// for an unregistered deviceID) toward that deviceID's strike count; a
// correct secret against a deactivated account does not, since the secret
// itself was valid and brute-forcing it is not what happened.
func (s *Server) deviceAuthFromRequest(r *http.Request) (userID string, device state.NativeDevice, ok bool, retryAfter time.Duration) {
	deviceID, deviceSecret := deviceCredentialsFromRequest(r)
	if deviceID == "" || deviceSecret == "" {
		return "", state.NativeDevice{}, false, 0
	}
	lockoutKey := s.deviceLockoutKey(deviceID, r)
	if allowed, wait := s.deviceLockout.tryAttempt(lockoutKey); !allowed {
		return "", state.NativeDevice{}, false, wait
	}
	ownerID, okOwner := s.lookupUserByDevice(deviceID)
	if !okOwner {
		return "", state.NativeDevice{}, false, 0
	}
	store, err := s.userStore(ownerID)
	if err != nil {
		return "", state.NativeDevice{}, false, 0
	}
	dev, okDev := store.GetNativeDevice(deviceID)
	if !okDev {
		return "", state.NativeDevice{}, false, 0
	}
	if !users.VerifySecretHash(dev.SecretHash, deviceSecret) {
		return "", state.NativeDevice{}, false, 0
	}
	// Honor account deactivation on the device path the same way currentUser
	// does on the session path: a deactivated (offboarded/compromised) account
	// must lose device access immediately, not keep it until the device secret
	// is separately purged. Without this check, deactivation/password-reset
	// silently fail to revoke a paired device.
	//
	// cancelAttempt, not a bare return: the secret was CORRECT, so no guessing
	// happened and the strike tryAttempt reserved on the way in must go back.
	// Leaving it counted (which is what a bare return does) meant a deactivated
	// account's phone burned all deviceMaxFailures within seconds of its normal
	// retry cadence and then got 429 instead of 401 — so a client reading
	// writeDeviceAuthFailure's documented contract backs off forever instead of
	// telling its user to re-pair.
	u, err := s.users.Get(ownerID)
	if err != nil || !u.Active {
		s.deviceLockout.cancelAttempt(lockoutKey)
		return "", state.NativeDevice{}, false, 0
	}
	s.deviceLockout.recordSuccess(lockoutKey)
	return ownerID, dev, true, 0
}

// writeDeviceAuthFailure writes the HTTP response for a failed
// deviceAuthFromRequest call: 429 with a Retry-After header when retryAfter
// is nonzero (the deviceID is locked out), 401 otherwise (missing/unknown/
// wrong credentials). Shared by every handler that authenticates directly
// via deviceAuthFromRequest and writes to w itself; server_userscope.go's
// resolveMailAuthContext doesn't have a ResponseWriter at that point, so it
// signals the same distinction via a sentinel error instead (see
// mailLockedOutError in server_userscope.go).
func writeDeviceAuthFailure(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	http.Error(w, "invalid device credentials", http.StatusUnauthorized)
}
