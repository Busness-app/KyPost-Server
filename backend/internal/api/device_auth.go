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
// clientIP), so anyone who learns a device id cannot lock that device out of
// mail sync, contacts sync and push-MFA approval by burning its strike budget
// from an unrelated address. handleLogin keys on username+clientIP likewise.
//
// Per-IP scoping bounds guessing, not CPU: an attacker with many addresses
// gets a fresh budget at each. That is only acceptable because verification is
// a SHA-256 compare (users.VerifyDeviceSecret). Never make it expensive again
// without re-keying this.
//
// One definition, shared with the tests that inspect the lockout map.
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
	if !users.VerifyDeviceSecret(dev.SecretHash, deviceSecret) {
		return "", state.NativeDevice{}, false, 0
	}
	// Deactivation must revoke device access immediately, exactly as
	// currentUser enforces it on the session path — not only once the device
	// secret is separately purged.
	//
	// cancelAttempt, not a bare return: the secret was CORRECT, so the strike
	// goes back. Counting it would burn a deactivated account's phone through
	// deviceMaxFailures at its normal retry cadence and answer 429, so a client
	// following writeDeviceAuthFailure's contract backs off forever instead of
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
