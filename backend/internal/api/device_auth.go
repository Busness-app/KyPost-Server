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

// maxDeviceSecretLen bounds the secret header. Minted secrets are a fixed
// 192-bit random value in hex/base64; nothing legitimate approaches this.
const maxDeviceSecretLen = 512

// deviceCredentialsFromRequest reads the two device headers, rejecting any
// value too long to have been registered.
//
// The length bound is load-bearing, not tidiness. deviceID reaches
// deviceLockoutKey, which is a map key held for deviceLockoutFor — so an
// unbounded header is an unbounded allocation an unauthenticated caller
// chooses the size of. Go's DefaultMaxHeaderBytes is a 1 MiB TOTAL per
// connection with no per-header limit, so a single request could park a
// megabyte in the lockout table. maxDeviceTextLen is the same cap
// handleNativeRegister applies when a device id is stored, so a longer one
// could never have been registered and there is nothing to authenticate.
func deviceCredentialsFromRequest(r *http.Request) (deviceID, deviceSecret string) {
	deviceID = strings.TrimSpace(r.Header.Get(headerDeviceID))
	deviceSecret = r.Header.Get(headerDeviceSecret)
	if len(deviceID) > maxDeviceTextLen || len(deviceSecret) > maxDeviceSecretLen {
		return "", ""
	}
	return deviceID, deviceSecret
}

// deviceLockoutKey scopes the device brute-force lockout to (deviceID,
// clientIP), so anyone who learns a device id cannot lock that device out of
// mail sync, contacts sync and push-MFA approval by burning its strike budget
// from an unrelated address. handleLogin keys on username+clientIP likewise.
//
// Per-IP scoping bounds guessing, not CPU: an attacker with many addresses
// gets a fresh budget at each — across distinct prefixes, at least, since the
// address is folded to a /64 for IPv6 (see lockoutKeyForIP). That is only
// acceptable because verification is a SHA-256 compare
// (users.VerifyDeviceSecret). Never make it expensive again without re-keying
// this.
//
// One definition, shared with the tests that inspect the lockout map.
func (s *Server) deviceLockoutKey(deviceID string, r *http.Request) string {
	return deviceID + "\x00" + lockoutKeyForIP(clientIP(r))
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
// Every failure branch below that follows the lockout check pays toward that
// deviceID's strike count; a correct secret against a deactivated account
// does not, since the secret itself was valid and brute-forcing it is not
// what happened.
//
// The lockout is spent only once the deviceID has been resolved to a device
// that actually exists. Reserving a strike first — which is what this did —
// let an unauthenticated caller mint a lockout entry per invented device id.
// tryAttempt sheds NEW keys at loginLockoutHardCap and recordSuccess DELETES
// an entry on every success, so a healthy paired device is always a new key:
// 50,000 anonymous requests filled the table and every genuine device, with
// the correct secret from an unrelated address, got 429 until the cooldown
// expired. Resolving first means only a real, currently-paired device id can
// occupy a slot, and an unknown id costs one throttled map lookup.
//
// The reservation still precedes the credential comparison, which is what
// tryAttempt's doc requires — the concurrent-burst property is unchanged.
func (s *Server) deviceAuthFromRequest(r *http.Request) (userID string, device state.NativeDevice, ok bool, retryAfter time.Duration) {
	deviceID, deviceSecret := deviceCredentialsFromRequest(r)
	if deviceID == "" || deviceSecret == "" {
		return "", state.NativeDevice{}, false, 0
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
	lockoutKey := s.deviceLockoutKey(deviceID, r)
	if allowed, wait := s.deviceLockout.tryAttempt(lockoutKey); !allowed {
		return "", state.NativeDevice{}, false, wait
	}
	// A legacy (pre-HashDeviceSecret) device secret still verifies through
	// scrypt, so this can shed. Both outcomes deny the request here; the
	// difference is that a shed one must not be cached as a failure, which is
	// what cancelAttempt below already arranges for the other correct-secret
	// paths.
	okSecret, err := users.VerifyDeviceSecret(r.Context(), dev.SecretHash, deviceSecret)
	if err != nil || !okSecret {
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
	// MustChangePassword confines a SESSION to the password-change and logout
	// routes (see withAuth and withMailAuth). A device credential was exempt
	// from that entirely, which mattered because an admin password reset is the
	// standard response to a compromised account: it sets this flag, and a
	// device credential minted around that moment kept full mail and contacts
	// access on an account the admin had just confined.
	//
	// Refused rather than confined: unlike a browser, a device has nothing
	// useful to do inside the confinement — it cannot present the
	// password-change form — so the honest answer is that this credential is
	// not usable until the account's owner completes the change.
	//
	// cancelAttempt for the same reason as the deactivation branch above: the
	// secret was correct, so the strike goes back rather than backing the client
	// off forever.
	if u.MustChangePassword {
		s.deviceLockout.cancelAttempt(lockoutKey)
		return "", state.NativeDevice{}, false, 0
	}
	s.deviceLockout.recordSuccess(lockoutKey)
	return ownerID, dev, true, 0
}

// meterDeviceWrite applies the per-account write meter to a device-authenticated
// MUTATING route. Call it after deviceAuthFromRequest has succeeded; it reports
// whether the handler should continue.
//
// withAuth, withMailAuth and withDAVBasicAuth all call meterAccountWrite, so
// every other credential type is capped at accountWriteBurst. withDeviceAuth
// cannot: it is an inert marker (route_auth_markers.go) with no shared
// middleware to hang the call on, so commit a8904dd — "meter every auth
// wrapper" — closed the other three legs and left this one. Four mutating
// routes accepted an unbounded request rate as a result, which left a device
// credential STRONGER than a session on this one axis while the trust model
// ranks it weaker.
//
// Called explicitly at each site rather than folded into deviceAuthFromRequest:
// that function is used by seven production call sites and roughly thirty
// tests, and it has no ResponseWriter, so metering inside it would mean
// churning all of them to reach four. Explicit also keeps the double-response
// hazard visible — meterAccountWrite writes its own 429, so a caller must
// return immediately rather than fall through to writeDeviceAuthFailure.
//
// Safe on a handler serving both verbs: meterAccountWrite returns true
// immediately for GET, HEAD and OPTIONS, so reads are never throttled.
func (s *Server) meterDeviceWrite(w http.ResponseWriter, r *http.Request, userID string) bool {
	return s.meterAccountWrite(w, r, userID)
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
