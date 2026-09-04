package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/state"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// Headers a paired native client presents on every ongoing request (mail
// sync, contacts sync, App Pull, push-MFA-approve, self-deregister) to prove
// it is a specific device that is still in the account's NativeDevices list.
// Each device has its own secret minted at registration time — there is no
// account-wide shared secret and no legacy query-param fallback.
const (
	// maxDeviceIDLen matches users.maxDeviceSlotIDLen: a device id becomes the
	// `device:<id>` envelope slot name, so the two bounds must not disagree.
	maxDeviceIDLen = 128

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

// retryAfterKDFBusy is the retryAfter deviceAuthFromRequest returns when the
// device secret was never compared because the derivation slots were saturated.
// Negative so it can never read as a lockout cooldown — every caller tests
// retryAfter > 0 for that — and so writeDeviceAuthFailure can answer
// writeKDFBusy's 503, which is what every other shed path in this package does.
const retryAfterKDFBusy = -1 * time.Second

// deviceAuthFromRequest resolves and authenticates the paired device calling
// r: it extracts deviceId/deviceSecret from headers, finds which user owns
// deviceId, loads that user's live NativeDevice record by ID, and verifies
// deviceSecret against the stored SecretHash. ok=false covers missing
// headers, an unknown device, a wrong secret, and a deviceId that once
// existed but has since been removed (unpaired) — that last case is what
// makes removing a device an immediate, real revocation.
//
// retryAfter is positive exactly when deviceID is currently locked out after
// deviceMaxFailures failed attempts (see s.deviceLockout), and
// retryAfterKDFBusy when the secret was never checked because the derivation
// slots were saturated; callers must distinguish both ("come back later") from
// an ordinary ok=false ("bad credentials") and answer 429 or 503 rather than
// 401 — see writeDeviceAuthFailure. Every failure branch below that follows the
// lockout check pays toward that deviceID's strike count; a correct secret
// against a deactivated account does not, since the secret itself was valid and
// brute-forcing it is not what happened, and neither does a shed one, since no
// secret was examined at all.
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
	// scrypt, so this can shed. An error means the secret was never COMPARED —
	// users.ErrKDFBusy, or this request's context going away — while a stored
	// hash that is malformed rather than merely wrong comes back (false, nil)
	// and is an ordinary credential failure. So a shed refunds its strike and
	// answers busy, exactly as every other derivation call site here does;
	// counting it would lock a phone out of mail sync over a load spike.
	okSecret, err := users.VerifyDeviceSecret(r.Context(), dev.SecretHash, deviceSecret)
	if err != nil {
		s.deviceLockout.cancelAttempt(lockoutKey)
		return "", state.NativeDevice{}, false, retryAfterKDFBusy
	}
	if !okSecret {
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
// deviceAuthFromRequest call: 503 with Retry-After when the secret could not be
// checked at all (retryAfterKDFBusy), 429 with a Retry-After header when
// retryAfter is positive (the deviceID is locked out), 401 otherwise
// (missing/unknown/wrong credentials). Shared by every handler that
// authenticates directly via deviceAuthFromRequest and writes to w itself;
// server_userscope.go's resolveMailAuthContext doesn't have a ResponseWriter at
// that point, so it signals the same distinctions via a sentinel error instead
// (see mailLockedOutError in server_userscope.go).
func writeDeviceAuthFailure(w http.ResponseWriter, retryAfter time.Duration) {
	if retryAfter == retryAfterKDFBusy {
		writeKDFBusy(w)
		return
	}
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
		return
	}
	http.Error(w, "invalid device credentials", http.StatusUnauthorized)
}

// validDeviceID reports whether a NEW device id is safe to hash.
//
// deviceId is client-chosen and becomes part of the enrollment code's hash
// preimage: SHA-256(rawKey ‖ uint16BE(len(idUtf8)) ‖ idUtf8 ‖ uint64BE(bucket)).
// Three independent implementations — browser, Android, Qt — must produce the
// same bytes from the same id, and the spec mandates UTF-8 and a length prefix
// but says nothing about normalisation or character set.
//
// That gap is dangerous out of proportion to its size. If any implementation
// normalises differently (NFC vs NFD), or a JSON round-trip alters the string,
// the derived codes never match — and the browser reports a mismatch as "the
// key this server gave the browser is not the key on that device", the most
// alarming message in the product. A user cannot tell that apart from a hostile
// server. An encoding bug would present as an attack.
//
// Restricting new ids to an unambiguous ASCII subset removes the class rather
// than documenting a rule nothing enforces. The set is deliberately narrow:
// every character survives UTF-8, NFC and NFD identically, and none of them
// needs escaping in the `device:<id>` envelope slot name.
func validDeviceID(id string) bool {
	if id == "" || len(id) > maxDeviceIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == ':', r == '-':
		default:
			return false
		}
	}
	return true
}
