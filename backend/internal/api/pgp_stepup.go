package api

import (
	"net/http"

	"kypost-server/backend/internal/users"
)

// Step-up authentication for the operations that replace or destroy a PGP
// identity.
//
// A session cookie is a bearer token. Everything else it authorises is bounded
// by the session's own lifetime — read the mail, send a message, change a
// setting — and ends when the session does. Replacing the published public key
// is not: it outlives the session, it redirects every future correspondent to a
// key the attacker holds, and WKD and Autocrypt publish it for them. Deleting
// the identity is worse still and is not undoable at all — mail already
// encrypted to that key stays unreadable.
//
// So these three take the same standard the one endpoint that hands back a
// private key already took (handlePGPExportLegacyKey): the account password,
// re-entered now, not merely a session that once involved one.
//
// It does NOT gate first-time setup. An account with no identity yet has
// nothing to lose to this attack — there is no key to replace and none to
// strand — and requiring a password to create one would put a credential prompt
// in the middle of onboarding to protect nothing.

// pgpStepUpRequired reports whether this account already has a PGP identity, and
// so whether replacing or destroying it needs a fresh credential.
func pgpStepUpRequired(u users.User) bool {
	return u.PGPProtection() != "" || u.PGPFingerprint != ""
}

// confirmAccountCredential verifies a re-entered account credential, writing
// the response and returning false if it does not check out.
//
// password and authSecret are the two forms a caller may present; which one is
// checked depends on what the ACCOUNT stores, not on what arrives — see
// verifyAccountCredential and login_params.go. A client-protected account never
// sends its password to this server at all, so requiring one here would make
// the step-up impossible for exactly the accounts that have most to protect.
//
// Rate-limited on the same per-account throttle the MFA path uses, because an
// endpoint that says "wrong password" without limit is a password oracle
// whatever else it is for.
func (s *Server) confirmAccountCredential(w http.ResponseWriter, r *http.Request, userID, password, authSecret string) bool {
	u, err := s.users.Get(userID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return false
	}
	if allowed, _ := s.mfaLockout.tryAttempt(userID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return false
	}
	confirmed, err := verifyAccountCredential(r.Context(), u, password, authSecret)
	if err != nil {
		// Nothing was checked, so the throttle strike goes back with it.
		s.mfaLockout.cancelAttempt(userID)
		writeKDFBusy(w)
		return false
	}
	if !confirmed {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return false
	}
	s.mfaLockout.recordSuccess(userID)
	return true
}

// requirePGPStepUp gates an operation that would replace or destroy an existing
// PGP identity. It returns true when the caller may proceed: either because
// there is no identity to protect yet, or because they just proved the account
// credential.
func (s *Server) requirePGPStepUp(w http.ResponseWriter, r *http.Request, userID, password, authSecret string) bool {
	u, err := s.users.Get(userID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return false
	}
	if !pgpStepUpRequired(u) {
		return true
	}
	return s.confirmAccountCredential(w, r, userID, password, authSecret)
}
