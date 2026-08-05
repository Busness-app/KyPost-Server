package api

import (
	"net/http"
	"strconv"
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
// So these take the same standard the one endpoint that hands back a private
// key already took (handlePGPExportLegacyKey): the account password, re-entered
// now, not merely a session that once involved one.
//
// This includes FIRST-TIME setup, and it did not. The carve-out reasoned that
// "an account with no identity yet has nothing to lose", which is true of the
// asset the operation destroys and false of the asset it creates. A hijacked
// session could POST /api/pgp/identity/client with no credential of any kind
// and install an attacker-held key as the victim's published identity;
// PublishWKD and AdvertiseAutocrypt both default true, so the victim's outbound
// mail then advertises it and WKD serves it to every correspondent. A
// five-minute hijack became a permanent published-key substitution that
// outlives the session — precisely the durability property cited two paragraphs
// up to justify gating identity REPLACEMENT.
//
// The onboarding cost the carve-out was avoiding turns out not to exist: every
// client-custody path already had the password in hand, because it wraps the
// private key with it.

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
	if !s.confirmAccountCredentialNoRecord(w, r, userID, password, authSecret) {
		return false
	}
	s.passwordChangeLockout.recordSuccess(stepUpLockoutKey(userID, r))
	return true
}

// stepUpLockoutKey keys credential-confirmation attempts on the acting account
// AND the client address.
//
// This is deliberately NOT mfaLockout's key space. mfaLockout is account-wide on
// purpose — a password holder can mint unlimited fresh sign-in challenges, so
// only a cross-challenge account counter keeps a six-digit TOTP code out of
// reach of online guessing. Spending that same counter on a PASSWORD check let
// anyone holding a stolen session exhaust the owner's second-factor and
// recovery-code budget from their own machine, turning the control into the
// attack.
//
// A password is a high-entropy secret, so it can be throttled the way
// handleChangePassword throttles the same secret: per (account, address). The
// two counters guard different things and must not be shared.
func stepUpLockoutKey(userID string, r *http.Request) string {
	return clampLockoutKeyComponent(userID) + "\x00" + lockoutKeyForIP(clientIP(r))
}

// confirmAccountCredentialNoRecord is confirmAccountCredential without clearing
// the account's failure counter on success.
//
// For a caller that checks ONE factor, clearing on success is right: the caller
// proved the credential, so accumulated failures are forgiven. For a caller that
// goes on to check a SECOND factor on the same counter it is not — recordSuccess
// deletes the entry outright, so the second check would start from zero on every
// request and its throttle would never fire. Such a caller uses this and records
// the success itself once every factor has passed. See handleAuthStepUp.
func (s *Server) confirmAccountCredentialNoRecord(w http.ResponseWriter, r *http.Request, userID, password, authSecret string) bool {
	u, err := s.users.Get(userID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return false
	}
	lockKey := stepUpLockoutKey(userID, r)
	if allowed, _ := s.passwordChangeLockout.tryAttempt(lockKey); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return false
	}
	confirmed, err := verifyAccountCredential(r.Context(), u, password, authSecret)
	if err != nil {
		// Nothing was checked, so the throttle strike goes back with it.
		s.passwordChangeLockout.cancelAttempt(lockKey)
		writeKDFBusy(w)
		return false
	}
	if !confirmed {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return false
	}
	return true
}

// requirePGPStepUp gates an operation that creates, replaces or destroys a PGP
// identity. It returns true when the caller may proceed, which now means only
// one thing: they just proved the account credential.
func (s *Server) requirePGPStepUp(w http.ResponseWriter, r *http.Request, userID, password, authSecret string) bool {
	return s.confirmAccountCredential(w, r, userID, password, authSecret)
}

// clearDeviceEnrollmentsFor resets every paired device's enrollment state after
// the account's PGP identity is written or cleared.
//
// This mirrors, in the other store, what users.Store already does for
// PGPWrappedEnvelopes on those same writes: every non-password slot seals the
// OLD key, so an identity change invalidates them all. The enrollment record
// lives in state.Store, which users.Store has no coupling to, so the two halves
// cannot be done in one place and this must be called at each identity write.
//
// It matters most in the flow it otherwise breaks. Rotating the identity is the
// documented way to un-enroll a lost phone — the server cannot reach the copy
// that phone re-sealed into its own keystore — so a user rotating their key is
// often doing it *to revoke*. Leaving the marker set meant the Security page
// went on reporting that phone as protected immediately afterwards.
//
// Failure is logged, not fatal. The identity write has already committed by the
// time this runs, and refusing the request afterwards would report failure for
// something that happened. A stale marker is a wrong indicator; a caller who
// retries because they were told the write failed can do worse.
func (s *Server) clearDeviceEnrollmentsFor(userID, reason string) {
	store, err := s.userStore(userID)
	if err != nil {
		s.logger.Error("could not open state to clear device enrollment",
			"user_id", userID, "reason", reason, "error", err.Error())
		return
	}
	n, err := store.ClearDeviceEnrollments()
	if err != nil {
		s.logger.Error("could not clear device enrollment after an identity change",
			"user_id", userID, "reason", reason, "error", err.Error())
		return
	}
	if n > 0 {
		s.logger.Info("cleared device enrollment after an identity change",
			"user_id", userID, "reason", reason, "devices", strconv.Itoa(n))
	}
}
