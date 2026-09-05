package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/totp"
	"github.com/Busness-app/kypost-server/backend/internal/mfa"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// Re-authentication for a whole surface rather than for one operation.
//
// pgp_stepup.go gates the individual calls that replace or destroy a PGP
// identity, and it gates them on the account credential alone. This endpoint is
// the coarser thing the Security page asks for before it renders anything: prove
// the credential AND the second factor, right now.
//
// The two are not redundant. The per-operation gates answer "may this request
// happen"; they are the security boundary and stay exactly where they are. This
// one answers "should this screen be legible to whoever is sitting here" — the
// unattended-session case, where the session is genuine and the person is not.
// A caller who skips the page and posts straight to the endpoints gets nowhere
// new, because every endpoint that matters still re-verifies for itself.
//
// It deliberately records nothing. There is no "stepped-up session" flag to
// mint, expire, or forget to check, because no server-side decision is made
// from the result — the client asks, the server answers, and the client decides
// what to draw. Adding session state here would look like an authorisation
// boundary without being one.

// totpCodeShape distinguishes a TOTP code from a recovery code by shape, so a
// mistyped six-digit code is never run through ConsumeRecoveryCode. That call
// still derives scrypt for every legacy-format code an account holds, and an
// authenticated caller should not be able to spend that by fat-fingering a
// digit. Recovery codes are xxxx-xxxx-xxxx (see mfa.GenerateRecoveryCodes) and
// can never collide with this.
var totpCodeShape = regexp.MustCompile(`^[0-9]{6}$`)

func (s *Server) handleAuthStepUp(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Password string `json:"password"`
		// AuthSecret is the client-derived credential, for an account whose
		// password never reaches this server. See login_params.go.
		AuthSecret string `json:"authSecret,omitempty"`
		Code       string `json:"code,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Credential first, and on the same throttle every other step-up uses. The
	// second factor is only worth checking once the first one holds, and
	// checking it first would turn this into a free TOTP oracle for anyone
	// holding a stolen session.
	// Deliberately WITHOUT clearing the throttle on success: this endpoint spends
	// the same per-account counter twice, once per factor, and clearing it between
	// them left the second factor with no throttle at all.
	//
	// confirmAccountCredential's recordSuccess DELETES the account's entry
	// (failureLockout.recordSuccess), so a correct credential reset the counter to
	// zero and confirmSecondFactor's tryAttempt then started from one — every
	// request, forever. mfaMaxFailures could never be reached, and the comment on
	// confirmSecondFactor's throttle ("six digits do not survive one") described a
	// control that was not running. The success is recorded once, below, after
	// BOTH factors hold.
	if !s.confirmAccountCredentialNoRecord(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if u.TOTPEnabled && !s.confirmSecondFactor(w, r, u, strings.TrimSpace(req.Code)) {
		return
	}
	// One success per counter: the credential half runs on the (account,
	// address)-keyed step-up throttle, the second-factor half on the
	// account-wide mfaLockout. They were a single counter, which is what let a
	// wrong password here deny the owner their own TOTP.
	s.passwordChangeLockout.recordSuccess(stepUpLockoutKey(ac.UserID, r))
	s.mfaLockout.recordSuccess(ac.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// confirmSecondFactor verifies a TOTP code, or a one-time recovery code in its
// place, for an account that has TOTP enabled. It writes the response and
// returns false on any failure.
//
// Recovery codes are accepted here for the same reason login accepts them: a
// user whose authenticator is gone logs in with a recovery code, and the Security
// page is the only place they can turn TOTP off. TOTP-only here would let them
// in the front door and lock the door they came for. The code is consumed, as
// one-time codes are — the alternative is a second credential that survives
// unlimited reuse.
func (s *Server) confirmSecondFactor(w http.ResponseWriter, r *http.Request, u users.User, code string) bool {
	if code == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "a two-factor code is required", "totpRequired": true})
		return false
	}
	if u.TOTPSecretEnc == "" {
		http.Error(w, "two-factor auth is not usable on this account", http.StatusConflict)
		return false
	}
	// Per-account throttle, the same one the login MFA path uses. An endpoint
	// that says "wrong code" without limit is a brute-force target whatever
	// else it is for, and six digits do not survive one.
	if allowed, _ := s.mfaLockout.tryAttempt(u.ID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return false
	}

	if totpCodeShape.MatchString(code) {
		secret, err := mfa.OpenTOTPSecret(u.TOTPSecretEnc, s.totpSecretKeyPath)
		if err != nil {
			s.mfaLockout.cancelAttempt(u.ID)
			http.Error(w, "failed to load second factor", http.StatusInternalServerError)
			return false
		}
		step, valid := totp.Validate(secret, code, time.Now())
		if !valid {
			http.Error(w, "invalid code", http.StatusUnauthorized)
			return false
		}
		// The per-account replay guard, shared with the login challenge
		// (server_auth_session.go) and with enrollment (mfa_handlers.go).
		// LastUsedTOTPStep is scoped to the ACCOUNT, so a code spent here is
		// spent everywhere, and a code already spent at login cannot be
		// re-presented here inside the same window.
		//
		// Unlike the login path this says so plainly instead of answering like
		// a wrong code. The caller has already proved the account credential,
		// so there is nothing left to leak to them — and the case is common
		// enough (log in with a code, walk straight to this page, authenticator
		// still showing the same digits) that a bare "invalid code" would send
		// people hunting for a problem that does not exist.
		if _, err := s.users.SetLastUsedTOTPStep(u.ID, step); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "that code was already used — wait for your authenticator to show the next one",
			})
			return false
		}
		s.mfaLockout.recordSuccess(u.ID)
		return true
	}

	// A KDF slot per comparison rather than one around the whole call, for the
	// reason spelled out on handleMFARecoveryCode: a miss is up to
	// recoveryCodeCount derivations at 128 MiB each, and holding one slot
	// across all of them parks a large share of the instance's derivation
	// capacity. The request context passes straight through.
	_, matched, err := s.users.ConsumeRecoveryCode(r.Context(), u.ID, code, s.recoveryCodeDigest)
	switch {
	case errors.Is(err, errKDFBusy), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Shed mid-check: no verdict was reached, so the strike goes back.
		s.mfaLockout.cancelAttempt(u.ID)
		writeKDFBusy(w)
		return false
	case err != nil:
		s.mfaLockout.cancelAttempt(u.ID)
		http.Error(w, "failed to verify recovery code", http.StatusInternalServerError)
		return false
	}
	if !matched {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return false
	}
	s.mfaLockout.recordSuccess(u.ID)
	return true
}
