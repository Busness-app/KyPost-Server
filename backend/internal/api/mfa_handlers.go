package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/ky-primitives/totp"
	"github.com/Busness-app/kypost-server/backend/internal/mfa"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// mfaTOTPIssuer is the issuer label shown by authenticator apps.
const mfaTOTPIssuer = "KyPost"

// recoveryCodeCount is how many one-time recovery codes are minted at
// enrollment and on regeneration.
const recoveryCodeCount = 10

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	// Deliberately not named approverDevices: that identifier is a
	// package-level function (push_mfa_handlers.go) computing the fanout
	// set for an active challenge; this local variable lists every paired
	// device (with its raw approver flag) for the management UI, which is a
	// different, broader set on purpose.
	deviceStatuses := []map[string]any{}
	if store, err := s.userStore(ac.UserID); err == nil {
		devices, err := store.ListNativeDevicesStrict()
		if err != nil {
			http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
			return
		}
		for _, d := range devices {
			// canApprove tells the UI whether this device's transport may carry
			// a challenge at all, so it can explain the exclusion rather than
			// offer a toggle that silently does nothing.
			entry := map[string]any{
				"deviceId":   d.DeviceID,
				"deviceName": d.DeviceName,
				"platform":   d.Platform,
				"approver":   d.MFAApprover,
				"canApprove": MFATransportEligible(d),
			}
			if !MFATransportEligible(d) {
				entry["cannotApproveReason"] = "UnifiedPush delivery cannot carry sign-in approvals: the request includes sign-in details and would cross an unencrypted public broker. Mail notifications still work."
			}
			deviceStatuses = append(deviceStatuses, entry)
		}
	} else {
		http.Error(w, "failed to open user state", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totpEnabled":            u.TOTPEnabled,
		"recoveryCodesRemaining": len(u.RecoveryCodesHash),
		"pushMfaEnabled":         u.PushMFAEnabled,
		"approverDevices":        deviceStatuses,
	})
}

func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if u.TOTPEnabled {
		http.Error(w, "two-factor auth is already enabled; disable it first", http.StatusConflict)
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		http.Error(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}
	sealed, err := mfa.SealTOTPSecret(secret, s.totpSecretKeyPath)
	if err != nil {
		http.Error(w, "failed to secure secret", http.StatusInternalServerError)
		return
	}
	if _, err := s.users.SetPendingTOTPSecret(u.ID, sealed); err != nil {
		http.Error(w, "failed to stage secret", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":     secret,
		"otpauthUri": totp.ProvisioningURI(mfaTOTPIssuer, u.Username, secret),
	})
}

func (s *Server) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// Decoded in one pass: the credential travels in the same body as the code,
	// so this cannot go through requirePasswordConfirm (which consumes r.Body).
	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
		// AuthSecret is the client-derived credential, for an account whose
		// password never reaches this server. See login_params.go.
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	// Re-authenticate before INSTALLING the factor, mirroring handleMFADisable
	// and handleMFARecoveryCodesRegenerate. The asymmetry was the bug: removing
	// a factor was gated and adding one was not, so a stolen session could
	// enrol a secret the owner does not hold and take all ten recovery codes —
	// and a password change clears no MFA state, so it survived the victim's
	// own remediation. Checked here rather than at setup because handing out a
	// secret is harmless; committing it is not.
	if allowed, retryAfter := s.loginLockout.tryAttempt(mfaConfirmLockoutKey(ac, r)); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return
	}
	confirmed, err := verifyAccountCredential(r.Context(), u, req.Password, req.AuthSecret)
	if err != nil {
		// Shed before the derivation ran: nothing was examined, so the strike
		// tryAttempt just spent goes back. Charging it would let a load spike
		// lock an account out of enrolling a second factor.
		s.loginLockout.cancelAttempt(mfaConfirmLockoutKey(ac, r))
		writeKDFBusy(w)
		return
	}
	if !confirmed {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	s.loginLockout.recordSuccess(mfaConfirmLockoutKey(ac, r))
	if u.TOTPEnabled {
		http.Error(w, "two-factor auth is already enabled", http.StatusConflict)
		return
	}
	if u.TOTPSecretEnc == "" {
		http.Error(w, "start setup before confirming", http.StatusBadRequest)
		return
	}
	secret, err := mfa.OpenTOTPSecret(u.TOTPSecretEnc, s.totpSecretKeyPath)
	if err != nil {
		http.Error(w, "failed to load pending secret", http.StatusInternalServerError)
		return
	}
	step, valid := totp.Validate(secret, strings.TrimSpace(req.Code), time.Now())
	if !valid {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	// Per-account replay guard, shared with handleMFATOTP's login challenge
	// (see server.go): LastUsedTOTPStep is scoped to the account, not to any
	// one endpoint, so the exact code just used to confirm/enable TOTP here
	// must be recorded too — otherwise it stays replayable once against a
	// login MFA challenge in the same 30-90s validation window, since
	// LastUsedTOTPStep would still be at its zero value after enrollment and
	// 0 < any real step always passes that guard. Runs only after the code
	// has already validated, mirroring handleMFATOTP's ordering.
	if _, err := s.users.SetLastUsedTOTPStep(u.ID, step); err != nil {
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	codes, hashes, err := s.newRecoveryCodes(r.Context())
	if err != nil {
		http.Error(w, "failed to generate recovery codes", http.StatusInternalServerError)
		return
	}
	// u.TOTPSecretEnc is the secret the code above was validated against. Passing
	// it back makes the commit conditional on nothing having re-staged the
	// enrolment in the meantime — see EnableTOTP.
	if _, err := s.users.EnableTOTP(u.ID, u.TOTPSecretEnc, time.Now().UTC().Format(time.RFC3339), hashes); err != nil {
		if errors.Is(err, users.ErrTOTPEnrollmentRestarted) {
			http.Error(w, "two-factor enrolment was restarted; start setup again", http.StatusConflict)
			return
		}
		http.Error(w, "failed to enable two-factor auth", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recoveryCodes": codes})
}

func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requirePasswordConfirm(w, r)
	if !ok {
		return
	}
	if _, err := s.users.DisableTOTP(u.ID); err != nil {
		http.Error(w, "failed to disable two-factor auth", http.StatusInternalServerError)
		return
	}
	s.revokeUserSessions(u.ID, currentSessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMFARecoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	u, ok := s.requirePasswordConfirm(w, r)
	if !ok {
		return
	}
	if !u.TOTPEnabled {
		http.Error(w, "two-factor auth is not enabled", http.StatusBadRequest)
		return
	}
	codes, hashes, err := s.newRecoveryCodes(r.Context())
	if err != nil {
		http.Error(w, "failed to generate recovery codes", http.StatusInternalServerError)
		return
	}
	if _, err := s.users.ReplaceRecoveryCodes(u.ID, hashes); err != nil {
		http.Error(w, "failed to store recovery codes", http.StatusInternalServerError)
		return
	}
	s.revokeUserSessions(u.ID, currentSessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recoveryCodes": codes})
}

// requirePasswordConfirm decodes a {password} body, loads the caller, and
// re-verifies their password. On any failure it writes the response and
// returns ok=false. Subject to the same three-strikes/15-minute lockout as
// handleLogin (keyed by the caller's own username, since they're already
// authenticated) — without it, an attacker holding a stolen but
// non-privileged session could use this as an unrate-limited oracle to
// brute-force the account's real login password.
func (s *Server) requirePasswordConfirm(w http.ResponseWriter, r *http.Request) (users.User, bool) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return users.User{}, false
	}
	if allowed, retryAfter := s.loginLockout.tryAttempt(mfaConfirmLockoutKey(ac, r)); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return users.User{}, false
	}
	var req struct {
		Password string `json:"password"`
		// AuthSecret is the client-derived credential, for an account whose
		// password never reaches this server. See login_params.go.
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		// Never reached a credential check, so give the strike back.
		s.loginLockout.cancelAttempt(mfaConfirmLockoutKey(ac, r))
		http.Error(w, "invalid request", http.StatusBadRequest)
		return users.User{}, false
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		s.loginLockout.cancelAttempt(mfaConfirmLockoutKey(ac, r))
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return users.User{}, false
	}
	confirmed, err := verifyAccountCredential(r.Context(), u, req.Password, req.AuthSecret)
	if err != nil {
		// Never reached a credential check, so the strike goes back — same
		// reasoning as the decode and load failures above.
		s.loginLockout.cancelAttempt(mfaConfirmLockoutKey(ac, r))
		writeKDFBusy(w)
		return users.User{}, false
	}
	if !confirmed {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return users.User{}, false
	}
	s.loginLockout.recordSuccess(mfaConfirmLockoutKey(ac, r))
	return u, true
}

// newRecoveryCodes mints recoveryCodeCount codes and their digests. No KDF:
// see mfa.RecoveryCodeDigest.
func (s *Server) newRecoveryCodes(_ context.Context) (plaintext []string, hashes []string, err error) {
	plaintext, err = mfa.GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, nil, err
	}
	hashes = make([]string, 0, len(plaintext))
	for _, c := range plaintext {
		hashes = append(hashes, mfa.RecoveryCodeDigest(c))
	}
	return plaintext, hashes, nil
}

// mfaConfirmLockoutKey scopes the re-authentication throttle on the MFA
// management endpoints to (account, client IP).
//
// On the account ALONE — which is what these two used — a thief holding a
// stolen cookie burns the whole budget from their own machine and locks the
// real owner out of /api/mfa/totp/confirm, /totp/disable and
// /recovery-codes/regenerate for fifteen minutes, renewable indefinitely,
// during exactly the incident where those are the remedy. The control becomes
// the attack. handleLogin and handleChangePassword both compose the client IP
// for this reason, and the latter's comment states the rule; these two were the
// remaining keyspace that did not.
//
// Same shape as deviceLockoutKey and handleChangePassword's: the account
// identifier, a NUL, and the IP folded to a /64 for IPv6.
func mfaConfirmLockoutKey(ac AuthContext, r *http.Request) string {
	return ac.UserID + "\x00" + lockoutKeyForIP(clientIP(r))
}
