package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"kypost-server/backend/internal/config"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/state"
)

// approverDevices returns the devices eligible to approve a push-2FA challenge
// for a user. Devices explicitly flagged MFAApprover=true are preferred; if the
// user has push 2FA enabled but no device carries the flag (e.g. devices paired
// before the flag existed), every paired device is treated as an approver so a
// legacy pairing keeps working without a migration.
func approverDevices(store *state.Store) ([]state.NativeDevice, error) {
	all, err := store.ListNativeDevicesStrict()
	if err != nil {
		return nil, err
	}
	approvers := make([]state.NativeDevice, 0, len(all))
	for _, d := range all {
		if d.MFAApprover {
			approvers = append(approvers, d)
		}
	}
	if len(approvers) > 0 {
		return approvers, nil
	}
	return all, nil
}

// MFATransportEligible reports whether a device's push transport may carry an
// MFA challenge.
//
// UnifiedPush is excluded: a challenge carries sign-in metadata (IP address,
// user agent, and the match digits themselves), and that must not traverse an
// unencrypted public broker such as ntfy.sh until end-to-end encryption exists.
// The devices stay fully usable for mail notifications.
//
// This catches more than it looks like: normalizeNativeTransport maps platform
// "linux" to the unifiedpush transport, so a Linux client that does not name a
// transport explicitly is excluded here too.
func MFATransportEligible(d state.NativeDevice) bool {
	return strings.ToLower(strings.TrimSpace(d.Transport)) != "unifiedpush"
}

// mfaApproverDevices returns the devices that can actually be sent a challenge —
// approver-eligible AND on a transport allowed to carry one.
//
// Every caller deciding "can push approval work for this user" must use this
// rather than approverDevices. The enable gate and the dispatcher used to apply
// the two rules separately and drifted apart, so a user whose only paired device
// was UnifiedPush could turn push approval on, receive {"ok":true}, and then
// never be sent a challenge.
func mfaApproverDevices(store *state.Store) ([]state.NativeDevice, error) {
	candidates, err := approverDevices(store)
	if err != nil {
		return nil, err
	}
	eligible := make([]state.NativeDevice, 0, len(candidates))
	for _, d := range candidates {
		if MFATransportEligible(d) {
			eligible = append(eligible, d)
		}
	}
	return eligible, nil
}

// handleMFAPushEnabled toggles push 2FA for the calling user. Enabling requires
// TOTP already enabled (so a fallback always exists) and at least one paired
// approver-eligible device. Disabling has no preconditions.
func (s *Server) handleMFAPushEnabled(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
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
	if req.Enabled {
		if !u.TOTPEnabled {
			http.Error(w, "enable an authenticator app (TOTP) before enabling push approval, so you always have a fallback", http.StatusBadRequest)
			return
		}
		store, err := s.userStore(ac.UserID)
		if err != nil {
			http.Error(w, "failed to open user state", http.StatusInternalServerError)
			return
		}
		// Must match dispatchPushChallenge exactly, or we accept the setting and
		// then silently never deliver a challenge.
		eligible, err := mfaApproverDevices(store)
		if err != nil {
			http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
			return
		}
		if len(eligible) == 0 {
			msg := "pair a device on the Notifications page before enabling push approval"
			paired, err := approverDevices(store)
			if err != nil {
				http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
				return
			}
			if len(paired) > 0 {
				// They have devices; every one is on an excluded transport.
				// Saying so beats "pair a device" when they already did.
				msg = "your paired devices cannot receive sign-in approvals: UnifiedPush delivery (used by the Linux client by default) is excluded because approval requests carry sign-in details and would cross an unencrypted public broker. Pair an Android or iOS device to use push approval."
			}
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
	}
	if _, err := s.users.SetPushMFAEnabled(u.ID, req.Enabled); err != nil {
		http.Error(w, "failed to update push 2fa", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pushMfaEnabled": req.Enabled})
}

// handleNativeDeviceMFA flips a specific device's MFAApprover flag. Ownership is
// guaranteed structurally: storeFor resolves the caller's own state store, so a
// user can only toggle their own devices.
func (s *Server) handleNativeDeviceMFA(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceId"))
	if deviceID == "" {
		http.Error(w, "deviceId is required", http.StatusBadRequest)
		return
	}
	var req struct {
		Approver bool `json:"approver"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	updated, err := store.SetNativeDeviceMFAApprover(deviceID, req.Approver)
	if err != nil {
		http.Error(w, "failed to update device", http.StatusInternalServerError)
		return
	}
	if !updated {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deviceId": deviceID, "approver": req.Approver})
}

// loginContext is the "where is this sign-in coming from" detail shown on the
// approval screen. Both fields are attacker-influenced (a User-Agent is
// whatever the client sent; the IP is the connection's, or a proxy header the
// deployment trusts), so both are length-capped before they travel — the client
// caps them too, but a security screen should not depend on the far end for
// that.
type loginContext struct {
	ipAddress string
	userAgent string
}

// maxPushContextLen mirrors MfaChallengePayloadParser.MAX_CONTEXT_LENGTH.
const maxPushContextLen = 120

func newLoginContext(r *http.Request) loginContext {
	if r == nil {
		return loginContext{}
	}
	return loginContext{
		ipAddress: truncateContext(clientIP(r)),
		userAgent: truncateContext(r.UserAgent()),
	}
}

func truncateContext(v string) string {
	v = strings.TrimSpace(v)
	// Rune-wise, so a multi-byte character is never cut in half into invalid
	// UTF-8 that the client then renders as replacement glyphs.
	runes := []rune(v)
	if len(runes) > maxPushContextLen {
		return string(runes[:maxPushContextLen])
	}
	return v
}

// dispatchPushChallenge fans an MFA-challenge push out to every approver-eligible
// device of userID. Best-effort and asynchronous: it runs in its own goroutine so
// relay latency never blocks login, and dispatch failures are logged only (the
// user can still fall back to TOTP). Delivery goes through
// processor.SendNativePushToDevices — the same pull-mode fallback, stale-device
// cleanup, and health recording every other native push in this app gets —
// scoped to the approver-filtered device list rather than every paired device.
// The data payload is the contract a future kypost-android build must recognize.
//
// UnifiedPush devices are excluded from MFA challenges pending end-to-end encryption
// support; MFA metadata is sensitive and should not traverse unencrypted public
// UnifiedPush brokers (e.g., ntfy.sh). Devices remain usable for mail notifications.
// contentPreviewEnabled reports whether userID opted into sending message
// metadata through the push relay. Defaults false on any read error.
func (s *Server) contentPreviewEnabled(userID string) bool {
	settings, err := config.LoadUserSettings(s.userSettingsPath(userID))
	if err != nil {
		return false
	}
	return settings.Notifications.ContentPreview
}

func (s *Server) dispatchPushChallenge(userID, challengeID string, ctx loginContext, issuedAt time.Time, matchDigits string, decoyDigits []string) {
	store, err := s.userStore(userID)
	if err != nil {
		s.logger.Error("push mfa: open user state failed", "error", err.Error())
		return
	}
	// mfaApproverDevices applies the transport rule too — the same call the
	// enable gate makes, so the two cannot disagree about whether this user can
	// receive a challenge.
	filteredDevices, err := mfaApproverDevices(store)
	if err != nil {
		s.logger.Error("push mfa: list paired devices failed", "user_id", userID, "challenge_id", challengeID, "error", err.Error())
		return
	}
	if len(filteredDevices) == 0 {
		// Log it. A user reporting "the approval never arrives" previously left
		// no trace at all, which made this indistinguishable from a relay
		// outage or a dropped notification.
		paired, err := approverDevices(store)
		if err != nil {
			s.logger.Error("push mfa: list paired devices failed", "user_id", userID, "challenge_id", challengeID, "error", err.Error())
			return
		}
		s.logger.Info("push mfa: no eligible approver device, challenge not sent",
			"user_id", userID,
			"challenge_id", challengeID,
			"paired_approver_devices", strconv.Itoa(len(paired)),
			"reason", "all paired devices are on transports excluded from MFA challenges (UnifiedPush)")
		return
	}

	// Everything past challengeId is context for the human, and it is the point
	// of the approval screen. The payload used to be the id alone, so the person
	// approving had no origin, no time, and no way to tell their own sign-in
	// from an attacker's — every anti-fatigue control around it (the five-minute
	// window, the push cooldown, per-challenge re-auth) guarded a decision made
	// blind, which is the gap MFA-fatigue attacks walk through.
	//
	// The field names and formats are the shipped client's contract; see
	// MfaChallengePayloadParser in kypost-android. It caps context strings at
	// 120 characters and discards matchDigits that are not exactly two digits,
	// falling back to a bare Approve button — so sending a malformed value is
	// the same as sending nothing.
	data := map[string]string{
		"type":        "mfa_challenge",
		"challengeId": challengeID,
		"issuedAt":    strconv.FormatInt(issuedAt.UnixMilli(), 10),
	}
	// ipAddress/userAgent are gated on the same setting as mail previews.
	// This payload takes the identical route — backend, relay Worker, then
	// Google or Apple, in cleartext to each hop — and ContentPreview exists
	// precisely so that route carries no correspondence metadata by default.
	// The sign-in source IP is often a different machine from the phone being
	// asked to approve, so it is genuinely new information to those parties.
	// Everything the client needs to render number matching (type, challengeId,
	// issuedAt, matchDigits) is still sent.
	if s.contentPreviewEnabled(userID) {
		if ctx.ipAddress != "" {
			data["ipAddress"] = ctx.ipAddress
		}
		if ctx.userAgent != "" {
			data["userAgent"] = ctx.userAgent
		}
	}
	if matchDigits != "" {
		data["matchDigits"] = matchDigits
		if len(decoyDigits) > 0 {
			data["decoyDigits"] = strings.Join(decoyDigits, ",")
		}
	}

	message := processor.NativePushMessage{
		Title: "Approve sign-in",
		Body:  "Tap to approve or deny a sign-in to your account.",
		Data:  data,
	}
	_, err = processor.SendNativePushToDevices(context.Background(), s.nativePushDispatcher, s.health, store, filteredDevices, message,
		func(device state.NativeDevice, platform string, sendErr error) {
			s.logger.Error("push mfa: dispatch failed", "device_id", strings.TrimSpace(device.DeviceID), "platform", platform, "error", sendErr.Error())
		})
	if err != nil {
		s.logger.Error("push mfa: dispatch failed", "user_id", userID, "error", err.Error())
	}
}

// handlePushPoll reports the live status of a push challenge. In-memory only, so
// the browser can poll it every ~1.5s. Missing/expired challenges report
// "expired" with a 200 so the client reads a uniform {status} shape.
func (s *Server) handlePushPoll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	status, ok := s.mfaChallenges.PushStatus(strings.TrimSpace(req.ChallengeID))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"status": "expired"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status})
}

// handlePushFinish mints the session for an approved push challenge, consuming
// (deleting) the challenge atomically. Not approved => 409; missing/expired =>
// 401. Authenticated solely by possession of the challengeId (no session cookie),
// exactly like the TOTP finish path.
func (s *Server) handlePushFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	userID, err := s.mfaChallenges.ConsumePushApproval(strings.TrimSpace(req.ChallengeID))
	if err != nil {
		if errors.Is(err, mfa.ErrPushNotApproved) {
			http.Error(w, "challenge not approved", http.StatusConflict)
			return
		}
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	u, err := s.users.Get(userID)
	if err != nil || !u.Active {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	// Re-check live push-MFA state even though the challenge was already
	// approved: an admin clearing this account's MFA (handleUsersClearMFA)
	// turns PushMFAEnabled off, and while that same action also purges
	// live challenges via mfaChallenges.DeleteByUser, this check is the
	// second, independent gate — without it, a challenge approved just
	// before the clear (and not yet finished) would still mint a session
	// if the purge and this call raced.
	if !u.PushMFAEnabled {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

// handlePushRespond is the endpoint a paired mobile device calls to approve or
// deny a login challenge. It authenticates with the device's own
// X-Kypost-Device-Id/X-Kypost-Device-Secret credentials (see
// device_auth.go) — no session cookie. It enforces that the responding
// device's owner is exactly the user the challenge was minted for (a device
// can never approve another user's login), and that the device is still
// permitted to approve.
func (s *Server) handlePushRespond(w http.ResponseWriter, r *http.Request) {
	userID, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	// This route MUTATES on a device credential, which no shared middleware
	// meters. See meterDeviceWrite.
	if !s.meterDeviceWrite(w, r, userID) {
		return
	}
	var req struct {
		ChallengeID string `json:"challengeId"`
		Approve     bool   `json:"approve"`
		// MatchDigits is the number the approver read off the browser that
		// started the sign-in. Required to approve, ignored to deny.
		MatchDigits string `json:"matchDigits"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		http.Error(w, "challengeId is required", http.StatusBadRequest)
		return
	}

	// Load the challenge and enforce that the device's owner is the very user
	// the challenge belongs to. This is the core cross-user protection.
	ch, okCh := s.mfaChallenges.Get(challengeID)
	if !okCh {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	if ch.UserID != userID {
		http.Error(w, "challenge does not belong to this device", http.StatusForbidden)
		return
	}

	// The challenge's owning user must have push 2FA explicitly enabled. A
	// challenge is created for TOTP-only users too (since login always offers
	// TOTP), and every native device defaults to MFAApprover=true for ordinary
	// push notifications regardless of this setting — without this check, any
	// paired device could silently approve a login for a user who never opted
	// into push as a second factor.
	owner, err := s.users.Get(userID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if !owner.PushMFAEnabled {
		http.Error(w, "push approval is not enabled for this account", http.StatusForbidden)
		return
	}

	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	// The device must be permitted to approve. Under the graceful default (no
	// device flagged as approver) any paired device may approve; once any device
	// is explicitly an approver, only approvers may.
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
		return
	}
	hasApprover := false
	for _, d := range devices {
		if d.MFAApprover {
			hasApprover = true
			break
		}
	}
	if hasApprover && !device.MFAApprover {
		http.Error(w, "device is not permitted to approve sign-in", http.StatusForbidden)
		return
	}

	// The number match is verified HERE, not on the device. The device decides
	// which tile the human pressed; only the server knows which one was right,
	// and this endpoint is reachable by anyone holding device credentials — so
	// a client-side comparison would be decoration.
	status, err := s.mfaChallenges.ResolvePushWithMatch(challengeID, device.DeviceID, req.Approve, strings.TrimSpace(req.MatchDigits))
	if err != nil {
		if errors.Is(err, mfa.ErrChallengeAlreadyResolved) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "challenge already resolved", "status": status})
			return
		}
		if errors.Is(err, mfa.ErrMatchAttemptsExhausted) {
			// A wrong number is terminal for push (see mfa.maxMatchAttempts).
			// Not 401 — the device's credentials were fine — and not 400, which
			// would read as "try again": there is nothing to try again. The
			// sign-in is still completable, on TOTP, in the browser.
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":  "that is not the number shown in the browser; push approval is now locked for this sign-in, finish it with your authenticator app",
				"status": mfa.PushLocked,
			})
			return
		}
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
}
