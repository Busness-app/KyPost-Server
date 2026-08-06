// Web push, native device pairing, the App Pull queue, and the HMAC pairing
// tokens that gate them (also used by pickup links and PGP QR key exchange —
// see pickup_handlers.go and pgp_qr_handlers.go).
//
// handleNotificationPreferences leads the file rather than sitting with the
// other per-user preference handlers in server.go, because it is read and
// written by the same subscription flow as everything below it.
package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
)

type notificationSubscriptionPayload struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		Auth   string `json:"auth"`
		P256DH string `json:"p256dh"`
	} `json:"keys"`
}

type notificationTestPayload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Field bounds for anything a registration persists and the poller later
// carries into a delivery attempt.
//
// The body limit on these handlers is 1 MiB, which is the bound on ONE request.
// It is not a bound on what gets stored: every one of these fields was written
// verbatim at whatever length the caller chose, up to that limit, and then read
// back on every poll tick — a push endpoint URL is dialled, a device name and
// user agent are returned by the devices listing. Generous against real values
// (a push endpoint URL is a few hundred bytes; the RFC 8291 keys are fixed-size
// base64), tight against a caller filling the store with the largest values the
// body limit allows.
const (
	maxPushEndpointLen = 2048
	maxPushKeyLen      = 256
	maxDeviceTokenLen  = 4096
	maxDeviceTextLen   = 256
	maxUserAgentLen    = 512
)

// clampField trims s and cuts it to max bytes. Used on stored metadata (user
// agent, device name, app version) where over-length is not worth refusing the
// registration over — unlike the credential fields, which are rejected outright
// because a truncated one would be silently wrong.
func clampField(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

func (s *Server) handleNotificationVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	publicKey := strings.TrimSpace(s.cfg.Notifications.PublicKey)
	s.cfgMu.RUnlock()
	if publicKey == "" {
		http.Error(w, "notification public key not configured", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": publicKey})
}

func (s *Server) handleNotificationSubscriptions(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var payload notificationSubscriptionPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid subscription payload", http.StatusBadRequest)
			return
		}
		payload.Endpoint = strings.TrimSpace(payload.Endpoint)
		payload.Keys.Auth = strings.TrimSpace(payload.Keys.Auth)
		payload.Keys.P256DH = strings.TrimSpace(payload.Keys.P256DH)
		if payload.Endpoint == "" || payload.Keys.Auth == "" || payload.Keys.P256DH == "" {
			http.Error(w, "endpoint and keys are required", http.StatusBadRequest)
			return
		}
		if len(payload.Endpoint) > maxPushEndpointLen || len(payload.Keys.Auth) > maxPushKeyLen || len(payload.Keys.P256DH) > maxPushKeyLen {
			http.Error(w, "endpoint or keys are too long", http.StatusBadRequest)
			return
		}
		// Screened exactly like the UnifiedPush endpoint already is. This is a
		// user-supplied URL the poller later POSTs to, and it had only a
		// non-empty check — so it was an authenticated SSRF into the
		// deployment's private network, with POST /api/notifications/test
		// returning sent/failed/removedStale as a three-state oracle. The
		// netguard predicate lives in its own package precisely because a
		// security check with two homes gets fixed in one of them; this was the
		// third home.
		if err := processor.ValidateUnifiedPushEndpointURL(payload.Endpoint); err != nil {
			http.Error(w, "invalid push endpoint: "+err.Error(), http.StatusBadRequest)
			return
		}

		sub := state.NotificationSubscription{
			Endpoint:  payload.Endpoint,
			Auth:      payload.Keys.Auth,
			P256DH:    payload.Keys.P256DH,
			UserAgent: clampField(r.Header.Get("User-Agent"), maxUserAgentLen),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := store.UpsertNotificationSubscription(sub); err != nil {
			// 409, not 500: the request is well-formed and the server is fine
			// — this account is simply at its cap and has to unsubscribe
			// something before adding another. Refreshing a subscription that
			// already exists never hits this.
			if errors.Is(err, state.ErrRegistrationLimit) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error": fmt.Sprintf("this account already has the maximum of %d push subscriptions; remove one first", state.MaxNotificationSubscriptions),
				})
				return
			}
			http.Error(w, "failed to persist notification subscription", http.StatusInternalServerError)
			return
		}
		subs, err := store.ListNotificationSubscriptionsStrict()
		if err != nil {
			http.Error(w, "failed to read notification subscriptions", http.StatusServiceUnavailable)
			return
		}
		count := len(subs)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "subscriptions": count})
	case http.MethodDelete:
		var payload struct {
			Endpoint string `json:"endpoint"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid unsubscribe payload", http.StatusBadRequest)
			return
		}
		endpoint := strings.TrimSpace(payload.Endpoint)
		if endpoint == "" {
			http.Error(w, "endpoint is required", http.StatusBadRequest)
			return
		}
		removed, err := store.RemoveNotificationSubscription(endpoint)
		if err != nil {
			http.Error(w, "failed to remove notification subscription", http.StatusInternalServerError)
			return
		}
		subs, err := store.ListNotificationSubscriptionsStrict()
		if err != nil {
			http.Error(w, "failed to read notification subscriptions", http.StatusServiceUnavailable)
			return
		}
		count := len(subs)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "subscriptions": count})
	}
}

func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// Before any work. This handler dispatches to every registration the
	// account has, serially, each with its own network timeout — so without a
	// meter it is an authenticated user's switch for making the server spend
	// unbounded time on outbound requests to destinations they chose.
	if allowed, retryAfter := s.notificationTestCooldown.tryConsume(ac.UserID); !allowed {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "a test notification was just sent; try again shortly",
			"retryAfterSeconds": int(retryAfter.Seconds()) + 1,
		})
		return
	}
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	var payload notificationTestPayload
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload)
	title := strings.TrimSpace(payload.Title)
	body := strings.TrimSpace(payload.Body)
	if title == "" {
		title = "KyPost Test Notification"
	}
	if body == "" {
		body = "Push delivery is working across all subscribed devices."
	}

	// A test notification's only job is to prove delivery, so it lands the user
	// back on the settings that configure it — a tab on Configuration.
	message := map[string]any{
		"title": title,
		"body":  body,
		"url":   "/config?tab=notifications",
		"tag":   "kypost-test",
	}
	payloadBytes, err := json.Marshal(message)
	if err != nil {
		http.Error(w, "failed to serialize notification payload", http.StatusInternalServerError)
		return
	}

	subs, err := store.ListNotificationSubscriptionsStrict()
	if err != nil {
		http.Error(w, "failed to read notification subscriptions", http.StatusServiceUnavailable)
		return
	}
	sent := 0
	failed := 0
	removed := 0
	if len(subs) > 0 {
		// Read under cfgMu like every other s.cfg access. These two were bare
		// field reads racing PUT /api/config's write — benign-looking because
		// they are strings, but a torn read of a key path is a push that fails
		// for no discoverable reason.
		s.cfgMu.RLock()
		vapidPublic := s.cfg.Notifications.PublicKey
		vapidKeyPath := s.cfg.Notifications.PrivateKeyPath
		s.cfgMu.RUnlock()
		outcome, err := processor.SendWebPush(r.Context(), store, vapidPublic, vapidKeyPath, 3600, payloadBytes)
		if err != nil {
			http.Error(w, "failed to load notification private key", http.StatusInternalServerError)
			return
		}
		sent = outcome.Sent
		failed = outcome.Failed
		removed = outcome.Removed
	}

	nativeDevices, err := store.ListNativeDevicesStrict()
	if err != nil {
		http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
		return
	}
	nativeSent := 0
	nativeFailed := 0
	nativeRemoved := 0
	nativeError := ""
	if len(nativeDevices) > 0 {
		nativeMessage := processor.NativePushMessage{
			Title: title,
			Body:  body,
			Data:  map[string]string{"url": "/config?tab=notifications"},
		}
		outcome, err := processor.SendNativePush(r.Context(), s.nativePushDispatcher, s.health, store, nativeMessage, func(device state.NativeDevice, platform string, sendErr error) {
			// "sent_via", not "sender" — this names the delivery path, not an
			// email's From address. See the matching note in processor/poller.go.
			s.logger.Error("test native notification failed", "device_id", strings.TrimSpace(device.DeviceID), "platform", platform, "sent_via", "relay", "error", sendErr.Error())
		})
		if outcome.Queued {
			// App Pull mode: queue the test for the device to fetch over HTTP
			// instead of dispatching through the relay/Firebase.
			if err != nil {
				nativeError = "failed to queue pull notification: " + err.Error()
				s.logger.Error("test native pull notification failed", "error", err.Error())
			} else {
				nativeSent = outcome.Sent
			}
		} else {
			nativeSent = outcome.Sent
			nativeFailed = outcome.Failed
			nativeRemoved = outcome.Removed
		}
	}

	resp := map[string]any{
		"ok":                  failed == 0 && nativeFailed == 0 && nativeError == "",
		"subscriptions":       len(subs),
		"sent":                sent,
		"failed":              failed,
		"removedStale":        removed,
		"activeSubscriptions": len(subs),
		"nativeDevices":       len(nativeDevices),
		"nativeSent":          nativeSent,
		"nativeFailed":        nativeFailed,
		"nativeRemovedStale":  nativeRemoved,
	}
	if nativeError != "" {
		resp["nativeError"] = nativeError
	}
	writeJSON(w, http.StatusOK, resp)
}

// nativePairingTokenTTL is the validity window for a native-device pairing
// token, shared by the token-minting call site (handleNotificationPairing)
// and the nonce-consumption TTL in handleNotificationNativeRegister — a
// single constant so the two can't drift out of sync.
const nativePairingTokenTTL = 90 * time.Second

func (s *Server) handleNotificationPairing(w http.ResponseWriter, r *http.Request) {
	ac, okAuth := authFromContext(r)
	if !okAuth {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	store, err := s.userStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		http.Error(w, "failed to load subscriber id", http.StatusInternalServerError)
		return
	}
	// Keep the unauthenticated register endpoint's subscriber -> user index
	// warm so a device pairing right after this call resolves immediately.
	s.userMu.Lock()
	s.subIndex[subscriberID] = ac.UserID
	s.userMu.Unlock()
	configured := s.pairingSecret != ""
	configurationError := ""
	if !configured {
		configurationError = "pairing is not configured on the server; set PAIRING_SECRET"
	}
	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	registerEndpoint := ""
	pullEndpoint := ""
	if serverBaseURL != "" {
		registerEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/register"
		pullEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/pull"
	}
	pairingTTLSeconds := int64(nativePairingTokenTTL.Seconds())
	resp := map[string]any{
		"subscriberId":      subscriberID,
		"serverBaseUrl":     serverBaseURL,
		"registerEndpoint":  registerEndpoint,
		"pullEndpoint":      pullEndpoint,
		"deliveryMode":      store.NativeDeliveryMode(),
		"pairingTtlSeconds": pairingTTLSeconds,
		"configured":        configured,
	}
	if configurationError != "" {
		resp["configurationError"] = configurationError
	}
	if configured {
		token, expiresAt, err := s.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Duration(pairingTTLSeconds)*time.Second)
		if err != nil {
			s.logger.Error("failed to create pairing token", "subscriber_id", subscriberID, "error", err.Error())
			http.Error(w, "failed to prepare mobile pairing", http.StatusInternalServerError)
			return
		}
		resp["pairingToken"] = token
		resp["pairingExpiresAt"] = expiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

type nativeRegisterRequest struct {
	SubscriberID string `json:"subscriberId"`
	PairingToken string `json:"pairingToken"`
	DeviceToken  string `json:"deviceToken"`
	DeviceID     string `json:"deviceId,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Transport    string `json:"transport,omitempty"`
	DeviceName   string `json:"deviceName,omitempty"`
	AppVersion   string `json:"appVersion,omitempty"`
	// EncryptionEnrolled is the device's own answer to "can I still open my
	// enrollment envelope". A POINTER because absent and false mean different
	// things: an older client that does not send it has no opinion and must not
	// have the marker cleared out from under it, while a client that sends false
	// is reporting that its keystore key is gone.
	EncryptionEnrolled *bool `json:"encryptionEnrolled,omitempty"`
}

func (s *Server) handleNotificationNativeRegister(w http.ResponseWriter, r *http.Request) {
	if s.pairingSecret == "" {
		http.Error(w, "pairing is not configured", http.StatusServiceUnavailable)
		return
	}

	var req nativeRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	subscriberID := strings.TrimSpace(req.SubscriberID)
	pairingToken := strings.TrimSpace(req.PairingToken)
	deviceToken := strings.TrimSpace(req.DeviceToken)
	if subscriberID == "" || pairingToken == "" || deviceToken == "" {
		http.Error(w, "subscriberId, pairingToken, and deviceToken are required", http.StatusBadRequest)
		return
	}
	// Bounded before anything persists it. deviceToken is an FCM/APNs token or
	// a UnifiedPush endpoint URL, and deviceId is client-chosen — all three are
	// stored and read back on every delivery.
	if len(deviceToken) > maxDeviceTokenLen || len(strings.TrimSpace(req.DeviceID)) > maxDeviceTextLen {
		http.Error(w, "deviceToken or deviceId is too long", http.StatusBadRequest)
		return
	}

	platform := normalizeNativePlatform(req.Platform)
	transport, err := normalizeNativeTransport(req.Transport, req.Platform)
	if err != nil {
		http.Error(w, "invalid transport: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Authorize FIRST. Validating the endpoint URL ends in a DNS lookup, so
	// doing it before this check let an anonymous caller aim the server's
	// resolver at any nameserver they chose, and read back — from the error
	// text — whether an internal name existed and what private address it
	// resolved to, out of the handler whose job is to prevent SSRF.
	claims, err := s.decodeAndVerifyPairingToken(pairingToken, pairingPurposeNativeDevice, time.Now().UTC())
	if err != nil {
		http.Error(w, "invalid or expired pairing token", http.StatusUnauthorized)
		return
	}

	// For UnifiedPush, the deviceToken is an HTTPS endpoint URL the client
	// fully controls, not an opaque token — reject anything that could be used
	// for SSRF against internal services (private/loopback/link-local hosts).
	// The sender re-checks at send time too, against DNS rebinding.
	//
	// The reason is deliberately not echoed: it distinguished a nonexistent
	// host from one that resolved into RFC1918, and named the address.
	if transport == "unifiedpush" {
		if err := processor.ValidateUnifiedPushEndpointURL(deviceToken); err != nil {
			http.Error(w, "invalid unifiedpush deviceToken", http.StatusBadRequest)
			return
		}
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(claims.Sub)), []byte(subscriberID)) != 1 {
		http.Error(w, "invalid or expired pairing token", http.StatusUnauthorized)
		return
	}
	// The pairing token proved this device was handed a QR minted by a
	// signed-in user; resolve which user's device list to write into.
	//
	// Resolved BEFORE the nonce is consumed so that the re-pair check below can
	// refuse without burning the token: a legitimate device that omits its
	// secret would otherwise have to send the user back to the QR screen.
	ownerID, okOwner := s.lookupUserBySubscriber(subscriberID)
	if !okOwner {
		http.Error(w, "unknown subscriber", http.StatusUnauthorized)
		return
	}
	store, err := s.userStore(ownerID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	// RE-BINDING AN EXISTING DEVICE ID IS NOT ORDINARY REGISTRATION.
	//
	// A pairing token proves someone held a live session; it does not prove
	// possession of the device being rebound. Without this check, a stolen
	// session could point register at a victim's live deviceId and
	// upsertNativeDeviceTx would overwrite SecretHash and PushToken while
	// PRESERVING MFAApprover and the enrollment columns — silently revoking the
	// real phone, redirecting its push notifications, and inheriting its right
	// to approve sign-ins. No new row appears, so the device list looks
	// unchanged. That turns an ephemeral stolen cookie into a device credential
	// with no TTL, which is precisely what pgp_stepup.go refuses to let a
	// session do to key material.
	//
	// Step-up is not reachable here: this route is withTokenAuth and carries no
	// AuthContext, so there is no session credential to re-prove. A legitimate
	// device refreshing its push token still holds its current secret, so proof
	// of possession is the check that fits.
	if requested := strings.TrimSpace(req.DeviceID); requested != "" {
		if existing, found := store.GetNativeDevice(requested); found {
			okSecret, secretErr := users.VerifyDeviceSecret(r.Context(), existing.SecretHash, r.Header.Get(headerDeviceSecret))
			if secretErr != nil || !okSecret {
				writeJSON(w, http.StatusConflict, map[string]any{
					"error": "device id already registered; present its current secret to re-pair, or unpair it first",
				})
				return
			}
		} else if !validDeviceID(requested) {
			// A NEW id must be portable across the three implementations that
			// hash it. Checked only for new ids so that a device registered
			// before this bound is not stranded on its next token refresh —
			// it re-registers through the branch above, which proves possession.
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "deviceId must be 1-128 characters of A-Z a-z 0-9 . _ : or -",
			})
			return
		}
	}

	// Native pairing tokens are meant to be redeemed exactly once — the
	// QR/deep-link a user scans to pair a new device. Without this, the same
	// captured token stays valid for its full TTL and could register an
	// unlimited number of devices.
	if !s.consumeNativePairingNonce(claims.Nonce, nativePairingTokenTTL) {
		http.Error(w, "pairing token already used", http.StatusConflict)
		return
	}

	// A device id is global (the deviceIndex maps it to exactly one owner), but
	// the id is client-supplied. Reserve it atomically (check-and-set under
	// one lock, not a separate check followed by a later write) so a caller
	// can't hijack a victim's device-index entry and deny that device
	// service, even under concurrent registration requests.
	// release is armed immediately and unconditionally: every return between
	// here and commitDeviceID below is a path that reserved an ID and then did
	// not write a device under it. See reserveDeviceID for what one of those
	// costs if it survives.
	reservation, reserved := s.reserveDeviceID(ownerID, strings.TrimSpace(req.DeviceID))
	if !reserved {
		http.Error(w, "device id already registered", http.StatusConflict)
		return
	}
	defer reservation.Release()

	// Mint this device's own pairing secret. Only its hash is ever persisted
	// (see state.NativeDevice.SecretHash); the raw value is returned once
	// below and never retrievable again.
	rawSecret, err := randomToken(24)
	if err != nil {
		http.Error(w, "failed to mint device secret", http.StatusInternalServerError)
		return
	}
	secretHash := users.HashDeviceSecret(rawSecret)

	device := state.NativeDevice{
		DeviceID:    strings.TrimSpace(req.DeviceID),
		Platform:    platform,
		Transport:   transport,
		PushToken:   deviceToken,
		DeviceName:  clampField(req.DeviceName, maxDeviceTextLen),
		AppVersion:  clampField(req.AppVersion, maxDeviceTextLen),
		UserAgent:   clampField(r.Header.Get("User-Agent"), maxUserAgentLen),
		UserID:      ownerID,
		MFAApprover: true,
		SecretHash:  secretHash,
	}
	if err := store.UpsertNativeDevice(device); err != nil {
		// See the same branch on the web-push subscription handler: at the cap
		// the request is refused, not failed. Re-pairing a device that is
		// already registered updates its row and never reaches this.
		if errors.Is(err, state.ErrRegistrationLimit) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error": fmt.Sprintf("this account already has the maximum of %d paired devices; unpair one first", state.MaxNativeDevices),
			})
			return
		}
		http.Error(w, "failed to persist native device", http.StatusInternalServerError)
		return
	}

	// Resolve the canonical device ID by token: the upsert may have merged
	// this registration into an existing row (same token + platform), whose
	// ID wins over whatever the request carried.
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
		return
	}
	registeredDeviceID := device.DeviceID
	for i := len(devices) - 1; i >= 0; i-- {
		if strings.TrimSpace(devices[i].PushToken) == deviceToken && devices[i].Platform == device.Platform {
			registeredDeviceID = devices[i].DeviceID
			break
		}
	}

	// Point the index at the ID the device was actually persisted under. When
	// UpsertNativeDevice merged this registration into an existing row the
	// requested ID never got a record, so Commit settles that one too. The
	// deferred Release above becomes a no-op.
	reservation.Commit(registeredDeviceID)

	// Written against registeredDeviceID rather than the requested id, because
	// the upsert may have merged this registration into an existing row.
	if req.EncryptionEnrolled != nil {
		if err := store.SetNativeDeviceEncryptionEnrolled(registeredDeviceID, *req.EncryptionEnrolled); err != nil {
			// Not fatal to registration: push must keep working even if the
			// enrollment marker cannot be written.
			s.logger.Error("could not record device encryption state",
				"device_id", registeredDeviceID, "error", err.Error())
		}
	}

	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	pullEndpoint := ""
	if serverBaseURL != "" {
		pullEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/pull"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"synced":       true,
		"deviceId":     registeredDeviceID,
		"deviceSecret": rawSecret,
		"devices":      len(devices),
		"deliveryMode": store.NativeDeliveryMode(),
		"pullEndpoint": pullEndpoint,
		"transport":    transport,
	})
}

func (s *Server) handleNotificationNativeDevices(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		devices, err := store.ListNativeDevicesStrict()
		if err != nil {
			http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
			return
		}
		redacted := make([]state.NativeDevice, len(devices))
		for i, d := range devices {
			redacted[i] = d.Redacted()
		}
		// deliveryMode rides along so the UI can render the Relay Push / App
		// Pull toggle without calling GET /api/notifications/pairing, which
		// mints a live 90-second pairing token as a side effect. Reading a
		// setting should not hand out a credential.
		writeJSON(w, http.StatusOK, map[string]any{
			"devices":      redacted,
			"deliveryMode": store.NativeDeliveryMode(),
		})
	case http.MethodDelete:
		var payload struct {
			DeviceID string `json:"deviceId"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		deviceID := strings.TrimSpace(payload.DeviceID)
		if deviceID == "" {
			http.Error(w, "deviceId is required", http.StatusBadRequest)
			return
		}
		removed, err := store.RemoveNativeDevice(deviceID)
		if err != nil {
			http.Error(w, "failed to remove native device", http.StatusInternalServerError)
			return
		}
		// Only when this user actually owned it. The eviction used to be
		// unconditional, so a DELETE naming someone else's deviceId reported
		// removed=false and still dropped their index entry — briefly breaking
		// their device auth until the next rescan repaired it.
		if removed {
			s.userMu.Lock()
			delete(s.deviceIndex, deviceID)
			s.userMu.Unlock()
		}
		devices, err := store.ListNativeDevicesStrict()
		if err != nil {
			http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "devices": len(devices)})
	}
}

func normalizeNativePlatform(platform string) string {
	clean := strings.ToLower(strings.TrimSpace(platform))
	if clean == "" {
		// Legacy clients that omit platform entirely default to android.
		return "android"
	}
	// Pass any other platform name through unchanged so a new client isn't
	// silently mislabeled as android — it just shows up under its own name.
	return clean
}

func normalizeNativeTransport(transport, platform string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(transport))
	switch clean {
	case "fcm", "apns", "unifiedpush":
		return clean, nil
	case "":
		// Derive from platform if transport not specified (legacy behavior).
		switch strings.ToLower(strings.TrimSpace(platform)) {
		case "ios", "macos":
			return "apns", nil
		case "linux":
			return "unifiedpush", nil
		default:
			return "fcm", nil
		}
	default:
		return "", fmt.Errorf("unrecognized transport %q", clean)
	}
}

func (s *Server) handleNotificationNativeUnpair(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
		return
	}
	removed := 0
	for _, device := range devices {
		if strings.TrimSpace(device.DeviceID) == "" {
			continue
		}
		ok, err := store.RemoveNativeDevice(device.DeviceID)
		if err != nil {
			http.Error(w, "failed to revoke paired devices", http.StatusInternalServerError)
			return
		}
		if ok {
			removed++
			s.userMu.Lock()
			delete(s.deviceIndex, device.DeviceID)
			s.userMu.Unlock()
		}
	}
	devices, err = store.ListNativeDevicesStrict()
	if err != nil {
		http.Error(w, "failed to read paired devices", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "devices": len(devices)})
}

// handleNotificationNativeDeregister lets a paired device remove itself —
// e.g. on app logout/uninstall — without going through a web session. It
// authenticates with the device's own X-Kypost-Device-Id/
// X-Kypost-Device-Secret credentials (deviceAuthFromRequest), so a device can
// only ever remove itself, never another device on the account.
func (s *Server) handleNotificationNativeDeregister(w http.ResponseWriter, r *http.Request) {
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
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	if _, err := store.RemoveNativeDevice(device.DeviceID); err != nil {
		http.Error(w, "failed to remove device", http.StatusInternalServerError)
		return
	}
	s.userMu.Lock()
	delete(s.deviceIndex, device.DeviceID)
	s.userMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleNotificationNativeMode switches native delivery between the relay-backed
// push mode and App Pull mode for the signed-in user.
func (s *Server) handleNotificationNativeMode(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != state.DeliveryModePush && mode != state.DeliveryModePull {
		http.Error(w, "mode must be \"push\" or \"pull\"", http.StatusBadRequest)
		return
	}
	if err := store.SetNativeDeliveryMode(mode); err != nil {
		http.Error(w, "failed to persist delivery mode", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deliveryMode": store.NativeDeliveryMode()})
}

// handleNotificationNativePull serves queued notifications to a paired mobile
// app polling over plain HTTP — the App Pull path that bypasses the Cloudflare
// relay and Firebase entirely. It is unauthenticated by web session; the
// device proves it is that specific still-paired device with its own
// deviceId + deviceSecret (minted at registration), sent via the
// X-Kypost-Device-Id/X-Kypost-Device-Secret headers (see device_auth.go). The
// client passes ?after=<cursor> to fetch only notifications newer than its
// last poll.
func (s *Server) handleNotificationNativePull(w http.ResponseWriter, r *http.Request) {
	userID, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	var after int64
	if raw := strings.TrimSpace(r.URL.Query().Get("after")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			after = parsed
		}
	}
	notifications, cursor, err := store.PullNotificationsAfterStrict(after)
	if err != nil {
		http.Error(w, "failed to read notifications", http.StatusServiceUnavailable)
		return
	}
	if notifications == nil {
		notifications = []state.PullNotification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveryMode":  store.NativeDeliveryMode(),
		"cursor":        cursor,
		"notifications": notifications,
	})
}

func (s *Server) handleDesktopPair(w http.ResponseWriter, r *http.Request) {
	ac, okAuth := authFromContext(r)
	if !okAuth {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	store, err := s.userStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	// Check rate limit: max 5 failed attempts per hour
	allowed, remaining, err := store.CheckDesktopPairingRateLimit()
	if err != nil {
		s.logger.Error("rate limit check failed", "user_id", ac.UserID, "error", err.Error())
		http.Error(w, "failed to check rate limit", http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.logger.Error("desktop pairing rate limit exceeded", "user_id", ac.UserID)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate limit exceeded: too many pairing attempts. Try again later.",
		})
		return
	}

	// Generate 16 bytes (128 bits) of cryptographically secure random data
	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "failed to generate pairing code", http.StatusInternalServerError)
		return
	}

	// Return as 32-character hex string (no formatting, delivered via API/QR only)
	pairingCode := strings.ToUpper(hex.EncodeToString(codeBytes))

	// Store pairing code with 5-minute expiration
	if err := store.SetDesktopPairingCode(pairingCode, 5*time.Minute); err != nil {
		s.logger.Error("failed to store desktop pairing code", "user_id", ac.UserID, "error", err.Error())
		http.Error(w, "failed to create pairing code", http.StatusInternalServerError)
		return
	}

	// Record successful pairing initiation
	_ = store.RecordDesktopPairingAttempt(pairingCode, true)

	// No part of the code goes in the log. This used to emit pairingCode[:8]
	// labelled "code_hash", which it was not — it was the first 32 bits of the
	// raw credential, in a file that is not treated as secret. The user id and
	// timestamp are what an operator actually correlates on; the attempt log
	// keeps a real hash if a redemption ever needs matching to an issuance.
	s.logger.Info("desktop pairing initiated", "user_id", ac.UserID)

	// Build server URL and register endpoint for desktop app
	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	registerEndpoint := ""
	if serverBaseURL != "" {
		registerEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/desktop/register"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"pairingCode":      pairingCode,
		"ttlSeconds":       300,
		"rateLimit":        remaining,
		"serverBaseUrl":    serverBaseURL,
		"registerEndpoint": registerEndpoint,
	})
}

// Pairing tokens are minted for exactly one of these purposes and are only
// ever valid for that same purpose. Without this separation, a token minted
// for one flow (e.g. a low-stakes pickup link, mailed in plaintext to a
// recipient with no account) could be replayed against a different, more
// sensitive flow (e.g. native device pairing, which grants full mail sync
// and push-MFA-approval rights) if an attacker obtained it.
const (
	pairingPurposeNativeDevice = "native-device"
	pairingPurposePGPQRKey     = "pgp-qr-key"
	pairingPurposePickupLink   = "pickup-link"
)

type pairingTokenClaims struct {
	Sub     string `json:"sub"`
	Exp     int64  `json:"exp"`
	Nonce   string `json:"n"`
	Purpose string `json:"purpose"`
}

func (s *Server) createPairingToken(subscriberID, purpose string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().UTC().Add(ttl)
	claims := pairingTokenClaims{
		Sub:     strings.TrimSpace(subscriberID),
		Exp:     expiresAt.Unix(),
		Nonce:   hex.EncodeToString(nonceBytes),
		Purpose: purpose,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	mac := hmac.New(sha256.New, []byte(s.pairingSecret))
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, expiresAt, nil
}

// decodeAndVerifyPairingToken decodes token (in the shape produced by
// createPairingToken), verifies its HMAC signature, checks expiry, and
// checks that the token's purpose matches wantPurpose, returning its claims.
// The purpose check is a plain != — the purpose isn't secret, unlike the
// HMAC signature and (in validatePairingToken) the subject, which correctly
// stay constant-time comparisons. Shared by validatePairingToken (which
// additionally checks the subject against a caller-supplied expectation) and
// parsePairingTokenUserID (which returns the subject to the caller instead).
func (s *Server) decodeAndVerifyPairingToken(token, wantPurpose string, now time.Time) (pairingTokenClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return pairingTokenClaims{}, errors.New("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return pairingTokenClaims{}, errors.New("invalid token payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return pairingTokenClaims{}, errors.New("invalid token signature")
	}

	mac := hmac.New(sha256.New, []byte(s.pairingSecret))
	mac.Write(payload)
	expectedSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, expectedSig) != 1 {
		return pairingTokenClaims{}, errors.New("signature mismatch")
	}

	var claims pairingTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return pairingTokenClaims{}, errors.New("invalid token claims")
	}
	if claims.Exp <= 0 || now.UTC().Unix() > claims.Exp {
		return pairingTokenClaims{}, errors.New("token expired")
	}
	if claims.Purpose != wantPurpose {
		return pairingTokenClaims{}, errors.New("purpose mismatch")
	}

	return claims, nil
}

func (s *Server) validatePairingToken(subscriberID, token, wantPurpose string, now time.Time) error {
	claims, err := s.decodeAndVerifyPairingToken(token, wantPurpose, now)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(claims.Sub)), []byte(strings.TrimSpace(subscriberID))) != 1 {
		return errors.New("subscriber mismatch")
	}
	return nil
}

// parsePairingTokenUserID decodes and HMAC-verifies token without requiring
// the caller to already know the expected subject, returning the subject
// the token was minted for. Used by the QR key-fetch endpoint, which must
// learn which user a token belongs to rather than confirm a known one —
// unlike validatePairingToken (used for pickup links, where the URL path
// already carries the expected ID to check against).
func (s *Server) parsePairingTokenUserID(token, wantPurpose string, now time.Time) (string, error) {
	claims, err := s.decodeAndVerifyPairingToken(token, wantPurpose, now)
	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}
