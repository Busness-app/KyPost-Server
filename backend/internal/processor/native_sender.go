package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/netguard"
	"kypost-server/backend/internal/state"
)

var ErrNativeDeviceStale = errors.New("native device token is stale")

type NativePushMessage struct {
	Title string
	Body  string
	Data  map[string]string
}

// RelaySender forwards native push requests to the central Cloudflare Worker
// relay, which holds the single Firebase service account the published mobile
// app is built against. Self-hosted servers never talk to FCM directly; they
// authenticate to the relay with a per-server API key. The relay delivers to
// every platform (iOS and Android), so it is the only native sender.
type RelaySender struct {
	relayURL string
	apiKey   string
	client   *http.Client
}

// relaySendRequest is the JSON body POSTed to the relay's /send endpoint.
type relaySendRequest struct {
	Token    string            `json:"token"`
	Title    string            `json:"title"`
	Body     string            `json:"body"`
	Data     map[string]string `json:"data,omitempty"`
	Platform string            `json:"platform,omitempty"`
}

func logNativeSenderError(log *logging.Logger, reason, detail string) {
	if log == nil {
		return
	}
	log.Error("native push relay not configured", "reason", reason, "detail", detail)
}

// newRelaySenderFromEnvWithPrefix builds a relay sender for the given prefix
// (e.g. "PUSH_RELAY" or "APNS_RELAY"), or returns nil if not configured.
func newRelaySenderFromEnvWithPrefix(log *logging.Logger, prefix string) *RelaySender {
	relayURL := strings.TrimRight(strings.TrimSpace(os.Getenv(prefix+"_URL")), "/")
	if relayURL == "" {
		return nil
	}
	client := &http.Client{Timeout: 15 * time.Second}

	apiKey, err := resolveRelayKeyWithPrefix(log, prefix, relayURL, client)
	if err != nil {
		logNativeSenderError(log, prefix+" relay key unavailable", err.Error())
		return nil
	}
	if apiKey == "" {
		logNativeSenderError(log, prefix+"_KEY missing", "no key in "+prefix+"_KEY, the key file, or from auto-registration")
		return nil
	}

	return &RelaySender{
		relayURL: relayURL,
		apiKey:   apiKey,
		client:   client,
	}
}

// relayKeyFilePathWithPrefix is where an auto-registered key is persisted.
// Parameterized by prefix so distinct relays (PUSH_RELAY vs APNS_RELAY) store
// keys in distinct files and don't collide on disk.
func relayKeyFilePathWithPrefix(prefix string) string {
	if p := strings.TrimSpace(os.Getenv(prefix + "_KEY_FILE")); p != "" {
		return p
	}
	// e.g. "push_relay_key" for PUSH_RELAY, "apns_relay_key" for APNS_RELAY.
	name := strings.ToLower(strings.TrimSuffix(prefix, "_RELAY")) + "_relay_key"
	return filepath.Join(config.SecretDir(), name)
}

// resolveRelayKeyWithPrefix obtains the per-server relay key for a given relay prefix,
// in order of preference:
//  1. {prefix}_KEY (explicit env, e.g. an operator-issued key)
//  2. the persisted key file (a previous auto-registration)
//  3. auto-registration: POST /register, then persist the returned key
func resolveRelayKeyWithPrefix(log *logging.Logger, prefix, relayURL string, client *http.Client) (string, error) {
	if key := strings.TrimSpace(os.Getenv(prefix + "_KEY")); key != "" {
		return key, nil
	}

	path := relayKeyFilePathWithPrefix(prefix)
	if b, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			return key, nil
		}
	}

	key, err := registerWithRelay(relayURL, client)
	if err != nil {
		return "", err
	}
	if err := fsutil.AtomicWriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		if log != nil {
			log.Error("failed to persist auto-registered relay key", "prefix", prefix, "path", path, "error", err.Error())
		}
	} else if log != nil {
		log.Info("auto-registered with relay", "prefix", prefix, "key_file", path)
	}
	return key, nil
}

// registerWithRelay self-issues a per-server key from the relay's public
// /register endpoint. No credentials are required; the relay ties one active
// key to the requesting IP.
func registerWithRelay(relayURL string, client *http.Client) (string, error) {
	label, _ := os.Hostname()
	if strings.TrimSpace(label) == "" {
		label = "kypost-server"
	}
	body, err := json.Marshal(map[string]string{"label": label})
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, relayURL+"/register", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("push relay registration failed: status=%d response=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var parsed struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return "", fmt.Errorf("push relay registration returned invalid JSON: %w", err)
	}
	key := strings.TrimSpace(parsed.Key)
	if key == "" {
		return "", errors.New("push relay registration returned no key")
	}
	return key, nil
}

// UnifiedPushSender directly POSTs to UnifiedPush endpoints (e.g., ntfy.sh topics).
// Unlike FCM/APNs relays, there is no shared credential—the endpoint URL itself
// is public, and anyone who knows it can POST. See: https://unifiedpush.org/
//
// Because the endpoint is fully client-supplied at registration time, this is a
// classic SSRF surface: without validation, a malicious/compromised client could
// register an "endpoint" pointing at internal services (cloud metadata IPs,
// admin panels on the server's own network) and have this server dutifully POST
// to it on every notification. Defense is two-layered: ValidateUnifiedPushEndpointURL
// rejects obviously-unsafe endpoints at registration time, and the sender's own
// dial hook re-resolves and re-checks the IP immediately before every connection
// (registration-time DNS can be rebound to a private address afterward).
type UnifiedPushSender struct {
	client *http.Client
}

// isPrivateOrReservedIP reports whether ip must never be reached via a
// server-supplied UnifiedPush endpoint: loopback, RFC1918/RFC4193 private,
// link-local (this also covers the 169.254.169.254 cloud metadata address),
// multicast, or unspecified.
func isPrivateOrReservedIP(ip net.IP) bool {
	return netguard.IsPrivateOrReserved(ip)
}

// ValidateUnifiedPushEndpointURL rejects UnifiedPush endpoint URLs that are
// not safe to POST to from the server: non-https schemes, and hosts that
// resolve (or are given as IP literals) to a private/loopback/link-local
// address. Used at registration time so bad endpoints are rejected up front;
// see UnifiedPushSender for the send-time recheck against DNS rebinding.
func ValidateUnifiedPushEndpointURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("endpoint must use https")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("endpoint missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrReservedIP(ip) {
			return errors.New("endpoint resolves to a private or reserved address")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve endpoint host: %w", err)
	}
	for _, ip := range ips {
		if isPrivateOrReservedIP(ip) {
			return fmt.Errorf("endpoint host resolves to a private or reserved address (%s)", ip)
		}
	}
	return nil
}

// safeDialContext re-resolves the target host and refuses to connect if every
// candidate address is private/reserved. Run at actual dial time (not just
// registration time) so a hostname that was public at registration but has
// since been rebound to an internal address (DNS rebinding) is still blocked.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var chosen net.IP
	for _, ip := range ips {
		if !isPrivateOrReservedIP(ip) {
			chosen = ip
			break
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("refusing to dial %q: no public address available", host)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(chosen.String(), port))
}

// NewUnifiedPushSender constructs a direct HTTPS client for UnifiedPush endpoints,
// with dial-time SSRF protection (see safeDialContext) and redirects disabled
// (a redirect target bypasses the pre-dial check otherwise).
func NewUnifiedPushSender() *UnifiedPushSender {
	return &UnifiedPushSender{
		client: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{DialContext: safeDialContext},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("redirects are not followed for UnifiedPush endpoints")
			},
		},
	}
}

// Send POSTs a JSON payload to the UnifiedPush endpoint. The endpoint URL
// (stored in device.PushToken) is a public URL like https://ntfy.sh/<topic>.
func (s *UnifiedPushSender) Send(ctx context.Context, device state.NativeDevice, message NativePushMessage) error {
	endpointURL := strings.TrimSpace(device.PushToken)
	if endpointURL == "" {
		return errors.New("missing UnifiedPush endpoint URL")
	}
	if !strings.HasPrefix(endpointURL, "https://") {
		return errors.New("UnifiedPush endpoint must use https")
	}

	// Mirror the shape of pull-mode payloads for consistency on the client side.
	payload := map[string]any{
		"title": message.Title,
		"body":  message.Body,
	}
	if len(message.Data) > 0 {
		payload["data"] = message.Data
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	trimmed := strings.TrimSpace(string(respBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Treat 404/410 as stale: the endpoint is no longer valid.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return fmt.Errorf("%w: status=%d response=%s", ErrNativeDeviceStale, resp.StatusCode, trimmed)
	}

	return fmt.Errorf("UnifiedPush endpoint failed: status=%d response=%s", resp.StatusCode, trimmed)
}

// NativePushDispatcher routes native push notifications to the appropriate transport:
// UnifiedPush (direct HTTPS POST), FCM relay, or APNs relay.
type NativePushDispatcher struct {
	fcmSender         *RelaySender
	apnsSender        *RelaySender
	unifiedPushSender *UnifiedPushSender
}

// NewNativePushDispatcher constructs a dispatcher with FCM (PUSH_RELAY_*),
// APNs (APNS_RELAY_*), and UnifiedPush senders. Relay senders may be nil if not configured.
func NewNativePushDispatcher(log *logging.Logger) *NativePushDispatcher {
	return &NativePushDispatcher{
		fcmSender:         newRelaySenderFromEnvWithPrefix(log, "PUSH_RELAY"),
		apnsSender:        newRelaySenderFromEnvWithPrefix(log, "APNS_RELAY"),
		unifiedPushSender: NewUnifiedPushSender(),
	}
}

// nativeSender is implemented by every native push transport (*RelaySender,
// *UnifiedPushSender), letting selectSender return one without a type switch
// at each call site.
type nativeSender interface {
	Send(ctx context.Context, device state.NativeDevice, message NativePushMessage) error
}

// selectSender returns the appropriate sender for a device based on its Transport
// and Platform, or an error if no sender is available.
func (d *NativePushDispatcher) selectSender(device state.NativeDevice) (nativeSender, error) {
	transport := strings.ToLower(strings.TrimSpace(device.Transport))

	// If transport is explicit, use it; otherwise derive from platform (legacy).
	if transport == "" {
		switch strings.ToLower(strings.TrimSpace(device.Platform)) {
		case "ios", "macos":
			transport = "apns"
		default:
			transport = "fcm"
		}
	}

	switch transport {
	case "unifiedpush":
		return d.unifiedPushSender, nil
	case "apns":
		if d.apnsSender != nil {
			return d.apnsSender, nil
		}
		return nil, fmt.Errorf("APNs relay not configured")
	case "fcm":
		if d.fcmSender != nil {
			return d.fcmSender, nil
		}
		return nil, fmt.Errorf("FCM relay not configured")
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
}

// Send dispatches a native push to the appropriate sender based on device.Transport/Platform.
func (d *NativePushDispatcher) Send(ctx context.Context, device state.NativeDevice, message NativePushMessage) error {
	sender, err := d.selectSender(device)
	if err != nil {
		return err
	}
	return sender.Send(ctx, device, message)
}

func (s *RelaySender) Send(ctx context.Context, device state.NativeDevice, message NativePushMessage) error {
	registrationToken := strings.TrimSpace(device.PushToken)
	if registrationToken == "" {
		return errors.New("missing push token")
	}

	body, err := json.Marshal(relaySendRequest{
		Token:    registrationToken,
		Title:    message.Title,
		Body:     message.Body,
		Data:     message.Data,
		Platform: device.Platform,
	})
	if err != nil {
		return err
	}

	sendURL := s.relayURL + "/send"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	trimmed := strings.TrimSpace(string(respBody))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if isRelayStaleResponse(resp.StatusCode, trimmed) {
		return fmt.Errorf("%w: status=%d response=%s", ErrNativeDeviceStale, resp.StatusCode, trimmed)
	}
	return fmt.Errorf("push relay send failed: status=%d response=%s", resp.StatusCode, trimmed)
}

// isRelayStaleResponse reports whether the relay signalled that the device
// token is no longer registered. The relay returns HTTP 410 with
// {"stale":true} for unregistered tokens; we also match the underlying FCM
// wording defensively in case it is surfaced verbatim.
func isRelayStaleResponse(statusCode int, response string) bool {
	if statusCode == http.StatusGone {
		return true
	}
	lower := strings.ToLower(response)
	if strings.Contains(lower, `"stale":true`) || strings.Contains(lower, `"stale": true`) {
		return true
	}
	if strings.Contains(lower, "unregistered") || strings.Contains(lower, "notregistered") || strings.Contains(lower, "registration-token-not-registered") {
		return true
	}
	if statusCode == http.StatusNotFound && strings.Contains(lower, "requested entity was not found") {
		return true
	}
	return false
}
