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
	"strconv"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/netguard"
	"github.com/Busness-app/kypost-server/backend/internal/state"
)

var ErrNativeDeviceStale = errors.New("native device token is stale")

const (
	// unifiedPushTTLSeconds bounds how long a distributor holds an undelivered
	// notification. Five minutes: a mail alert that arrives later is noise.
	unifiedPushTTLSeconds = 300
	// webPushSubscriber is the VAPID "sub" claim, matching SendWebPush's
	// existing convention — distributors do not act on it.
	webPushSubscriber = "mailto:noreply@localhost"
)

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

// ValidateRelayURL refuses a relay base URL that would put the per-server relay
// key on the wire in cleartext. Every request this sender makes — /register and
// every /send — carries that key as a bearer token, alongside the notification
// title and body, so an http:// relay URL is not a weaker transport, it is a
// credential disclosure to anyone on the path.
//
// Checked at construction rather than at send time so a typo in PUSH_RELAY_URL
// fails loudly at startup, before auto-registration has already handed the
// freshly minted key to a plaintext endpoint.
//
// Loopback over http is allowed: it never leaves the host, and it is how the
// relay is exercised locally and in tests.
func ValidateRelayURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid relay URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("relay URL missing host")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.New("relay URL must use https (http is allowed only for loopback)")
	default:
		return fmt.Errorf("relay URL must use https, got scheme %q", u.Scheme)
	}
}

// newRelaySenderFromEnvWithPrefix builds a relay sender for the given prefix
// (e.g. "PUSH_RELAY" or "APNS_RELAY"), or returns nil if not configured.
func newRelaySenderFromEnvWithPrefix(log *logging.Logger, prefix string) *RelaySender {
	relayURL := strings.TrimRight(strings.TrimSpace(os.Getenv(prefix+"_URL")), "/")
	if relayURL == "" {
		return nil
	}
	if err := ValidateRelayURL(relayURL); err != nil {
		logNativeSenderError(log, prefix+"_URL is not usable", err.Error())
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
	// VAPID identity, shared with browser Web Push. Here it only signs the
	// Authorization JWT; most distributors do not check it. Empty
	// vapidPrivateKey means the key could not be loaded, and Send falls back to
	// the unencrypted POST rather than dropping the notification.
	vapidPublicKey  string
	vapidPrivateKey string
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
func NewUnifiedPushSender(log *logging.Logger, vapidPublicKey, vapidPrivateKeyPath string) *UnifiedPushSender {
	// Never fail construction: a server that cannot read its VAPID key must
	// still deliver notifications, unencrypted, rather than deliver none.
	privateKey := ""
	if strings.TrimSpace(vapidPrivateKeyPath) != "" {
		loaded, err := config.LoadVAPIDPrivateKey(vapidPrivateKeyPath)
		if err != nil {
			if log != nil {
				log.Error("unifiedpush: VAPID private key unreadable, payloads will be sent unencrypted", "path", vapidPrivateKeyPath, "error", err.Error())
			}
		} else {
			privateKey = loaded
		}
	}
	return &UnifiedPushSender{
		vapidPublicKey:  strings.TrimSpace(vapidPublicKey),
		vapidPrivateKey: privateKey,
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

	// RFC 8291 when the device gave us key material and we hold a VAPID key;
	// otherwise the historical cleartext POST, so a device registered by an
	// older client keeps receiving notifications instead of silently none.
	if device.P256DH != "" && device.Auth != "" && s.vapidPrivateKey != "" {
		return s.sendEncrypted(ctx, endpointURL, device, body)
	}
	return s.sendPlaintext(ctx, endpointURL, body)
}

// sendEncrypted POSTs an RFC 8291 (aes128gcm) payload the connector can open.
// It hands webpush-go this sender's own client, not the bare *http.Client
// webpush-go would otherwise build: the endpoint URL is user-supplied, so
// losing safeDialContext and the redirect refusal here would reopen the SSRF
// hole UnifiedPushSender exists to close.
func (s *UnifiedPushSender) sendEncrypted(ctx context.Context, endpointURL string, device state.NativeDevice, body []byte) error {
	resp, err := webpush.SendNotificationWithContext(ctx, body, &webpush.Subscription{
		Endpoint: endpointURL,
		Keys:     webpush.Keys{Auth: device.Auth, P256dh: device.P256DH},
	}, &webpush.Options{
		Subscriber:      webPushSubscriber,
		VAPIDPublicKey:  s.vapidPublicKey,
		VAPIDPrivateKey: s.vapidPrivateKey,
		TTL:             unifiedPushTTLSeconds,
		HTTPClient:      s.client,
	})
	if err != nil {
		return fmt.Errorf("encrypted POST failed: %w", err)
	}
	defer resp.Body.Close()
	return interpretUnifiedPushResponse(resp)
}

func (s *UnifiedPushSender) sendPlaintext(ctx context.Context, endpointURL string, body []byte) error {
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
	return interpretUnifiedPushResponse(resp)
}

// interpretUnifiedPushResponse maps the endpoint's status to this package's
// error vocabulary. Shared by both paths on purpose: stale detection that
// differed between them would leave dead endpoints on the encrypted path
// being retried forever.
func interpretUnifiedPushResponse(resp *http.Response) error {
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	trimmed := strings.TrimSpace(string(respBody))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Treat 404/410 as stale: the endpoint is no longer valid.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		return &relayStatusError{Code: resp.StatusCode, Body: trimmed, RetryAfter: parseRetryAfter(resp.Header), err: fmt.Errorf("%w: status=%d response=%s", ErrNativeDeviceStale, resp.StatusCode, trimmed)}
	}

	return &relayStatusError{Code: resp.StatusCode, Body: trimmed, RetryAfter: parseRetryAfter(resp.Header), err: fmt.Errorf("UnifiedPush endpoint failed: status=%d response=%s", resp.StatusCode, trimmed)}
}

// relayStatusError carries the far end's HTTP status as a FIELD, so
// classification never has to go looking for it in text.
//
// push_failure_reason.go used to recover the code with a regex over
// err.Error(). The comment there claimed that matching "status=NNN" meant
// matching only this package's own formatting — but FindStringSubmatch scans the
// whole string, and these errors carry up to 8 KiB of the remote server's
// response body, from a host the device's owner chose. A body containing
// "status=401" steered the published health field. The impact was bounded (the
// output is drawn from a closed vocabulary either way), but a parser reading
// attacker-supplied text to decide anything is the wrong shape.
type relayStatusError struct {
	Code int
	Body string
	// RetryAfter is the far end's Retry-After header, parsed, or zero when it
	// sent none. Honoured by sendWithRetry: a relay that says when to come back
	// knows better than any backoff curve we could pick.
	RetryAfter time.Duration
	err        error
}

// parseRetryAfter reads the delay form of Retry-After. The HTTP-date form is
// ignored on purpose: it needs a trusted clock at both ends, and every relay
// this talks to sends seconds.
//
// Bounded, because the value comes from the far end. An unbounded parse lets a
// hostile or broken relay park a goroutine for as long as it likes.
func parseRetryAfter(h http.Header) time.Duration {
	raw := strings.TrimSpace(h.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 0
	}
	if d := time.Duration(seconds) * time.Second; d <= maxRelayRetryAfter {
		return d
	}
	return maxRelayRetryAfter
}

func (e *relayStatusError) Error() string { return e.err.Error() }
func (e *relayStatusError) Unwrap() error { return e.err }

// NativePushDispatcher routes native push notifications to the appropriate transport:
// UnifiedPush (direct HTTPS POST), FCM relay, or APNs relay.
type NativePushDispatcher struct {
	fcmSender         *RelaySender
	apnsSender        *RelaySender
	unifiedPushSender *UnifiedPushSender
}

// NewNativePushDispatcher constructs a dispatcher with FCM (PUSH_RELAY_*),
// APNs (APNS_RELAY_*), and UnifiedPush senders. Relay senders may be nil if not
// configured. The VAPID pair is the browser-push one (cfg.Notifications), reused
// here to encrypt UnifiedPush payloads — see NewUnifiedPushSender.
func NewNativePushDispatcher(log *logging.Logger, vapidPublicKey, vapidPrivateKeyPath string) *NativePushDispatcher {
	return &NativePushDispatcher{
		fcmSender:         newRelaySenderFromEnvWithPrefix(log, "PUSH_RELAY"),
		apnsSender:        newRelaySenderFromEnvWithPrefix(log, "APNS_RELAY"),
		unifiedPushSender: NewUnifiedPushSender(log, vapidPublicKey, vapidPrivateKeyPath),
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
		return &relayStatusError{Code: resp.StatusCode, Body: trimmed, RetryAfter: parseRetryAfter(resp.Header), err: fmt.Errorf("%w: status=%d response=%s", ErrNativeDeviceStale, resp.StatusCode, trimmed)}
	}
	return &relayStatusError{Code: resp.StatusCode, Body: trimmed, RetryAfter: parseRetryAfter(resp.Header), err: fmt.Errorf("push relay send failed: status=%d response=%s", resp.StatusCode, trimmed)}
}

// isRelayStaleResponse reports whether the relay signalled that the device
// token is no longer registered. The relay returns HTTP 410 with
// {"stale":true} for unregistered tokens; we also match the underlying FCM
// wording defensively in case it is surfaced verbatim.
// Deliberately narrow: 410 AND the structured body, which is exactly what both
// relay Workers emit. The previous form matched a bare 410 with no body, and
// four substrings anywhere in an 8 KiB body at any non-2xx status, with nothing
// tying the response to the token that was sent. Since the consequence is
// retiring a device — and a device row carries its authentication secret, not
// just a push token — that handed the relay far more authority than delivering
// a notification requires.
func isRelayStaleResponse(statusCode int, response string) bool {
	if statusCode != http.StatusGone {
		return false
	}
	lower := strings.ToLower(response)
	return strings.Contains(lower, `"stale":true`) || strings.Contains(lower, `"stale": true`)
}
