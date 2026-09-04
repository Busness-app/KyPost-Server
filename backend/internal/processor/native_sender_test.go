package processor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/state"
)

func TestRelaySenderSendSuccess(t *testing.T) {
	var seenAuth string
	var seenBody relaySendRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/send" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		seenAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")

	sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY")
	if sender == nil {
		t.Fatal("newRelaySenderFromEnvWithPrefix(nil, \"PUSH_RELAY\") returned nil")
	}
	sender.client = ts.Client()

	err := sender.Send(context.Background(), state.NativeDevice{PushToken: "device-token", Platform: "android"}, NativePushMessage{Title: "Title", Body: "Body", Data: map[string]string{"messageId": "m1"}})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if seenAuth != "Bearer test-api-key" {
		t.Fatalf("authorization header = %q, want %q", seenAuth, "Bearer test-api-key")
	}
	if seenBody.Token != "device-token" || seenBody.Title != "Title" || seenBody.Body != "Body" {
		t.Fatalf("unexpected relay body: %+v", seenBody)
	}
	if seenBody.Platform != "android" {
		t.Fatalf("platform = %q, want %q", seenBody.Platform, "android")
	}
	if seenBody.Data["messageId"] != "m1" {
		t.Fatalf("data messageId = %q, want %q", seenBody.Data["messageId"], "m1")
	}
}

func TestRelaySenderSendReturnsStaleError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/send" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"stale":true}`))
	}))
	defer ts.Close()

	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")

	sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY")
	if sender == nil {
		t.Fatal("newRelaySenderFromEnvWithPrefix(nil, \"PUSH_RELAY\") returned nil")
	}
	sender.client = ts.Client()

	err := sender.Send(context.Background(), state.NativeDevice{PushToken: "device-token"}, NativePushMessage{Title: "Title", Body: "Body"})
	if !errors.Is(err, ErrNativeDeviceStale) {
		t.Fatalf("Send() error = %v, want ErrNativeDeviceStale", err)
	}
}

func TestNewRelaySenderFromEnvRequiresURL(t *testing.T) {
	t.Setenv("PUSH_RELAY_URL", "")
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")
	if sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY"); sender != nil {
		t.Fatal("NewRelaySenderFromEnv should return nil when PUSH_RELAY_URL is empty")
	}
}

// When there is no key and registration fails (e.g. the relay has registration
// disabled), the sender must not be created.
func TestNewRelaySenderFromEnvRegistrationFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/register" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"self-registration is disabled"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "")
	t.Setenv("PUSH_RELAY_KEY_FILE", filepath.Join(t.TempDir(), "push_relay_key"))

	if sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY"); sender != nil {
		t.Fatal("NewRelaySenderFromEnv should return nil when registration fails")
	}
}

// With no key configured, the server self-registers, persists the key, reuses it
// on the next boot, and does not register a second time.
func TestNewRelaySenderFromEnvAutoRegisterPersistsAndReuses(t *testing.T) {
	var registerCalls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&registerCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"id-1","label":"srv","key":"minted-key","expiresAt":null}`))
	}))
	defer ts.Close()

	keyFile := filepath.Join(t.TempDir(), "push_relay_key")
	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "")
	t.Setenv("PUSH_RELAY_KEY_FILE", keyFile)

	sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY")
	if sender == nil {
		t.Fatal("expected sender from auto-registration")
	}
	if sender.apiKey != "minted-key" {
		t.Fatalf("apiKey = %q, want %q", sender.apiKey, "minted-key")
	}
	if got := atomic.LoadInt32(&registerCalls); got != 1 {
		t.Fatalf("register calls = %d, want 1", got)
	}
	if b, err := os.ReadFile(keyFile); err != nil || string(b) != "minted-key\n" {
		t.Fatalf("key file = %q (err %v), want %q", string(b), err, "minted-key\n")
	}

	// Second boot: key is read from the file, no re-registration.
	sender2 := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY")
	if sender2 == nil || sender2.apiKey != "minted-key" {
		t.Fatalf("second sender did not reuse persisted key: %+v", sender2)
	}
	if got := atomic.LoadInt32(&registerCalls); got != 1 {
		t.Fatalf("register calls after reuse = %d, want 1 (should not re-register)", got)
	}
}

// Apple platforms (iOS and macOS) must route to the APNs sender; everything
// else (including empty/unknown) falls back to FCM (legacy behavior with empty Transport).
func TestDispatcherLegacyPlatformRoutingWithoutExplicitTransport(t *testing.T) {
	fcm := &RelaySender{}
	apns := &RelaySender{}
	d := &NativePushDispatcher{fcmSender: fcm, apnsSender: apns, unifiedPushSender: NewUnifiedPushSender(nil, "", "")}

	cases := []struct {
		platform string
		want     interface{} // *RelaySender
	}{
		{"ios", apns},
		{"iOS ", apns},
		{"macos", apns},
		{"MacOS", apns},
		{"android", fcm},
		{"", fcm},
		{"windows", fcm},
	}
	for _, c := range cases {
		device := state.NativeDevice{Transport: "", Platform: c.platform}
		sender, _ := d.selectSender(device)
		if sender != c.want {
			t.Errorf("selectSender(Platform=%q, Transport=\"\") routed to the wrong sender (got %T, want %T)", c.platform, sender, c.want)
		}
	}
}

// An explicit PUSH_RELAY_KEY takes precedence and never triggers registration or
// touches the key file.
func TestNewRelaySenderFromEnvExplicitKeyWins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("registration must not be called when PUSH_RELAY_KEY is set (path %s)", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	keyFile := filepath.Join(t.TempDir(), "push_relay_key")
	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "explicit-key")
	t.Setenv("PUSH_RELAY_KEY_FILE", keyFile)

	sender := newRelaySenderFromEnvWithPrefix(nil, "PUSH_RELAY")
	if sender == nil || sender.apiKey != "explicit-key" {
		t.Fatalf("expected explicit key to win, got %+v", sender)
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("key file should not be written when PUSH_RELAY_KEY is set (stat err = %v)", err)
	}
}

// UnifiedPushSender must POST to the endpoint URL with JSON payload.
func TestUnifiedPushSenderSendSuccess(t *testing.T) {
	var seenBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`OK`))
	}))
	defer ts.Close()

	sender := NewUnifiedPushSender(nil, "", "")
	sender.client = ts.Client()

	err := sender.Send(context.Background(), state.NativeDevice{PushToken: ts.URL + "/topic"}, NativePushMessage{Title: "Title", Body: "Body", Data: map[string]string{"type": "mail"}})
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if seenBody["title"] != "Title" || seenBody["body"] != "Body" {
		t.Fatalf("unexpected body: %+v", seenBody)
	}
	if d, ok := seenBody["data"].(map[string]any); !ok || d["type"] != "mail" {
		t.Fatalf("data mismatch: %+v", seenBody["data"])
	}
}

// UnifiedPushSender must treat 404/410 as stale.
func TestUnifiedPushSenderReturnsStaleError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	sender := NewUnifiedPushSender(nil, "", "")
	sender.client = ts.Client()

	err := sender.Send(context.Background(), state.NativeDevice{PushToken: ts.URL + "/topic"}, NativePushMessage{Title: "Title", Body: "Body"})
	if !errors.Is(err, ErrNativeDeviceStale) {
		t.Fatalf("Send() error = %v, want ErrNativeDeviceStale", err)
	}
}

// Dispatcher must route by Transport field (explicit > platform-derived).
func TestDispatcherSelectSenderByTransport(t *testing.T) {
	fcm := &RelaySender{}
	apns := &RelaySender{}
	up := &UnifiedPushSender{}
	d := &NativePushDispatcher{fcmSender: fcm, apnsSender: apns, unifiedPushSender: up}

	cases := []struct {
		name      string
		device    state.NativeDevice
		wantType  string
		wantError bool
	}{
		// Explicit transport wins.
		{"unifiedpush explicit", state.NativeDevice{Transport: "unifiedpush", Platform: "android"}, "UnifiedPushSender", false},
		{"fcm explicit", state.NativeDevice{Transport: "fcm", Platform: "ios"}, "RelaySender", false},
		{"apns explicit", state.NativeDevice{Transport: "apns", Platform: "android"}, "RelaySender", false},

		// Platform-derived when transport is empty.
		{"ios derived apns", state.NativeDevice{Transport: "", Platform: "ios"}, "RelaySender", false},
		{"android derived fcm", state.NativeDevice{Transport: "", Platform: "android"}, "RelaySender", false},
		{"macos derived apns", state.NativeDevice{Transport: "", Platform: "macos"}, "RelaySender", false},

		// Unknown platform defaults to FCM.
		{"unknown platform", state.NativeDevice{Transport: "", Platform: "windows"}, "RelaySender", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sender, err := d.selectSender(c.device)
			if (err != nil) != c.wantError {
				t.Fatalf("selectSender() error = %v, wantError %v", err, c.wantError)
			}
			if sender == nil && !c.wantError {
				t.Fatal("selectSender() returned nil sender")
			}
		})
	}
}

// Dispatcher Send method must dispatch to the correct sender type.
func TestDispatcherSendRoutesCorrectly(t *testing.T) {
	upTS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upTS.Close()

	d := &NativePushDispatcher{
		fcmSender:         nil, // Not configured; will error if used
		apnsSender:        nil,
		unifiedPushSender: NewUnifiedPushSender(nil, "", ""),
	}
	d.unifiedPushSender.client = upTS.Client()

	// UnifiedPush device should route to the UP sender (which succeeds).
	err := d.Send(context.Background(), state.NativeDevice{Transport: "unifiedpush", PushToken: upTS.URL}, NativePushMessage{Title: "Test"})
	if err != nil {
		t.Fatalf("Send() with unifiedpush transport error = %v", err)
	}

	// FCM device with no FCM relay configured should error.
	err = d.Send(context.Background(), state.NativeDevice{Transport: "fcm"}, NativePushMessage{Title: "Test"})
	if err == nil {
		t.Fatal("Send() with fcm transport but no relay should error")
	}
}

// isPrivateOrReservedIP must flag every address class that must never be
// reached via a client-supplied UnifiedPush endpoint (SSRF defense), and
// leave ordinary public addresses alone.
func TestIsPrivateOrReservedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},             // loopback
		{"::1", true},                   // IPv6 loopback
		{"10.0.0.5", true},              // RFC1918 private
		{"172.16.0.1", true},            // RFC1918 private
		{"192.168.1.1", true},           // RFC1918 private
		{"169.254.169.254", true},       // link-local / cloud metadata
		{"169.254.0.1", true},           // link-local
		{"fc00::1", true},               // RFC4193 unique local (IPv6 private)
		{"fe80::1", true},               // IPv6 link-local
		{"0.0.0.0", true},               // unspecified
		{"224.0.0.1", true},             // multicast
		{"8.8.8.8", false},              // public
		{"1.1.1.1", false},              // public
		{"2606:4700:4700::1111", false}, // public IPv6 (Cloudflare)
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("net.ParseIP(%q) returned nil", c.ip)
		}
		if got := isPrivateOrReservedIP(ip); got != c.want {
			t.Errorf("isPrivateOrReservedIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

// ValidateUnifiedPushEndpointURL must reject non-https schemes and IP-literal
// hosts in private/reserved ranges (including the cloud metadata address),
// and accept public IP-literal hosts. IP literals avoid any DNS dependency
// in this test.
func TestValidateUnifiedPushEndpointURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http scheme rejected", "http://8.8.8.8/topic", true},
		{"no scheme rejected", "8.8.8.8/topic", true},
		{"public IPv4 literal accepted", "https://8.8.8.8/topic", false},
		{"loopback rejected", "https://127.0.0.1/topic", true},
		{"cloud metadata rejected", "https://169.254.169.254/latest/meta-data", true},
		{"rfc1918 rejected", "https://10.0.0.5/topic", true},
		{"rfc1918 192.168 rejected", "https://192.168.1.1/topic", true},
		{"ipv6 loopback rejected", "https://[::1]/topic", true},
		{"invalid url rejected", "https://%zz", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateUnifiedPushEndpointURL(c.url)
			if (err != nil) != c.wantErr {
				t.Errorf("ValidateUnifiedPushEndpointURL(%q) error = %v, wantErr %v", c.url, err, c.wantErr)
			}
		})
	}
}

// Send must reject non-https endpoints even if a device record somehow ended
// up with one (defense in depth alongside registration-time validation).
func TestUnifiedPushSenderSendRejectsNonHTTPS(t *testing.T) {
	sender := NewUnifiedPushSender(nil, "", "")
	err := sender.Send(context.Background(), state.NativeDevice{PushToken: "http://example.com/topic"}, NativePushMessage{Title: "Test"})
	if err == nil {
		t.Fatal("Send() with http:// endpoint should error")
	}
}

// The dispatcher's UnifiedPush sender must refuse to dial private/loopback
// addresses even when not overridden with a test client, proving the
// production dial path (safeDialContext) is actually wired in and not just
// bypassed by tests that swap in ts.Client().
func TestUnifiedPushSenderRefusesPrivateAddressAtDialTime(t *testing.T) {
	sender := NewUnifiedPushSender(nil, "", "")
	// A loopback listener the sender must refuse to connect to via its real
	// (non-test-overridden) transport, proving safeDialContext is active.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	// Use the sender's real transport (not ts.Client()) so safeDialContext runs;
	// only borrow the test server's TLS trust so the handshake itself would
	// otherwise succeed if the dial were allowed through.
	sender.client.Transport.(*http.Transport).TLSClientConfig = ts.Client().Transport.(*http.Transport).TLSClientConfig

	err := sender.Send(context.Background(), state.NativeDevice{PushToken: ts.URL + "/topic"}, NativePushMessage{Title: "Test"})
	if err == nil {
		t.Fatal("Send() to a loopback address should be refused by safeDialContext")
	}
}
