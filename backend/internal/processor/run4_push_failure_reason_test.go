package processor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/health"
	"github.com/Busness-app/kypost-server/backend/internal/state"
)

// run-4 M8: health.Status.NativePushLastError is serialized by the
// unauthenticated /api/health, and it was fed err.Error() verbatim.
//
// Two ways that leaks. http.Client wraps transport failures in *url.Error,
// which stringifies the full request URL — and for a UnifiedPush device the
// endpoint URL *is* the credential (https://ntfy.sh/<private-topic>), so any
// transport failure published it to the internet. And the UnifiedPush sender
// embeds up to 8 KiB of the remote server's raw response body, so a user who
// points a device at a host they control can plant arbitrary text on the
// instance's anonymous health JSON.
//
// The health field now carries a coarse classification and the platform. The
// detail stays in the log, where it is useful and not public.

func TestClassifyPushFailureNeverEchoesTheEndpointURL(t *testing.T) {
	secret := "https://ntfy.sh/kypost-a8f3e91c-private"
	err := fmt.Errorf("POST failed: %w", &url.Error{
		Op:  "Post",
		URL: secret,
		Err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
	})

	got := classifyNativePushFailure("android", err)

	if strings.Contains(got, "ntfy.sh") || strings.Contains(got, "kypost-a8f3e91c-private") {
		t.Fatalf("the endpoint URL reached the public health field: %q", got)
	}
	if !strings.Contains(got, "android") {
		t.Fatalf("classification dropped the platform: %q", got)
	}
}

func TestClassifyPushFailureNeverEchoesTheRemoteResponseBody(t *testing.T) {
	planted := "<script>alert(1)</script> ATTACKER CONTROLLED TEXT"
	err := fmt.Errorf("UnifiedPush endpoint failed: status=%d response=%s", http.StatusTeapot, planted)

	got := classifyNativePushFailure("android", err)

	if strings.Contains(got, "ATTACKER CONTROLLED") || strings.Contains(got, "<script>") {
		t.Fatalf("attacker-controlled text reached the public health field: %q", got)
	}
}

// A coarse classification is only worth having if it still tells an operator
// which way to look.
func TestClassifyPushFailureDistinguishesTheUsefulCases(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "transport",
			err:  fmt.Errorf("POST failed: %w", &url.Error{Op: "Post", URL: "https://h/x", Err: errors.New("connection refused")}),
			want: "unreachable",
		},
		{
			name: "timeout",
			err:  fmt.Errorf("POST failed: %w", context.DeadlineExceeded),
			want: "timeout",
		},
		{
			// The reason the code is a field and not a regex match. The body is
			// written by whoever owns the host the device points at, and it used
			// to be scanned for "status=NNN" alongside our own formatting.
			name: "attacker-controlled body cannot forge the status",
			err: &relayStatusError{
				Code: 502,
				Body: "status=401 status=429 nice try",
				err:  errors.New("UnifiedPush endpoint failed: status=502 response=status=401 status=429 nice try"),
			},
			want: "server_error",
		},
		{
			name: "auth",
			err:  &relayStatusError{Code: 401, Body: "bad key", err: errors.New("relay rejected the request: status=401 response=bad key")},
			want: "unauthorized",
		},
		{
			name: "rate limited",
			err:  &relayStatusError{Code: 429, Body: "slow down", err: errors.New("relay rejected the request: status=429 response=slow down")},
			want: "rate_limited",
		},
		{
			name: "remote server error",
			err:  &relayStatusError{Code: 503, Body: "maintenance", err: errors.New("UnifiedPush endpoint failed: status=503 response=maintenance")},
			want: "server_error",
		},
		{
			name: "other client error",
			err:  &relayStatusError{Code: 418, Body: "teapot", err: errors.New("UnifiedPush endpoint failed: status=418 response=teapot")},
			want: "rejected",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyNativePushFailure("android", tc.err)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("classifyNativePushFailure = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

// The classification is a closed vocabulary. Anything unrecognised must fall
// back to a fixed string rather than passing the error through, or the leak
// returns the first time an unfamiliar error shape appears.
func TestClassifyPushFailureFallsBackToAFixedString(t *testing.T) {
	got := classifyNativePushFailure("ios", errors.New("something nobody anticipated: https://secret.example/topic-abc"))

	if strings.Contains(got, "secret.example") || strings.Contains(got, "topic-abc") {
		t.Fatalf("an unrecognised error was passed through verbatim: %q", got)
	}
	if !strings.Contains(got, "ios") {
		t.Fatalf("classification dropped the platform: %q", got)
	}
}

// Whatever the input, the output must be drawn from the fixed vocabulary — a
// belt-and-braces check that no branch forgets and returns err.Error().
func TestClassifyPushFailureOutputIsAlwaysFromTheVocabulary(t *testing.T) {
	inputs := []error{
		errors.New("https://ntfy.sh/private-topic-xyz"),
		fmt.Errorf("wrapped: %w", &url.Error{Op: "Post", URL: "https://ntfy.sh/private", Err: errors.New("x")}),
		errors.New("status=500 response=" + strings.Repeat("A", 8192)),
		errors.New(""),
	}
	for _, in := range inputs {
		got := classifyNativePushFailure("android", in)
		reason := strings.TrimPrefix(got, "[android] ")
		if !nativePushFailureReasons[reason] {
			t.Fatalf("classifyNativePushFailure(%q) = %q, which is not in the vocabulary", in, got)
		}
	}
}

// End to end: what a failing relay actually leaves on the public health status.
// The classifier is unit-tested above, but the property that matters is what
// SendNativePushToDevices records, so this drives the real path with a relay
// that answers 500 and a body of its choosing.
func TestSendNativePushRecordsOnlyACoarseReasonOnHealth(t *testing.T) {
	planted := "SECRET-TOPIC-abc123 <script>x</script>"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(planted))
	}))
	defer ts.Close()

	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")
	dispatcher := NewNativePushDispatcher(nil, "", "")
	dispatcher.fcmSender.client = ts.Client()

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	device := state.NativeDevice{DeviceID: "dev-a", Platform: "android", PushToken: "token-a"}
	if err := store.UpsertNativeDevice(device); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	healthSvc := health.NewService()
	if _, err := SendNativePushToDevices(context.Background(), dispatcher, healthSvc, store,
		[]state.NativeDevice{device},
		NativePushMessage{Title: "t", Body: "b", Data: map[string]string{"messageId": "m1"}}, nil); err != nil {
		t.Fatalf("SendNativePushToDevices: %v", err)
	}

	status := healthSvc.GetStatus()
	if !status.NativePushFailing {
		t.Fatal("a 500 from the relay did not raise the failing flag")
	}
	if strings.Contains(status.NativePushLastError, "SECRET-TOPIC") || strings.Contains(status.NativePushLastError, "<script>") {
		t.Fatalf("the relay's response body reached the public health field: %q", status.NativePushLastError)
	}
	if strings.Contains(status.NativePushLastError, ts.URL) {
		t.Fatalf("the relay URL reached the public health field: %q", status.NativePushLastError)
	}
	reason := strings.TrimPrefix(status.NativePushLastError, "[android] ")
	if !nativePushFailureReasons[reason] {
		t.Fatalf("health carries %q, which is not in the vocabulary", status.NativePushLastError)
	}
}
