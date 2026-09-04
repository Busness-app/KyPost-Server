package processor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/health"
	"github.com/Busness-app/kypost-server/backend/internal/state"
)

// TestSendNativePushToDevicesFiltersToGivenList verifies that only the
// devices passed in are dispatched to, even when the store has more devices
// than that — the property push-2FA's approver-only fanout depends on.
func TestSendNativePushToDevicesFiltersToGivenList(t *testing.T) {
	var receivedTokens []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		receivedTokens = append(receivedTokens, body.Token)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	t.Setenv("PUSH_RELAY_URL", ts.URL)
	t.Setenv("PUSH_RELAY_KEY", "test-api-key")
	dispatcher := NewNativePushDispatcher(nil, "", "")
	dispatcher.fcmSender.client = ts.Client()

	dir := t.TempDir()
	store, err := state.New(dir)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	deviceA := state.NativeDevice{DeviceID: "dev-a", Platform: "android", PushToken: "token-a"}
	deviceB := state.NativeDevice{DeviceID: "dev-b", Platform: "android", PushToken: "token-b"}
	if err := store.UpsertNativeDevice(deviceA); err != nil {
		t.Fatalf("UpsertNativeDevice A: %v", err)
	}
	if err := store.UpsertNativeDevice(deviceB); err != nil {
		t.Fatalf("UpsertNativeDevice B: %v", err)
	}

	healthSvc := health.NewService()
	outcome, err := SendNativePushToDevices(context.Background(), dispatcher, healthSvc, store,
		[]state.NativeDevice{deviceA}, // only A, even though the store has A and B
		NativePushMessage{Title: "t", Body: "b", Data: map[string]string{"messageId": "m1"}}, nil)
	if err != nil {
		t.Fatalf("SendNativePushToDevices: %v", err)
	}
	if outcome.Sent != 1 || outcome.Devices != 1 {
		t.Fatalf("outcome = %+v, want Sent=1 Devices=1", outcome)
	}
	if len(receivedTokens) != 1 || receivedTokens[0] != "token-a" {
		t.Fatalf("relay received tokens %v, want exactly [token-a]", receivedTokens)
	}
}
