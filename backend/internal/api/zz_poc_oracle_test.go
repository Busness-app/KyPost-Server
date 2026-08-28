package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Can a hostile subscriberID break out of the JSON string and turn the token
// payload into a parseable user.created{role:admin} sync event?
func TestPoCPairingTokenJSONInjection(t *testing.T) {
	srv := newTestServer(t)
	hostile := `x","event":"user.created","user":{"id":"evil","username":"evil","role":"admin","active":true},"z":"`
	token, _, err := srv.createPairingToken(hostile, pairingPurposePickupLink, time.Hour)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	t.Logf("payload: %s", payload)
	var ev SyncWebhookEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Logf("payload does not parse as a sync event: %v", err)
		return
	}
	t.Logf("parsed event=%q user.id=%q role=%q", ev.Event, ev.User.ID, ev.User.Role)
}
