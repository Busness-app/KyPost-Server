package api

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// registerWithKeys drives a full native registration carrying the given
// transport and WebPush key material, and returns the recorder.
func registerWithKeys(t *testing.T, srv *Server, subscriberID, deviceID, transport, p256dh, auth string) *httptest.ResponseRecorder {
	t.Helper()
	token, _, err := srv.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Minute)
	if err != nil {
		t.Fatalf("createPairingToken: %v", err)
	}
	deviceToken := "native-device-token"
	if transport == "unifiedpush" {
		deviceToken = "https://8.8.8.8/topic-" + deviceID
	}
	body, _ := json.Marshal(map[string]any{
		"subscriberId": subscriberID,
		"pairingToken": token,
		"deviceToken":  deviceToken,
		"deviceId":     deviceID,
		"platform":     "android",
		"transport":    transport,
		"p256dh":       p256dh,
		"auth":         auth,
	})
	rec := httptest.NewRecorder()
	srv.handleNotificationNativeRegister(rec, httptest.NewRequest(http.MethodPost, "/api/notifications/native/register", jsonBody(body)))
	return rec
}

func webPushKeyPair(t *testing.T) (p256dh, auth string) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(secret)
}

// Without persisting the keys the sender has nothing to encrypt to, and the
// payload goes to the distributor's broker in the clear.
func TestNativeRegisterPersistsUnifiedPushWebPushKeys(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	p256dh, auth := webPushKeyPair(t)

	rec := registerWithKeys(t, srv, subscriberID, "device-up", "unifiedpush", p256dh, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	devices := store.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].P256DH != p256dh {
		t.Errorf("P256DH = %q, want %q", devices[0].P256DH, p256dh)
	}
	if devices[0].Auth != auth {
		t.Errorf("Auth = %q, want %q", devices[0].Auth, auth)
	}
}

// Malformed key material must be refused at the door. Storing it would produce
// a device whose every notification fails to encrypt at send time, far from
// the request that caused it.
func TestNativeRegisterRejectsMalformedWebPushKeys(t *testing.T) {
	goodP256DH, goodAuth := webPushKeyPair(t)

	cases := []struct {
		name   string
		p256dh string
		auth   string
	}{
		{"p256dh is not a point", "not-a-key", goodAuth},
		{"auth is the wrong length", goodP256DH, base64.RawURLEncoding.EncodeToString(make([]byte, 4))},
		{"p256dh without auth", goodP256DH, ""},
		{"auth without p256dh", "", goodAuth},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newTestServer(t)
			store := testUserStore(t, srv)
			subscriberID, err := store.GetOrCreateSubscriberID()
			if err != nil {
				t.Fatalf("GetOrCreateSubscriberID: %v", err)
			}

			rec := registerWithKeys(t, srv, subscriberID, "device-bad", "unifiedpush", c.p256dh, c.auth)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if devices := store.ListNativeDevices(); len(devices) != 0 {
				t.Fatalf("len(devices) = %d, want 0 — a rejected registration must not persist", len(devices))
			}
		})
	}
}

// Key material only means something for UnifiedPush. An FCM device that sends
// it anyway must not carry a stray auth secret in its record.
func TestNativeRegisterIgnoresWebPushKeysOnNonUnifiedPushTransports(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}
	p256dh, auth := webPushKeyPair(t)

	rec := registerWithKeys(t, srv, subscriberID, "device-fcm", "fcm", p256dh, auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	devices := store.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("len(devices) = %d, want 1", len(devices))
	}
	if devices[0].P256DH != "" || devices[0].Auth != "" {
		t.Fatalf("fcm device carries WebPush keys: p256dh=%q auth=%q", devices[0].P256DH, devices[0].Auth)
	}
}

// A UnifiedPush device from a client that predates the key exchange keeps
// registering, and keeps receiving the unencrypted payload it can read.
func TestNativeRegisterAcceptsUnifiedPushWithoutKeys(t *testing.T) {
	srv := newTestServer(t)
	store := testUserStore(t, srv)
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		t.Fatalf("GetOrCreateSubscriberID: %v", err)
	}

	rec := registerWithKeys(t, srv, subscriberID, "device-legacy", "unifiedpush", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	devices := store.ListNativeDevices()
	if len(devices) != 1 || devices[0].P256DH != "" || devices[0].Auth != "" {
		t.Fatalf("unexpected device state: %+v", devices)
	}
}
