package state

import "testing"

// The WebPush auth secret is a forgery capability, not a public key: anyone
// holding it together with the endpoint URL (which Redacted deliberately keeps,
// since the UI shows it) can encrypt a notification the device will accept and
// display. It must never leave the server in an API response.
func TestRedactedClearsTheWebPushAuthSecret(t *testing.T) {
	device := NativeDevice{
		DeviceID:   "device-1",
		PushToken:  "https://ntfy.sh/topic",
		Transport:  "unifiedpush",
		SecretHash: "hash",
		P256DH:     "BJxc0000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		Auth:       "c2VjcmV0LWF1dGgtdmFsdWU",
	}

	got := device.Redacted()

	if got.Auth != "" {
		t.Errorf("Redacted().Auth = %q, want empty", got.Auth)
	}
	if got.SecretHash != "" {
		t.Errorf("Redacted().SecretHash = %q, want empty", got.SecretHash)
	}
	// P256DH is the device's public key. It confers nothing on its own and the
	// device published it; there is no reason to strip it.
	if got.P256DH != device.P256DH {
		t.Errorf("Redacted().P256DH = %q, want it preserved", got.P256DH)
	}
	if got.DeviceID != device.DeviceID || got.Transport != device.Transport {
		t.Errorf("Redacted() altered a non-secret field: %+v", got)
	}
}
