package state

import "testing"

// TestClearDeviceEnrollmentsResetsEveryDevice covers the rotation path.
//
// Every writer of a user's PGP identity clears PGPWrappedEnvelopes, because
// every non-password slot seals the OLD key. Nothing did the same for the
// enrollment columns, which live in a different store — so after an identity
// rotation every device still reported itself enrolled with a stale published
// key, while the envelope it named had already been destroyed.
//
// That lands squarely in the revocation flow: rotating the identity is the
// documented way to un-enroll a lost phone, and the Security page went on
// listing that phone as protected.
func TestClearDeviceEnrollmentsResetsEveryDevice(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")
	seedDevice(t, store, "dev-2")

	for _, id := range []string{"dev-1", "dev-2"} {
		if _, err := store.SetNativeDeviceEnrollmentKey(id, "PUBKEY-"+id, "2026-08-05T00:00:00Z"); err != nil {
			t.Fatalf("SetNativeDeviceEnrollmentKey(%s): %v", id, err)
		}
		if err := store.SetNativeDeviceEncryptionEnrolled(id, true); err != nil {
			t.Fatalf("SetNativeDeviceEncryptionEnrolled(%s): %v", id, err)
		}
	}

	n, err := store.ClearDeviceEnrollments()
	if err != nil {
		t.Fatalf("ClearDeviceEnrollments: %v", err)
	}
	if n != 2 {
		t.Fatalf("cleared %d devices, want 2", n)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	for _, d := range devices {
		if d.EnrollmentPublicKey != "" || d.EnrollmentKeyAt != "" {
			t.Fatalf("stale published key survived rotation: %+v", d)
		}
		if d.EncryptionEnrolled {
			t.Fatalf("device still reports enrolled after rotation: %+v", d)
		}
	}
}

// The devices themselves must survive. Rotation invalidates the sealing, not
// the pairing — a user who rotates their key still expects push and sync to
// keep working on every paired device.
func TestClearDeviceEnrollmentsKeepsThePairing(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")
	if _, err := store.SetNativeDeviceEnrollmentKey("dev-1", "PUBKEY", "2026-08-05T00:00:00Z"); err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if _, err := store.SetNativeDeviceMFAApprover("dev-1", true); err != nil {
		t.Fatalf("SetNativeDeviceMFAApprover: %v", err)
	}

	if _, err := store.ClearDeviceEnrollments(); err != nil {
		t.Fatalf("ClearDeviceEnrollments: %v", err)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("rotation removed a paired device: %+v", devices)
	}
	d := devices[0]
	if d.PushToken == "" || d.Platform == "" {
		t.Fatalf("rotation damaged the pairing record: %+v", d)
	}
	if !d.MFAApprover {
		t.Fatal("rotation cleared the push-MFA approver flag, which it does not govern")
	}
}

// An account with no devices, or none enrolled, must not be an error — every
// identity write calls this, including the overwhelming majority that have
// nothing to clear.
func TestClearDeviceEnrollmentsIsFineWithNothingToDo(t *testing.T) {
	store := enrollmentTestStore(t)
	n, err := store.ClearDeviceEnrollments()
	if err != nil {
		t.Fatalf("ClearDeviceEnrollments on an empty store: %v", err)
	}
	if n != 0 {
		t.Fatalf("cleared %d on an empty store, want 0", n)
	}

	seedDevice(t, store, "dev-1")
	n, err = store.ClearDeviceEnrollments()
	if err != nil {
		t.Fatalf("ClearDeviceEnrollments with an unenrolled device: %v", err)
	}
	if n != 0 {
		t.Fatalf("cleared %d unenrolled devices, want 0", n)
	}
}
