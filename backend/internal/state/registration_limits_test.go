package state

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
)

// The two push fanouts are serial and each destination gets its own network
// timeout, so the number of rows these tables hold is a multiplier on how long
// one user's poll tick takes — and poller.tick does not finish until its
// slowest user does. Before the cap, an authenticated user could register
// registrations without bound and hold up mail polling for the whole instance
// without doing anything they were not allowed to do.

func TestNotificationSubscriptionsAreCapped(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < MaxNotificationSubscriptions; i++ {
		sub := NotificationSubscription{
			Endpoint: fmt.Sprintf("https://push.example/%d", i),
			Auth:     "auth", P256DH: "key",
		}
		if err := store.UpsertNotificationSubscription(sub); err != nil {
			t.Fatalf("subscription %d rejected below the cap: %v", i, err)
		}
	}

	err = store.UpsertNotificationSubscription(NotificationSubscription{
		Endpoint: "https://push.example/one-too-many", Auth: "auth", P256DH: "key",
	})
	if !errors.Is(err, ErrRegistrationLimit) {
		t.Fatalf("subscription past the cap: got err %v, want ErrRegistrationLimit", err)
	}

	// A device at the cap must still be able to rotate its keys, or the cap
	// becomes a way to lock working subscriptions into a stale state.
	refresh := NotificationSubscription{
		Endpoint: "https://push.example/0", Auth: "rotated", P256DH: "rotated",
	}
	if err := store.UpsertNotificationSubscription(refresh); err != nil {
		t.Fatalf("refreshing an existing subscription at the cap: %v", err)
	}
	subs, err := store.ListNotificationSubscriptionsStrict()
	if err != nil {
		t.Fatalf("ListNotificationSubscriptionsStrict: %v", err)
	}
	if len(subs) != MaxNotificationSubscriptions {
		t.Fatalf("subscriptions = %d, want %d", len(subs), MaxNotificationSubscriptions)
	}
	for _, s := range subs {
		if s.Endpoint == "https://push.example/0" && s.Auth != "rotated" {
			t.Fatal("refresh at the cap did not update the existing row")
		}
	}
}

func TestNativeDevicesAreCapped(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < MaxNativeDevices; i++ {
		device := NativeDevice{
			DeviceID:  "device-" + strconv.Itoa(i),
			Platform:  "android",
			PushToken: "token-" + strconv.Itoa(i),
		}
		if err := store.UpsertNativeDevice(device); err != nil {
			t.Fatalf("device %d rejected below the cap: %v", i, err)
		}
	}

	err = store.UpsertNativeDevice(NativeDevice{
		DeviceID: "one-too-many", Platform: "android", PushToken: "token-extra",
	})
	if !errors.Is(err, ErrRegistrationLimit) {
		t.Fatalf("device past the cap: got err %v, want ErrRegistrationLimit", err)
	}

	// Re-registering an existing device is how a real client refreshes an FCM
	// token. It must keep working at the cap.
	if err := store.UpsertNativeDevice(NativeDevice{
		DeviceID: "device-0", Platform: "android", PushToken: "rotated-token",
	}); err != nil {
		t.Fatalf("re-registering an existing device at the cap: %v", err)
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("ListNativeDevicesStrict: %v", err)
	}
	if len(devices) != MaxNativeDevices {
		t.Fatalf("devices = %d, want %d", len(devices), MaxNativeDevices)
	}

	// And removing one makes room again, so the cap is a ceiling rather than a
	// one-way ratchet.
	if _, err := store.RemoveNativeDevice("device-1"); err != nil {
		t.Fatalf("RemoveNativeDevice: %v", err)
	}
	if err := store.UpsertNativeDevice(NativeDevice{
		DeviceID: "replacement", Platform: "android", PushToken: "token-replacement",
	}); err != nil {
		t.Fatalf("registering after freeing a slot: %v", err)
	}
}
