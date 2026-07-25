package state

import (
	"testing"
	"time"
)

func TestSetOllamaUpdateNotifiedFiresOncePerVersion(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	notify, err := store.SetOllamaUpdateNotified("0.32.2")
	if err != nil {
		t.Fatalf("SetOllamaUpdateNotified (first): %v", err)
	}
	if !notify {
		t.Fatal("expected notify=true the first time a new upstream version is recorded")
	}

	notify, err = store.SetOllamaUpdateNotified("0.32.2")
	if err != nil {
		t.Fatalf("SetOllamaUpdateNotified (repeat): %v", err)
	}
	if notify {
		t.Fatal("expected notify=false when the same version is recorded again")
	}

	// A second Store instance rooted at the same dir (mirrors the
	// server/daemon process split) must see the persisted notification too.
	other, err := New(dir)
	if err != nil {
		t.Fatalf("New (second instance): %v", err)
	}
	if notify, err := other.SetOllamaUpdateNotified("0.32.2"); err != nil || notify {
		t.Fatalf("second instance: notify=%v, err=%v; want notify=false (already recorded on disk)", notify, err)
	}

	notify, err = other.SetOllamaUpdateNotified("0.33.0")
	if err != nil {
		t.Fatalf("SetOllamaUpdateNotified (newer version): %v", err)
	}
	if !notify {
		t.Fatal("expected notify=true when a genuinely newer upstream version appears")
	}
}

func TestNotificationSubscriptionsSyncAcrossStoreInstances(t *testing.T) {
	dir := t.TempDir()

	daemonStore, err := New(dir)
	if err != nil {
		t.Fatalf("New daemon store: %v", err)
	}
	serverStore, err := New(dir)
	if err != nil {
		t.Fatalf("New server store: %v", err)
	}

	sub := NotificationSubscription{
		Endpoint:  "https://push.example/endpoint-1",
		Auth:      "auth-token",
		P256DH:    "p256-token",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := serverStore.UpsertNotificationSubscription(sub); err != nil {
		t.Fatalf("UpsertNotificationSubscription: %v", err)
	}

	subs := daemonStore.ListNotificationSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("ListNotificationSubscriptions len = %d, want 1", len(subs))
	}
	if subs[0].Endpoint != sub.Endpoint {
		t.Fatalf("endpoint = %q, want %q", subs[0].Endpoint, sub.Endpoint)
	}
}

func TestUpsertNotificationSubscriptionPreservesLatestSharedState(t *testing.T) {
	dir := t.TempDir()

	daemonStore, err := New(dir)
	if err != nil {
		t.Fatalf("New daemon store: %v", err)
	}
	serverStore, err := New(dir)
	if err != nil {
		t.Fatalf("New server store: %v", err)
	}

	if err := daemonStore.SetCheckpoint("uid-42"); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}

	sub := NotificationSubscription{
		Endpoint:  "https://push.example/endpoint-2",
		Auth:      "auth-token",
		P256DH:    "p256-token",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := serverStore.UpsertNotificationSubscription(sub); err != nil {
		t.Fatalf("UpsertNotificationSubscription: %v", err)
	}

	reloadedStore, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded store: %v", err)
	}
	if got := reloadedStore.Checkpoint(); got != "uid-42" {
		t.Fatalf("checkpoint = %q, want %q", got, "uid-42")
	}
}

func TestMarkProcessedDoesNotWipeNotificationSubscriptions(t *testing.T) {
	dir := t.TempDir()

	daemonStore, err := New(dir)
	if err != nil {
		t.Fatalf("New daemon store: %v", err)
	}
	serverStore, err := New(dir)
	if err != nil {
		t.Fatalf("New server store: %v", err)
	}

	sub := NotificationSubscription{
		Endpoint:  "https://push.example/endpoint-3",
		Auth:      "auth-token",
		P256DH:    "p256-token",
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := serverStore.UpsertNotificationSubscription(sub); err != nil {
		t.Fatalf("UpsertNotificationSubscription: %v", err)
	}

	// Simulate daemon writing unrelated state after registration.
	if err := daemonStore.MarkProcessed("msg-123"); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}

	reloadedStore, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded store: %v", err)
	}
	subs := reloadedStore.ListNotificationSubscriptions()
	if len(subs) != 1 {
		t.Fatalf("ListNotificationSubscriptions len = %d, want 1", len(subs))
	}
	if subs[0].Endpoint != sub.Endpoint {
		t.Fatalf("endpoint = %q, want %q", subs[0].Endpoint, sub.Endpoint)
	}
}

func TestNativeDevicesSyncAcrossStoreInstances(t *testing.T) {
	dir := t.TempDir()

	daemonStore, err := New(dir)
	if err != nil {
		t.Fatalf("New daemon store: %v", err)
	}
	serverStore, err := New(dir)
	if err != nil {
		t.Fatalf("New server store: %v", err)
	}

	device := NativeDevice{
		DeviceID:     "device-1",
		Platform:     "android",
		PushToken:    "token-1",
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := serverStore.UpsertNativeDevice(device); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	devices := daemonStore.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("ListNativeDevices len = %d, want 1", len(devices))
	}
	if devices[0].DeviceID != device.DeviceID {
		t.Fatalf("deviceId = %q, want %q", devices[0].DeviceID, device.DeviceID)
	}
}

func TestUpsertNativeDeviceMergesBySamePushToken(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First registration without a device ID mints one.
	if err := s.UpsertNativeDevice(NativeDevice{Platform: "macos", PushToken: "tok-mac", DeviceName: "Mac 1"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	first := s.ListNativeDevices()
	if len(first) != 1 || first[0].DeviceID == "" {
		t.Fatalf("ListNativeDevices after first upsert = %+v, want 1 device with minted ID", first)
	}

	// Re-registering the same token+platform without an ID (a re-pair from a
	// fresh deep link) must update the row, not pair the device twice.
	if err := s.UpsertNativeDevice(NativeDevice{Platform: "macos", PushToken: "tok-mac", DeviceName: "Mac 2"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	merged := s.ListNativeDevices()
	if len(merged) != 1 {
		t.Fatalf("ListNativeDevices len = %d, want 1 (same token must merge)", len(merged))
	}
	if merged[0].DeviceID != first[0].DeviceID {
		t.Fatalf("deviceId = %q, want original %q", merged[0].DeviceID, first[0].DeviceID)
	}
	if merged[0].DeviceName != "Mac 2" {
		t.Fatalf("deviceName = %q, want updated %q", merged[0].DeviceName, "Mac 2")
	}
	if merged[0].RegisteredAt != first[0].RegisteredAt {
		t.Fatalf("registeredAt = %q, want preserved %q", merged[0].RegisteredAt, first[0].RegisteredAt)
	}

	// Same token on a different platform stays a separate device (simulator
	// placeholder tokens collide across platforms).
	if err := s.UpsertNativeDevice(NativeDevice{Platform: "ios", PushToken: "tok-mac"}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	if got := len(s.ListNativeDevices()); got != 2 {
		t.Fatalf("ListNativeDevices len = %d, want 2 (different platform must not merge)", got)
	}
}

func TestSetCheckpointDoesNotWipeNativeDevices(t *testing.T) {
	dir := t.TempDir()

	daemonStore, err := New(dir)
	if err != nil {
		t.Fatalf("New daemon store: %v", err)
	}
	serverStore, err := New(dir)
	if err != nil {
		t.Fatalf("New server store: %v", err)
	}

	device := NativeDevice{
		DeviceID:     "device-2",
		Platform:     "android",
		PushToken:    "token-2",
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := serverStore.UpsertNativeDevice(device); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	if err := daemonStore.SetCheckpoint("uid-77"); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}

	reloadedStore, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded store: %v", err)
	}
	if got := reloadedStore.Checkpoint(); got != "uid-77" {
		t.Fatalf("checkpoint = %q, want %q", got, "uid-77")
	}
	devices := reloadedStore.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("ListNativeDevices len = %d, want 1", len(devices))
	}
	if devices[0].DeviceID != device.DeviceID {
		t.Fatalf("deviceId = %q, want %q", devices[0].DeviceID, device.DeviceID)
	}
}

// TestMarkProcessedPreservesConcurrentCheckpointWrite guards against
// MarkProcessed persisting a stale in-memory checkpoint over one the other
// process (e.g. the server) just wrote to disk. a is opened before b writes
// its checkpoint, so a's in-memory checkpoint is stale "" at the time it
// calls MarkProcessed; MarkProcessed must refresh from disk first so that
// stale "" is never written back over b's value.
func TestMarkProcessedPreservesConcurrentCheckpointWrite(t *testing.T) {
	dir := t.TempDir()

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	if err := b.SetCheckpoint("uid-99"); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}

	// a's in-memory checkpoint is still stale ("") at this point.
	if err := a.MarkProcessed("msg-1"); err != nil {
		t.Fatalf("MarkProcessed: %v", err)
	}

	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded: %v", err)
	}
	if got := reloaded.Checkpoint(); got != "uid-99" {
		t.Fatalf("checkpoint = %q, want %q (MarkProcessed must not stomp a concurrent checkpoint write)", got, "uid-99")
	}
}

// TestSetCheckpointPreservesConcurrentAICreditsWrite guards against
// SetCheckpoint persisting stale in-memory AI-credits state over what another
// process just wrote to disk.
func TestSetCheckpointPreservesConcurrentAICreditsWrite(t *testing.T) {
	dir := t.TempDir()

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	if _, err := b.SetAICreditsExhausted("t1"); err != nil {
		t.Fatalf("SetAICreditsExhausted: %v", err)
	}

	// a's in-memory aiCreditsExhausted is still stale (false) at this point.
	if err := a.SetCheckpoint("uid-1"); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}

	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded: %v", err)
	}
	exhausted, at := reloaded.AICreditsExhausted()
	if !exhausted || at != "t1" {
		t.Fatalf("aiCreditsExhausted state lost after SetCheckpoint: exhausted=%v at=%q, want true/%q", exhausted, at, "t1")
	}
}

// TestCleanupPreservesConcurrentCheckpointWrite guards against Cleanup
// persisting a stale in-memory checkpoint over one another process just
// wrote to disk.
func TestCleanupPreservesConcurrentCheckpointWrite(t *testing.T) {
	dir := t.TempDir()

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	if err := b.SetCheckpoint("uid-cleanup"); err != nil {
		t.Fatalf("SetCheckpoint: %v", err)
	}

	// a's in-memory checkpoint is still stale ("") at this point.
	if err := a.Cleanup(30); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded: %v", err)
	}
	if got := reloaded.Checkpoint(); got != "uid-cleanup" {
		t.Fatalf("checkpoint = %q, want %q (Cleanup must not stomp a concurrent checkpoint write)", got, "uid-cleanup")
	}
}

// TestSetAICreditsExhaustedRefreshesBeforeTransitionCheck guards against the
// false->true transition-detecting early-return firing off stale in-memory
// state. b is opened before a marks the flag exhausted, so b's in-memory
// aiCreditsExhausted is stale (false) when b subsequently calls
// SetAICreditsExhausted; the refresh must happen before the early-return so b
// recognizes the flag is already set (no second transition) and does not
// stomp a's timestamp.
func TestSetAICreditsExhaustedRefreshesBeforeTransitionCheck(t *testing.T) {
	dir := t.TempDir()

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	transitioned, err := a.SetAICreditsExhausted("t1")
	if err != nil {
		t.Fatalf("SetAICreditsExhausted (a): %v", err)
	}
	if !transitioned {
		t.Fatal("expected a's call to be the real false->true transition")
	}

	// b's in-memory aiCreditsExhausted is still stale (false) at this point.
	transitioned, err = b.SetAICreditsExhausted("t2")
	if err != nil {
		t.Fatalf("SetAICreditsExhausted (b): %v", err)
	}
	if transitioned {
		t.Fatal("expected b to see (via fresh disk read) that the flag is already exhausted, not a new transition")
	}

	reloaded, err := New(dir)
	if err != nil {
		t.Fatalf("New reloaded: %v", err)
	}
	exhausted, at := reloaded.AICreditsExhausted()
	if !exhausted {
		t.Fatal("expected aiCreditsExhausted to remain true")
	}
	if at != "t1" {
		t.Fatalf("aiCreditsExhaustedAt = %q, want %q (b's stale write must not stomp a's timestamp)", at, "t1")
	}
}

// TestClearAICreditsExhaustedRefreshesBeforeTransitionCheck guards against
// the true->false transition-detecting early-return firing off stale
// in-memory state. b is opened while the flag is exhausted, so b's in-memory
// aiCreditsExhausted is stale (true) after a clears it on disk; the refresh
// must happen before the early-return so b recognizes the flag is already
// cleared (no second transition/duplicate notification).
func TestClearAICreditsExhaustedRefreshesBeforeTransitionCheck(t *testing.T) {
	dir := t.TempDir()

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}

	if _, err := a.SetAICreditsExhausted("t1"); err != nil {
		t.Fatalf("SetAICreditsExhausted: %v", err)
	}

	// b loads while the flag is exhausted on disk.
	b, err := New(dir)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	transitioned, err := a.ClearAICreditsExhausted()
	if err != nil {
		t.Fatalf("ClearAICreditsExhausted (a): %v", err)
	}
	if !transitioned {
		t.Fatal("expected a's call to be the real true->false transition")
	}

	// b's in-memory aiCreditsExhausted is still stale (true) at this point,
	// even though the flag was already cleared on disk by a.
	transitioned, err = b.ClearAICreditsExhausted()
	if err != nil {
		t.Fatalf("ClearAICreditsExhausted (b): %v", err)
	}
	if transitioned {
		t.Fatal("expected b to see (via fresh disk read) that the flag is already cleared, not a new transition")
	}
}

func TestNativeDeviceMFAApproverToggle(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.UpsertNativeDevice(NativeDevice{DeviceID: "dev-1", Platform: "android", PushToken: "tok-1", UserID: "user-1", MFAApprover: true}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}

	got, ok := s.GetNativeDevice("dev-1")
	if !ok || !got.MFAApprover || got.UserID != "user-1" {
		t.Fatalf("GetNativeDevice = %+v ok=%v", got, ok)
	}

	updated, err := s.SetNativeDeviceMFAApprover("dev-1", false)
	if err != nil || !updated {
		t.Fatalf("SetNativeDeviceMFAApprover: updated=%v err=%v", updated, err)
	}
	got, _ = s.GetNativeDevice("dev-1")
	if got.MFAApprover {
		t.Fatalf("expected approver cleared, got %+v", got)
	}

	missing, err := s.SetNativeDeviceMFAApprover("nope", true)
	if err != nil || missing {
		t.Fatalf("expected updated=false for unknown device, got updated=%v err=%v", missing, err)
	}
}

// TestUpsertNativeDevicePreservesRevokedMFAApprover guards against a routine
// push-token refresh (which always re-registers with MFAApprover: true)
// silently undoing a user's explicit revocation of a device's approver
// status, via both the device-ID match path and the push-token+platform
// merge path used when a device re-pairs without its ID.
func TestUpsertNativeDevicePreservesRevokedMFAApprover(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.UpsertNativeDevice(NativeDevice{DeviceID: "dev-1", Platform: "ios", PushToken: "tok-1", UserID: "user-1", MFAApprover: true}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
	if updated, err := s.SetNativeDeviceMFAApprover("dev-1", false); err != nil || !updated {
		t.Fatalf("SetNativeDeviceMFAApprover: updated=%v err=%v", updated, err)
	}

	// A routine re-registration by device ID (e.g. push-token refresh) always
	// sends MFAApprover: true — it must not resurrect the revoked approver.
	if err := s.UpsertNativeDevice(NativeDevice{DeviceID: "dev-1", Platform: "ios", PushToken: "tok-1-refreshed", UserID: "user-1", MFAApprover: true}); err != nil {
		t.Fatalf("UpsertNativeDevice (id match): %v", err)
	}
	got, ok := s.GetNativeDevice("dev-1")
	if !ok || got.MFAApprover {
		t.Fatalf("expected revoked approver to survive id-match re-registration, got %+v ok=%v", got, ok)
	}

	// Same scenario via the push-token+platform merge path (re-pair without
	// a device ID).
	if err := s.UpsertNativeDevice(NativeDevice{Platform: "ios", PushToken: "tok-1-refreshed", UserID: "user-1", MFAApprover: true}); err != nil {
		t.Fatalf("UpsertNativeDevice (token match): %v", err)
	}
	got, ok = s.GetNativeDevice("dev-1")
	if !ok || got.MFAApprover {
		t.Fatalf("expected revoked approver to survive token-match re-registration, got %+v ok=%v", got, ok)
	}
}

// TestDecisionsSortByInstantNotString pins that ordering survives a
// timestamp written with a non-UTC offset — string comparison of RFC3339
// silently scrambles that case, parsed-instant comparison does not.
func TestDecisionsSortByInstantNotString(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 09:00-04:00 is 13:00Z — later than 12:00Z, but sorts EARLIER as a
	// string because "0" < "1".
	older := Decision{MessageID: "older", AtUTC: "2026-07-25T12:00:00Z"}
	newer := Decision{MessageID: "newer", AtUTC: "2026-07-25T09:00:00-04:00"}
	for _, d := range []Decision{older, newer} {
		if err := s.AddDecision(d); err != nil {
			t.Fatalf("AddDecision: %v", err)
		}
	}
	got := s.Decisions(0)
	if len(got) != 2 {
		t.Fatalf("Decisions len = %d, want 2", len(got))
	}
	if got[0].MessageID != "newer" {
		t.Fatalf("Decisions[0] = %q, want %q (newest first)", got[0].MessageID, "newer")
	}
}

// TestValidateDesktopPairingCodeDoesNotHalfDeleteExpired pins that
// validating an expired code is a pure read: it must not leave the in-memory
// map disagreeing with disk.
func TestValidateDesktopPairingCodeDoesNotHalfDeleteExpired(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.SetDesktopPairingCode("code-abc", time.Millisecond); err != nil {
		t.Fatalf("SetDesktopPairingCode: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if s.ValidateDesktopPairingCode("code-abc") {
		t.Fatal("expired code validated as good")
	}
	// A second reader (fresh Store over the same dir) must see exactly what
	// the first one saw — no silent divergence between memory and disk.
	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	if s2.ValidateDesktopPairingCode("code-abc") {
		t.Fatal("expired code validated as good on reload")
	}
}
