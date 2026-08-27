package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMigrationImportsEveryFieldFromJSON is the safety net on the upgrade
// path. It is deliberately exhaustive: an account's device pairings, audit
// history and pull queue all live in state.json, and a field silently dropped
// here is data loss an operator only notices later.
func TestMigrationImportsEveryFieldFromJSON(t *testing.T) {
	dir := t.TempDir()
	seenAt := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

	sf := stateFile{
		LastCheckpoint: "42",
		Processed:      map[string]string{"m1": seenAt, "m2": seenAt},
		Notifications: []NotificationSubscription{
			{Endpoint: "https://push.example/a", Auth: "au", P256DH: "p2", UserAgent: "UA", UpdatedAt: seenAt},
		},
		NativeDevices: []NativeDevice{
			{DeviceID: "dev-1", Platform: "android", PushToken: "tok", DeviceName: "Phone",
				AppVersion: "1.2", UserAgent: "UA", RegisteredAt: seenAt, UpdatedAt: seenAt,
				UserID: "u1", MFAApprover: true, Transport: "fcm", SecretHash: "sha256:abc"},
		},
		SubscriberID:                "sub-123",
		NativeDeliveryMode:          "pull",
		PullNotifications:           []PullNotification{{Seq: 7, Title: "T", Body: "B", Data: map[string]string{"k": "v"}, CreatedAt: seenAt}},
		PullSeq:                     7,
		AICreditsExhausted:          true,
		AICreditsExhaustedAt:        seenAt,
		OllamaUpdateNotifiedVersion: "0.32.3",
	}
	writeJSON(t, filepath.Join(dir, "state.json"), sf)
	writeJSON(t, filepath.Join(dir, "decisions.json"), []Decision{
		{MessageID: "m1", Sender: "a@b.test", Subject: "one", Label: "Primary", Status: "ok", AtUTC: seenAt},
		{MessageID: "m2", Sender: "c@d.test", Subject: "two", Label: "Work", Status: "ok", AtUTC: seenAt},
	})

	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()

	if got := checkpointForTest(t, s); got != "42" {
		t.Errorf("Checkpoint = %q, want 42", got)
	}
	if !seenForTest(t, s, "m1") || !seenForTest(t, s, "m2") {
		t.Error("processed message ids did not survive migration")
	}
	if got := s.SubscriberID(); got != "sub-123" {
		t.Errorf("SubscriberID = %q, want sub-123", got)
	}
	if got := s.NativeDeliveryMode(); got != DeliveryModePull {
		t.Errorf("NativeDeliveryMode = %q, want pull", got)
	}
	if subs := s.ListNotificationSubscriptions(); len(subs) != 1 || subs[0].Endpoint != "https://push.example/a" || subs[0].Auth != "au" {
		t.Errorf("notification subscriptions = %+v", subs)
	}
	devices := s.ListNativeDevices()
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}
	d := devices[0]
	if d.DeviceID != "dev-1" || d.Platform != "android" || d.PushToken != "tok" || d.DeviceName != "Phone" ||
		d.AppVersion != "1.2" || d.UserID != "u1" || !d.MFAApprover || d.Transport != "fcm" || d.SecretHash != "sha256:abc" {
		t.Errorf("device lost fields in migration: %+v", d)
	}
	notes, cursor := s.PullNotificationsAfter(0)
	if len(notes) != 1 || notes[0].Title != "T" || notes[0].Data["k"] != "v" {
		t.Errorf("pull notifications = %+v", notes)
	}
	if cursor != 7 {
		t.Errorf("pull cursor = %d, want 7", cursor)
	}
	if exhausted, at := s.AICreditsExhausted(); !exhausted || at != seenAt {
		t.Errorf("AICreditsExhausted = %v/%q", exhausted, at)
	}
	if notify, _ := s.SetOllamaUpdateNotified("0.32.3"); notify {
		t.Error("SetOllamaUpdateNotified re-notified for a version already recorded before migration")
	}
	if ds := s.Decisions(0); len(ds) != 2 {
		t.Errorf("decisions = %d, want 2", len(ds))
	}
}

// The originals must survive the migration: renamed, never deleted.
func TestMigrationKeepsTheOriginalFiles(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "state.json"), stateFile{LastCheckpoint: "9"})
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	if _, err := os.Stat(filepath.Join(dir, "state.json.migrated")); err != nil {
		t.Fatalf("original state.json was not preserved as .migrated: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); !os.IsNotExist(err) {
		t.Error("state.json still present; it should have been renamed")
	}
}

// A second open must not re-import (which would resurrect data deleted since)
// and must not fail.
func TestMigrationRunsExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	// Timestamped in the past so Cleanup(0) actually removes it.
	writeJSON(t, filepath.Join(dir, "decisions.json"),
		[]Decision{{MessageID: "m1", AtUTC: time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)}})

	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s1.Cleanup(0); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if got := len(s1.Decisions(0)); got != 0 {
		t.Fatalf("setup: %d decisions after cleanup, want 0", got)
	}
	s1.Close()

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if got := len(s2.Decisions(0)); got != 0 {
		t.Fatalf("reopen re-imported %d decisions that had been deleted", got)
	}
}

// A corrupt state.json must fail loudly rather than start empty — an operator
// needs to know before their device pairings and history are quietly gone.
func TestMigrationRefusesCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("New succeeded on unparseable state.json; it must refuse rather than silently start empty")
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
