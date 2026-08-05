package state

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// legacyDevicesDDL is native_devices exactly as it was before the enrollment
// columns existed, so the upgrade test can build a pre-migration database.
const legacyDevicesDDL = `CREATE TABLE native_devices (
	device_id     TEXT PRIMARY KEY,
	platform      TEXT NOT NULL DEFAULT '',
	push_token    TEXT NOT NULL DEFAULT '',
	device_name   TEXT NOT NULL DEFAULT '',
	app_version   TEXT NOT NULL DEFAULT '',
	user_agent    TEXT NOT NULL DEFAULT '',
	registered_at TEXT NOT NULL DEFAULT '',
	updated_at    TEXT NOT NULL DEFAULT '',
	user_id       TEXT NOT NULL DEFAULT '',
	mfa_approver  INTEGER NOT NULL DEFAULT 0,
	transport     TEXT NOT NULL DEFAULT '',
	secret_hash   TEXT NOT NULL DEFAULT '',
	seq           INTEGER NOT NULL
)`

const legacyDeviceSeedSQL = `INSERT INTO native_devices(device_id, platform, push_token, seq)
	VALUES('legacy-dev', 'android', 'tok', 1)`

func enrollmentTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func seedDevice(t *testing.T, store *Store, deviceID string) {
	t.Helper()
	if err := store.UpsertNativeDevice(NativeDevice{
		DeviceID: deviceID, Platform: "android", PushToken: "tok-" + deviceID,
	}); err != nil {
		t.Fatalf("UpsertNativeDevice: %v", err)
	}
}

func TestSetNativeDeviceEnrollmentKeyRoundTrips(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")

	got, err := store.SetNativeDeviceEnrollmentKey("dev-1", "BASE64PUBKEY", "2026-08-04T00:00:00Z")
	if err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if got.EnrollmentPublicKey != "BASE64PUBKEY" || got.EnrollmentKeyAt != "2026-08-04T00:00:00Z" {
		t.Fatalf("not persisted on the returned record: %+v", got)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("ListNativeDevicesStrict: %v", err)
	}
	if len(devices) != 1 || devices[0].EnrollmentPublicKey != "BASE64PUBKEY" {
		t.Fatalf("not persisted through a reload: %+v", devices)
	}
	// The pairing secret must never ride along into an API response.
	if devices[0].Redacted().SecretHash != "" {
		t.Fatal("Redacted() no longer clears SecretHash")
	}
}

func TestSetNativeDeviceEnrollmentKeyUnknownDevice(t *testing.T) {
	store := enrollmentTestStore(t)
	if _, err := store.SetNativeDeviceEnrollmentKey("nope", "K", "2026-08-04T00:00:00Z"); err == nil {
		t.Fatal("publishing a key for an unknown device silently succeeded")
	}
}

// The marker is device-reported, so it must be able to go BOTH ways: an app
// reinstall destroys the keystore key, and a marker that only ever turned on
// would tell the user a device is protected when it can no longer read anything.
func TestEncryptionEnrolledMarkerClearsAgain(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")

	if err := store.SetNativeDeviceEncryptionEnrolled("dev-1", true); err != nil {
		t.Fatalf("set true: %v", err)
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !devices[0].EncryptionEnrolled {
		t.Fatal("marker did not turn on")
	}

	if err := store.SetNativeDeviceEncryptionEnrolled("dev-1", false); err != nil {
		t.Fatalf("set false: %v", err)
	}
	devices, err = store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if devices[0].EncryptionEnrolled {
		t.Fatal("marker could not be turned back off")
	}
}

// TestReRegistrationPreservesTheEnrollmentKey covers what the plan did not ask
// for and what the store already does for mfa_approver.
//
// A device re-registers on every app start and whenever its push token rotates,
// and upsertNativeDeviceTx rebuilds the whole row from the request. Without an
// explicit carry-forward, an ordinary push-token refresh silently erases the
// enrollment key the device published — mid-ceremony, so the browser then seals
// to a key that no longer exists and the user is told enrollment failed for no
// visible reason.
func TestReRegistrationPreservesTheEnrollmentKey(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")
	if _, err := store.SetNativeDeviceEnrollmentKey("dev-1", "PUBKEY", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}
	if err := store.SetNativeDeviceEncryptionEnrolled("dev-1", true); err != nil {
		t.Fatalf("SetNativeDeviceEncryptionEnrolled: %v", err)
	}

	// Same device id, refreshed push token: the ordinary re-registration path.
	if err := store.UpsertNativeDevice(NativeDevice{
		DeviceID: "dev-1", Platform: "android", PushToken: "rotated-token",
	}); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if devices[0].EnrollmentPublicKey != "PUBKEY" {
		t.Fatalf("re-registration erased the published enrollment key: %+v", devices[0])
	}
	if devices[0].EnrollmentKeyAt != "2026-08-04T00:00:00Z" {
		t.Fatalf("re-registration erased the publish time: %+v", devices[0])
	}
	if !devices[0].EncryptionEnrolled {
		t.Fatalf("re-registration cleared the enrollment marker: %+v", devices[0])
	}
}

// TestReRegistrationByPushTokenPreservesTheEnrollmentKey covers the OTHER
// re-registration branch: a device arriving with a new id but a push token the
// store already knows is adopted onto the existing row. mfa_approver is carried
// across that branch too, and the enrollment fields must be.
func TestReRegistrationByPushTokenPreservesTheEnrollmentKey(t *testing.T) {
	store := enrollmentTestStore(t)
	seedDevice(t, store, "dev-1")
	if _, err := store.SetNativeDeviceEnrollmentKey("dev-1", "PUBKEY", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetNativeDeviceEnrollmentKey: %v", err)
	}

	// A fresh install reusing the same push token, which the store matches onto
	// the existing row rather than creating a second device.
	if err := store.UpsertNativeDevice(NativeDevice{
		DeviceID: "dev-2", Platform: "android", PushToken: "tok-dev-1",
	}); err != nil {
		t.Fatalf("re-register by token: %v", err)
	}

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected the push-token match to adopt the existing row, got %d devices", len(devices))
	}
	if devices[0].EnrollmentPublicKey != "PUBKEY" {
		t.Fatalf("the push-token re-registration branch erased the enrollment key: %+v", devices[0])
	}
}

// TestEnrollmentColumnsAreAddedToAnExistingDatabase is the upgrade path.
//
// openDB applies a const of CREATE TABLE IF NOT EXISTS statements and nothing
// else, so adding columns to that const reaches NEW databases only. Every
// existing install has a native_devices table without them, and without a real
// additive migration every device query on those installs fails with "no such
// column" — mail sync, contacts sync and push MFA at once, on upgrade.
//
// This builds the pre-migration table shape by hand and then opens the store
// over it, which is the only way to exercise what an upgrade actually does.
func TestEnrollmentColumnsAreAddedToAnExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// The native_devices table exactly as it was before this change.
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Exec(legacyDevicesDDL); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := db.Exec(legacyDeviceSeedSQL); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The upgrade.
	store, err := New(dir)
	if err != nil {
		t.Fatalf("New over an existing database: %v", err)
	}
	defer store.Close()

	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		t.Fatalf("listing devices on an upgraded database failed: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "legacy-dev" {
		t.Fatalf("the pre-existing device did not survive the upgrade: %+v", devices)
	}
	// Absent, not enrolled — and able to become enrolled.
	if devices[0].EnrollmentPublicKey != "" || devices[0].EncryptionEnrolled {
		t.Fatalf("a legacy row decoded as enrolled: %+v", devices[0])
	}
	if _, err := store.SetNativeDeviceEnrollmentKey("legacy-dev", "K", "2026-08-05T00:00:00Z"); err != nil {
		t.Fatalf("could not publish a key on an upgraded row: %v", err)
	}
}
