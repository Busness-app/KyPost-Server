package users

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// newTestStore returns a Store backed by a fresh temp dir, already seeded
// with the first-run admin.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	return store
}

func TestLoadOrMigrateFreshInstallMintsDefaultAdmin(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	all, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("len(all) = %d, want 1", len(all))
	}
	u := all[0]
	if u.Role != RoleAdmin || !u.Active || !u.MustChangePassword {
		t.Fatalf("unexpected default admin: %+v", u)
	}
}

func TestLoadOrMigrateImportsLegacyAdminEnv(t *testing.T) {
	dir := t.TempDir()
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	adminEnvPath := filepath.Join(dir, "admin.env")
	content := "ADMIN_USER=legacyadmin\nADMIN_PASS_HASH=" + hash + "\nMUST_CHANGE_PASSWORD=false\n"
	if err := os.WriteFile(adminEnvPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := LoadOrMigrate(dir, adminEnvPath)
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.GetByUsername("legacyadmin")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if u.Role != RoleAdmin || !u.Active || u.MustChangePassword {
		t.Fatalf("unexpected migrated admin: %+v", u)
	}
	if !VerifyPassword(u, "hunter2") {
		t.Fatalf("VerifyPassword: expected migrated password to verify")
	}
}

func TestLoadOrMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	firstUsers, _ := first.List()

	second, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate (second): %v", err)
	}
	secondUsers, _ := second.List()

	if len(firstUsers) != 1 || len(secondUsers) != 1 || firstUsers[0].ID != secondUsers[0].ID {
		t.Fatalf("expected the same single user across loads: first=%+v second=%+v", firstUsers, secondUsers)
	}
}

func TestStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}

	u, err := store.Create("alice", "correct-horse-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !VerifyPassword(u, "correct-horse-testpassword") {
		t.Fatalf("VerifyPassword: expected new user's password to verify")
	}

	if _, err := store.Create("alice", "other-testpassword", RoleUser); err != ErrUsernameTaken {
		t.Fatalf("Create duplicate: err = %v, want ErrUsernameTaken", err)
	}

	if _, err := store.SetRole(u.ID, RoleAdmin); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	got, err := store.Get(u.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Role != RoleAdmin {
		t.Fatalf("Role = %v, want admin", got.Role)
	}

	if _, err := store.SetPassword(u.ID, "new-password-testpassword", true); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	got, _ = store.Get(u.ID)
	if !got.MustChangePassword || !VerifyPassword(got, "new-password-testpassword") {
		t.Fatalf("unexpected state after SetPassword: %+v", got)
	}

	if _, err := store.Deactivate(u.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	got, _ = store.Get(u.ID)
	if got.Active {
		t.Fatalf("expected deactivated user to be inactive")
	}

	if _, err := store.Reactivate(u.ID); err != nil {
		t.Fatalf("Reactivate: %v", err)
	}
	got, _ = store.Get(u.ID)
	if !got.Active {
		t.Fatalf("expected reactivated user to be active")
	}

	if _, err := store.Get("does-not-exist"); err != ErrNotFound {
		t.Fatalf("Get unknown: err = %v, want ErrNotFound", err)
	}
}

func TestTOTPEnrollmentLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create("carol", "pw-carol-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Pending secret does not enable TOTP.
	if _, err := store.SetPendingTOTPSecret(u.ID, "sealed-secret-json"); err != nil {
		t.Fatalf("SetPendingTOTPSecret: %v", err)
	}
	got, _ := store.Get(u.ID)
	if got.TOTPEnabled || got.TOTPSecretEnc != "sealed-secret-json" {
		t.Fatalf("after pending: %+v", got)
	}

	// Confirm enables and stores recovery hashes.
	h1, _ := HashPassword("aaaa-bbbb-cccc")
	h2, _ := HashPassword("dddd-eeee-ffff")
	if _, err := store.EnableTOTP(u.ID, "2026-07-09T00:00:00Z", []string{h1, h2}); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	got, _ = store.Get(u.ID)
	if !got.TOTPEnabled || got.TOTPConfirmedAt == "" || len(got.RecoveryCodesHash) != 2 {
		t.Fatalf("after confirm: %+v", got)
	}

	// Consume a recovery code removes exactly one matching hash.
	_, matched, err := store.ConsumeRecoveryCode(u.ID, "aaaa-bbbb-cccc", nil)
	if err != nil || !matched {
		t.Fatalf("ConsumeRecoveryCode good = (%v, %v)", matched, err)
	}
	got, _ = store.Get(u.ID)
	if len(got.RecoveryCodesHash) != 1 {
		t.Fatalf("after consume: %d hashes left, want 1", len(got.RecoveryCodesHash))
	}
	// A non-matching / already-used code does not match and does not write.
	_, matched, err = store.ConsumeRecoveryCode(u.ID, "aaaa-bbbb-cccc", nil)
	if err != nil || matched {
		t.Fatalf("ConsumeRecoveryCode reused = (%v, %v), want (false, nil)", matched, err)
	}

	// Disable clears everything.
	if _, err := store.DisableTOTP(u.ID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	got, _ = store.Get(u.ID)
	if got.TOTPEnabled || got.TOTPSecretEnc != "" || got.TOTPConfirmedAt != "" || len(got.RecoveryCodesHash) != 0 {
		t.Fatalf("after disable: %+v", got)
	}
}

func TestEnableTOTPRequiresPendingSecret(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create("dan", "pw-dan-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.EnableTOTP(u.ID, "2026-07-09T00:00:00Z", nil); err == nil {
		t.Fatalf("expected EnableTOTP without pending secret to error")
	}
}

func TestSetLastUsedTOTPStep(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create("judy", "pw-judy-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.LastUsedTOTPStep != 0 {
		t.Fatalf("expected zero-value LastUsedTOTPStep on a new user, got %d", u.LastUsedTOTPStep)
	}

	// First recording always succeeds (zero value never blocks).
	got, err := store.SetLastUsedTOTPStep(u.ID, 100)
	if err != nil {
		t.Fatalf("SetLastUsedTOTPStep(100): %v", err)
	}
	if got.LastUsedTOTPStep != 100 {
		t.Fatalf("LastUsedTOTPStep = %d, want 100", got.LastUsedTOTPStep)
	}

	// Replaying the exact same step is rejected and does not write.
	if _, err := store.SetLastUsedTOTPStep(u.ID, 100); !errors.Is(err, ErrTOTPStepNotNewer) {
		t.Fatalf("SetLastUsedTOTPStep(100) again = %v, want ErrTOTPStepNotNewer", err)
	}
	got, _ = store.Get(u.ID)
	if got.LastUsedTOTPStep != 100 {
		t.Fatalf("LastUsedTOTPStep after rejected replay = %d, want unchanged 100", got.LastUsedTOTPStep)
	}

	// An older step is also rejected.
	if _, err := store.SetLastUsedTOTPStep(u.ID, 99); !errors.Is(err, ErrTOTPStepNotNewer) {
		t.Fatalf("SetLastUsedTOTPStep(99) = %v, want ErrTOTPStepNotNewer", err)
	}
	got, _ = store.Get(u.ID)
	if got.LastUsedTOTPStep != 100 {
		t.Fatalf("LastUsedTOTPStep after rejected older step = %d, want unchanged 100", got.LastUsedTOTPStep)
	}

	// A genuinely later step succeeds and advances the recorded value.
	got, err = store.SetLastUsedTOTPStep(u.ID, 101)
	if err != nil {
		t.Fatalf("SetLastUsedTOTPStep(101): %v", err)
	}
	if got.LastUsedTOTPStep != 101 {
		t.Fatalf("LastUsedTOTPStep = %d, want 101", got.LastUsedTOTPStep)
	}
}

func TestSetPushMFAEnabled(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create("ivan", "pw-ivan-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPushMFAEnabled(u.ID, true); err != nil {
		t.Fatalf("SetPushMFAEnabled true: %v", err)
	}
	got, _ := store.Get(u.ID)
	if !got.PushMFAEnabled {
		t.Fatalf("expected PushMFAEnabled true")
	}
	if _, err := store.SetPushMFAEnabled(u.ID, false); err != nil {
		t.Fatalf("SetPushMFAEnabled false: %v", err)
	}
	got, _ = store.Get(u.ID)
	if got.PushMFAEnabled {
		t.Fatalf("expected PushMFAEnabled false")
	}
}

func TestValidatePasswordEnforcesMinLength(t *testing.T) {
	short := strings.Repeat("a", MinPasswordLen-1)
	if err := ValidatePassword(short); err == nil {
		t.Fatalf("ValidatePassword(%d chars) = nil, want ErrPasswordWeak", len(short))
	}
	if err := ValidatePassword(strings.Repeat("a", MinPasswordLen)); err != nil {
		t.Fatalf("ValidatePassword(%d chars) = %v, want nil", MinPasswordLen, err)
	}
	// Counted in runes, not bytes: a short multi-byte passphrase must still
	// be rejected rather than sneaking past on byte length.
	if err := ValidatePassword(strings.Repeat("é", MinPasswordLen-1)); err == nil {
		t.Fatal("ValidatePassword rejected on byte length, not rune length")
	}
}

func TestCreateRejectsWeakPassword(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Create("weakuser", "short", RoleUser); !errors.Is(err, ErrPasswordWeak) {
		t.Fatalf("Create with weak password: err = %v, want ErrPasswordWeak", err)
	}
}

func TestUsernamesAreCaseInsensitive(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Create("Casey", "casey-testpassword", RoleUser); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.Create("CASEY", "casey2-testpassword", RoleUser); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("Create differing only in case: err = %v, want ErrUsernameTaken", err)
	}
	for _, probe := range []string{"Casey", "casey", "CASEY", "  casey  "} {
		u, err := store.GetByUsername(probe)
		if err != nil {
			t.Fatalf("GetByUsername(%q): %v", probe, err)
		}
		if u.Username != "Casey" {
			t.Fatalf("GetByUsername(%q) = %q, want the stored form %q", probe, u.Username, "Casey")
		}
	}
}

func TestListIsSortedByUsername(t *testing.T) {
	store := newTestStore(t)
	for _, name := range []string{"zoe", "Adam", "mike"} {
		if _, err := store.Create(name, name+"-testpassword", RoleUser); err != nil {
			t.Fatalf("Create(%q): %v", name, err)
		}
	}
	all, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var got []string
	for _, u := range all {
		got = append(got, u.Username)
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool {
		return strings.ToLower(got[i]) < strings.ToLower(got[j])
	}) {
		t.Fatalf("List() not sorted by username: %v", got)
	}
}

// TestConcurrentStoresDoNotLoseUpdates is the check for the cross-process
// file lock. Two independent *Store values over the same users.json have
// independent mutexes — exactly the situation the api and daemon processes
// are in, since supervisord runs them as separate processes. Without the
// file lock in mutate, these interleaved read-modify-write cycles drop
// writes: each reads the same starting file and the last one to write wins.
func TestConcurrentStoresDoNotLoseUpdates(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrMigrate(dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	// A second Store over the same path, as a different process would have.
	second := newStore(filepath.Join(dir, "users.json"))

	const n = 12
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		u, err := first.Create(fmt.Sprintf("user%02d", i), "concurrent-testpassword", RoleUser)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		ids = append(ids, u.ID)
	}

	// Every mutation is a full-file rewrite. Run them all at once, split
	// across the two stores.
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		store := first
		if i%2 == 1 {
			store = second
		}
		go func(s *Store, id string) {
			defer wg.Done()
			if _, err := s.SetPGPIdentity(id, "fp-"+id, "kid", "pub", "enc", "generated", "now"); err != nil {
				t.Errorf("SetPGPIdentity(%s): %v", id, err)
			}
		}(store, id)
	}
	wg.Wait()

	all, err := first.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := 0
	for _, u := range all {
		if u.PGPFingerprint != "" {
			got++
		}
	}
	if got != n {
		t.Fatalf("%d/%d fingerprints survived concurrent mutation; lost %d updates", got, n, n-got)
	}
}
