package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/cryptutil"
)

func validService(t *testing.T) *Service {
	t.Helper()
	d := fixtureDirs(t)
	if err := os.WriteFile(filepath.Join(d.Config, "users.json"), []byte(`{"users":[{"role":"admin","active":true}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := cryptutil.SealString(`{"host":"mail.example","password":"test-only"}`, filepath.Join(d.Secret, "imap-config.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.Config, "users/u1/imap-config.json"), []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	return openService(t, d, config.BackupConfig{Dir: t.TempDir(), Keep: 1})
}
func pinTestKey(t *testing.T, s *Service) recoverykey.PrivateKey {
	t.Helper()
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PinKey(base64.StdEncoding.EncodeToString(key.Public().Bytes()), 2, 3); err != nil {
		t.Fatal(err)
	}
	return key
}
func TestBackupLocalRestoreAndDrill(t *testing.T) {
	s := validService(t)
	// Compose configures this optional path even when only the bundled prompt exists.
	t.Setenv("TUNING_FILE", filepath.Join(s.dirs.Config, "TUNING.md"))
	key := pinTestKey(t, s)
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(res.LocalPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("local mode: %v %v", info, err)
	}
	raw, err := os.ReadFile(res.LocalPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "opened")
	m, _, err := capsule.Open(raw, key, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range drillChecks(dir, m) {
		if !c.Passed {
			t.Errorf("restore failed: %s", c.Name)
		}
	}
	drill, err := s.Drill(context.Background())
	if err != nil || !drill.Passed {
		t.Fatalf("drill: %+v %v", drill, err)
	}
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := s.Status()
	if err != nil || len(st.LocalCopies) != 1 {
		t.Fatalf("retention: %+v %v", st, err)
	}
	key2, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PinKey(base64.StdEncoding.EncodeToString(key2.Public().Bytes()), 2, 3); !errors.Is(err, ErrKeyAlreadyPinned) {
		t.Fatalf("second pin: %v", err)
	}
	sealer, err := s.loadSealer()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.BackupSettingsTransaction(func(st recoveryclient.Settings) error {
		return recoveryclient.StorePairing(st, sealer, "https://r.example", "synthetic-token")
	}); err != nil {
		t.Fatal(err)
	}
	sealed, err := s.settings.Get("kyrecovery_token_enc")
	if err != nil || sealed == "synthetic-token" {
		t.Fatal("token stored in clear")
	}
	if err := s.Unpair(); err != nil {
		t.Fatal(err)
	}
	st, err = s.Status()
	if err != nil || st.Paired || st.KeyID != key.Public().ID() || len(st.LocalCopies) != 1 {
		t.Fatalf("unpair lost state: %+v %v", st, err)
	}
	if err := os.Remove(recoveryclient.RecoveryKeyPath(s.dirs.State)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background()); !errors.Is(err, recoveryclient.ErrKeyPinMissing) {
		t.Fatalf("missing pin: %v", err)
	}
}
func TestBackupRefusesUnsafeCollection(t *testing.T) {
	for _, kind := range []string{"symlink", "missing-totp", "external-key"} {
		t.Run(kind, func(t *testing.T) {
			s := validService(t)
			switch kind {
			case "symlink":
				if err := os.Symlink("/etc/passwd", filepath.Join(s.dirs.Config, "external")); err != nil {
					t.Fatal(err)
				}
			case "missing-totp":
				if err := os.Remove(filepath.Join(s.dirs.Secret, "totp-secret.key")); err != nil {
					t.Fatal(err)
				}
			case "external-key":
				t.Setenv("IMAP_CONFIG_KEY_FILE", "/elsewhere/key")
			}
			if _, err := s.Collect(); err == nil {
				t.Fatal("unsafe collection accepted")
			}
		})
	}
}
func TestDrillRejectsMalformedRecipe(t *testing.T) {
	s := validService(t)
	key := pinTestKey(t, s)
	raw, _, err := s.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "opened")
	m, _, err := capsule.Open(raw, key, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, recipe := range []any{nil, map[string]any{}, map[string]any{"version": float64(1), "required": []any{"../../etc/passwd"}, "sqlite": []any{}, "imap": []any{}}} {
		m.VerificationRecipe = recipe
		failed := false
		for _, c := range drillChecks(dir, m) {
			failed = failed || !c.Passed
		}
		if !failed {
			t.Fatal("malformed recipe silently skipped checks")
		}
	}
}
func TestBackupLockAcrossServiceInstances(t *testing.T) {
	s := validService(t)
	other := openService(t, s.dirs, s.cfg)
	release, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := other.Drill(context.Background()); !errors.Is(err, recoveryclient.ErrInProgress) {
		t.Fatalf("concurrent drill: %v", err)
	}
}
func TestSettingsTransactionRollsBackPairing(t *testing.T) {
	s := validService(t)
	sentinel := errors.New("simulated interrupted write")
	err := s.store.BackupSettingsTransaction(func(st recoveryclient.Settings) error {
		if err := st.Set("kyrecovery_url", "https://wrong.example"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, err := s.settings.Get("kyrecovery_url"); !errors.Is(err, recoveryclient.ErrNotFound) {
		t.Fatalf("partial pairing committed: %v", err)
	}
}
func TestRecipeRoundTripsAsJSON(t *testing.T) {
	s := validService(t)
	p, err := s.Collect()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p.VerificationRecipe)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v["required"].([]any); !ok {
		t.Fatal("recipe list absent")
	}
}

func TestBackupDestinationCannotHideUserData(t *testing.T) {
	s := validService(t)
	for _, dir := range []string{filepath.Join(s.dirs.Config, "users"), filepath.Join(s.dirs.State, "users"), s.dirs.Secret} {
		if _, err := New(s.dirs, config.BackupConfig{Dir: dir, Keep: 1}, s.store, "test"); err == nil {
			t.Fatalf("accepted data directory %s", dir)
		}
	}
	release, err := s.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := s.SetIntervalSeconds(900); !errors.Is(err, recoveryclient.ErrInProgress) {
		t.Fatalf("schedule during run: %v", err)
	}
}

func TestClientSealedPickupNeedsNoServerKey(t *testing.T) {
	s := validService(t)
	pickupDir := filepath.Join(s.dirs.State, "pickup")
	pickup := pgpmail.NewPickupStore(pickupDir, filepath.Join(s.dirs.Secret, "pickup-store.key"))
	if _, err := pickup.CreateClientSealed("u1", "recipient@example.com", "synthetic-client-envelope", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Collect(); err != nil {
		t.Fatalf("client-protected pickup blocked backup: %v", err)
	}
	raw := []byte(`{"bodyEnc":{"version":1,"nonce":"test","ciphertext":"test"}}`)
	if err := os.WriteFile(filepath.Join(pickupDir, "legacy.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Collect(); err == nil {
		t.Fatal("server-encrypted pickup accepted without key")
	}
}
