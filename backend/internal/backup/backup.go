// Package backup is kypost's adapter over ky-primitives/recoveryclient: what
// to seal, which key seals the pairing token, where settings and audit rows
// live. How a capsule is made, delivered or restored is the library's.
package backup

import (
	"context"
	"errors"
	"fmt"
	kylog "github.com/Busness-app/ky-primitives/logging"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoveryclient"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/cryptutil"
	"github.com/Busness-app/kypost-server/backend/internal/state"
)

// AppName is the service_name claimed at pairing and named in every manifest.
// KyRecovery pins it per token and refuses a deposit whose manifest says otherwise.
const AppName = "KyPost"

const tokenLabel = "kypost:setting:kyrecovery_token"

// ErrKeyAlreadyPinned wraps the library's fs.ErrExist from a second pin to a
// different key, so handlers have one name to map to 409.
var ErrKeyAlreadyPinned = errors.New("backup: a different recovery key is already pinned")

// Dirs are the three data roots a restore needs. Logs are not backed up.
type Dirs struct{ Config, State, Secret string }

// settings adapts the install-wide store to the library's Settings.
type settings struct{ st *state.Store }

func (s settings) Get(key string) (string, error) {
	v, err := s.st.Setting(key)
	if errors.Is(err, state.ErrNotFound) {
		return "", recoveryclient.ErrNotFound
	}
	return v, err
}
func (s settings) Set(key, val string) error { return s.st.SetSetting(key, val) }
func (s settings) Delete(key string) error   { return s.st.DeleteSetting(key) }

// Service is one process's handle on backups.
type Service struct {
	dirs     Dirs
	cfg      config.BackupConfig
	store    *state.Store
	settings settings
	client   *recoveryclient.Client
	version  string
	logger   *kylog.Logger
}

// New binds the data roots. Existing keys are loaded at operation time, so a
// fresh API can initialize its TOTP key before the first backup without the
// daemon generating a replacement key for encrypted data.
func New(d Dirs, bc config.BackupConfig, store *state.Store, appVersion string) (*Service, error) {
	cfg, err := kylog.FromEnv()
	if err != nil {
		return nil, err
	}
	cfg.App = "kypost"
	logger, err := kylog.New(cfg)
	if err != nil {
		return nil, err
	}
	for _, root := range []string{d.Config, d.State, d.Secret} {
		if !filepath.IsAbs(root) {
			return nil, errors.New("backup data directories must be absolute")
		}
	}
	if bc.Dir != "" {
		for _, root := range []string{d.Config, d.Secret, d.State} {
			rel, err := filepath.Rel(root, bc.Dir)
			if err != nil {
				return nil, err
			}
			inside := rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
			if inside && bc.Dir != filepath.Join(d.State, "backups") {
				return nil, errors.New("local backup directory must be outside data roots or exactly STATE_DIR/backups")
			}
		}
		for _, root := range []string{d.Config, d.State, d.Secret} {
			rel, err := filepath.Rel(bc.Dir, root)
			if err != nil {
				return nil, err
			}
			if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
				return nil, errors.New("backup directory must not contain a data root")
			}
		}
	}

	return &Service{
		dirs: d, cfg: bc, store: store, settings: settings{store}, logger: logger,
		client:  recoveryclient.NewClient(recoveryclient.Options{AllowPrivate: bc.AllowPrivateRecovery}),
		version: appVersion,
	}, nil
}

// AllowPrivate reports the KYPOST_BACKUP_ALLOW_PRIVATE_RECOVERY switch, for the
// pairing audit row and the screen.
func (s *Service) AllowPrivate() bool { return s.cfg.AllowPrivateRecovery }

func (s *Service) runConfig(sealer recoveryclient.Sealer) recoveryclient.RunConfig {
	return recoveryclient.RunConfig{
		DataDir: s.dirs.State, AppName: AppName, AppVersion: s.version,
		BackupDir: s.cfg.Dir, Keep: s.cfg.Keep, Sealer: sealer,
	}
}

// Run seals once and delivers to every configured destination.
func (s *Service) Run(ctx context.Context) (recoveryclient.Result, error) {
	release, err := s.lock()
	if err != nil {
		return recoveryclient.Result{}, err
	}
	defer release()
	if err := s.settings.Set("backup_last_attempt", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return recoveryclient.Result{}, err
	}
	if _, err := s.pairingConfigured(); err != nil {
		return recoveryclient.Result{}, err
	}
	sealer, err := s.loadSealer()
	if err != nil {
		return recoveryclient.Result{}, err
	}
	if _, err = s.loadKey(); err != nil {
		return recoveryclient.Result{}, err
	}
	return recoveryclient.Run(ctx, s.runConfig(sealer), s.settings, func() (recoveryclient.Payload, error) { return s.collect(ctx) }, s.client)
}

// Export seals once for download; nothing is delivered and nothing is stamped.
func (s *Service) Export(ctx context.Context) ([]byte, capsule.Manifest, error) {
	release, err := s.lock()
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	defer release()
	key, err := s.loadKey()
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	p, err := s.collect(ctx)
	if err != nil {
		return nil, capsule.Manifest{}, err
	}
	return recoveryclient.Seal(p, key)
}

// Pair claims a pairing code, pins the key write-once and stores the sealed token.
func (s *Service) Pair(ctx context.Context, rawURL, code string) (recoveryclient.RecoveryKey, error) {
	release, err := s.lock()
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	defer release()
	sealer, err := s.loadSealer()
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	if err := recoveryclient.ValidateURL(rawURL, s.cfg.AllowPrivateRecovery); err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	res, err := s.client.ClaimPairing(ctx, rawURL, code, AppName, AppName)
	if err != nil {
		return recoveryclient.RecoveryKey{}, err
	}
	return res.Key, s.store.BackupSettingsTransaction(func(st recoveryclient.Settings) error {
		if err := recoveryclient.StoreRecoveryKey(s.dirs.State, st, res.Key); err != nil {
			return pinErr(err)
		}
		return recoveryclient.StorePairing(st, sealer, rawURL, res.APIToken)
	})
}

// PinKey is the offline path to the same write-once pin.
func (s *Service) PinKey(publicKeyB64 string, k, n int) error {
	key, err := recoveryclient.ParsePinRequest(publicKeyB64, k, n)
	if err != nil {
		return err
	}
	release, err := s.lock()
	if err != nil {
		return err
	}
	defer release()
	return s.store.BackupSettingsTransaction(func(st recoveryclient.Settings) error {
		return pinErr(recoveryclient.StoreRecoveryKey(s.dirs.State, st, key))
	})
}

func pinErr(err error) error {
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w: %v", ErrKeyAlreadyPinned, err)
	}
	return err
}

// Unpair removes the URL and sealed token rows and nothing else.
func (s *Service) Unpair() error {
	release, err := s.lock()
	if err != nil {
		return err
	}
	defer release()
	return s.store.BackupSettingsTransaction(recoveryclient.ClearPairing)
}

// SetIntervalSeconds stores the admin's schedule; the library bounds it.
func (s *Service) SetIntervalSeconds(sec int64) error {
	release, err := s.lock()
	if err != nil {
		return err
	}
	defer release()
	return recoveryclient.SetInterval(s.settings, sec)
}

// NextRun is what the daemon loop polls.
func (s *Service) NextRun() (time.Time, bool, error) {
	return recoveryclient.NextRun(s.cfg.DepositInterval, s.settings)
}

// Audit records one row. A caller that cannot audit refuses (see api).
func (s *Service) Audit(action, actor, target, outcome string, details map[string]any) error {
	if err := s.store.RecordBackupAudit(action, actor, target, outcome, details); err != nil {
		return err
	}
	s.logger.Security(context.Background(), backupAuditEvent, kylog.Action(action), kylog.ActorID(actor), kylog.TargetID(target), kylog.Outcome(outcome))
	return nil
}

// Status is what the screen renders.
type Status struct {
	KeyID         string                     `json:"keyId,omitempty"`
	Threshold     int                        `json:"threshold,omitempty"`
	TotalShares   int                        `json:"totalShares,omitempty"`
	KeyProblem    string                     `json:"keyProblem,omitempty"`
	Paired        bool                       `json:"paired"`
	KyRecoveryURL string                     `json:"kyrecoveryUrl,omitempty"`
	LastReceipt   *recoveryclient.Receipt    `json:"lastReceipt,omitempty"`
	LocalDir      string                     `json:"localDir,omitempty"`
	LocalCopies   []recoveryclient.LocalCopy `json:"localCopies"`
	IntervalSec   int64                      `json:"intervalSec"`
	NextRun       string                     `json:"nextRun,omitempty"`
	AllowPrivate  bool                       `json:"allowPrivateRecovery"`
	Excluded      string                     `json:"excluded"`
	Recent        []state.BackupAudit        `json:"recent"`
}

func (s *Service) Status() (Status, error) {
	release, err := s.lock()
	if err != nil {
		return Status{}, err
	}
	defer release()
	st := Status{LocalDir: s.cfg.Dir, AllowPrivate: s.cfg.AllowPrivateRecovery, Excluded: ErrMailExcluded, LocalCopies: []recoveryclient.LocalCopy{}}
	key, err := s.loadKey()
	switch {
	case err == nil:
		st.KeyID, st.Threshold, st.TotalShares = key.Public.ID(), key.Threshold, key.TotalShares
	case errors.Is(err, recoveryclient.ErrNotPaired):
	case errors.Is(err, recoveryclient.ErrKeyMismatch), errors.Is(err, recoveryclient.ErrKeyPinMissing):
		st.KeyProblem = "recovery.pub does not match the pinned key ID; backups are refused until it is restored"
	default:
		return st, err
	}
	paired, err := s.pairingConfigured()
	if err != nil {
		return st, err
	}
	st.Paired = paired
	if paired {
		st.KyRecoveryURL, err = s.settings.Get("kyrecovery_url")
		if err != nil {
			return st, err
		}
	}

	if r, ok, err := recoveryclient.LastDeposit(s.settings); err != nil {
		return st, err
	} else if ok {
		st.LastReceipt = &r
	}
	if s.cfg.Dir != "" {
		copies, err := recoveryclient.ListLocalCopies(s.cfg.Dir, AppName)
		if err != nil {
			return st, err
		}
		st.LocalCopies = copies
	}
	iv, err := recoveryclient.Interval(s.cfg.DepositInterval, s.settings)
	if err != nil {
		return st, err
	}
	st.IntervalSec = int64(iv / time.Second)
	if next, on, err := s.NextRun(); err != nil {
		return st, err
	} else if on {
		st.NextRun = next.UTC().Format(time.RFC3339)
	}
	recent, err := s.store.RecentBackupAudit(20)
	if err != nil {
		return st, err
	}
	st.Recent = recent
	return st, nil
}

// The API and daemon must not mutate a pairing or prune local copies under an
// in-flight backup. A busy caller retries; no request queues behind a long upload.
func (s *Service) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(s.dirs.State, "backup-operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, recoveryclient.ErrInProgress
		}
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
func (s *Service) loadSealer() (recoveryclient.Sealer, error) {
	key, err := cryptutil.LoadKey(s.secretPath("TOTP_SECRET_KEY_FILE", "totp-secret.key"))
	if err != nil {
		return nil, fmt.Errorf("backup requires the existing TOTP master key: %w", err)
	}
	return recoveryclient.NewAESGCMSealer(key, tokenLabel)
}
func (s *Service) secretPath(env, name string) string {
	if path := os.Getenv(env); path != "" {
		return path
	}
	return filepath.Join(s.dirs.Secret, name)
}
func (s *Service) loadKey() (recoveryclient.RecoveryKey, error) {
	key, err := recoveryclient.LoadRecoveryKey(s.dirs.State, s.settings)
	if errors.Is(err, recoveryclient.ErrNotPaired) {
		_, pinErr := s.settings.Get("kyrecovery_key_id")
		if pinErr == nil {
			return key, recoveryclient.ErrKeyPinMissing
		}
		if !errors.Is(pinErr, recoveryclient.ErrNotFound) {
			return key, pinErr
		}
	}
	return key, err
}

func (s *Service) pairingConfigured() (bool, error) {
	url, ue := s.settings.Get("kyrecovery_url")
	token, te := s.settings.Get("kyrecovery_token_enc")
	if ue != nil && !errors.Is(ue, recoveryclient.ErrNotFound) {
		return false, ue
	}
	if te != nil && !errors.Is(te, recoveryclient.ErrNotFound) {
		return false, te
	}
	if url == "" && token == "" {
		return false, nil
	}
	if url == "" || token == "" {
		return false, errors.New("incomplete KyRecovery pairing; unpair and pair again")
	}
	return true, nil
}

// Configured distinguishes a never-configured instance from a broken pin.
func (s *Service) Configured() (bool, error) {
	for _, key := range []string{"kyrecovery_key_id", "kyrecovery_url", "kyrecovery_token_enc"} {
		_, err := s.settings.Get(key)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, recoveryclient.ErrNotFound) {
			return false, err
		}
	}
	return false, nil
}

var backupAuditEvent = kylog.DeclareEvent("kypost_backup_action", "backup action", slog.LevelInfo)

func (s *Service) IntervalSeconds() (int64, error) {
	d, err := recoveryclient.Interval(s.cfg.DepositInterval, s.settings)
	return int64(d / time.Second), err
}
func (s *Service) PinnedKeyID() (string, error) {
	key, err := s.loadKey()
	if err != nil {
		return "", err
	}
	return key.Public.ID(), nil
}
