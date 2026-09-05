package backup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/cryptutil"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busness-app/kypost-server/backend/internal/state"
	"gopkg.in/yaml.v3"
)

const ErrMailExcluded = "IMAP mail and the rebuildable mail cache are excluded; encrypted pickup messages awaiting collection are included"
const scratchDirName = "backup-scratch"

var required = []string{"config/config.yaml", "config/users.json", "private/totp-secret.key", "state/state.db"}

func skip(name string) bool {
	return name == "supervisor.sock" || name == "supervisord.pid" || name == "poll-now.trigger" || name == "mailcache.json" || name == scratchDirName || strings.HasSuffix(name, ".lock") ||
		strings.HasSuffix(name, ".migrated") || strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") || strings.HasSuffix(name, "-journal")
}

func (s *Service) Collect() (recoveryclient.Payload, error) { return s.collect(context.Background()) }

func (s *Service) collect(ctx context.Context) (recoveryclient.Payload, error) {
	var empty recoveryclient.Payload
	// Individual secret overrides must remain at their canonical location. A
	// capsule cannot reproduce an arbitrary host mount on a different machine.
	for env, name := range map[string]string{"IMAP_CONFIG_KEY_FILE": "imap-config.key", "TOTP_SECRET_KEY_FILE": "totp-secret.key", "PGP_PRIVATE_KEY_FILE": "pgp-private-key.key", "PICKUP_STORE_KEY_FILE": "pickup-store.key", "PAIRING_SECRET_FILE": "pairing.key", "POW_SECRET_FILE": "pow.key", "PUSH_RELAY_KEY_FILE": "push_relay_key", "APNS_RELAY_KEY_FILE": "apns_relay_key"} {
		if path := strings.TrimSpace(os.Getenv(env)); path != "" && filepath.Clean(path) != filepath.Join(s.dirs.Secret, name) {
			return empty, fmt.Errorf("backup does not support %s outside its default SECRET_DIR location; restore the standard layout before backing up", env)
		}
	}
	if _, err := cryptutil.LoadKey(filepath.Join(s.dirs.Secret, "totp-secret.key")); err != nil {
		return empty, fmt.Errorf("required TOTP master key: %w", err)
	}
	scratchRoot := filepath.Join(s.dirs.State, scratchDirName)
	if err := os.MkdirAll(scratchRoot, 0700); err != nil {
		return empty, err
	}
	scratch, err := os.MkdirTemp(scratchRoot, "snapshot-")
	if err != nil {
		return empty, err
	}
	defer os.RemoveAll(scratch)
	files := []recoveryclient.File{}
	var total int64
	have := map[string]bool{}
	imaps := []string{}
	add := func(rel string, data []byte) error {
		if int64(len(data)) > recoveryclient.MaxCapsuleFileBytes {
			return fmt.Errorf("%s exceeds the 64 MiB per-file backup cap", rel)
		}
		total += int64(len(data))
		if total > recoveryclient.MaxCapsuleTotalBytes {
			return fmt.Errorf("payload exceeds the 256 MiB backup cap")
		}
		have[rel] = true
		files = append(files, recoveryclient.File{Path: rel, Data: data, Mode: 0600})
		return nil
	}
	for _, r := range []struct{ path, prefix string }{{s.dirs.Config, "config"}, {s.dirs.Secret, "private"}, {s.dirs.State, "state"}} {
		root, err := os.OpenRoot(r.path)
		if err != nil {
			return empty, err
		}
		err = func() error {
			defer root.Close()
			return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				if rel != "." && skip(d.Name()) {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
				// Exclude the configured capsule destination, even when nested in a data root.
				full := filepath.Join(r.path, filepath.FromSlash(rel))
				if s.cfg.Dir != "" && full == s.cfg.Dir {
					if d.IsDir() {
						return fs.SkipDir
					}
					return fmt.Errorf("backup directory is not a directory")
				}
				if d.IsDir() {
					return nil
				}
				if !d.Type().IsRegular() {
					return fmt.Errorf("cannot back up non-regular file %s/%s", r.prefix, rel)
				}
				name := r.prefix + "/" + rel
				info, err := d.Info()
				if err != nil {
					return err
				}
				if info.Size() > recoveryclient.MaxCapsuleFileBytes {
					return fmt.Errorf("%s exceeds the 64 MiB per-file backup cap", name)
				}
				var raw []byte
				if d.Name() == "state.db" {
					raw, err = state.SnapshotDB(ctx, full, scratch)
				} else {
					f, e := root.Open(rel)
					if e != nil {
						return e
					}
					remaining := min(recoveryclient.MaxCapsuleFileBytes, recoveryclient.MaxCapsuleTotalBytes-total)
					raw, err = io.ReadAll(io.LimitReader(f, remaining+1))
					f.Close()
				}
				if err != nil {
					return fmt.Errorf("collect %s: %w", name, err)
				}
				if d.Name() == "imap-config.json" {
					imaps = append(imaps, name)
				}
				return add(name, raw)
			})
		}()
		if err != nil {
			return empty, err
		}
	}
	for _, name := range required {
		if !have[name] {
			return empty, fmt.Errorf("refusing to seal without %s", name)
		}
	}
	if len(imaps) > 0 {
		if _, err := cryptutil.LoadKey(filepath.Join(s.dirs.Secret, "imap-config.key")); err != nil {
			return empty, fmt.Errorf("IMAP master key required by stored credentials: %w", err)
		}
	}
	// Validate configured file dependencies against the collected roots. Environment
	// credentials and TLS mounts are restored separately from the operator's .env.
	var cfg config.Config
	for _, f := range files {
		if f.Path == "config/config.yaml" {
			if err := yaml.Unmarshal(f.Data, &cfg); err != nil {
				return empty, err
			}
		}
	}
	tuningPath := strings.TrimSpace(os.Getenv("TUNING_FILE"))
	// The classifier skips a missing optional override and uses its bundled
	// prompt. Compose sets this path even when no override has been created.
	if _, err := os.Stat(tuningPath); os.IsNotExist(err) {
		tuningPath = ""
	}
	for label, path := range map[string]string{"VAPID private key": cfg.Notifications.PrivateKeyPath, "TUNING_FILE": tuningPath} {
		if path == "" {
			continue
		}
		included := false
		for _, root := range []struct{ path, prefix string }{{s.dirs.Config, "config"}, {s.dirs.Secret, "private"}, {s.dirs.State, "state"}} {
			rel, err := filepath.Rel(root.path, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				included = included || have[root.prefix+"/"+filepath.ToSlash(rel)]
			}
		}
		if !included {
			return empty, fmt.Errorf("%s is outside the supported backup layout or missing; place it inside CONFIG_DIR or SECRET_DIR", label)
		}
	}
	if err := validateDependencies(files); err != nil {
		return empty, err
	}
	return recoveryclient.Payload{ServiceName: AppName, AppVersion: s.version, Files: files,
		Dependencies:       map[string]any{"ollama": "model cache downloads again", "layout": "restore config, private and state to CONFIG_DIR, SECRET_DIR and STATE_DIR"},
		VerificationRecipe: map[string]any{"version": 1, "mail": ErrMailExcluded, "required": required, "sqlite": "all-state-databases", "imap": "all-stored-credentials"}}, nil
}

// validateDependencies refuses a capsule whose stored identities cannot be
// opened after restore. Client-wrapped PGP keys stay opaque throughout.
func validateDependencies(files []recoveryclient.File) error {
	byPath := map[string][]byte{}
	for _, f := range files {
		byPath[f.Path] = f.Data
	}
	var accounts struct {
		Users []struct {
			TOTP string `json:"totpSecretEnc"`
			PGP  string `json:"pgpPrivateKeyEnc"`
		} `json:"users"`
	}
	if err := json.Unmarshal(byPath["config/users.json"], &accounts); err != nil {
		return fmt.Errorf("invalid users.json: %w", err)
	}
	requireKey := func(name string) error {
		raw, ok := byPath["private/"+name]
		if !ok {
			return fmt.Errorf("stored encrypted data requires private/%s", name)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(key) != 32 {
			return fmt.Errorf("invalid private/%s", name)
		}
		return nil
	}
	for _, u := range accounts.Users {
		if u.TOTP != "" {
			if err := requireKey("totp-secret.key"); err != nil {
				return err
			}
		}
		if u.PGP != "" {
			if err := requireKey("pgp-private-key.key"); err != nil {
				return err
			}
		}
	}
	for name, raw := range byPath {
		if strings.HasPrefix(name, "state/pickup/") && strings.HasSuffix(name, ".json") {
			var record pgpmail.PickupRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				return fmt.Errorf("invalid pickup record %s: %w", name, err)
			}
			if record.SubjectEnc != nil || record.BodyEnc != (cryptutil.EncryptedPayload{}) {
				if err := requireKey("pickup-store.key"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
