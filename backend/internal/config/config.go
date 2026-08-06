package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"kypost-server/backend/internal/fsutil"

	"gopkg.in/yaml.v3"
)

type Paths struct {
	ConfigFile string
	StateDir   string
	LogDir     string
}

// The container's data directories. These literals used to be copy-pasted as
// EnvOrDefault fallbacks across eight packages and twenty-odd call sites, and
// several secret files hardcoded "/kypost/private/..." independently of
// SECRET_DIR — so overriding SECRET_DIR moved some secrets and not others,
// and any code path that forgot one env var silently reached for the host's
// root directory instead of failing. Declare them once.
const (
	DefaultConfigDir = "/kypost/config"
	DefaultStateDir  = "/kypost/state"
	DefaultLogDir    = "/kypost/logs"
	DefaultSecretDir = "/kypost/private"
)

// ConfigDir, StateDir, LogDir and SecretDir resolve the four data directories
// from the environment, falling back to the container defaults above.
func ConfigDir() string { return EnvOrDefault("CONFIG_DIR", DefaultConfigDir) }
func StateDir() string  { return EnvOrDefault("STATE_DIR", DefaultStateDir) }
func LogDir() string    { return EnvOrDefault("LOG_DIR", DefaultLogDir) }
func SecretDir() string { return EnvOrDefault("SECRET_DIR", DefaultSecretDir) }

// SecretFile resolves the path to a single secret. A per-secret env override
// (e.g. PGP_PRIVATE_KEY_FILE) still wins so existing deployments that point
// individual keys elsewhere keep working, but the fallback is now derived
// from SecretDir() rather than being its own hardcoded absolute path. That is
// what makes SECRET_DIR actually relocate every secret — including in tests,
// which is why this exists.
func SecretFile(envKey, name string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	return filepath.Join(SecretDir(), name)
}

// EnvOrDefault returns the trimmed value of the environment variable key, or
// fallback if it is unset or blank after trimming.
func EnvOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// EnvInt returns the environment variable key parsed as a positive int, or
// fallback if it is unset, unparseable, or not positive.
func EnvInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

type Config struct {
	Timezone string `yaml:"timezone" json:"timezone"`
	LogLevel string `yaml:"logLevel" json:"logLevel"`

	Scan struct {
		IntervalSeconds int `yaml:"intervalSeconds" json:"intervalSeconds"`
	} `yaml:"scan" json:"scan"`

	RateLimits struct {
		PerMinute int `yaml:"perMinute" json:"perMinute"`
		PerHour   int `yaml:"perHour" json:"perHour"`
	} `yaml:"rateLimits" json:"rateLimits"`

	Redaction struct {
		Patterns []Pattern `yaml:"patterns" json:"patterns"`
	} `yaml:"redaction" json:"redaction"`

	Labels struct {
		Allowlist       []string            `yaml:"allowlist" json:"allowlist"`
		KeywordMappings map[string][]string `yaml:"keywordMappings" json:"keywordMappings"`
	} `yaml:"labels" json:"labels"`

	Notifications NotificationKeys `yaml:"notifications" json:"-"`
}

// NotificationKeys is the shared VAPID signing identity for the whole
// install. Delivery preferences (mode/keywords) are per-user and live in
// UserSettings instead.
type NotificationKeys struct {
	PublicKey      string `yaml:"publicKey" json:"-"`
	PrivateKeyPath string `yaml:"privateKeyPath" json:"-"`
}

// UserSettings is the small per-user preferences document stored at
// CONFIG_DIR/users/<userID>/config.yaml.
type UserSettings struct {
	Notifications UserNotificationSettings `yaml:"notifications" json:"notifications"`
	Labels        UserLabelSettings        `yaml:"labels" json:"labels"`
}

type UserNotificationSettings struct {
	Mode     string   `yaml:"mode" json:"mode"`
	Keywords []string `yaml:"keywords" json:"keywords"`
	// ContentPreview controls whether the sender and subject of a message
	// are placed in the push payload, or whether the notification is
	// generic ("KyPost" / "You have a new email.").
	//
	// It defaults to FALSE, and that default is the point. A push
	// notification is not delivered by this server: it travels
	// backend -> Cloudflare Worker relay -> Google FCM or Apple APNs, in
	// cleartext to each of those hops. Putting the sender and subject in it
	// hands the correspondence graph of a self-hosted, PGP-advertising mail
	// product to exactly the third parties its users chose self-hosting to
	// avoid. Encrypting the body buys nothing if the Subject header is
	// couriered to Google on arrival.
	//
	// Users who want previews can have them — this is their mail and their
	// call — but it must be a decision they made, not a default they never
	// saw. See the copy on Configuration's Notifications tab.
	//
	// Note the absence of omitempty: false must serialize, or a user who
	// turns previews off round-trips back to "unset" and the field reads as
	// absent rather than as the choice they made. (Absent still means
	// false, so an older settings file is private by default too.)
	ContentPreview bool `yaml:"contentPreview" json:"contentPreview"`
}

// UserLabelSettings controls whether the AI classification pipeline
// automatically applies keyword labels for this user. When
// AutoApplyEnabled is false, classification is skipped entirely and every
// message is tagged with the account's default label instead (see
// disabledLabelingFallback in processor/poller.go).
type UserLabelSettings struct {
	AutoApplyEnabled bool `yaml:"autoApplyEnabled" json:"autoApplyEnabled"`
}

func DefaultUserSettings() UserSettings {
	var s UserSettings
	s.Notifications.Mode = "none"
	s.Notifications.Keywords = []string{}
	s.Labels.AutoApplyEnabled = true
	return s
}

// LoadUserSettings reads a per-user settings file, returning defaults if it
// does not exist yet.
func LoadUserSettings(path string) (UserSettings, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultUserSettings(), nil
		}
		return UserSettings{}, err
	}
	s := DefaultUserSettings()
	if err := yaml.Unmarshal(b, &s); err != nil {
		return UserSettings{}, err
	}
	if s.Notifications.Keywords == nil {
		s.Notifications.Keywords = []string{}
	}
	return s, nil
}

func SaveUserSettings(path string, s UserSettings) error {
	b, err := yaml.Marshal(s)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path, b, 0o600)
}

// UpdateUserSettings applies mutate to the settings at path as one
// read-modify-write cycle, holding an inter-process file lock across the whole
// cycle.
//
// Load-then-Save from a handler is not enough, and this was the only store in
// the project with neither a mutex nor a file lock. AtomicWriteFile means a
// reader never sees a torn file, but atomicity is not serialization: the two
// preference handlers each load the whole settings struct, replace one section
// and write it all back, so a PUT to /api/labels/preferences landing between
// another request's load and save silently reverts whatever that request set —
// including the contentPreview privacy opt-out, which is worse than never
// having offered it, because the user ticked the box and believes it.
//
// A missing file starts from DefaultUserSettings rather than the zero value, so
// sections the caller does not touch keep their intended defaults instead of
// being written as false/empty. Nothing is persisted if mutate returns an
// error.
//
// A read that FAILS is not a missing file and must not be treated as one.
// LoadUserSettings already answers "no file yet" with the defaults, so every
// error left here is a real one — an unreadable file, or YAML that no longer
// parses — and starting from defaults after one meant the next preference PUT
// silently reset notification mode, keywords and the contentPreview privacy
// opt-out, then overwrote the only copy of the document that would have shown
// what they were.
func UpdateUserSettings(path string, mutate func(*UserSettings) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir user settings dir: %w", err)
	}
	return fsutil.WithFileLock(path, func() error {
		s, err := LoadUserSettings(path)
		if err != nil {
			return fmt.Errorf("load user settings: %w", err)
		}
		if err := mutate(&s); err != nil {
			return err
		}
		return SaveUserSettings(path, s)
	})
}

// LoadLegacyNotificationPrefs extracts the pre-multi-user mode/keywords
// fields from a legacy global config.yaml, for one-time migration into the
// first admin user's settings file.
func LoadLegacyNotificationPrefs(path string) (UserNotificationSettings, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return UserNotificationSettings{}, false
	}
	var legacy struct {
		Notifications UserNotificationSettings `yaml:"notifications"`
	}
	if err := yaml.Unmarshal(b, &legacy); err != nil {
		return UserNotificationSettings{}, false
	}
	if strings.TrimSpace(legacy.Notifications.Mode) == "" {
		return UserNotificationSettings{}, false
	}
	return legacy.Notifications, true
}

type Pattern struct {
	Name        string `yaml:"name" json:"name"`
	Regex       string `yaml:"regex" json:"regex"`
	Replacement string `yaml:"replacement" json:"replacement"`
}

func Default() Config {
	cfg := Config{
		Timezone: "America/New_York",
		LogLevel: "info",
	}
	cfg.Scan.IntervalSeconds = 90
	cfg.RateLimits.PerMinute = 10
	cfg.RateLimits.PerHour = 20
	cfg.Redaction.Patterns = []Pattern{
		{Name: "email", Regex: `(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`, Replacement: "[REDACTED_EMAIL]"},
		{Name: "phone", Regex: `\b(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b`, Replacement: "[REDACTED_PHONE]"},
		{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Replacement: "[REDACTED_SSN]"},
		{Name: "iban", Regex: `\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`, Replacement: "[REDACTED_IBAN]"},
		{Name: "card", Regex: `\b(?:\d[ -]*?){13,19}\b`, Replacement: "[REDACTED_CARD]"},
	}
	cfg.Labels.KeywordMappings = map[string][]string{}
	return cfg
}

func LoadOrInit(path string) (Config, error) {
	configDir := filepath.Dir(path)
	// Same SECRET_DIR convention processor.relayKeyFilePathWithPrefix uses.
	secretDir := SecretDir()
	if _, err := os.Stat(path); err == nil {
		cfg, err := Load(path)
		if err != nil {
			return Config{}, err
		}
		changed, err := ensureNotificationKeyMaterial(configDir, secretDir, &cfg)
		if err != nil {
			return Config{}, err
		}
		if changed {
			if err := Save(path, cfg); err != nil {
				return Config{}, err
			}
		}
		return cfg, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Config{}, fmt.Errorf("mkdir config dir: %w", err)
	}
	cfg := Default()
	_, err := ensureNotificationKeyMaterial(configDir, secretDir, &cfg)
	if err != nil {
		return Config{}, err
	}
	if err := Save(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	warnRetiredClassifier(b)
	return cfg, nil
}

// warnRetiredClassifier says so out loud when config.yaml still carries the
// retired `classifier:` block.
//
// yaml.Unmarshal ignores unknown keys, so an install that pointed
// classification at a remote endpoint keeps starting cleanly — but it is now
// classifying against the OLLAMA_* env vars instead, with no other symptom.
// A silent change of where email content is sent deserves a line in the log.
func warnRetiredClassifier(raw []byte) {
	var probe struct {
		Classifier map[string]any `yaml:"classifier"`
	}
	if err := yaml.Unmarshal(raw, &probe); err != nil || len(probe.Classifier) == 0 {
		return
	}
	slog.Warn("ignoring the retired `classifier:` block in config.yaml; " +
		"classification now uses the OLLAMA_* environment variables only. " +
		"Remove the block to silence this warning.")
}

func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	// Atomic temp+rename like every other persisted file in this project.
	// os.WriteFile truncates in place, and the daemon calls Load on every
	// tick — a read landing inside that window sees an empty file, which
	// unmarshals successfully into the zero value, so Load silently returns
	// Default() rather than an error. That drops any operator-configured
	// redaction pattern from what gets fed to the classifier, for a tick.
	return fsutil.AtomicWriteFile(path, b, 0o600)
}

// ensureNotificationKeyMaterial fills in the VAPID identity, generating the
// private key on first use.
//
// New installs put the key in secretDir. It used to go to configDir, which made
// it the one secret in this system outside SECRET_DIR — those are separate
// volumes with separate lifecycles, and an operator who copies "the config"
// reasonably does not expect a signing key to come with it.
//
// An install that already records a path keeps it, which is why the assignment
// is guarded rather than unconditional. The VAPID public key is registered with
// every browser that has ever subscribed to notifications, so relocating an
// existing key would invalidate every live subscription — a worse outcome than
// the key sitting in a directory it should not have been in. New installs get
// the right layout; existing ones keep working.
func ensureNotificationKeyMaterial(configDir, secretDir string, cfg *Config) (bool, error) {
	changed := false
	if strings.TrimSpace(cfg.Notifications.PrivateKeyPath) == "" {
		dir := strings.TrimSpace(secretDir)
		if dir == "" {
			dir = configDir
		}
		cfg.Notifications.PrivateKeyPath = filepath.Join(dir, "notifications-vapid-private.pem")
		changed = true
	}
	key, err := loadOrCreateNotificationPrivateKey(cfg.Notifications.PrivateKeyPath)
	if err != nil {
		return changed, err
	}
	// elliptic.Marshal is deprecated since Go 1.21. ECDH().Bytes() produces
	// the identical uncompressed SEC 1 point (0x04 || X || Y) that VAPID
	// requires, so this is an encoding-compatible swap, not a format change.
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		return changed, fmt.Errorf("encode notification public key: %w", err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(ecdhPub.Bytes())
	if cfg.Notifications.PublicKey != publicKey {
		cfg.Notifications.PublicKey = publicKey
		changed = true
	}
	return changed, nil
}

// LoadVAPIDPrivateKey reads the notification VAPID private key PEM at path and
// returns it in the base64url raw-scalar form the webpush library expects.
func LoadVAPIDPrivateKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return "", fmt.Errorf("vapid pem block missing")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	// ecdh.PrivateKey.Bytes() returns the scalar already fixed-width and
	// left-padded, which is what VAPID wants. key.D.Bytes() (deprecated since
	// Go 1.26) strips leading zeros, hence the manual padding this replaces.
	ecdhKey, err := key.ECDH()
	if err != nil {
		return "", fmt.Errorf("convert vapid private key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(ecdhKey.Bytes()), nil
}

func parseNotificationPrivateKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("decode notification private key: pem block missing")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse notification private key: %w", err)
	}
	return key, nil
}

// loadOrCreateNotificationPrivateKey reads the VAPID private key at path,
// generating and persisting a new one on first run.
//
// daemon and server are separate OS processes that each independently call
// this on boot. On a fresh install both can observe "file doesn't exist"
// and race to generate + write a keypair; whichever write lands last "wins"
// on disk while the other process would otherwise keep running with a
// DIFFERENT keypair in memory, so the persisted public key in config.yaml
// could end up not matching the private key on disk. To prevent that, the
// whole read-check-generate-write sequence is guarded by a syscall.Flock on
// a sibling lock file. Flock (rather than an O_EXCL lock file) is used
// deliberately: it is released automatically by the kernel if the holding
// process dies, so a crash mid-lock can never deadlock a future boot. The
// losing side of the race re-reads the file after acquiring the lock
// instead of trusting its own already-generated in-memory key, so every
// caller converges on the single keypair that actually ends up on disk.
func loadOrCreateNotificationPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir notification key dir: %w", err)
	}

	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open notification key lock: %w", err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock notification key: %w", err)
	}
	// Unlock errors are not actionable: the deferred Close below releases the
	// lock regardless, and the process is on its way out of this function
	// either way. Discard explicitly rather than implicitly.
	defer func() { _ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) }()

	// Re-check under the lock: another process/goroutine may have already
	// generated and written the key while we were waiting for the lock. If
	// so, use what's actually on disk rather than generating our own.
	if b, err := os.ReadFile(path); err == nil {
		return parseNotificationPrivateKeyPEM(b)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate notification key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal notification key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := fsutil.AtomicWriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write notification key: %w", err)
	}
	return key, nil
}
