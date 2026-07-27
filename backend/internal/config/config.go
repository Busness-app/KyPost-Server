package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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

	Classifier struct {
		BaseURL      string `yaml:"baseUrl" json:"baseUrl"`
		APIKey       string `yaml:"apiKey" json:"apiKey"`
		ClassifyPath string `yaml:"classifyPath" json:"classifyPath"`
		// APIKeySet is a computed, response-only indicator of whether an API
		// key is configured. It is never persisted and never populated on
		// the live in-memory config; handleConfig sets it on a response
		// copy only, after zeroing APIKey, so the plaintext key is never
		// echoed back to any caller.
		APIKeySet bool `yaml:"-" json:"apiKeySet"`
	} `yaml:"classifier" json:"classifier"`

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
	// saw. See the copy on the Notifications page.
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
	// Empty means "fall back to the OLLAMA_* env vars"; see newClassifierClient.
	cfg.Classifier.BaseURL = ""
	cfg.Classifier.APIKey = ""
	cfg.Classifier.ClassifyPath = ""
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
	if _, err := os.Stat(path); err == nil {
		cfg, err := Load(path)
		if err != nil {
			return Config{}, err
		}
		changed, err := ensureNotificationKeyMaterial(configDir, &cfg)
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
	_, err := ensureNotificationKeyMaterial(configDir, &cfg)
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
	return cfg, nil
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

func ensureNotificationKeyMaterial(configDir string, cfg *Config) (bool, error) {
	changed := false
	if strings.TrimSpace(cfg.Notifications.PrivateKeyPath) == "" {
		cfg.Notifications.PrivateKeyPath = filepath.Join(configDir, "notifications-vapid-private.pem")
		changed = true
	}
	key, err := loadOrCreateNotificationPrivateKey(cfg.Notifications.PrivateKeyPath)
	if err != nil {
		return changed, err
	}
	publicKey := base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y))
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
	scalar := key.D.Bytes()
	out := make([]byte, 32)
	copy(out[32-len(scalar):], scalar)
	return base64.RawURLEncoding.EncodeToString(out), nil
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
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

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
