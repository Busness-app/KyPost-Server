package pgpdiscovery

import (
	"encoding/json"
	"os"
	"path/filepath"

	"kypost-server/backend/internal/fsutil"
)

type Settings struct {
	AutoEncryptWhenKeyKnown bool `json:"autoEncryptWhenKeyKnown"`
	StoreDiscoveredKeys     bool `json:"storeDiscoveredKeys"`
}

func path(dir string) string { return filepath.Join(dir, "pgp-discovery.json") }

// Load reads settings, returning defaults (auto-encrypt off, store keys on)
// when the file does not exist.
func Load(dir string) (Settings, error) {
	b, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return Settings{AutoEncryptWhenKeyKnown: false, StoreDiscoveredKeys: true}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func Save(dir string, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path(dir), b, 0o600)
}
