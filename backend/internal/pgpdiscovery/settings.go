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
	AdvertiseAutocrypt      bool `json:"advertiseAutocrypt"`
}

func path(dir string) string { return filepath.Join(dir, "pgp-discovery.json") }

// Load reads settings, returning defaults (auto-encrypt off, store keys on, advertise autocrypt on)
// when the file does not exist.
func Load(dir string) (Settings, error) {
	b, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return Settings{AutoEncryptWhenKeyKnown: false, StoreDiscoveredKeys: true, AdvertiseAutocrypt: true}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	// Decode with pointer fields so "absent" is distinguishable from "false"
	// for the two on-by-default booleans (legacy files predate them).
	var raw struct {
		AutoEncryptWhenKeyKnown bool  `json:"autoEncryptWhenKeyKnown"`
		StoreDiscoveredKeys     *bool `json:"storeDiscoveredKeys"`
		AdvertiseAutocrypt      *bool `json:"advertiseAutocrypt"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Settings{}, err
	}
	s := Settings{
		AutoEncryptWhenKeyKnown: raw.AutoEncryptWhenKeyKnown,
		StoreDiscoveredKeys:     raw.StoreDiscoveredKeys == nil || *raw.StoreDiscoveredKeys,
		AdvertiseAutocrypt:      raw.AdvertiseAutocrypt == nil || *raw.AdvertiseAutocrypt,
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
