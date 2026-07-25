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
	// PublishWKD controls whether this user's key is served over Web Key
	// Directory at all (subject also to the domain being verified at the
	// instance level, and the requested address being one of the user's own
	// publishable addresses). Publishing confirms an address exists and is
	// reachable, so it stays an explicit per-user opt-out, on by default.
	PublishWKD bool `json:"publishWKD"`
}

func path(dir string) string { return filepath.Join(dir, "pgp-discovery.json") }

// Load reads settings, returning defaults (auto-encrypt off, store keys on, advertise autocrypt on,
// publish WKD on) when the file does not exist.
func Load(dir string) (Settings, error) {
	b, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return Settings{AutoEncryptWhenKeyKnown: false, StoreDiscoveredKeys: true, AdvertiseAutocrypt: true, PublishWKD: true}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	// Decode with pointer fields so "absent" is distinguishable from "false"
	// for the on-by-default booleans (legacy files predate them).
	var raw struct {
		AutoEncryptWhenKeyKnown bool  `json:"autoEncryptWhenKeyKnown"`
		StoreDiscoveredKeys     *bool `json:"storeDiscoveredKeys"`
		AdvertiseAutocrypt      *bool `json:"advertiseAutocrypt"`
		PublishWKD              *bool `json:"publishWKD"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Settings{}, err
	}
	s := Settings{
		AutoEncryptWhenKeyKnown: raw.AutoEncryptWhenKeyKnown,
		StoreDiscoveredKeys:     raw.StoreDiscoveredKeys == nil || *raw.StoreDiscoveredKeys,
		AdvertiseAutocrypt:      raw.AdvertiseAutocrypt == nil || *raw.AdvertiseAutocrypt,
		PublishWKD:              raw.PublishWKD == nil || *raw.PublishWKD,
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
