package pgpdiscovery_test

import (
	"os"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/pgpdiscovery"
)

func TestLoadDefaultsAdvertiseAutocryptOn(t *testing.T) {
	dir := t.TempDir()
	s, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AdvertiseAutocrypt {
		t.Fatal("AdvertiseAutocrypt should default to true when no file exists")
	}
}

func TestLoadLegacyFileDefaultsAdvertiseAutocryptOn(t *testing.T) {
	dir := t.TempDir()
	// A settings file written before this field existed.
	if err := os.WriteFile(filepath.Join(dir, "pgp-discovery.json"),
		[]byte(`{"autoEncryptWhenKeyKnown":false,"storeDiscoveredKeys":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AdvertiseAutocrypt {
		t.Fatal("legacy file (no field) should load AdvertiseAutocrypt=true")
	}
}

func TestLoadDefaultsPublishWKDOn(t *testing.T) {
	dir := t.TempDir()
	s, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.PublishWKD {
		t.Fatal("PublishWKD should default to true when no file exists")
	}
}

func TestLoadLegacyFileDefaultsPublishWKDOn(t *testing.T) {
	dir := t.TempDir()
	// A settings file written before this field existed.
	if err := os.WriteFile(filepath.Join(dir, "pgp-discovery.json"),
		[]byte(`{"autoEncryptWhenKeyKnown":false,"storeDiscoveredKeys":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s.PublishWKD {
		t.Fatal("legacy file (no field) should load PublishWKD=true")
	}
}

func TestLoadExplicitPublishWKDFalse(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pgp-discovery.json"),
		[]byte(`{"publishWKD":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.PublishWKD {
		t.Fatal("explicit publishWKD:false must be respected, not defaulted to true")
	}
}

// Preserve existing tests for backward compatibility
func TestDefaultsWhenAbsent(t *testing.T) {
	s, err := pgpdiscovery.Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.AutoEncryptWhenKeyKnown {
		t.Fatalf("AutoEncryptWhenKeyKnown default should be false")
	}
	if !s.StoreDiscoveredKeys {
		t.Fatalf("StoreDiscoveredKeys default should be true")
	}
}

func TestSaveThenLoad(t *testing.T) {
	dir := t.TempDir()
	want := pgpdiscovery.Settings{AutoEncryptWhenKeyKnown: true, StoreDiscoveredKeys: false}
	if err := pgpdiscovery.Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := pgpdiscovery.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
