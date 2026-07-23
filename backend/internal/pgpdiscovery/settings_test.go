package pgpdiscovery

import (
	"testing"
)

func TestDefaultsWhenAbsent(t *testing.T) {
	s, err := Load(t.TempDir())
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
	want := Settings{AutoEncryptWhenKeyKnown: true, StoreDiscoveredKeys: false}
	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
