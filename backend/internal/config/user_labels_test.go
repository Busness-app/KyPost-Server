package config

import (
	"path/filepath"
	"testing"
)

func houseConfig() Config {
	cfg := Default()
	cfg.Labels.Allowlist = []string{"Primary", "Promotions"}
	cfg.Labels.KeywordMappings = map[string][]string{"Primary": {"Primary", "Important"}}
	return cfg
}

// An account that predates per-user labels was being classified against the
// house list. Adopting it verbatim is the only migration that leaves its mail
// sorted the way it already was.
func TestLoadUserLabelSettingsSeedsFromTheHouseList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	got, err := LoadUserLabelSettings(path, houseConfig())
	if err != nil {
		t.Fatalf("LoadUserLabelSettings: %v", err)
	}
	if len(got.Labels.Allowlist) != 2 || got.Labels.Allowlist[0] != "Primary" {
		t.Fatalf("allowlist = %v, want the house list", got.Labels.Allowlist)
	}
	if len(got.Labels.KeywordMappings["Primary"]) != 2 {
		t.Fatalf("keywordMappings = %v, want the house mappings", got.Labels.KeywordMappings)
	}
	if !got.Labels.Seeded {
		t.Fatal("Seeded was not set, so the next load would seed again")
	}
}

// The seed is written, not merely returned: a poller tick that seeded in memory
// only would re-seed on every tick and quietly undo the user's edits.
func TestSeedIsPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := LoadUserLabelSettings(path, houseConfig()); err != nil {
		t.Fatalf("first load: %v", err)
	}

	reread, err := LoadUserSettings(path)
	if err != nil {
		t.Fatalf("LoadUserSettings: %v", err)
	}
	if !reread.Labels.Seeded || len(reread.Labels.Allowlist) != 2 {
		t.Fatalf("seed was not written to disk: %+v", reread.Labels)
	}
}

// The whole point of per-user labels: after seeding, the two are independent.
func TestEditingTheHouseListDoesNotReachIntoASeededAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := LoadUserLabelSettings(path, houseConfig()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	moved := houseConfig()
	moved.Labels.Allowlist = []string{"Something", "Else", "Entirely"}

	got, err := LoadUserLabelSettings(path, moved)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(got.Labels.Allowlist) != 2 || got.Labels.Allowlist[0] != "Primary" {
		t.Fatalf("allowlist = %v, want the account's own list untouched", got.Labels.Allowlist)
	}
}

// "No labels" and "never set up" are different states, and a slice cannot tell
// them apart across a YAML round-trip — yaml.Marshal writes a nil slice as `[]`.
// Without the Seeded flag, clearing every label would be undone on next load.
func TestAnAccountThatClearedEveryLabelIsNotReseeded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := LoadUserLabelSettings(path, houseConfig()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := UpdateUserSettings(path, func(s *UserSettings) error {
		s.Labels.Allowlist = []string{}
		s.Labels.KeywordMappings = map[string][]string{}
		return nil
	}); err != nil {
		t.Fatalf("clear: %v", err)
	}

	got, err := LoadUserLabelSettings(path, houseConfig())
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(got.Labels.Allowlist) != 0 {
		t.Fatalf("allowlist = %v, want it to stay empty", got.Labels.Allowlist)
	}
}

// Seeding must not alias the house list: a later edit through the returned
// slice would otherwise mutate the instance config in memory.
func TestSeedCopiesRatherThanAliasingTheHouseList(t *testing.T) {
	house := houseConfig()
	var s UserSettings
	if !SeedUserLabels(&s, house) {
		t.Fatal("SeedUserLabels reported no change on a fresh account")
	}

	s.Labels.Allowlist[0] = "Mutated"
	s.Labels.KeywordMappings["Primary"][0] = "Mutated"

	if house.Labels.Allowlist[0] != "Primary" {
		t.Fatalf("house allowlist was aliased: %v", house.Labels.Allowlist)
	}
	if house.Labels.KeywordMappings["Primary"][0] != "Primary" {
		t.Fatalf("house mappings were aliased: %v", house.Labels.KeywordMappings)
	}
}

func TestSeedUserLabelsIsIdempotent(t *testing.T) {
	var s UserSettings
	if !SeedUserLabels(&s, houseConfig()) {
		t.Fatal("first seed reported no change")
	}
	if SeedUserLabels(&s, houseConfig()) {
		t.Fatal("second seed reported a change; seeding is not idempotent")
	}
}
