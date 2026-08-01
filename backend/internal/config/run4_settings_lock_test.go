package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// run-4 LOW-5: per-user config.yaml was the only store with neither a mutex nor
// a file lock. SaveUserSettings writes atomically, so a reader never sees a
// torn file — but atomicity is not the same as serialization. Two handlers each
// doing Load -> mutate one section -> Save lose one another's writes, and the
// audit reproduced exactly that: a concurrent PUT /api/labels/preferences
// reverting the contentPreview privacy opt-out that a PUT to the notification
// preferences had just set.
//
// A privacy setting that silently reverts is worse than one that never existed,
// because the user checked the box and believes it.

func TestUpdateUserSettingsDoesNotLoseAConcurrentSectionWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	// Two writers, each owning a different section, exactly as the two
	// preference handlers do.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = UpdateUserSettings(path, func(s *UserSettings) error {
				s.Notifications.Mode = "all"
				return nil
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = UpdateUserSettings(path, func(s *UserSettings) error {
				s.Labels.AutoApplyEnabled = false
				return nil
			})
		}
	}()
	wg.Wait()

	got, err := LoadUserSettings(path)
	if err != nil {
		t.Fatalf("LoadUserSettings: %v", err)
	}
	if got.Notifications.Mode != "all" {
		t.Fatalf("the notifications section was lost: %+v", got.Notifications)
	}
	if got.Labels.AutoApplyEnabled {
		t.Fatalf("the labels section was lost: %+v", got.Labels)
	}
}

func TestUpdateUserSettingsStartsFromDefaultsWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := UpdateUserSettings(path, func(s *UserSettings) error {
		s.Labels.AutoApplyEnabled = false
		return nil
	}); err != nil {
		t.Fatalf("UpdateUserSettings: %v", err)
	}

	got, err := LoadUserSettings(path)
	if err != nil {
		t.Fatalf("LoadUserSettings: %v", err)
	}
	if got.Labels.AutoApplyEnabled {
		t.Fatal("the mutation was not persisted")
	}
	// Untouched sections must hold their defaults, not zero values.
	if got.Notifications.Keywords == nil {
		t.Fatal("defaults were not applied to the sections the caller did not touch")
	}
}

// A mutation that fails must leave the file as it was, not half-written.
func TestUpdateUserSettingsDoesNotPersistOnMutateError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := UpdateUserSettings(path, func(s *UserSettings) error {
		s.Notifications.Mode = "all"
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	wantErr := errSentinel{}
	if err := UpdateUserSettings(path, func(s *UserSettings) error {
		s.Notifications.Mode = "clobbered"
		return wantErr
	}); err != wantErr {
		t.Fatalf("err = %v, want the mutate error to propagate", err)
	}

	got, err := LoadUserSettings(path)
	if err != nil {
		t.Fatalf("LoadUserSettings: %v", err)
	}
	if got.Notifications.Mode != "all" {
		t.Fatalf("a failed mutation was persisted anyway: %q", got.Notifications.Mode)
	}
}

type errSentinel struct{}

func (errSentinel) Error() string { return "mutate failed" }

// A settings file that exists but cannot be parsed is not a first run. Treating
// it as one meant the next preference PUT started from defaults and then
// overwrote the document — silently resetting notification mode, keywords and
// the contentPreview opt-out, and destroying the evidence in the same write.
func TestUpdateUserSettingsRefusesToOverwriteAnUnparseableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	corrupt := []byte("notifications: [this is not\n  a settings document\n")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := UpdateUserSettings(path, func(s *UserSettings) error {
		s.Labels.AutoApplyEnabled = true
		return nil
	}); err == nil {
		t.Fatal("UpdateUserSettings accepted an unparseable settings file")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("the unparseable file was overwritten:\n%s", got)
	}
}
