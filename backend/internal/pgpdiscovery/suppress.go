package pgpdiscovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Discovery-suppression reasons.
const (
	ReasonDeleted  = "deleted"  // the discovery-created contact was deleted
	ReasonExplicit = "explicit" // the user rejected the key but kept the contact
)

// Suppression is one address the user has opted out of automatic PGP key
// discovery. Email is stored normalized (lowercased, trimmed).
type Suppression struct {
	Email        string `json:"email"`
	SuppressedAt string `json:"suppressedAt"`
	Reason       string `json:"reason"`
}

func suppressionsPath(dir string) string {
	return filepath.Join(dir, "pgp-discovery-suppressions.json")
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// LoadSuppressions reads the caller's opt-out list, returning an empty slice
// when the file does not exist.
func LoadSuppressions(dir string) ([]Suppression, error) {
	b, err := os.ReadFile(suppressionsPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Suppression
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func saveSuppressions(dir string, list []Suppression) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(suppressionsPath(dir), b, 0o600)
}

// AddSuppression records (or refreshes) a discovery opt-out for email. It is
// idempotent on the normalized address: re-adding updates the timestamp and
// reason instead of appending a duplicate. An empty address is a no-op.
func AddSuppression(dir, email, reason string) error {
	e := normalizeEmail(email)
	if e == "" {
		return nil
	}
	list, err := LoadSuppressions(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range list {
		if normalizeEmail(list[i].Email) == e {
			list[i].Email = e
			list[i].SuppressedAt = now
			list[i].Reason = reason
			return saveSuppressions(dir, list)
		}
	}
	list = append(list, Suppression{Email: e, SuppressedAt: now, Reason: reason})
	return saveSuppressions(dir, list)
}

// RemoveSuppression deletes the opt-out for email ("allow discovery again"),
// reporting whether an entry was present.
func RemoveSuppression(dir, email string) (bool, error) {
	e := normalizeEmail(email)
	list, err := LoadSuppressions(dir)
	if err != nil {
		return false, err
	}
	kept := make([]Suppression, 0, len(list))
	removed := false
	for _, s := range list {
		if normalizeEmail(s.Email) == e {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return false, nil
	}
	return true, saveSuppressions(dir, kept)
}

// SuppressedSet returns the normalized suppressed addresses as a set for the
// resolver's O(1) skip check.
func SuppressedSet(dir string) (map[string]bool, error) {
	list, err := LoadSuppressions(dir)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(list))
	for _, s := range list {
		set[normalizeEmail(s.Email)] = true
	}
	return set, nil
}
