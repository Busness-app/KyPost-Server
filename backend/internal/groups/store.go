package groups

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Store is one user's contact-group list, persisted as groups.json alongside
// contacts.json in the user's state directory. Every read and mutation
// re-reads the file from disk first, matching contacts.Store's convention,
// since the API and daemon processes share no memory.
type Store struct {
	mu      sync.Mutex
	baseDir string
	groups  []Group
	seq     int64
}

type groupsFile struct {
	Groups []Group `json:"groups"`
	Seq    int64   `json:"seq"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, groups: []Group{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "groups.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(gf groupsFile) {
	s.groups = append([]Group{}, gf.Groups...)
	s.seq = gf.Seq
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	if err := fsutil.PersistJSONFile(s.path(), groupsFile{Groups: s.groups, Seq: s.seq}); err != nil {
		return fmt.Errorf("write groups: %w", err)
	}
	return nil
}

// List returns all groups, sorted by name for stable UI ordering.
func (s *Store) List() []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	out := make([]Group, len(s.groups))
	copy(out, s.groups)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a group by ID.
func (s *Store) Get(id string) (Group, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.refreshFromDiskLocked()
	for _, g := range s.groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}

// Upsert creates (when g.ID is empty) or renames/replaces a group, stamping
// a new Rev/UpdatedAt.
func (s *Store) Upsert(g Group) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Group{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Group{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.seq++
	g.Rev = s.seq
	g.UpdatedAt = now

	if g.ID == "" {
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return Group{}, err
		}
		g.ID = id
		g.CreatedAt = now
		s.groups = append(s.groups, g)
		if err := s.persistLocked(); err != nil {
			return Group{}, err
		}
		return g, nil
	}

	for i, existing := range s.groups {
		if existing.ID == g.ID {
			if g.CreatedAt == "" {
				g.CreatedAt = existing.CreatedAt
			}
			s.groups[i] = g
			if err := s.persistLocked(); err != nil {
				return Group{}, err
			}
			return g, nil
		}
	}

	g.CreatedAt = now
	s.groups = append(s.groups, g)
	if err := s.persistLocked(); err != nil {
		return Group{}, err
	}
	return g, nil
}

// Delete removes a group outright. Groups aren't sync-tracked (no CardDAV or
// mobile-sync consumer observes them incrementally yet), so a hard delete is
// sufficient — no tombstone/GC machinery. Callers are responsible for
// stripping the deleted ID from any contact's GroupIDs.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return false, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return false, err
	}
	for i, g := range s.groups {
		if g.ID != id {
			continue
		}
		s.groups = append(s.groups[:i], s.groups[i+1:]...)
		if err := s.persistLocked(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
