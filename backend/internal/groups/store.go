package groups

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// refreshFromDiskLocked re-reads groups.json into memory. Its error is never
// discarded: the in-memory copy is a cache of a file two processes write, so a
// failed re-read means this process does not know what the groups are — and a
// group is a recipient set. See contacts.Store for the same rule.
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
func (s *Store) List() ([]Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, fmt.Errorf("read groups: %w", err)
	}
	out := make([]Group, len(s.groups))
	copy(out, s.groups)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns a group by ID.
func (s *Store) Get(id string) (Group, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Group{}, false, fmt.Errorf("read groups: %w", err)
	}
	for _, g := range s.groups {
		if g.ID == id {
			return g, true, nil
		}
	}
	return Group{}, false, nil
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
		// The same ceiling EnsureByName enforces. It used to live only there, so
		// POST /api/groups — which calls straight into Upsert — walked past it.
		// A cap enforced on one of two create paths is not a cap.
		if len(s.groups) >= MaxGroupsPerUser {
			return Group{}, ErrTooManyGroups
		}
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

// MaxGroupsPerUser bounds how many groups one account may accumulate.
//
// Groups are created implicitly from a vCard's CATEGORIES, so without a ceiling
// a single imported card mints as many as it likes — and every one of them is
// re-read on every later PROPFIND and export, so the cost is permanent rather
// than one-off. 1,000 is far past any real address book's organisational
// scheme while keeping the whole file small enough to read cheaply.
const MaxGroupsPerUser = 1000

// ErrTooManyGroups reports that a batch would push the account past
// MaxGroupsPerUser. The batch is refused whole; nothing partial is written.
var ErrTooManyGroups = errors.New("groups: too many groups for this account")

// EnsureByName resolves category names to group IDs, creating the missing ones,
// in ONE locked read-modify-write.
//
// The caller used to loop over names calling Upsert, and each Upsert takes the
// file lock, reads and unmarshals the whole file, marshals it back and writes it
// with two fsyncs. That is quadratic in the number of names: 5,000 categories on
// one card measured 32 seconds on tmpfs, and a single vCard well under the
// import size cap can carry hundreds of thousands.
//
// Matching is case-insensitive and the result is de-duplicated, so a card
// listing "Work", "work" and "Work" again resolves to one id. Order follows
// first appearance. Blank names are skipped rather than creating an unnamed
// group.
func (s *Store) EnsureByName(names []string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, err
	}

	byName := make(map[string]string, len(s.groups))
	for _, g := range s.groups {
		byName[strings.ToLower(g.Name)] = g.ID
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ids := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	created := 0

	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true

		if id, ok := byName[key]; ok {
			ids = append(ids, id)
			continue
		}
		// Checked per new group rather than once up front, so a batch that only
		// references groups the account already has still succeeds at the cap —
		// otherwise being full would break ordinary sync of existing cards.
		// len(s.groups) already grows as this loop appends, so it alone is the
		// running total — adding created would count each new group twice and
		// halve the effective cap.
		if len(s.groups) >= MaxGroupsPerUser {
			return nil, ErrTooManyGroups
		}
		id, uerr := fsutil.NewUUIDv4()
		if uerr != nil {
			return nil, uerr
		}
		s.seq++
		s.groups = append(s.groups, Group{
			ID:        id,
			Name:      name,
			Rev:       s.seq,
			CreatedAt: now,
			UpdatedAt: now,
		})
		byName[key] = id
		ids = append(ids, id)
		created++
	}

	if created == 0 {
		return ids, nil
	}
	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return ids, nil
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
