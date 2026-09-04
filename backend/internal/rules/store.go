package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
)

// Store is one user's filter-rule list, persisted as rules.json in the
// user's state directory (sibling to contacts.json/groups.json/
// mailcache.json), modeled on internal/groups's store: every read and
// mutation re-reads the file from disk first, since the API and daemon
// processes share no memory.
type Store struct {
	mu      sync.Mutex
	baseDir string
	rules   []Rule
	seq     int64
}

type rulesFile struct {
	Rules []Rule `json:"rules"`
	Seq   int64  `json:"seq"`
}

func New(baseDir string) (*Store, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{baseDir: baseDir, rules: []Rule{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path() string {
	return filepath.Join(s.baseDir, "rules.json")
}

func (s *Store) load() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, s.persistLocked)
}

func (s *Store) applyFile(rf rulesFile) {
	s.rules = append([]Rule{}, rf.Rules...)
	s.seq = rf.Seq
}

func (s *Store) refreshFromDiskLocked() error {
	return fsutil.LoadJSONFile(s.path(), s.applyFile, nil)
}

func (s *Store) persistLocked() error {
	if err := fsutil.PersistJSONFile(s.path(), rulesFile{Rules: s.rules, Seq: s.seq}); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	return nil
}

// List returns all rules, sorted by Order for stable evaluation/UI ordering.
//
// The refresh error is returned, not swallowed. Rule actions include move,
// spam and delete, and the poller and the manual backfill both run this list
// against real mail: a swallowed read failure kept applying whatever this
// process last managed to load, so a rule the user had deleted went on deleting
// their messages for as long as rules.json stayed unreadable. Callers must skip
// evaluation on an error rather than act on a list they cannot confirm.
func (s *Store) List() ([]Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out, nil
}

// Get returns a rule by ID.
func (s *Store) Get(id string) (Rule, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Rule{}, false, fmt.Errorf("read rules: %w", err)
	}
	for _, r := range s.rules {
		if r.ID == id {
			return r, true, nil
		}
	}
	return Rule{}, false, nil
}

// Upsert creates (when r.ID is empty) or replaces a rule, stamping a new
// Rev/UpdatedAt (and CreatedAt/Order on create — Order defaults to the next
// slot at the end of the list unless the caller already set one).
func (s *Store) Upsert(r Rule) (Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return Rule{}, err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return Rule{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.seq++
	r.Rev = s.seq
	r.UpdatedAt = now

	if r.ID == "" {
		id, err := fsutil.NewUUIDv4()
		if err != nil {
			return Rule{}, err
		}
		r.ID = id
		r.CreatedAt = now
		if r.Order == 0 {
			r.Order = len(s.rules)
		}
		s.rules = append(s.rules, r)
		if err := s.persistLocked(); err != nil {
			return Rule{}, err
		}
		return r, nil
	}

	for i, existing := range s.rules {
		if existing.ID == r.ID {
			if r.CreatedAt == "" {
				r.CreatedAt = existing.CreatedAt
			}
			s.rules[i] = r
			if err := s.persistLocked(); err != nil {
				return Rule{}, err
			}
			return r, nil
		}
	}

	r.CreatedAt = now
	s.rules = append(s.rules, r)
	if err := s.persistLocked(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// Delete removes a rule outright (rules aren't sync-tracked by any other
// consumer, so no tombstone/GC machinery is needed).
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
	for i, r := range s.rules {
		if r.ID != id {
			continue
		}
		s.rules = append(s.rules[:i], s.rules[i+1:]...)
		if err := s.persistLocked(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// Reorder assigns Order = index in ids to each named rule (bumping Rev on
// each), leaving any rule ID not present in ids untouched. Unknown IDs in
// ids are ignored.
func (s *Store) Reorder(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	release, err := fsutil.LockFile(s.path())
	if err != nil {
		return err
	}
	defer release()
	if err := s.refreshFromDiskLocked(); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	position := map[string]int{}
	for i, id := range ids {
		position[id] = i
	}
	for i, r := range s.rules {
		pos, ok := position[r.ID]
		if !ok {
			continue
		}
		s.seq++
		s.rules[i].Order = pos
		s.rules[i].Rev = s.seq
		s.rules[i].UpdatedAt = now
	}
	return s.persistLocked()
}
