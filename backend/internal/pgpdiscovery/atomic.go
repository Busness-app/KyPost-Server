package pgpdiscovery

import (
	"sync"

	"github.com/Busness-app/kypost-server/backend/internal/fsutil"
)

// Every file in this package is mutated read-modify-write: load the current
// contents, change them, write the whole file back. Two callers doing that
// concurrently for the same user both read the same starting state and the
// second write silently discards the first one's change — a lost update.
// That is reachable in practice: the settings PUT handler and the two
// suppression call sites (deleting a contact, and explicitly suppressing
// addresses) each perform one of these cycles, and nothing stopped them
// overlapping.
//
// dirMu serializes those cycles per user state directory. Every mutator in
// this package must hold it for the whole load-modify-save sequence, not just
// the individual reads and writes.
//
// dirMu alone is a within-process lock, so Update pairs it with an
// inter-process file lock (fsutil.WithFileLock). The previous note here said
// a process-local lock was sufficient because every writer lives in the api
// process; that is a property of today's call sites, not of the file, and it
// is exactly the kind of assumption that rots silently the first time the
// poller grows a write path. The file lock costs one uncontended syscall.
//
// The keyed map is not swept: keys are user state directories, so the map is
// bounded by the account count and is not attacker-influenced.
var (
	dirMuMu sync.Mutex
	dirMus  = map[string]*sync.Mutex{}
)

func dirMu(dir string) *sync.Mutex {
	dirMuMu.Lock()
	defer dirMuMu.Unlock()
	mu, ok := dirMus[dir]
	if !ok {
		mu = &sync.Mutex{}
		dirMus[dir] = mu
	}
	return mu
}

// Update atomically applies mutate to the settings stored in dir and returns
// the result. Callers must use this rather than Load-then-Save when the new
// value depends on the current one: it holds the per-directory lock across
// the whole cycle, so a concurrent Update cannot interleave and clobber the
// change.
func Update(dir string, mutate func(Settings) Settings) (Settings, error) {
	mu := dirMu(dir)
	mu.Lock()
	defer mu.Unlock()

	var next Settings
	err := fsutil.WithFileLock(path(dir), func() error {
		current, err := Load(dir)
		if err != nil {
			return err
		}
		next = mutate(current)
		return Save(dir, next)
	})
	if err != nil {
		return Settings{}, err
	}
	return next, nil
}
