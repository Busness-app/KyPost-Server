package mailcache

// SyncContactKeyGeneration discards every cached signature verdict that was
// computed under a different contacts-store key generation.
//
// Called on the read path, where it is one integer comparison in the common
// case. This is what makes verdict invalidation cover EVERY contact writer
// instead of the three handlers that call InvalidatePGPVerdicts: a verdict
// carries the generation it was computed under, so a change made by mobile
// sync, CardDAV, vCard import, dedupe, the discovery-suppression button, or the
// daemon's Autocrypt harvest invalidates it just as surely as one made through
// the contacts API.
//
// Fails closed in the sense that matters: dropping a verdict costs one body
// re-fetch and a re-verification under current rules, while keeping a stale one
// shows a green "signature verified" badge for a trust basis the user has
// already removed.
func (s *Store) SyncContactKeyGeneration(gen int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refreshFromDiskLocked(); err != nil {
		return err
	}
	changed := false
	for _, w := range s.mailboxes {
		if w == nil {
			continue
		}
		for i := range w.Entries {
			e := &w.Entries[i]
			if !e.PGPSigned && !e.PGPVerified && e.PGPSignerFingerprint == "" {
				continue
			}
			if e.ContactKeyGen == gen {
				continue
			}
			clearPGPVerdict(e)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.persistLocked()
}
