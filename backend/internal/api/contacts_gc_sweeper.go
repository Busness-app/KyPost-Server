package api

import (
	"context"
	"time"
)

// StartContactsTombstoneSweeper reclaims deleted-contact tombstones past their
// retention window. Call once after NewServer.
//
// contacts.Store.GC has existed since tombstones did and had no caller anywhere
// in the repository — not even a test — while its ten sibling sweepers are all
// wired in startBackgroundSweepers, including the contact PHOTO sweeper
// immediately alongside it. Deleting a contact clears its personal fields but
// keeps the client-chosen UID, so without this every deletion leaves a
// permanent residue in contacts.json on the shared state volume, and a
// create-then-delete cycle grows the file monotonically.
//
// Hourly, mirroring StartContactPhotoSweeper: tombstone retention is measured in
// days, so the tick rate only has to be small relative to that.
func (s *Server) StartContactsTombstoneSweeper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			all, err := s.users.List()
			if err != nil {
				s.logger.Error("contacts tombstone sweep could not list users", "error", err.Error())
				continue
			}
			for _, u := range all {
				store, err := s.userContactsStore(u.ID)
				if err != nil {
					s.logger.Error("contacts tombstone sweep could not open store",
						"user_id", u.ID, "error", err.Error())
					continue
				}
				// Zero means the store's own default retention.
				if err := store.GC(0); err != nil {
					s.logger.Error("contacts tombstone sweep failed",
						"user_id", u.ID, "error", err.Error())
				}
			}
		}
	}
}
