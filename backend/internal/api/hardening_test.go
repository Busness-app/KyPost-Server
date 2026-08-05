package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/contacts"
)

// The JSON contact path accepted unbounded arrays while the vCard path that
// writes the SAME records has capped every repeatable family at
// maxValuesPerField since it was written. Per-user file, so this is self-DoS
// rather than a finding — but a client that can write a record the other writer
// refuses to produce is a bug waiting to be found through the reader they share.
func TestContactPayloadArraysAreCapped(t *testing.T) {
	var p contactPayload
	for i := 0; i < maxValuesPerField+50; i++ {
		p.Emails = append(p.Emails, contacts.ContactValue{Value: "a@example.com"})
		p.Phones = append(p.Phones, contacts.ContactValue{Value: "555"})
		p.IMs = append(p.IMs, contacts.ContactIM{Value: "x"})
		p.Websites = append(p.Websites, contacts.ContactURL{Value: "https://example.com"})
		p.Events = append(p.Events, contacts.ContactEvent{Date: "2026-01-01"})
		p.CustomFields = append(p.CustomFields, contacts.ContactCustomField{Value: "v"})
		p.GroupIDs = append(p.GroupIDs, "g")
	}

	c := p.toContact("uid-1")
	for name, got := range map[string]int{
		"emails":       len(c.Emails),
		"phones":       len(c.Phones),
		"ims":          len(c.IMs),
		"websites":     len(c.Websites),
		"events":       len(c.Events),
		"customFields": len(c.CustomFields),
		"groupIDs":     len(c.GroupIDs),
	} {
		if got != maxValuesPerField {
			t.Errorf("%s: %d entries stored, want the vCard path's cap of %d", name, got, maxValuesPerField)
		}
	}
}

// getOrCreateUserStore stamps userLastSeen on every access, and
// rescanDeviceIndex opens EVERY user's store — on a rebuild any caller can
// trigger, under a 30-second throttle, by presenting an unknown device id. So
// on any instance with device traffic every user looked freshly active twice a
// minute and sweepIdleUserStores could never evict anything: the bookkeeping
// recorded the server's own polling as user activity.
func TestDeviceIndexRescanIsNotUserActivity(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	// The user was genuinely active, a long time ago.
	if _, err := srv.userStore(userID); err != nil {
		t.Fatalf("userStore: %v", err)
	}
	stale := time.Now().Add(-userStoreIdleTTL - time.Hour)
	srv.userMu.Lock()
	srv.userLastSeen[userID] = stale
	srv.userMu.Unlock()

	// An unauthenticated caller presents an unknown device id, which is what
	// drives a rescan.
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/native/pull", nil)
	setDeviceHeaders(req, "never-registered-device", "whatever")
	if _, _, ok, _ := srv.deviceAuthFromRequest(req); ok {
		t.Fatal("an invented device id authenticated")
	}

	srv.userMu.Lock()
	seen := srv.userLastSeen[userID]
	srv.userMu.Unlock()
	if !seen.Equal(stale) {
		t.Fatalf("the rescan refreshed userLastSeen (%s -> %s); the idle-store sweep can never "+
			"evict anything on an instance with device traffic", stale, seen)
	}

	// And the sweep now actually reclaims.
	if removed := srv.sweepIdleUserStores(time.Now()); removed == 0 {
		t.Fatal("sweepIdleUserStores reclaimed nothing for a user idle well past the TTL")
	}
}
