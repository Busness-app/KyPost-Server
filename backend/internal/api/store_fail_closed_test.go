package api

import (
	"bytes"
	"context"
	"image"
	pngenc "image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/pgpdiscovery"

	"github.com/emersion/go-webdav/carddav"
)

// corruptContactsFile makes a user's contacts.json unreadable while leaving
// every warm in-memory copy exactly as it was — the state in which the
// discarded refresh error used to let a process keep answering from a cache it
// could no longer confirm. Stands in for any read failure: a truncated write, a
// damaged volume, a permissions change.
func corruptContactsFile(t *testing.T, srv *Server, userID string) {
	t.Helper()
	path := filepath.Join(srv.userStateDir(userID), "contacts.json")
	if err := os.WriteFile(path, []byte("{ this is not the contacts file"), 0o600); err != nil {
		t.Fatalf("corrupt contacts file: %v", err)
	}
}

// TestInboxDropsCachedVerdictsWhenTheAddressBookIsUnreadable covers the
// fail-OPEN that contacts.Store.PGPKeyGeneration returning an error closes.
//
// A cached "signature verified" verdict is only valid while the address book
// that produced it is unchanged, and the generation counter is what says so.
// With the refresh error discarded, an unreadable contacts.json made the
// counter answer from whatever this process last loaded — so it still matched
// the verdict's stamp, and the green badge survived a key removal the user may
// have made specifically to retire it.
//
// The pre-damage verified badge is what makes the post-damage absence mean
// something: it proves the entry, the stamp and the generation all lined up, so
// the only thing that changed is the unreadable file.
func TestInboxDropsCachedVerdictsWhenTheAddressBookIsUnreadable(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:        "not-parsed-here",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	gen, err := store.PGPKeyGeneration()
	if err != nil {
		t.Fatalf("PGPKeyGeneration: %v", err)
	}

	cache := testInboxCache(t)
	warm := func() {
		t.Helper()
		if err := cache.Upsert("INBOX", []mailcache.Entry{{
			UID: 1, MessageID: "1", Subject: "signed", Sender: "bob@example.com",
			Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "body-1",
			PGPClassified: true, PGPSigned: true, PGPVerified: true,
			PGPSignerFingerprint:    "AABBCCDD",
			PGPVerdictSchemaVersion: mailcache.PGPVerdictSchema,
			ContactKeyGen:           gen,
		}}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	verifiedCount := func() int {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, &fakeMailClient{}, cache, config.Default(), "", 1, 0, false, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("serveInbox status = %d, body=%s", rec.Code, rec.Body.String())
		}
		n := 0
		for _, e := range allEmails(decodeInboxResponse(t, rec)) {
			if e.PGPVerified {
				n++
			}
		}
		return n
	}

	warm()
	if got := verifiedCount(); got != 1 {
		t.Fatalf("precondition: verified entries = %d, want 1 — the cached verdict must be served while the address book is intact", got)
	}

	warm()
	corruptContactsFile(t, srv, userID)
	if got := verifiedCount(); got != 0 {
		t.Fatalf("verified entries = %d after contacts.json became unreadable, want 0: "+
			"a green badge survived an address book this process could not confirm", got)
	}
}

// TestRecipientPlanRefusesWhenTheAddressBookIsUnreadable covers the fail-OPEN
// that findContact returning an error closes.
//
// A recipient whose contact could not be read used to land in withoutKeyEmails
// — the same bucket as a recipient who genuinely has no key — and that bucket
// is what the send path offers the pickup fallback for, which stores the
// message's plaintext server-side for seven days and mails the link in the
// clear. A storage fault must not talk the sender into downgrading a recipient
// whose pinned key was there the whole time.
func TestRecipientPlanRefusesWhenTheAddressBookIsUnreadable(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName: "Alice",
		Emails:        []contacts.ContactValue{{Value: "alice@example.com"}},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	resolver := &keyResolver{store: store, settings: pgpdiscovery.Settings{}, discover: false}
	if _, err := buildPGPRecipientPlan(context.Background(), []string{"alice@example.com"}, nil, nil, resolver); err != nil {
		t.Fatalf("precondition: plan failed while the address book was intact: %v", err)
	}

	corruptContactsFile(t, srv, userID)

	plan, err := buildPGPRecipientPlan(context.Background(), []string{"alice@example.com"}, nil, nil, resolver)
	if err == nil {
		t.Fatalf("plan succeeded with an unreadable address book, withoutKeyEmails=%v — "+
			"the caller would offer the plaintext pickup fallback for a storage fault", plan.withoutKeyEmails)
	}
}

// TestContactPhotoSweepStopsWhenTheAddressBookIsUnreadable covers the worst
// instance of the discarded refresh error: the sweep deletes every photo file
// the contacts store does not reference, so a read that silently yielded no
// contacts deleted the user's entire photo directory.
func TestContactPhotoSweepStopsWhenTheAddressBookIsUnreadable(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	var png bytes.Buffer
	if err := pngenc.Encode(&png, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatalf("encode test photo: %v", err)
	}
	ref, err := srv.storeContactPhoto(userID, png.Bytes())
	if err != nil {
		t.Fatalf("storeContactPhoto: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{FormattedName: "Bob", PhotoRef: ref}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	photoPath := srv.userContactPhotoPath(userID, ref)
	if _, err := os.Stat(photoPath); err != nil {
		t.Fatalf("precondition: photo not on disk: %v", err)
	}
	if err := srv.sweepContactPhotos(userID); err != nil {
		t.Fatalf("precondition: sweep failed while the address book was intact: %v", err)
	}
	if _, err := os.Stat(photoPath); err != nil {
		t.Fatalf("precondition: sweep deleted a referenced photo: %v", err)
	}

	corruptContactsFile(t, srv, userID)

	if err := srv.sweepContactPhotos(userID); err == nil {
		t.Error("sweep reported success with an unreadable address book")
	}
	if _, err := os.Stat(photoPath); err != nil {
		t.Fatalf("sweep deleted a referenced photo after failing to read the address book: %v", err)
	}
}

// TestCardDAVSyncReportsAFailureToSaveItsState covers the discarded write that
// let this endpoint answer 200 after failing to persist the sync outcome.
//
// The payload it writes carries the discovered address-book path, the
// timestamp and the counters. Dropping it means the next sync repeats
// discovery and re-imports from scratch, while the UI reports a success whose
// state was never recorded — the durable cursor never advanced.
func TestCardDAVSyncReportsAFailureToSaveItsState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory does not block writes")
	}
	allowLoopbackOutboundForTest(t)
	backend := &fakeMultiBookBackend{prefix: "/carddav"}
	mux := http.NewServeMux()
	mux.Handle("/carddav/", &carddav.Handler{Backend: backend, Prefix: "/carddav"})
	remote := httptest.NewServer(mux)
	defer remote.Close()

	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	// Keep the config-encryption key inside the test's own tempdir; the
	// default path is not writable here.
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	cfgBody := `{"serverUrl":"` + remote.URL + `/carddav/` + fakeUsername + `","username":"` + fakeUsername + `","password":"irrelevant"}`
	if rec := doWKDRoute(srv, userID, http.MethodPost, "/api/contacts/carddav-client/config", cfgBody); rec.Code != http.StatusOK {
		t.Fatalf("save carddav config: status %d body=%s", rec.Code, rec.Body.String())
	}

	if rec := doWKDRoute(srv, userID, http.MethodPost, "/api/contacts/carddav-client/sync", ""); rec.Code != http.StatusOK {
		t.Fatalf("precondition: sync failed while everything was writable: status %d body=%s", rec.Code, rec.Body.String())
	}

	// Make only the config directory read-only. The contacts store lives in the
	// state directory and stays writable, so the sync itself still succeeds and
	// the write of its outcome is the single thing that fails.
	cfgDir := filepath.Dir(srv.userCardDAVClientConfigPath(userID))
	if err := os.Chmod(cfgDir, 0o500); err != nil {
		t.Fatalf("chmod config dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cfgDir, 0o700) })

	rec := doWKDRoute(srv, userID, http.MethodPost, "/api/contacts/carddav-client/sync", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("sync answered %d after failing to persist its state, want 500: the UI would "+
			"report a success whose cursor never advanced", rec.Code)
	}
}
