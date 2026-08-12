package mailcache

import (
	"os"
	"strings"
	"testing"
)

func ov(uid int, subject, status string) Overview {
	return Overview{UID: uid, Subject: subject, Sender: "a@example.com", Status: status, AtUTC: "2026-01-01T00:00:00Z"}
}

// entry models an API write: something that both fetched a body AND classified
// the message. PGPClassified is part of "warm" now, because a body alone is
// what the daemon poller produces and it never looks for PGP content. A fixture
// without it is a poller write, and Snapshot deliberately reports those cold.
func entry(uid int, subject, status string, body string) Entry {
	return Entry{
		UID: uid, MessageID: itoaTest(uid), Subject: subject, Sender: "a@example.com",
		Status: status, AtUTC: "2026-01-01T00:00:00Z", Body: body, PGPClassified: true,
	}
}

func itoaTest(uid int) string {
	e := entryFromOverview(Overview{UID: uid})
	return e.MessageID
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestSync_NewMessagesReportedWithIncreasingRev(t *testing.T) {
	s := newTestStore(t)
	res, err := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.New) != 2 || len(res.Updated) != 0 || len(res.Removed) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.New[0].Rev >= res.New[1].Rev {
		t.Fatalf("expected increasing rev, got %d then %d", res.New[0].Rev, res.New[1].Rev)
	}
	if res.Cursor != res.New[1].Rev {
		t.Fatalf("cursor should equal highest rev, got cursor=%d highest=%d", res.Cursor, res.New[1].Rev)
	}
}

func TestSync_FlagChangeReportedAsUpdatedNotNew(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)
	cursorAfterFirst := first.Cursor

	live := []Overview{ov(1, "a", "read"), ov(2, "b", "unread")}
	second, err := s.Sync("INBOX", 10, live, cursorAfterFirst)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(second.New) != 0 {
		t.Fatalf("expected no New entries, got %+v", second.New)
	}
	if len(second.Updated) != 1 || second.Updated[0].UID != 1 || second.Updated[0].Status != "read" {
		t.Fatalf("expected uid 1 updated to read, got %+v", second.Updated)
	}
}

func TestSync_UnchangedEntryKeepsOldRevAndIsOmitted(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0)

	second, err := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, first.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(second.New) != 0 || len(second.Updated) != 0 || len(second.Removed) != 0 {
		t.Fatalf("expected no changes, got %+v", second)
	}
	if second.Cursor != first.Cursor {
		t.Fatalf("cursor should not advance when nothing changed: first=%d second=%d", first.Cursor, second.Cursor)
	}
}

func TestSync_WindowFalloutReportedAsRemoved(t *testing.T) {
	s := newTestStore(t)
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)

	res, err := s.Sync("INBOX", 10, []Overview{ov(2, "b", "unread")}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Removed) != 1 || res.Removed[0].UID != 1 {
		t.Fatalf("expected uid 1 removed, got %+v", res.Removed)
	}

	// Reintroducing uid 1 later must report it as New again, not resurrect
	// stale state, since it left the window entirely in between.
	res2, err := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, res.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	found := false
	for _, e := range res2.New {
		if e.UID == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected uid 1 to reappear as New, got %+v", res2)
	}
}

func TestSync_MultiPollerSinceFiltering(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0)

	// A second poller polls with the same since=0 baseline as `first` did,
	// but its Sync call happens after some other caller's Sync already
	// advanced the window (simulated by calling Sync again with a flag
	// change before this caller "asks").
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "read")}, first.Cursor)

	// Now a caller whose last known cursor predates both calls (since=0)
	// must still see uid 1, classified as New (it never saw the UID
	// before), not Updated.
	res, err := s.Sync("INBOX", 10, []Overview{ov(1, "a", "read")}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.New) != 1 || res.New[0].UID != 1 {
		t.Fatalf("expected uid 1 reported as New for a since=0 caller, got New=%+v Updated=%+v", res.New, res.Updated)
	}
}

func TestSync_LimitChangeResetsWindowWithoutRemoved(t *testing.T) {
	s := newTestStore(t)
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)

	// Same live UIDs but a different limit — must reset comparison state:
	// no Removed even though nothing actually disappeared, everything New.
	res, err := s.Sync("INBOX", 50, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("expected no removed on limit change, got %+v", res.Removed)
	}
	if len(res.New) != 2 {
		t.Fatalf("expected both entries reported New after limit change, got %+v", res.New)
	}
}

func TestStore_PersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s1.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	s2, err := New(dir)
	if err != nil {
		t.Fatalf("New (second store): %v", err)
	}
	entries, _ := s2.Snapshot("INBOX", 1)
	if len(entries) != 1 || entries[0].UID != 1 {
		t.Fatalf("expected persisted entry to be visible from a second Store instance, got %+v", entries)
	}
}

func TestStore_IndependentMailboxWindows(t *testing.T) {
	s := newTestStore(t)
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0)
	s.Sync("Archive/2026", 10, []Overview{ov(1, "x", "read"), ov(2, "y", "read")}, 0)

	inbox, _ := s.Snapshot("INBOX", 1)
	archive, _ := s.Snapshot("Archive/2026", 2)
	if len(inbox) != 1 {
		t.Fatalf("expected INBOX window to have 1 entry, got %d", len(inbox))
	}
	if len(archive) != 2 {
		t.Fatalf("expected Archive/2026 window to have 2 entries, got %d", len(archive))
	}
}

func TestUpsert_NoRemovalInferenceFromPartialInput(t *testing.T) {
	s := newTestStore(t)
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)

	// The daemon only ever sees a subset (new unread mail) — upserting just
	// uid 3 must not cause uid 1 or 2 to be treated as gone.
	if err := s.Upsert("INBOX", []Entry{entry(3, "c", "unread", "body-3")}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, _ := s.Snapshot("INBOX", 3)
	if len(entries) != 3 {
		t.Fatalf("expected all 3 entries to remain in the window, got %+v", entries)
	}
}

func TestUpsert_BodyAttachedWithoutBumpingRev(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0)
	revBefore := first.New[0].Rev

	if err := s.Upsert("INBOX", []Entry{entry(1, "a", "unread", "warmed-body")}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, warmed := s.Snapshot("INBOX", 1)
	if !warmed {
		t.Fatalf("expected snapshot to be fully warmed after Upsert attached a body")
	}
	if entries[0].Body != "warmed-body" {
		t.Fatalf("expected body to be attached, got %+v", entries[0])
	}
	if entries[0].Rev != revBefore {
		t.Fatalf("attaching a body alone should not bump Rev: before=%d after=%d", revBefore, entries[0].Rev)
	}
}

// TestPGPProtectedSubject_WarmedWithoutChurnAndPreserved proves the warm-only
// protected subject: a decrypt-warm Upsert attaches it without bumping Rev
// (Subject stays the placeholder overview subject, so entryMeta is unchanged),
// and a later metadata-only overview change preserves it rather than resetting
// it from the placeholder-carrying overview.
func TestPGPProtectedSubject_WarmedWithoutChurnAndPreserved(t *testing.T) {
	s := newTestStore(t)
	// The overview subject is the placeholder for an encrypted message.
	first, _ := s.Sync("INBOX", 10, []Overview{ov(1, "[Encrypted] Email Sent by KyPost", "unread")}, 0)
	revBefore := first.New[0].Rev

	warm := entry(1, "[Encrypted] Email Sent by KyPost", "unread", "decrypted-body")
	warm.PGPEncrypted = true
	warm.PGPProtectedSubject = "Quarterly numbers"
	if err := s.Upsert("INBOX", []Entry{warm}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, _ := s.Snapshot("INBOX", 1)
	if entries[0].PGPProtectedSubject != "Quarterly numbers" {
		t.Fatalf("expected protected subject warmed in, got %+v", entries[0])
	}
	if entries[0].Subject != "[Encrypted] Email Sent by KyPost" {
		t.Fatalf("Subject must stay the placeholder overview subject, got %q", entries[0].Subject)
	}
	if entries[0].Rev != revBefore {
		t.Fatalf("warming a protected subject must not bump Rev: before=%d after=%d", revBefore, entries[0].Rev)
	}

	// A read-flag flip via overview (still the placeholder subject) must keep
	// the warmed protected subject.
	second, err := s.Sync("INBOX", 10, []Overview{ov(1, "[Encrypted] Email Sent by KyPost", "read")}, first.Cursor)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(second.Updated) != 1 {
		t.Fatalf("expected the read-flag change reported as an update, got %+v", second)
	}
	entries, _ = s.Snapshot("INBOX", 1)
	if entries[0].PGPProtectedSubject != "Quarterly numbers" {
		t.Fatalf("metadata-only overview change must preserve the protected subject, got %+v", entries[0])
	}
}

// TestPGPBody_NeverPersisted proves the warm path stores a decrypted OpenPGP
// message's flags but not its plaintext, for both a brand-new UID and one
// already in the window. The assertion is against the file on disk, not just
// the in-memory snapshot, because the whole point is what an attacker holding
// the volume can read.
func TestPGPBody_NeverPersisted(t *testing.T) {
	s := newTestStore(t)

	// New UID: straight to Upsert without a prior Sync, so this exercises the
	// append branch rather than the update branch.
	fresh := entry(1, "[Encrypted] Email Sent by KyPost", "unread", "the secret plaintext")
	fresh.PGPEncrypted = true
	fresh.PGPSigned = true
	fresh.PGPVerified = true
	fresh.PGPSignerFingerprint = "ABCD"
	if err := s.Upsert("INBOX", []Entry{fresh}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 10)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %+v", entries)
	}
	if entries[0].Body != "" {
		t.Fatalf("a decrypted PGP body must not be stored, got %q", entries[0].Body)
	}
	// The flags are the reason we do not simply drop the whole entry: clients
	// render the badge from them and know to fetch the body live.
	if !entries[0].PGPEncrypted || !entries[0].PGPSigned || !entries[0].PGPVerified {
		t.Fatalf("PGP flags must survive alongside the dropped body, got %+v", entries[0])
	}
	if entries[0].PGPSignerFingerprint != "ABCD" {
		t.Fatalf("signer fingerprint must survive, got %+v", entries[0])
	}

	raw, err := os.ReadFile(s.path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), "the secret plaintext") {
		t.Fatalf("decrypted plaintext reached %s", s.path())
	}

	// Existing UID: an older build may already have written plaintext for this
	// message, so a re-warm must clear it rather than leave it behind.
	stale := entry(2, "s", "unread", "previously cached plaintext")
	if err := s.Upsert("INBOX", []Entry{stale}); err != nil {
		t.Fatalf("Upsert stale: %v", err)
	}
	rewarm := entry(2, "s", "unread", "the secret plaintext")
	rewarm.PGPEncrypted = true
	if err := s.Upsert("INBOX", []Entry{rewarm}); err != nil {
		t.Fatalf("Upsert rewarm: %v", err)
	}
	entries, _ = s.Snapshot("INBOX", 10)
	for _, e := range entries {
		if e.UID == 2 && e.Body != "" {
			t.Fatalf("re-warming an encrypted message must clear a previously cached body, got %q", e.Body)
		}
	}

	raw, err = os.ReadFile(s.path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), "previously cached plaintext") {
		t.Fatalf("stale plaintext survived a re-warm in %s", s.path())
	}
}

// TestNonPGPBody_StillWarmed guards the other side: dropping PGP bodies must
// not turn into dropping every body, which would silently cost a live fetch on
// every open for ordinary mail.
func TestNonPGPBody_StillWarmed(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("INBOX", []Entry{entry(1, "s", "unread", "ordinary body")}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, _ := s.Snapshot("INBOX", 10)
	if len(entries) != 1 || entries[0].Body != "ordinary body" {
		t.Fatalf("expected an ordinary body warmed into the cache, got %+v", entries)
	}
}

func TestHasAttachments_WarmPathSetsIt_OverviewLeavesUnset(t *testing.T) {
	s := newTestStore(t)

	// Overview sync (the cheap path) carries no attachment info, so the flag
	// stays false regardless of the real message.
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread")}, 0)
	entries, _ := s.Snapshot("INBOX", 1)
	if entries[0].HasAttachments {
		t.Fatalf("overview-sync path must leave HasAttachments false, got %+v", entries[0])
	}

	// Warm path (poller Upsert) carries an authoritative flag from the full
	// GetEmails parse — adopt it.
	warm := entry(1, "a", "unread", "warmed-body")
	warm.HasAttachments = true
	if err := s.Upsert("INBOX", []Entry{warm}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, _ = s.Snapshot("INBOX", 1)
	if !entries[0].HasAttachments {
		t.Fatalf("warm path must set HasAttachments, got %+v", entries[0])
	}

	// A metadata-only overview change (e.g. read flag) must preserve the
	// warmed flag, not reset it from the attachment-less overview.
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "read")}, 0)
	entries, _ = s.Snapshot("INBOX", 1)
	if !entries[0].HasAttachments {
		t.Fatalf("overview-sync metadata change must preserve HasAttachments, got %+v", entries[0])
	}

	// A later warm with no attachments must clear it back (unconditional
	// adoption, unlike Body's empty-string sentinel).
	warm.Status = "read"
	warm.HasAttachments = false
	if err := s.Upsert("INBOX", []Entry{warm}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	entries, _ = s.Snapshot("INBOX", 1)
	if entries[0].HasAttachments {
		t.Fatalf("warm path must clear HasAttachments when the message has none, got %+v", entries[0])
	}
}

func TestUpsert_WindowCapTrimsOldestUIDs(t *testing.T) {
	s := newTestStore(t)
	entries := make([]Entry, 0, maxWindowEntries+5)
	for i := 1; i <= maxWindowEntries+5; i++ {
		entries = append(entries, entry(i, "s", "unread", "b"))
	}
	if err := s.Upsert("INBOX", entries); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	all, _ := s.Snapshot("INBOX", maxWindowEntries)
	if len(all) != maxWindowEntries {
		t.Fatalf("expected window capped at %d entries, got %d", maxWindowEntries, len(all))
	}
	if all[0].UID != 6 {
		t.Fatalf("expected lowest-UID entries evicted, lowest remaining uid = %d, want 6", all[0].UID)
	}
}

func TestSnapshot_FullyWarmedBoundary(t *testing.T) {
	s := newTestStore(t)
	s.Sync("INBOX", 10, []Overview{ov(1, "a", "unread"), ov(2, "b", "unread")}, 0)

	// Fewer entries than limit -> not fully warmed.
	if _, warmed := s.Snapshot("INBOX", 5); warmed {
		t.Fatalf("expected fullyWarmed=false when window has fewer entries than limit")
	}

	// Enough entries but none have a Body (Sync never sets Body) -> not warmed.
	if _, warmed := s.Snapshot("INBOX", 2); warmed {
		t.Fatalf("expected fullyWarmed=false when entries lack Body")
	}

	// Warm one of two entries -> still not fully warmed.
	s.Upsert("INBOX", []Entry{entry(1, "a", "unread", "body-1")})
	if _, warmed := s.Snapshot("INBOX", 2); warmed {
		t.Fatalf("expected fullyWarmed=false when only some entries have Body")
	}

	// Warm both -> fully warmed.
	s.Upsert("INBOX", []Entry{entry(2, "b", "unread", "body-2")})
	if _, warmed := s.Snapshot("INBOX", 2); !warmed {
		t.Fatalf("expected fullyWarmed=true when all requested entries have Body")
	}
}

// A client-protected message is encrypted AND has no body, by design — the
// server does not decrypt it. The flags must survive an Upsert into an
// existing entry anyway, or the message is cached as ordinary mail and the
// phone never offers to decrypt it.
func TestUpsertKeepsPGPFlagsForBodylessClientProtectedMessage(t *testing.T) {
	s := newTestStore(t)

	// The poller/Sync creates the entry first, from overviews, with no PGP data.
	if err := s.Upsert("INBOX", []Entry{{UID: 7, MessageID: "7", Subject: "..."}}); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	// Then the API warms it with the classification and no body.
	if err := s.Upsert("INBOX", []Entry{{
		UID: 7, MessageID: "7", Subject: "...",
		Body:         "",
		PGPEncrypted: true,
	}}); err != nil {
		t.Fatalf("warm upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if !entries[0].PGPEncrypted {
		t.Fatal("PGPEncrypted was dropped for a bodyless client-protected message")
	}
}

// The other half of the original comment is real: a FAILED decrypt also
// leaves an empty body, and caching that would make a transient failure
// sticky. Only a clean classification is durable.
func TestUpsertStillDropsFlagsWhenDecryptFailed(t *testing.T) {
	s := newTestStore(t)

	if err := s.Upsert("INBOX", []Entry{{UID: 8, MessageID: "8"}}); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	if err := s.Upsert("INBOX", []Entry{{
		UID: 8, MessageID: "8",
		Body:            "",
		PGPEncrypted:    true,
		PGPDecryptError: "no secret key",
	}}); err != nil {
		t.Fatalf("warm upsert: %v", err)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].PGPEncrypted {
		t.Fatal("a failed decrypt was cached; it must stay uncached and retryable")
	}
}

// The error is a signal for the guard, not durable state. If it survived
// into the window, a transient failure would keep suppressing the flags
// long after the decrypt would have succeeded.
func TestUpsertNeverStoresADecryptError(t *testing.T) {
	s := newTestStore(t)

	if err := s.Upsert("INBOX", []Entry{{
		UID: 9, MessageID: "9", PGPEncrypted: true, PGPDecryptError: "no secret key",
	}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// White-box: package mailcache can read unexported state directly,
	// bypassing the disk round trip (Snapshot's refreshFromDiskLocked +
	// json:"-") that would otherwise mask whether the in-memory clear at
	// store.go's new-UID branch actually runs. This is the only assertion
	// in this test that covers that line; the Snapshot-based checks below
	// are covered by the json:"-" tag alone regardless of it.
	if got := s.mailboxes["INBOX"].Entries[0].PGPDecryptError; got != "" {
		t.Fatalf("in-memory window kept a decrypt error: %q", got)
	}

	entries, _ := s.Snapshot("INBOX", 1)
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if entries[0].PGPDecryptError != "" {
		t.Fatalf("a decrypt error was stored: %q", entries[0].PGPDecryptError)
	}
}
