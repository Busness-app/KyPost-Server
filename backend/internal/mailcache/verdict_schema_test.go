package mailcache

import (
	"testing"
)

// signedEntry is an entry carrying a cached "signature verified" verdict.
//
// Signed but NOT encrypted, deliberately: warmBody refuses to persist a
// decrypted OpenPGP body, so an encrypted entry has no warm body for the
// invalidation to have to drop and these tests could not see that half.
func signedEntry(uid int, schema int) Entry {
	e := entry(uid, "subject", "unread", "cached body")
	e.PGPSigned = true
	e.PGPVerified = true
	e.PGPSignerFingerprint = "5D18B163"
	e.PGPVerdictSchemaVersion = schema
	return e
}

// TestStaleVerdictsAreDroppedOnLoad is run-8 finding F11.
//
// There was no schema, version or generation field anywhere in this package and
// no invalidation hook. Sync explicitly carries PGPVerified forward and the
// delta branch serves it with no body fetch and no re-verification, so a
// verdict computed under a superseded binding survived the upgrade and replayed
// under the new rules — the fix did not apply retroactively to the artifacts it
// was written to correct, and the reader still saw the old green badge.
func TestStaleVerdictsAreDroppedOnLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A verdict from an older binding. Written through Upsert then aged, since
	// Upsert stamps the current version on the way in.
	if err := s.Upsert("INBOX", []Entry{signedEntry(1, 0)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	s.mu.Lock()
	s.mailboxes["INBOX"].Entries[0].PGPVerdictSchemaVersion = PGPVerdictSchema - 1
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatalf("persist: %v", err)
	}
	s.mu.Unlock()

	// A fresh process reading the same file.
	reopened, err := New(dir)
	if err != nil {
		t.Fatalf("New (reopen): %v", err)
	}
	// The bool reports "window fully warm and at least `limit` long", which is
	// not what these tests are about.
	got, _ := mustSnapshot(t, reopened, "INBOX", 10)
	if len(got) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(got))
	}
	if got[0].PGPVerified || got[0].PGPSigned || got[0].PGPSignerFingerprint != "" {
		t.Fatalf("a verdict computed under superseded binding rules replayed: %+v", got[0])
	}
	if got[0].Body != "" {
		t.Fatal("the warm body survived; the entry serves from cache and so never " +
			"re-verifies under the current rules")
	}
}

// A verdict stamped with the CURRENT rules must survive, or every restart would
// throw away every warm body on the instance.
func TestCurrentVerdictsSurviveALoad(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Upsert("INBOX", []Entry{signedEntry(1, PGPVerdictSchema)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	reopened, err := New(dir)
	if err != nil {
		t.Fatalf("New (reopen): %v", err)
	}
	// The bool reports "window fully warm and at least `limit` long", which is
	// not what these tests are about.
	got, _ := mustSnapshot(t, reopened, "INBOX", 10)
	if len(got) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(got))
	}
	if !got[0].PGPVerified || got[0].Body == "" {
		t.Fatalf("a current verdict was discarded: %+v", got[0])
	}
}

// Sync carries the verdict forward across a metadata-only change; the stamp has
// to travel with it, or the next load cannot tell an old verdict from a current
// one and the invalidation above becomes a no-op.
func TestSyncCarriesTheVerdictStamp(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("INBOX", []Entry{signedEntry(1, PGPVerdictSchema)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Same UID, flag flipped: a metadata-only change.
	if _, err := s.Sync("INBOX", 10, []Overview{ov(1, "subject", "read")}, 0); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got, _ := mustSnapshot(t, s, "INBOX", 10)
	if len(got) != 1 {
		t.Fatalf("Snapshot returned %d entries, want 1", len(got))
	}
	if got[0].PGPVerdictSchemaVersion != PGPVerdictSchema {
		t.Fatalf("Sync laundered the verdict into an unstamped entry (schema=%d); it would "+
			"then be indistinguishable from a current one", got[0].PGPVerdictSchemaVersion)
	}
}

// TestInvalidatePGPVerdictsClearsTheWindow is F11's other half: remediating the
// contact must remediate the mail. Removing or replacing a contact's key is the
// obvious response to a forged badge, and it left every verdict that key had
// already produced standing in the 5,000-entry window.
func TestInvalidatePGPVerdictsClearsTheWindow(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("INBOX", []Entry{signedEntry(1, PGPVerdictSchema)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := s.Upsert("Archive", []Entry{signedEntry(2, PGPVerdictSchema)}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := s.InvalidatePGPVerdicts(); err != nil {
		t.Fatalf("InvalidatePGPVerdicts: %v", err)
	}
	for _, mailbox := range []string{"INBOX", "Archive"} {
		got, _ := mustSnapshot(t, s, mailbox, 10)
		if len(got) != 1 {
			t.Fatalf("%s: Snapshot returned %d entries, want 1", mailbox, len(got))
		}
		if got[0].PGPVerified || got[0].PGPSignerFingerprint != "" {
			t.Fatalf("%s: the verdict survived the key change that invalidated it: %+v", mailbox, got[0])
		}
	}
}
