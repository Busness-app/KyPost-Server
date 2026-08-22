package mailcache

import "testing"

// Sync's carry-forward branch runs precisely BECAUSE the envelope differs, and
// it cannot tell "same message, flag flipped" from "this UID now names a
// different message". Nothing in this codebase tracks UIDVALIDITY, the IMAP
// value whose whole purpose is to say UIDs were renumbered — so after a mailbox
// is deleted and recreated, restored from backup, or migrated between
// providers, the branch grafted a previous message's body and signature verdict
// onto a different message's envelope.
//
// A flag flip changes neither sender nor timestamp, so requiring those to match
// separates the two cases without needing UIDVALIDITY plumbed through.
func TestSyncDoesNotGraftAVerdictOntoADifferentMessage(t *testing.T) {
	s := newTestStore(t)

	warm := Entry{
		UID: 1, MessageID: "1", Subject: "Q3 board packet", Sender: "alice@example.com",
		AtUTC: "2026-08-01T10:00:00Z", Status: "unread",
		Body: "the board packet, in full", PGPSigned: true, PGPVerified: true,
		PGPSignerFingerprint: "A11CE", PGPClassified: true,
		PGPVerdictSchemaVersion: PGPVerdictSchema,
	}
	if err := s.Upsert("INBOX", []Entry{warm}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// UIDVALIDITY rolled: UID 1 is now somebody else's message entirely.
	_, err := s.Sync("INBOX", 10, []Overview{{
		UID: 1, Subject: "Re: invoice", Sender: "eve@evil.example",
		AtUTC: "2026-08-11T09:00:00Z", Status: "unread",
	}}, 0)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got, _ := mustSnapshot(t, s, "INBOX", 1)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	e := got[0]
	if e.PGPVerified || e.PGPSigned || e.PGPSignerFingerprint != "" {
		t.Fatalf("a verdict for Alice's message survived onto Eve's: signed=%v verified=%v fp=%q",
			e.PGPSigned, e.PGPVerified, e.PGPSignerFingerprint)
	}
	if e.Body != "" {
		t.Fatalf("Alice's plaintext survived onto Eve's envelope: %q", e.Body)
	}
}

// The case the carry-forward exists for must keep working: marking a message
// read changes its status and nothing else, and must not cost a body re-fetch
// or reset the badge.
func TestSyncKeepsTheVerdictAcrossAFlagFlip(t *testing.T) {
	s := newTestStore(t)

	warm := Entry{
		UID: 1, MessageID: "1", Subject: "Q3 board packet", Sender: "alice@example.com",
		AtUTC: "2026-08-01T10:00:00Z", Status: "unread",
		Body: "the board packet, in full", PGPSigned: true, PGPVerified: true,
		PGPSignerFingerprint: "A11CE", PGPClassified: true,
		PGPVerdictSchemaVersion: PGPVerdictSchema,
	}
	if err := s.Upsert("INBOX", []Entry{warm}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if _, err := s.Sync("INBOX", 10, []Overview{{
		UID: 1, Subject: "Q3 board packet", Sender: "alice@example.com",
		AtUTC: "2026-08-01T10:00:00Z", Status: "read",
	}}, 0); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	got, _ := mustSnapshot(t, s, "INBOX", 1)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	e := got[0]
	if !e.PGPVerified || e.Body == "" {
		t.Fatalf("a flag flip must not cost the verdict or the warm body: verified=%v body=%q",
			e.PGPVerified, e.Body)
	}
	if e.Status != "read" {
		t.Fatalf("the new status should have been adopted, got %q", e.Status)
	}
}
