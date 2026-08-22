package mailcache

import (
	"testing"
)

// The poller cannot classify PGP: fetchUnreadPage never calls
// pgpDetectSignature, and imapadapter.Message carries no signature field to
// copy. Its cache writes therefore say nothing about signatures — but an entry
// with PGPSigned=false was indistinguishable from one the API had classified as
// carrying none, so a poller write ERASED the API's marker.
//
// That matters more than it reads: PGPSigned is the sole trigger for the
// browser's signature verification, so erasing it does not merely drop a badge,
// it silently turns the check off and makes a signed message look exactly like
// an unsigned one.
func TestUnclassifiedWriteDoesNotErasePGPSigned(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The API classified this message: it carries a signature.
	classified := Entry{
		UID: 7, MessageID: "7", Subject: "Signed", Sender: "alice@example.com",
		AtUTC: "2026-08-11T10:00:00Z", Status: "unread",
		Body: "signed message text", PGPSigned: true, PGPClassified: true,
		PGPVerdictSchemaVersion: PGPVerdictSchema,
	}
	if err := s.Upsert("INBOX", []Entry{classified}); err != nil {
		t.Fatalf("Upsert classified: %v", err)
	}

	// The poller writes the same UID a tick later, with a body and no PGP
	// fields at all — exactly what mailCacheEntriesFromMessages produces.
	pollerWrite := Entry{
		UID: 7, MessageID: "7", Subject: "Signed", Sender: "alice@example.com",
		AtUTC: "2026-08-11T10:00:00Z", Status: "unread",
		Body: "signed message text",
	}
	if err := s.Upsert("INBOX", []Entry{pollerWrite}); err != nil {
		t.Fatalf("Upsert poller: %v", err)
	}

	got, _ := mustSnapshot(t, s, "INBOX", 1)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	if !got[0].PGPSigned {
		t.Fatal("a writer that never looked for a signature erased the marker of one that did")
	}
}

// The converse must still work: a writer that DID classify, and found no
// signature, has to be able to clear a stale marker.
func TestClassifiedWriteCanClearPGPSigned(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := s.Upsert("INBOX", []Entry{{
		UID: 7, MessageID: "7", Subject: "Was signed", Sender: "alice@example.com",
		AtUTC: "2026-08-11T10:00:00Z", Status: "unread",
		Body: "text", PGPSigned: true, PGPClassified: true,
		PGPVerdictSchemaVersion: PGPVerdictSchema,
	}}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := s.Upsert("INBOX", []Entry{{
		UID: 7, MessageID: "7", Subject: "Was signed", Sender: "alice@example.com",
		AtUTC: "2026-08-11T10:00:00Z", Status: "unread",
		Body: "text", PGPSigned: false, PGPClassified: true,
	}}); err != nil {
		t.Fatalf("Upsert reclassify: %v", err)
	}

	got, _ := mustSnapshot(t, s, "INBOX", 1)
	if len(got) != 1 {
		t.Fatalf("expected one entry, got %d", len(got))
	}
	if got[0].PGPSigned {
		t.Fatal("a writer that DID classify must be able to clear the marker")
	}
}
