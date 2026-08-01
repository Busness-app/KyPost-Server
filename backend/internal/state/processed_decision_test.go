package state

import "testing"

// RecordProcessedDecision exists because "recorded in the audit log" and
// "retired from the poll queue" are one state change written to two tables.
// Issued separately they could diverge in either direction: a message retired
// with no record of what happened to it, or a record without the marker, which
// makes the next tick reprocess the message and notify every paired device a
// second time.

func TestRecordProcessedDecisionWritesBoth(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	decision := Decision{MessageID: "42", Sender: "a@example.com", Status: "applied", Label: "Updates"}
	if err := store.RecordProcessedDecision(decision); err != nil {
		t.Fatalf("RecordProcessedDecision: %v", err)
	}

	seen, err := store.Seen("42")
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if !seen {
		t.Fatal("message was not retired, so the next tick would classify and notify for it again")
	}
	decisions, err := store.DecisionsStrict(0)
	if err != nil {
		t.Fatalf("DecisionsStrict: %v", err)
	}
	if len(decisions) != 1 || decisions[0].MessageID != "42" || decisions[0].Label != "Updates" {
		t.Fatalf("decisions = %+v, want one row for message 42", decisions)
	}
}

// A failed write must leave NEITHER side, not one — that is the whole point of
// the transaction, and the two orders it replaced each left a different one.
//
// The failure is induced by closing the database, which is the one way to make
// a write fail deterministically without reaching into SQLite. It stands in for
// the real cause: SQLITE_BUSY past the busy_timeout, which is reachable because
// the api and daemon processes contend on this file.
func TestRecordProcessedDecisionLeavesNeitherSideOnFailure(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.RecordProcessedDecision(Decision{MessageID: "7", Status: "applied"}); err != nil {
		t.Fatalf("RecordProcessedDecision: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.RecordProcessedDecision(Decision{MessageID: "8", Status: "applied"}); err == nil {
		t.Fatal("expected an error writing to a closed store")
	}

	reopened, err := New(store.baseDir)
	if err != nil {
		t.Fatalf("New (reopen): %v", err)
	}
	decisions, err := reopened.DecisionsStrict(0)
	if err != nil {
		t.Fatalf("DecisionsStrict: %v", err)
	}
	for _, d := range decisions {
		if d.MessageID == "8" {
			t.Fatal("a decision was recorded for a message that was never retired")
		}
	}
	seen, err := reopened.Seen("8")
	if err != nil {
		t.Fatalf("Seen: %v", err)
	}
	if seen {
		t.Fatal("a message was retired with no decision recorded for it")
	}
}
