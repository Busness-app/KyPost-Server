package contacts

import (
	"os"
	"path/filepath"
	"testing"
)

func batchTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	return s
}

func TestApplyBatchAppliesUpsertsAndDeletes(t *testing.T) {
	s := batchTestStore(t)

	seed, err := s.Upsert(Contact{FormattedName: "To Be Deleted"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	ops := []BatchOp{
		{Contact: Contact{FormattedName: "Alice"}},
		{Contact: Contact{FormattedName: "Bob"}},
		{Delete: true, UID: seed.UID},
		// A delete of an unknown UID is the client reporting a contact that is
		// already gone; the desired end state is satisfied, so it is not an error.
		{Delete: true, UID: "never-existed"},
	}
	if err := s.ApplyBatch(ops); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	list := mustList(t, s)
	if len(list) != 2 {
		t.Fatalf("List() = %d contacts, want 2: %+v", len(list), list)
	}
	names := map[string]bool{}
	for _, c := range list {
		names[c.FormattedName] = true
	}
	if !names["Alice"] || !names["Bob"] {
		t.Errorf("expected Alice and Bob, got %v", names)
	}
	// Get deliberately returns tombstones (sync clients need to observe the
	// deletion), so assert on the tombstone rather than on absence.
	deleted, ok := mustGet(t, s, seed.UID)
	if !ok {
		t.Fatal("the deleted contact's tombstone is gone; sync clients would never see the delete")
	}
	if !deleted.Deleted {
		t.Error("the contact was not tombstoned by the batch")
	}
	if deleted.FormattedName != "" {
		t.Errorf("tombstone still carries PII: FormattedName = %q", deleted.FormattedName)
	}
}

// TestApplyBatchWritesOnce is the performance half. The handler used to call
// Upsert per change, and each call rewrites the whole file with an fsync — so a
// large offline push from a phone was one full-file rewrite per contact.
func TestApplyBatchWritesOnce(t *testing.T) {
	s := batchTestStore(t)
	path := filepath.Join(s.baseDir, "contacts.json")

	// The file exists from New's seeding; capture its identity.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	ops := make([]BatchOp, 0, 200)
	for i := range 200 {
		ops = append(ops, BatchOp{Contact: Contact{FormattedName: string(rune('A'+i%26)) + "-name"}})
	}
	if err := s.ApplyBatch(ops); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}

	if got := len(mustList(t, s)); got != 200 {
		t.Fatalf("List() = %d, want 200", got)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if after.Size() <= before.Size() {
		t.Errorf("file did not grow (%d -> %d); the batch did not persist", before.Size(), after.Size())
	}

	// And the batch must be durable: a fresh Store over the same directory sees
	// all 200.
	reloaded, err := New(s.baseDir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := len(mustList(t, reloaded)); got != 200 {
		t.Errorf("reloaded store has %d contacts, want 200", got)
	}
}

// TestApplyBatchIsAllOrNothing is the correctness half.
//
// The per-change loop it replaced left earlier changes committed when a later
// one failed, and returned an error — after which the client resynced from its
// old base cursor and re-applied everything it had already applied. Either the
// whole batch lands or none of it does.
func TestApplyBatchIsAllOrNothing(t *testing.T) {
	s := batchTestStore(t)
	seed, err := s.Upsert(Contact{FormattedName: "Existing"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	beforeCount := len(mustList(t, s))
	beforeSeq := s.seq

	// Force the write to fail: replace contacts.json with a directory, which
	// makes the atomic rename onto it fail.
	path := filepath.Join(s.baseDir, "contacts.json")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err = s.ApplyBatch([]BatchOp{
		{Contact: Contact{FormattedName: "New One"}},
		{Delete: true, UID: seed.UID},
	})
	if err == nil {
		t.Fatal("ApplyBatch returned nil despite an unwritable store")
	}

	// The file is still unreadable, so the readers must refuse rather than
	// answer from the in-memory copy — that is the whole point of them
	// returning an error.
	if _, lerr := s.List(); lerr == nil {
		t.Error("List() answered from memory while contacts.json was unreadable")
	}
	if _, _, gerr := s.Get(seed.UID); gerr == nil {
		t.Error("Get() answered from memory while contacts.json was unreadable")
	}

	// In-memory state must be rolled back, not left ahead of the file. Checked
	// against the fields directly, since the readers now (correctly) refuse.
	if got := len(s.contacts); got != beforeCount {
		t.Errorf("in-memory contacts = %d after a failed batch, want %d: state is ahead of disk",
			got, beforeCount)
	}
	if s.seq != beforeSeq {
		t.Errorf("seq advanced to %d after a failed batch, want %d — revisions would be handed "+
			"out for changes that were never persisted", s.seq, beforeSeq)
	}
	kept := false
	for _, c := range s.contacts {
		if c.UID == seed.UID && !c.Deleted {
			kept = true
		}
	}
	if !kept {
		t.Error("the pre-existing contact was left tombstoned in memory after the batch failed")
	}
}

func TestApplyBatchEmptyIsNoop(t *testing.T) {
	s := batchTestStore(t)
	if err := s.ApplyBatch(nil); err != nil {
		t.Errorf("ApplyBatch(nil) = %v, want nil", err)
	}
	if err := s.ApplyBatch([]BatchOp{}); err != nil {
		t.Errorf("ApplyBatch([]) = %v, want nil", err)
	}
}
