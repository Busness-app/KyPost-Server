package pgpmail

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// run-4 LOW-9: PickupRecord.Subject sat on disk in cleartext while the body
// next to it was sealed. The send path goes out of its way to avoid leaking the
// subject — sendPickupNotification deliberately mails
// pgpmail.OuterPlaceholderSubject instead of the real one, "since leaking the
// subject here would defeat subject protection" — and then the real subject was
// written unsealed to the same volume as the ciphertext it was protecting.
//
// For most mail the subject gives away the substance of the message, which is
// why the client-sealed mode puts it *inside* the sealed blob.

func TestPickupSubjectIsNotStoredInCleartext(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "pickup")
	store := NewPickupStore(base, filepath.Join(dir, "pickup.key"))

	const secretSubject = "Q3 layoffs: final list"
	id, err := store.Create("user-1", "r@example.com", secretSubject, "body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(base, id+".json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if strings.Contains(string(raw), secretSubject) {
		t.Fatalf("subject is on disk in cleartext:\n%s", raw)
	}
}

func TestPickupSubjectSurvivesSealRoundTrip(t *testing.T) {
	store := newTestPickupStore(t)
	const subject = "Q3 layoffs: final list"
	id, err := store.Create("user-1", "r@example.com", subject, "the body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, body, mode, err := store.View(id)
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if got != subject {
		t.Fatalf("subject = %q, want %q", got, subject)
	}
	if body != "the body" || mode != "plain" {
		t.Fatalf("unexpected body/mode: %q %q", body, mode)
	}
}

// Records written before the subject was sealed must keep working — they
// predate the change by at most one TTL, but silently losing their subject
// would be a worse outcome than the leak being fixed.
func TestPickupLegacyCleartextSubjectStillReadable(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "pickup")
	store := NewPickupStore(base, filepath.Join(dir, "pickup.key"))

	// Create normally, then rewrite the record in the legacy shape: cleartext
	// Subject, no SubjectEnc.
	id, err := store.Create("user-1", "r@example.com", "ignored", "the body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	path := filepath.Join(base, id+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var record PickupRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	record.SubjectEnc = nil
	record.Subject = "Legacy Subject"
	out, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	subject, body, _, err := store.View(id)
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if subject != "Legacy Subject" {
		t.Fatalf("subject = %q, want the legacy cleartext value", subject)
	}
	if body != "the body" {
		t.Fatalf("body = %q", body)
	}
}

// Consuming a record must leave nothing readable behind, sealed subject
// included.
func TestPickupTombstoneClearsSealedSubject(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "pickup")
	store := NewPickupStore(base, filepath.Join(dir, "pickup.key"))

	id, err := store.Create("user-1", "r@example.com", "Q3 layoffs", "body", "plain", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, _, err := store.View(id); err != nil {
		t.Fatalf("View: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(base, id+".json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var record PickupRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if record.SubjectEnc != nil {
		t.Fatal("tombstone still carries the sealed subject")
	}
	if record.Subject != "" {
		t.Fatal("tombstone still carries a cleartext subject")
	}
}
