package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpmail"
)

// TestContactCreateBackfillsPGPKeyFingerprint drives POST /api/contacts with
// a manually-entered armored key and no fingerprint (the client payload never
// carries one) and confirms the handler backfills PGPKeyFingerprint so the
// resolver's TOFU key_changed guard — gated on pinnedFP != "" — can protect
// this key too.
func TestContactCreateBackfillsPGPKeyFingerprint(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	payload := map[string]any{
		"fn":     "Alice",
		"emails": []map[string]string{{"value": "alice@example.com"}},
		"pgpKey": id.ArmoredPublicKey,
	}
	rec := doJSONAuth(srv, srv.withAuth(srv.handleContacts), http.MethodPost, "/api/contacts", payload, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var created contacts.Contact
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created contact: %v; body=%s", err, rec.Body.String())
	}
	if created.PGPKeyFingerprint == "" {
		t.Fatalf("expected PGPKeyFingerprint to be backfilled, got empty; body=%s", rec.Body.String())
	}
	if created.PGPKeyFingerprint != id.Fingerprint {
		t.Fatalf("PGPKeyFingerprint = %q, want %q", created.PGPKeyFingerprint, id.Fingerprint)
	}
	// Provenance fields must not be touched by the backfill.
	if created.PGPKeySource != "" || created.PGPKeyVerified {
		t.Fatalf("backfill should not set source/verified: source=%q verified=%v", created.PGPKeySource, created.PGPKeyVerified)
	}

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	stored, ok := store.Get(created.UID)
	if !ok {
		t.Fatalf("contact %s not found in store", created.UID)
	}
	if stored.PGPKeyFingerprint != id.Fingerprint {
		t.Fatalf("stored PGPKeyFingerprint = %q, want %q", stored.PGPKeyFingerprint, id.Fingerprint)
	}
}

// TestContactUpdateBackfillsPGPKeyFingerprint drives PUT
// /api/contacts/{id} against a legacy contact that already carries an
// armored key but no fingerprint (as if it predates fingerprint pinning) and
// confirms an unrelated update backfills the fingerprint without touching
// PGPKeySource/PGPKeyVerified.
func TestContactUpdateBackfillsPGPKeyFingerprint(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)

	id, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
		PGPKey:        id.ArmoredPublicKey,
		PGPKeySource:  "manual",
		// PGPKeyFingerprint intentionally left empty, simulating a legacy record.
	})
	if err != nil {
		t.Fatalf("Upsert existing: %v", err)
	}
	if existing.PGPKeyFingerprint != "" {
		t.Fatalf("test setup: expected empty fingerprint, got %q", existing.PGPKeyFingerprint)
	}

	payload := map[string]any{
		"fn":     "Bob Updated",
		"emails": []map[string]string{{"value": "bob@example.com"}},
		"pgpKey": id.ArmoredPublicKey,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/contacts/"+existing.UID, bytes.NewReader(body))
	req.SetPathValue("id", existing.UID)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactByID)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var updated contacts.Contact
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal updated contact: %v; body=%s", err, rec.Body.String())
	}
	if updated.PGPKeyFingerprint != id.Fingerprint {
		t.Fatalf("PGPKeyFingerprint = %q, want %q", updated.PGPKeyFingerprint, id.Fingerprint)
	}
	if updated.PGPKeySource != "" {
		t.Fatalf("backfill should not set PGPKeySource, got %q", updated.PGPKeySource)
	}
}
