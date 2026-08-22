package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
)

// run-4 M3, at the layer the finding was reproduced on. The store-level fix is
// covered in internal/contacts; this proves the sync endpoint — whose payload
// type has no field for PGP provenance at all — no longer strips the pin.
//
// It matters because the resolver's tierKeyChanged refusal is gated on a
// non-empty pin, so a stripped pin lets the next WKD result for that address be
// auto-trusted and used to encrypt.
func TestContactsSyncPushKeepsPGPKeyPin(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "pin-sync-device")

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	const armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----"
	seeded, err := store.Upsert(contacts.Contact{
		FormattedName:     "Bob",
		PGPKey:            armored,
		PGPKeyFingerprint: "AAAA1111BBBB2222",
		PGPKeySource:      "manual",
		PGPKeyVerified:    true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The phone pushes back an ordinary edit: same key, no provenance, because
	// its payload type has nowhere to put it.
	body, _ := json.Marshal(map[string]any{
		"changes": []map[string]any{{
			"uid":    seeded.UID,
			"fn":     "Bob Smith",
			"pgpKey": armored,
		}},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/sync", bytes.NewReader(body))
	setDeviceHeaders(req, deviceID, deviceSecret)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	got, ok := must2(store.Get(seeded.UID))
	if !ok {
		t.Fatal("contact not found after sync")
	}
	if got.FormattedName != "Bob Smith" {
		t.Fatalf("the sync did not apply: %q", got.FormattedName)
	}
	if got.PGPKeyFingerprint != "AAAA1111BBBB2222" {
		t.Fatalf("one routine sync stripped the TOFU pin: %q", got.PGPKeyFingerprint)
	}
	if got.PGPKeySource != "manual" || !got.PGPKeyVerified {
		t.Fatalf("sync stripped key provenance: source=%q verified=%v", got.PGPKeySource, got.PGPKeyVerified)
	}
}
