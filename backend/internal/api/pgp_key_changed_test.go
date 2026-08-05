package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

// TestKeyChangedRecipientIsNotTreatedAsKeyless pins the distinction the
// resolver draws and the send path threw away.
//
// When a contact's pinned fingerprint no longer matches what discovery returns,
// resolve() refuses to substitute the new key and reports tierKeyChanged with
// Usable:false — the TOFU control firing, and the one signal that a key
// substitution may be in progress. buildPGPRecipientPlan collapsed the result to
// (Armored, Usable) and discarded the tier, so a broken pin became
// indistinguishable from a recipient who never had a key.
//
// That matters because "no key on file" is exactly what AllowPickupFallback
// covers: the message plaintext is sealed server-side for seven days and an
// unauthenticated one-time link is mailed in the clear — to an attacker who, in
// the scenario that produced the broken pin, is already positioned on that
// domain's mail path.
//
// The browser path refuses this and says why: "A BROKEN PIN IS NOT A MISSING
// KEY, and it must not be reported as one" (frontend/src/App.tsx).
func TestKeyChangedRecipientIsNotTreatedAsKeyless(t *testing.T) {
	allowLoopbackOutboundForTest(t)

	// Same fixture shape as TestResolveTOFUMismatchDoesNotSwitch: the contact is
	// pinned to A's now-expired key, and WKD serves a different key (B) for the
	// same address.
	armoredA, fpA := generateExpiredIdentity(t, "Alice A", "alice@example.com")
	idB, err := pgpmail.GenerateIdentity("Alice B", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity B: %v", err)
	}
	keyB, _ := crypto.NewKeyFromArmored(idB.ArmoredPublicKey)
	binKeyB, _ := keyB.GetPublicKey()
	hu := wkdHashLocalPart("alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKeyB)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName:     "Alice",
		Emails:            []contacts.ContactValue{{Value: "alice@example.com"}},
		PGPKey:            armoredA,
		PGPKeyFingerprint: fpA,
		PGPKeySource:      contacts.PGPSourceManual,
		PGPKeyVerified:    true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	resolver := &keyResolver{
		store:    store,
		settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true},
		discover: true,
	}
	plan := buildPGPRecipientPlan(context.Background(),
		[]string{"alice@example.com"}, nil, nil, resolver)

	for _, e := range plan.withoutKeyEmails {
		if strings.EqualFold(e, "alice@example.com") {
			t.Fatal("a recipient whose key pin broke was folded into withoutKeyEmails, " +
				"where the pickup fallback mails their message in the clear")
		}
	}
	if len(plan.keyChangedEmails) != 1 {
		t.Fatalf("keyChangedEmails = %v, want the recipient reported separately",
			plan.keyChangedEmails)
	}
}
