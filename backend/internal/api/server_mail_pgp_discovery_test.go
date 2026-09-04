package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// TestBuildPlanUsesDiscovery asserts that buildPGPRecipientPlan routes
// through the resolver's discovery ladder (not just pinned contact keys):
// a recipient with no contact at all, but a usable key served over WKD,
// must land in the shared To/CC bucket rather than withoutKeyEmails.
func TestBuildPlanUsesDiscovery(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Erin", "erin@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("erin")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKey)
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
	resolver := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	plan := must1(buildPGPRecipientPlan(context.Background(), []string{"erin@example.com"}, nil, nil, resolver))

	if len(plan.toCCEmails) != 1 || plan.toCCEmails[0] != "erin@example.com" {
		t.Fatalf("expected erin in toCCEmails via WKD discovery, got toCC=%v withoutKey=%v", plan.toCCEmails, plan.withoutKeyEmails)
	}
	if len(plan.toCCKeys) != 1 || plan.toCCKeys[0] != id.ArmoredPublicKey {
		t.Fatalf("expected erin's WKD key in toCCKeys, got %v", plan.toCCKeys)
	}
	if len(plan.withoutKeyEmails) != 0 {
		t.Fatalf("expected no withoutKeyEmails, got %v", plan.withoutKeyEmails)
	}
}
