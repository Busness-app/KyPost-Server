package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// TestConfigGETIsScopedForNonAdmins is run-8 finding F15.
//
// GET /api/config is withAuth while PUT is withAdmin, and the asymmetry is
// load-bearing — NotificationsPage is a non-admin page and consumes it. But the
// whole document went out. A non-admin learned classifier.baseUrl, frequently
// an internal-network host they have no other route to discover, and the exact
// redaction.patterns regexes stripped from mail before it reaches the model,
// which tells them precisely which PII shapes SURVIVE redaction.
func TestConfigGETIsScopedForNonAdmins(t *testing.T) {
	srv := newTestServer(t)
	srv.cfgMu.Lock()
	srv.cfg.Redaction.Patterns = []config.Pattern{{Name: "ssn", Regex: `\d{3}-\d{2}-\d{4}`}}
	srv.cfg.Labels.Allowlist = []string{"Important"}
	srv.cfgMu.Unlock()

	member, err := srv.users.Create(context.Background(), "member", "pw-member-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	get := func(userID string) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
		authRequestAs(srv, req, userID)
		rec := httptest.NewRecorder()
		srv.withAuth(srv.handleConfig)(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/config: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	nonAdmin := get(member.ID)
	redaction, _ := nonAdmin["redaction"].(map[string]any)
	if patterns, ok := redaction["patterns"].([]any); ok && len(patterns) > 0 {
		t.Fatalf("a non-admin was told which PII shapes are redacted, i.e. which ones survive: %v", patterns)
	}
	// What the non-admin page actually needs must still be there.
	labels, _ := nonAdmin["labels"].(map[string]any)
	if allow, _ := labels["allowlist"].([]any); len(allow) != 1 {
		t.Fatalf("the label allowlist NotificationsPage consumes was stripped: %v", labels)
	}

	admin := get(srv.mustBootstrapUserID(t))
	adminRedaction, _ := admin["redaction"].(map[string]any)
	if patterns, _ := adminRedaction["patterns"].([]any); len(patterns) != 1 {
		t.Fatalf("an admin lost the redaction patterns they administer: %v", adminRedaction)
	}
}

// TestAdminResetReportsDestroyingAClientKey is run-8 finding F13's surviving
// residue. The impact claim it arrived with — permanent, unwarned key loss —
// was disproved: docs/E2E_PGP.md states the behaviour, SecurityPage warns the
// USER in those terms, and two recovery paths work. What is real is that the
// ADMIN was told nothing. The reset UI was a bare prompt, the handler never
// inspected PGPProtection, and the audit line recorded only user_id — so the
// administrator could not know they were about to destroy data, and no record
// existed afterwards that they had.
func TestAdminResetReportsDestroyingAClientKey(t *testing.T) {
	srv := newTestServer(t)
	victim, err := srv.users.Create(context.Background(), "victim", "pw-victim-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	reset := func(userID, password string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"password": password})
		req := httptest.NewRequest(http.MethodPost, "/api/users/"+userID+"/reset-password", bytes.NewReader(body))
		req.SetPathValue("id", userID)
		authRequestAs(srv, req, srv.mustBootstrapUserID(t))
		rec := httptest.NewRecorder()
		srv.handleUsersResetPassword(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("reset-password: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// Server-custody (or no key): nothing is destroyed, so nothing is claimed.
	if got := reset(victim.ID, "a-temporary-password-1"); got["pgpKeyInaccessible"] != false {
		t.Fatalf("pgpKeyInaccessible=%v for an account with no client-protected key", got["pgpKeyInaccessible"])
	}

	if _, err := srv.users.SetPGPIdentityClientProtected(victim.ID, "FPR", "KID", "PUB",
		`{"v":2,"ciphertext":"VICTIM"}`, "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	if got := reset(victim.ID, "a-temporary-password-2"); got["pgpKeyInaccessible"] != true {
		t.Fatalf("an admin reset destroyed a client-protected key and reported nothing (%v); "+
			"the admin has no way to know, before or after", got["pgpKeyInaccessible"])
	}
}
