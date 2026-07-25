package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/users"
)

// TestConfigPutRequiresAdmin is a regression test: PUT /api/config used to be
// reachable by any authenticated user, not just admins, letting a non-admin
// account overwrite install-wide settings (redaction patterns, rate limits,
// label allowlist) that only the Classifier sub-struct was ever meant to gate.
func TestConfigPutRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, regular := newTestUsers(t, srv)
	srv.configPath = t.TempDir() + "/config.yaml"

	srv.mu.Lock()
	originalPatternCount := len(srv.cfg.Redaction.Patterns)
	srv.mu.Unlock()
	if originalPatternCount == 0 {
		t.Fatal("expected the default config to seed at least one redaction pattern")
	}

	next := config.Default()
	next.Redaction.Patterns = nil // what a malicious/careless non-admin PUT would try to do
	body, _ := json.Marshal(next)

	// Non-admin PUT is rejected outright, before ever reaching handleConfig.
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, regular.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin PUT /api/config: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}

	srv.mu.Lock()
	stillIntact := len(srv.cfg.Redaction.Patterns)
	srv.mu.Unlock()
	if stillIntact != originalPatternCount {
		t.Fatalf("redaction patterns were modified by a rejected non-admin PUT: got %d, want %d", stillIntact, originalPatternCount)
	}

	// The same payload from an admin is accepted.
	req = httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin PUT /api/config: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestConfigGetMasksLLMAPIKeyForNonAdmin is a regression test: the remote-LLM
// API key is admin-only to edit (the frontend hides the "llm" tab from
// non-admins), but GET /api/config previously returned it in plaintext to
// any authenticated session regardless of role.
func TestConfigGetMasksLLMAPIKeyForNonAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, regular := newTestUsers(t, srv)

	srv.mu.Lock()
	srv.cfg.Classifier.APIKey = "sk-super-secret-key"
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authRequestAs(srv, req, regular.ID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("non-admin GET /api/config: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var nonAdminCfg config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &nonAdminCfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if nonAdminCfg.Classifier.APIKey != "" {
		t.Fatalf("non-admin GET /api/config leaked the LLM API key: %q", nonAdminCfg.Classifier.APIKey)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	var adminCfg config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &adminCfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if adminCfg.Classifier.APIKey != "" {
		t.Fatalf("admin GET /api/config leaked the LLM API key: %q", adminCfg.Classifier.APIKey)
	}
}

// TestConfigGetNeverEchoesAPIKeyButReportsAPIKeySet is a regression test for
// the secret-echo finding: handleConfig used to hand admins the real,
// plaintext Classifier.APIKey on every GET. Now GET must never echo the
// live key back to anyone, admin included, while still telling the caller
// (via the computed apiKeySet field) whether a key is configured — and it
// must never mutate the live in-memory config in the process.
func TestConfigGetNeverEchoesAPIKeyButReportsAPIKeySet(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	srv.mu.Lock()
	srv.cfg.Classifier.APIKey = "sk-super-secret-key"
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /api/config: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	classifier, ok := raw["classifier"].(map[string]any)
	if !ok {
		t.Fatalf("response missing classifier object: %v", raw)
	}
	if apiKey, _ := classifier["apiKey"].(string); apiKey != "" {
		t.Fatalf("admin GET /api/config leaked the LLM API key: %q", apiKey)
	}
	if apiKeySet, _ := classifier["apiKeySet"].(bool); !apiKeySet {
		t.Fatalf("apiKeySet = %v, want true when a key is configured", classifier["apiKeySet"])
	}

	// The live in-memory config must never be mutated by serving a GET.
	srv.mu.RLock()
	liveKey := srv.cfg.Classifier.APIKey
	srv.mu.RUnlock()
	if liveKey != "sk-super-secret-key" {
		t.Fatalf("GET /api/config mutated the live config's APIKey: got %q", liveKey)
	}

	// With no key configured, apiKeySet must report false.
	srv.mu.Lock()
	srv.cfg.Classifier.APIKey = ""
	srv.mu.Unlock()
	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	raw = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	classifier, _ = raw["classifier"].(map[string]any)
	if apiKeySet, _ := classifier["apiKeySet"].(bool); apiKeySet {
		t.Fatalf("apiKeySet = %v, want false when no key is configured", classifier["apiKeySet"])
	}
}

// TestConfigPutEmptyAPIKeyPreservesExisting is a regression test: PUTting a
// config with an empty Classifier.APIKey (as any GET response now always
// has, since the key is never echoed) must not wipe out a previously
// configured key.
func TestConfigPutEmptyAPIKeyPreservesExisting(t *testing.T) {
	srv := newTestServer(t)
	srv.configPath = t.TempDir() + "/config.yaml"
	admin, _ := newTestUsers(t, srv)

	srv.mu.Lock()
	srv.cfg.Classifier.APIKey = "sk-existing-key"
	srv.mu.Unlock()

	next := config.Default()
	next.Classifier.APIKey = "" // as a naive round-trip PUT would send
	next.Classifier.BaseURL = "http://localhost:1234"
	body, _ := json.Marshal(next)

	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	srv.mu.RLock()
	gotKey := srv.cfg.Classifier.APIKey
	gotBaseURL := srv.cfg.Classifier.BaseURL
	srv.mu.RUnlock()
	if gotKey != "sk-existing-key" {
		t.Fatalf("PUT with empty apiKey wiped the existing key: got %q, want %q", gotKey, "sk-existing-key")
	}
	if gotBaseURL != "http://localhost:1234" {
		t.Fatalf("PUT did not apply the other classifier field: got %q", gotBaseURL)
	}
}

// TestConfigRoundTripDoesNotCorruptChangeDetection is a regression test: a
// naive client that GETs the config and PUTs it straight back (unchanged
// from the user's perspective) must not be misread as a Classifier change.
// Two ways this could go wrong: apiKeySet=true echoed from the GET response
// could itself look like a diff against the live config's always-false
// apiKeySet, and the GET-zeroed apiKey="" could look like the live key was
// cleared. Either would spuriously flip classifierChanged, which gates a
// 403 for non-admins and triggers classifier.ResetWarmupState().
func TestConfigRoundTripDoesNotCorruptChangeDetection(t *testing.T) {
	srv := newTestServer(t)
	srv.configPath = t.TempDir() + "/config.yaml"
	admin, regular := newTestUsers(t, srv)

	srv.mu.Lock()
	srv.cfg.Classifier.APIKey = "sk-existing-key"
	srv.mu.Unlock()

	// Fetch the config the way the frontend would.
	req := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	classifier := raw["classifier"].(map[string]any)
	if classifier["apiKeySet"] != true {
		t.Fatalf("expected apiKeySet=true in the GET response, got %v", classifier["apiKeySet"])
	}
	if classifier["apiKey"] != "" {
		t.Fatalf("expected apiKey to be zeroed in the GET response, got %v", classifier["apiKey"])
	}

	// PUT it straight back, unmodified, as a non-admin. If the round-trip
	// spuriously registered as a Classifier change, this would 403.
	body, _ := json.Marshal(raw)
	req = httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	authRequestAs(srv, req, regular.ID)
	rec = httptest.NewRecorder()
	srv.withAuth(srv.handleConfig)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("non-admin round-trip PUT: status = %d, want 200 (change-detection falsely triggered), body=%s", rec.Code, rec.Body.String())
	}

	srv.mu.RLock()
	gotKey := srv.cfg.Classifier.APIKey
	srv.mu.RUnlock()
	if gotKey != "sk-existing-key" {
		t.Fatalf("round-trip PUT altered the existing key: got %q", gotKey)
	}
}

// TestChangePasswordRevokesOtherSessions is a regression test: changing a
// password used to leave every other live session for the account (e.g. a
// stolen cookie) valid for up to the remaining 24h sliding-expiry window.
// The session that performs the change itself must stay logged in.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create("heidi", "old-password-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	changingToken := "changing-session-token"
	otherToken := "other-stolen-session-token"
	srv.mu.Lock()
	srv.sessions[changingToken] = Session{UserID: u.ID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-a"}
	srv.sessions[otherToken] = Session{UserID: u.ID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-b"}
	srv.mu.Unlock()

	body, _ := json.Marshal(map[string]string{"oldPassword": "old-password-testpassword", "newPassword": "new-password-testpassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: "kypost_session", Value: changingToken})
	req.Header.Set("X-CSRF-Token", "csrf-a")
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleChangePassword)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change password: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	srv.mu.Lock()
	_, changingStillLive := srv.sessions[changingToken]
	_, otherStillLive := srv.sessions[otherToken]
	srv.mu.Unlock()
	if !changingStillLive {
		t.Error("the session that performed the password change was itself revoked; it should stay logged in")
	}
	if otherStillLive {
		t.Error("a different live session for the same account survived a password change; it should have been revoked")
	}
}

// TestAdminResetPasswordRevokesTargetSessions mirrors
// TestChangePasswordRevokesOtherSessions for the admin-triggered path: none
// of the target account's sessions belong to the admin, so all of them (not
// "all but one") must be revoked.
func TestAdminResetPasswordRevokesTargetSessions(t *testing.T) {
	srv := newTestServer(t)
	admin, target := newTestUsers(t, srv)

	targetToken := "target-session-token"
	srv.mu.Lock()
	srv.sessions[targetToken] = Session{UserID: target.ID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: "csrf-target"}
	srv.mu.Unlock()

	body, _ := json.Marshal(map[string]string{"password": "brand-new-password"})
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+target.ID+"/reset-password", bytes.NewReader(body))
	req.SetPathValue("id", target.ID)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersResetPassword)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin reset password: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	srv.mu.Lock()
	_, targetStillLive := srv.sessions[targetToken]
	srv.mu.Unlock()
	if targetStillLive {
		t.Error("target's session survived an admin password reset; it should have been revoked")
	}
}
