package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// TestHandleClassifierTestCooldownBlocksRapidRequests confirms the cooldown
// gate fires before the handler ever reaches the classifier network call:
// two back-to-back admin requests against an (intentionally unreachable)
// classifier backend must not both attempt classification — the second must
// be rejected with 429 purely on cooldown grounds.
func TestHandleClassifierTestCooldownBlocksRapidRequests(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	srv.mu.Lock()
	srv.cfg.Classifier.BaseURL = "http://127.0.0.1:1" // nothing listens here; connection refused fast
	srv.mu.Unlock()

	body := []byte(`{"prompt":"test"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/classifier/test", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleClassifierTest)(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("first request unexpectedly hit the cooldown: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/classifier/test", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleClassifierTest)(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request within the cooldown window: status = %d, want 429, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleClassifierTestCooldownIsPerAdmin confirms one admin's cooldown
// doesn't block a different admin from testing connectivity.
func TestHandleClassifierTestCooldownIsPerAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)
	secondAdmin, err := srv.users.Create("admin2", "pw-admin2-testpassword", users.RoleAdmin)
	if err != nil {
		t.Fatalf("Create second admin: %v", err)
	}

	srv.mu.Lock()
	srv.cfg.Classifier.BaseURL = "http://127.0.0.1:1"
	srv.mu.Unlock()

	body := []byte(`{"prompt":"test"}`)

	req := httptest.NewRequest(http.MethodPost, "/api/classifier/test", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleClassifierTest)(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("first admin's request unexpectedly hit the cooldown: status = %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/classifier/test", bytes.NewReader(body))
	authRequestAs(srv, req, secondAdmin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleClassifierTest)(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("second admin's request should not be blocked by the first admin's cooldown: status = %d", rec.Code)
	}
}
