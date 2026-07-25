package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/state"
)

func TestHandlePollNowRejectsNonAdmin(t *testing.T) {
	srv := newTestServer(t)
	_, regular := newTestUsers(t, srv)

	// No session at all -> 401.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/mail/poll-now", nil)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handlePollNow)(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: status = %d, want 401", rec.Code)
	}

	// Non-admin session -> 403.
	req = httptest.NewRequest(http.MethodPost, "/api/admin/mail/poll-now", nil)
	authRequestAs(srv, req, regular.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handlePollNow)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("as non-admin: status = %d, want 403", rec.Code)
	}
}

func TestHandlePollNowWithoutPollerConfigured(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/mail/poll-now", nil)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handlePollNow)(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no poller is wired, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlePollNowTriggersPoll(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	globalStore, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	classifierClient := classifier.NewHTTPClient("http://127.0.0.1:0", "", "", "", time.Second)
	wkdStore, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	poller, err := processor.New(config.Default(), srv.logger, globalStore, srv.users, srv.stateDir, srv.configDir, srv.health, classifierClient, wkdStore)
	if err != nil {
		t.Fatalf("processor.New: %v", err)
	}
	srv.SetPoller(poller)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/mail/poll-now", nil)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handlePollNow)(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body=%s", rec.Code, rec.Body.String())
	}
}
