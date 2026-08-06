package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

// newTestUsers returns the bootstrap admin plus a fresh non-admin user.
func newTestUsers(t *testing.T, srv *Server) (admin users.User, regular users.User) {
	t.Helper()
	all, err := srv.users.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("expected exactly one bootstrap user, got %+v err=%v", all, err)
	}
	admin = all[0]
	regular, err = srv.users.Create(context.Background(), "regular", "regular-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return admin, regular
}

func TestAdminRoutesRejectNonAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin, regular := newTestUsers(t, srv)

	adminOnly := map[string]http.HandlerFunc{
		"GET /api/logs":           srv.withAdmin(srv.handleLogs),
		"GET /api/logs/list":      srv.withAdmin(srv.handleLogsList),
		"GET /api/server/version": srv.withAdmin(srv.handleServerVersion),
		"GET /api/users":          srv.withAdmin(srv.handleUsersList),
		"POST /api/users":         srv.withAdmin(srv.handleUsersCreate),
		// A non-admin must not be able to reach handleConfig's PUT branch at
		// all (see server_config_test.go for the full, more direct
		// regression: a non-admin PUT that previously succeeded and could
		// rewrite install-wide redaction/rate-limit/label settings).
		"PUT /api/config": srv.withAdmin(srv.handleConfig),
	}

	for name, handler := range adminOnly {
		// No session at all -> 401.
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: status = %d, want 401", name, rec.Code)
		}

		// Non-admin session -> 403.
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		authRequestAs(srv, req, regular.ID)
		rec = httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s as non-admin: status = %d, want 403", name, rec.Code)
		}
	}

	// Admin session reaches the handler (users list responds 200).
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersList)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("users list as admin: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Users []users.Public `json:"users"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal users list: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("len(users) = %d, want 2", len(resp.Users))
	}
	for _, u := range resp.Users {
		if u.ID == "" || u.Username == "" {
			t.Fatalf("unexpected public user payload: %+v", u)
		}
	}
}

func TestUserLifecycleEndpoints(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	// Create.
	body, _ := json.Marshal(map[string]string{"username": "carol", "password": "carol-password", "role": "user"})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersCreate)(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created users.Public
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created user: %v", err)
	}
	if !created.MustChangePassword {
		t.Fatalf("expected newly created user to require a password change")
	}

	// Duplicate username -> 409.
	req = httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersCreate)(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create: status = %d, want 409", rec.Code)
	}

	// Promote to admin via PUT /api/users/{id}.
	body, _ = json.Marshal(map[string]string{"role": "admin"})
	req = httptest.NewRequest(http.MethodPut, "/api/users/"+created.ID, bytes.NewReader(body))
	req.SetPathValue("id", created.ID)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersUpdate)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("promote: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// Reset password.
	body, _ = json.Marshal(map[string]string{"password": "temp-password-1234"})
	req = httptest.NewRequest(http.MethodPost, "/api/users/"+created.ID+"/reset-password", bytes.NewReader(body))
	req.SetPathValue("id", created.ID)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersResetPassword)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset password: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got, _ := srv.users.Get(created.ID)
	okPassword, _ := users.VerifyPassword(context.Background(), got, "temp-password-1234")
	if !got.MustChangePassword || !okPassword {
		t.Fatalf("unexpected state after reset: %+v", got)
	}

	// Deactivate, then reactivate.
	req = httptest.NewRequest(http.MethodPost, "/api/users/"+created.ID+"/deactivate", nil)
	req.SetPathValue("id", created.ID)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersDeactivate)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/users/"+created.ID+"/reactivate", nil)
	req.SetPathValue("id", created.ID)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersReactivate)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("reactivate: status = %d, body=%s", rec.Code, rec.Body.String())
	}

	// Unknown id -> 404.
	req = httptest.NewRequest(http.MethodPost, "/api/users/nope/deactivate", nil)
	req.SetPathValue("id", "nope")
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersDeactivate)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deactivate unknown: status = %d, want 404", rec.Code)
	}
}

func TestLastActiveAdminIsProtected(t *testing.T) {
	srv := newTestServer(t)
	admin, _ := newTestUsers(t, srv)

	// Deactivating the only admin is refused.
	req := httptest.NewRequest(http.MethodPost, "/api/users/"+admin.ID+"/deactivate", nil)
	req.SetPathValue("id", admin.ID)
	authRequestAs(srv, req, admin.ID)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersDeactivate)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("deactivate last admin: status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	// Demoting the only admin is refused.
	body, _ := json.Marshal(map[string]string{"role": "user"})
	req = httptest.NewRequest(http.MethodPut, "/api/users/"+admin.ID, bytes.NewReader(body))
	req.SetPathValue("id", admin.ID)
	authRequestAs(srv, req, admin.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersUpdate)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("demote last admin: status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	// With a second active admin, deactivating the first is allowed.
	second, err := srv.users.Create(context.Background(), "second-admin", "password-two-testpassword", users.RoleAdmin)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/users/"+admin.ID+"/deactivate", nil)
	req.SetPathValue("id", admin.ID)
	authRequestAs(srv, req, second.ID)
	rec = httptest.NewRecorder()
	srv.withAdmin(srv.handleUsersDeactivate)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate with second admin present: status = %d, body=%s", rec.Code, rec.Body.String())
	}
}
