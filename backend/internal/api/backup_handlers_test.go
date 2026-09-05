package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kypost-server/backend/internal/backup"
	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/users"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRoutesRequireAdminCSRFAndCredential(t *testing.T) {
	srv := newTestServer(t)
	srv.backup, _ = backup.New(backup.Dirs{Config: srv.configDir, State: srv.stateDir, Secret: srv.configDir}, config.BackupConfig{Keep: 1}, srv.globalStore, "test")
	admin, err := srv.users.Create(context.Background(), "backup-admin", "long-password-for-backup", users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	user, err := srv.users.Create(context.Background(), "backup-user", "long-password-for-backup", users.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	adminToken, csrf := mintSessionForTest(srv, admin.ID)
	userToken, userCSRF := mintSessionForTest(srv, user.ID)
	routes := map[string]string{"run": "POST", "drill": "POST", "export-capsule": "POST", "pair-remote": "POST", "pin-key": "POST", "pairing": "DELETE", "schedule": "PUT"}
	for path, method := range routes {
		t.Run(path, func(t *testing.T) {
			srv.passwordChangeLockout.recordSuccess(clampLockoutKeyComponent(admin.ID) + "\x00" + lockoutKeyForIP("192.0.2.1"))
			for _, c := range []struct {
				token, csrf, body string
				want              int
			}{{"", "", "{}", 401}, {userToken, userCSRF, "{}", 403}, {adminToken, "", "{}", 403}, {adminToken, csrf, "{}", 401}} {
				req := httptest.NewRequest(method, "/api/admin/backup/"+path, bytes.NewBufferString(c.body))
				if c.token != "" {
					req.AddCookie(&http.Cookie{Name: "kypost_session", Value: c.token})
				}
				req.Header.Set("X-CSRF-Token", c.csrf)
				rec := httptest.NewRecorder()
				srv.routes().ServeHTTP(rec, req)
				if rec.Code != c.want {
					t.Fatalf("%s got %d want %d: %s", path, rec.Code, c.want, rec.Body.String())
				}
			}
		})
	}
}
func TestBackupPinScheduleAndAuditFailure(t *testing.T) {
	srv := newTestServer(t)
	srv.backup, _ = backup.New(backup.Dirs{Config: srv.configDir, State: srv.stateDir, Secret: srv.configDir}, config.BackupConfig{Keep: 1}, srv.globalStore, "test")
	const password = "long-password-for-backup"
	admin, err := srv.users.Create(context.Background(), "backup-admin", password, users.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	token, csrf := mintSessionForTest(srv, admin.ID)
	call := func(method, path string, body map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "/api/admin/backup/"+path, bytes.NewReader(raw))
		req.AddCookie(&http.Cookie{Name: "kypost_session", Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		return rec
	}
	key, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pin := map[string]any{"password": password, "publicKey": base64.StdEncoding.EncodeToString(key.Public().Bytes()), "threshold": 2, "totalShares": 3}
	if r := call("POST", "pin-key", pin); r.Code != 200 {
		t.Fatalf("pin %d: %s", r.Code, r.Body.String())
	}
	if r := call("PUT", "schedule", map[string]any{"password": password, "intervalSec": 900}); r.Code != 200 {
		t.Fatalf("schedule: %s", r.Body.String())
	}
	if r := call("PUT", "schedule", map[string]any{"password": password, "intervalSec": 1 << 55}); r.Code != 400 {
		t.Fatalf("overflow accepted: %d", r.Code)
	}
	rows, err := srv.globalStore.RecentBackupAudit(10)
	if err != nil || len(rows) < 4 {
		t.Fatalf("audit: %v %v", rows, err)
	}
	// Closing the audit store must prevent an unpair mutation before it starts.
	srv.globalStore.Close()
	if r := call("DELETE", "pairing", map[string]any{"password": password}); r.Code != 500 {
		t.Fatalf("audit outage: %d", r.Code)
	}
	if _, err := os.Stat(filepath.Join(srv.stateDir, "recovery.pub")); err != nil {
		t.Fatal(err)
	}
}
