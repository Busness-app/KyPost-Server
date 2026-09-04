package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/adapters/classifier"
	"github.com/Busness-app/kypost-server/backend/internal/ollamaupdate"
)

func TestHandleOllamaVersionBeforeFirstCheck(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ollama/version", nil)
	srv.handleOllamaVersion(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d before any version check has run", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleOllamaVersionReportsUpgradeAvailable(t *testing.T) {
	srv := newTestServer(t)
	srv.setOllamaStatus(ollamaVersionStatus{
		installedVersion: "0.32.1",
		latestVersion:    "0.33.0",
		upgradeAvailable: true,
		checkedAt:        time.Now().UTC(),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ollama/version", nil)
	srv.handleOllamaVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["installedVersion"] != "0.32.1" || resp["latestVersion"] != "0.33.0" {
		t.Fatalf("unexpected version fields: %+v", resp)
	}
	if upgrade, _ := resp["upgradeAvailable"].(bool); !upgrade {
		t.Fatalf("upgradeAvailable = %v, want true", resp["upgradeAvailable"])
	}
}

// TestRefreshOllamaVersionStatusDetectsUpgradeAndDedupesNotification drives
// refreshOllamaVersionStatus against a fake Ollama server (via the real
// classifier.HTTPClient) and a fake GitHub releases endpoint, and confirms:
// the cached status reflects the comparison, the global state store records
// exactly one "notify" transition for a given upstream version, and a
// second check for the same upstream version does not notify again.
func TestRefreshOllamaVersionStatusDetectsUpgradeAndDedupesNotification(t *testing.T) {
	srv := newTestServer(t)

	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.32.1"}`))
	}))
	defer ollamaSrv.Close()
	srv.SetClassifier(classifier.NewHTTPClient(ollamaSrv.URL, "", "", "", 0))

	githubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// run-4 N1: the checker reads the /releases LIST and skips anything
		// inside the soak window, so the fixture is a list and the release is
		// backdated well past it. A fresh release would correctly report
		// nothing — that is the fix, not a broken fixture.
		published := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
		_, _ = w.Write([]byte(`[{"tag_name":"v0.33.0","published_at":"` + published + `"}]`))
	}))
	defer githubSrv.Close()
	restoreReleasesURL := setOllamaReleasesURLForTest(t, githubSrv.URL)
	defer restoreReleasesURL()

	srv.refreshOllamaVersionStatus(context.Background())

	status := srv.getOllamaStatus()
	if status.installedVersion != "0.32.1" || status.latestVersion != "0.33.0" || !status.upgradeAvailable {
		t.Fatalf("unexpected status after first check: %+v", status)
	}

	notified, err := srv.globalStore.SetOllamaUpdateNotified("0.33.0")
	if err != nil {
		t.Fatalf("SetOllamaUpdateNotified: %v", err)
	}
	if notified {
		t.Fatal("refreshOllamaVersionStatus should already have consumed the notify transition for 0.33.0")
	}
}

// setOllamaReleasesURLForTest points ollamaupdate.LatestVersion at a test
// server for the duration of the calling test, restoring the real GitHub URL
// afterward via the returned func.
func setOllamaReleasesURLForTest(t *testing.T, url string) func() {
	t.Helper()
	ollamaupdate.SetReleasesURLForTest(url)
	return func() { ollamaupdate.SetReleasesURLForTest("") }
}
