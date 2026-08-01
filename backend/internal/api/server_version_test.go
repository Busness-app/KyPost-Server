package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCheckForServerUpdateNotifiesOncePerRelease drives checkForServerUpdate
// against a fake GitHub releases endpoint and confirms the two properties the
// email depends on: a newer release consumes the store's notify transition
// (so the admin is mailed), and a second check for the same release does not.
//
// The email send itself fails in this test — the fixture install has no admin
// IMAP config to send through — which is deliberate: checkForServerUpdate must
// still have latched the version, or a transient SMTP failure would turn into
// a mail on every tick forever.
func TestCheckForServerUpdateNotifiesOncePerRelease(t *testing.T) {
	srv := newTestServer(t)
	serveReleases(t, `[{"tag_name":"v99.0.0","published_at":"`+
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)+`"}]`)

	srv.checkForServerUpdate(context.Background())

	notify, err := srv.globalStore.SetServerUpdateNotified("99.0.0")
	if err != nil {
		t.Fatalf("SetServerUpdateNotified: %v", err)
	}
	if notify {
		t.Fatal("checkForServerUpdate should already have consumed the notify transition for 99.0.0")
	}
}

func TestServerVersionStatusAndEndpoint(t *testing.T) {
	srv := newTestServer(t)
	serveReleases(t, `[{"tag_name":"v99.0.0","published_at":"`+
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)+`"}]`)
	srv.checkForServerUpdate(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/server/version", nil)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.withAdmin(srv.handleServerVersion)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		InstalledVersion string `json:"installedVersion"`
		LatestVersion    string `json:"latestVersion"`
		UpgradeAvailable bool   `json:"upgradeAvailable"`
		CheckedAt        string `json:"checkedAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.InstalledVersion != serverVersion || got.LatestVersion != "99.0.0" || !got.UpgradeAvailable || got.CheckedAt == "" {
		t.Fatalf("unexpected status: %+v", got)
	}
}

// TestCheckForServerUpdateStaysQuietWhenCurrent covers the states that must
// not mail anyone: a released version this build is already at or past, and a
// repository with no releases published at all (which is where this project
// starts, and where an over-eager check would mail every operator hourly).
func TestCheckForServerUpdateStaysQuietWhenCurrent(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"already running the newest release", `[{"tag_name":"v` + serverVersion + `","published_at":"` +
			time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) + `"}]`},
		{"no releases published", `[]`},
		{"only a prerelease", `[{"tag_name":"v99.0.0","prerelease":true,"published_at":"` +
			time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) + `"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			serveReleases(t, tc.body)

			srv.checkForServerUpdate(context.Background())

			// Nothing was latched, so this first-ever record still transitions.
			notify, err := srv.globalStore.SetServerUpdateNotified("99.0.0")
			if err != nil {
				t.Fatalf("SetServerUpdateNotified: %v", err)
			}
			if !notify {
				t.Fatal("checkForServerUpdate notified about an update that is not one")
			}
		})
	}
}

// serveReleases points the self-update check at a local server returning body
// for the duration of the calling test.
func serveReleases(t *testing.T, body string) {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	orig := serverReleasesURL
	serverReleasesURL = gh.URL
	t.Cleanup(func() {
		serverReleasesURL = orig
		gh.Close()
	})
}
