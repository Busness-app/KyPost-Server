package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// serveClientReleases points linuxClientReleasesURL at a fake GitHub for the
// duration of one test. Mirrors serveReleases in server_version_test.go,
// which swaps a different variable.
func serveClientReleases(t *testing.T, body string) {
	t.Helper()
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	orig := linuxClientReleasesURL
	linuxClientReleasesURL = gh.URL
	t.Cleanup(func() {
		linuxClientReleasesURL = orig
		gh.Close()
	})
}

func published(ago time.Duration) string {
	return time.Now().UTC().Add(-ago).Format(time.RFC3339)
}

// TestLinuxClientStatusReportsNewestSoakedRelease covers the states the
// endpoint has to distinguish. The soak window is the interesting one: a
// Linux tag is not installable until flatpak.yml has finished BOTH arch
// bundles, and the aarch64 build has already failed twice on Flathub CDN
// faults, so advertising a fresh tag can point users at a release that has
// no bundle for their machine.
func TestLinuxClientStatusReportsNewestSoakedRelease(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "soaked release is reported",
			body: `[{"tag_name":"v0.3.0","published_at":"` + published(24*time.Hour) + `"}]`,
			want: "0.3.0",
		},
		{
			name: "release still inside the soak window is not",
			body: `[{"tag_name":"v0.3.0","published_at":"` + published(time.Hour) + `"}]`,
			want: "",
		},
		{
			name: "draft is skipped",
			body: `[{"tag_name":"v0.3.0","draft":true,"published_at":"` + published(24*time.Hour) + `"}]`,
			want: "",
		},
		{
			name: "prerelease is skipped",
			body: `[{"tag_name":"v0.3.0","prerelease":true,"published_at":"` + published(24*time.Hour) + `"}]`,
			want: "",
		},
		{
			name: "newest soaked release wins",
			body: `[{"tag_name":"v0.4.0","published_at":"` + published(time.Hour) + `"},` +
				`{"tag_name":"v0.3.0","published_at":"` + published(48*time.Hour) + `"}]`,
			want: "0.3.0",
		},
		{
			name: "no releases at all is an ordinary state",
			body: `[]`,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			serveClientReleases(t, tc.body)

			srv.checkForLinuxClientUpdate(context.Background())

			got := srv.getLinuxClientStatus()
			if got.latestVersion != tc.want {
				t.Fatalf("latestVersion = %q, want %q", got.latestVersion, tc.want)
			}
			if got.checkErr != "" {
				t.Fatalf("unexpected checkErr %q", got.checkErr)
			}
			if got.checkedAt.IsZero() {
				t.Fatal("checkedAt must be set even when there is nothing to report")
			}
		})
	}
}

// A GitHub outage must not become a permanent error on the user's About
// screen: the status records the failure, the next hourly tick retries.
func TestLinuxClientStatusRecordsCheckFailure(t *testing.T) {
	srv := newTestServer(t)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer gh.Close()
	orig := linuxClientReleasesURL
	linuxClientReleasesURL = gh.URL
	defer func() { linuxClientReleasesURL = orig }()

	srv.checkForLinuxClientUpdate(context.Background())

	if srv.getLinuxClientStatus().checkErr == "" {
		t.Fatal("a failed release check must be recorded")
	}
}

// testUserID returns the fixture user's ID, the same way authRequest does
// (server_native_test.go:101).
func testUserID(t *testing.T, s *Server) string {
	t.Helper()
	all, err := s.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	return all[0].ID
}

// The endpoint serves the cache and never performs network I/O of its own,
// so opening the client's About screen cannot generate a GitHub request.
func TestClientVersionEndpointServesCache(t *testing.T) {
	srv := newTestServer(t)
	srv.setLinuxClientStatus(linuxClientStatus{
		latestVersion: "0.3.0",
		checkedAt:     time.Now().UTC(),
	})

	id, secret := pairNativeDevice(t, srv, testUserID(t, srv), "device-e1")
	req := httptest.NewRequest(http.MethodGet, "/api/client/version", nil)
	req.Header.Set("X-Kypost-Device-Id", id)
	req.Header.Set("X-Kypost-Device-Secret", secret)
	rec := httptest.NewRecorder()
	withDeviceAuth(srv.handleClientVersion)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		LatestVersion string `json:"latestVersion"`
		CheckedAt     string `json:"checkedAt"`
		Error         string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.LatestVersion != "0.3.0" || got.CheckedAt == "" || got.Error != "" {
		t.Fatalf("unexpected body: %+v", got)
	}
}

// No device credential, no answer. The body carries nothing per-user, but an
// unauthenticated route is a new anonymous surface and this does not need to
// be one.
func TestClientVersionEndpointRejectsUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/client/version", nil)
	rec := httptest.NewRecorder()
	withDeviceAuth(srv.handleClientVersion)(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatalf("unauthenticated request was answered %d", rec.Code)
	}
}
