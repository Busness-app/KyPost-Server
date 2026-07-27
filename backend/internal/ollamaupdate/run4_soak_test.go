package ollamaupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// run-4 N1: the operator is emailed "a newer Ollama is available — rebuild",
// they rebuild, and they get the same Ollama. The advice could not work.
//
// The Dockerfile pins OLLAMA_VERSION plus its SHA-256, deliberately: piping
// install.sh into a shell is arbitrary remote code, and an unpinned install
// made builds unreproducible. The pin is advanced by .github/workflows/
// ollama-bump.yml, which only ever moves to a release that has been public for
// MIN_RELEASE_AGE_DAYS (3), and which opens a PR a human must merge.
//
// This checker had no such soak — it asked GitHub for releases/latest. So for
// at least three days after every single upstream release it reported an
// upgrade the project would not pin yet and no rebuild could deliver. A
// notification that is guaranteed to be premature on every release is one
// people learn to ignore.
//
// Both sides use the same soak window now, so the server only reports what a
// rebuilt image could actually contain.

type fakeRelease struct {
	TagName     string    `json:"tag_name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
}

func serveReleases(t *testing.T, releases []fakeRelease) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(releases)
	}))
	t.Cleanup(srv.Close)

	orig := releasesURLOverrideForTest
	releasesURLOverrideForTest = srv.URL
	t.Cleanup(func() { releasesURLOverrideForTest = orig })
}

func TestLatestVersionSkipsReleasesInsideTheSoakWindow(t *testing.T) {
	now := time.Now().UTC()
	serveReleases(t, []fakeRelease{
		{TagName: "v0.33.0", PublishedAt: now.Add(-2 * time.Hour)},       // too fresh
		{TagName: "v0.32.9", PublishedAt: now.Add(-10 * 24 * time.Hour)}, // soaked
	})

	got, err := LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "0.32.9" {
		t.Fatalf("LatestVersion = %q, want the soaked 0.32.9 — the project will not pin 0.33.0 for %v yet",
			got, MinReleaseAge)
	}
}

func TestLatestVersionIgnoresDraftsAndPrereleases(t *testing.T) {
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	serveReleases(t, []fakeRelease{
		{TagName: "v0.34.0", Draft: true, PublishedAt: old},
		{TagName: "v0.33.0", Prerelease: true, PublishedAt: old},
		{TagName: "v0.32.9", PublishedAt: old},
	})

	got, err := LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "0.32.9" {
		t.Fatalf("LatestVersion = %q, want 0.32.9", got)
	}
}

func TestLatestVersionStripsTheLeadingV(t *testing.T) {
	serveReleases(t, []fakeRelease{
		{TagName: "v0.32.1", PublishedAt: time.Now().UTC().Add(-30 * 24 * time.Hour)},
	})

	got, err := LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "0.32.1" {
		t.Fatalf("LatestVersion = %q, want 0.32.1", got)
	}
}

// Every release being too fresh is not an error the caller should surface as a
// failed check — it just means there is nothing to report yet.
func TestLatestVersionReportsNothingWhenEverythingIsTooFresh(t *testing.T) {
	now := time.Now().UTC()
	serveReleases(t, []fakeRelease{
		{TagName: "v0.33.0", PublishedAt: now.Add(-1 * time.Hour)},
	})

	got, err := LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if got != "" {
		t.Fatalf("LatestVersion = %q, want empty when nothing has soaked", got)
	}
}

// The soak window has to match the workflow's, or the two disagree again the
// moment either is tuned.
func TestSoakWindowMatchesTheBumpWorkflow(t *testing.T) {
	if MinReleaseAge != 3*24*time.Hour {
		t.Fatalf("MinReleaseAge = %v, want 72h to match MIN_RELEASE_AGE_DAYS in .github/workflows/ollama-bump.yml",
			MinReleaseAge)
	}
}
