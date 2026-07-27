package ollamaupdate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		name      string
		latest    string
		installed string
		want      bool
	}{
		{"patch bump", "0.32.2", "0.32.1", true},
		{"minor bump", "0.33.0", "0.32.9", true},
		{"equal", "0.32.1", "0.32.1", false},
		{"installed ahead", "0.32.1", "0.32.2", false},
		{"differing component counts", "0.32.1.1", "0.32.1", true},
		{"malformed latest", "not-a-version", "0.32.1", false},
		{"malformed installed", "0.32.1", "not-a-version", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNewer(tc.latest, tc.installed); got != tc.want {
				t.Fatalf("IsNewer(%q, %q) = %v, want %v", tc.latest, tc.installed, got, tc.want)
			}
		})
	}
}

// run-4 N1 changed the endpoint from /releases/latest (one object) to /releases
// (a list), so the soak window can be applied — see MinReleaseAge. The response
// shape here changed with it. The User-Agent assertion is the part worth
// keeping: GitHub rejects requests without one.
func TestLatestVersionSendsAUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua == "" {
			t.Errorf("request missing User-Agent header (GitHub API rejects requests without one)")
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"tag_name": "v0.32.1", "published_at": time.Now().UTC().Add(-30 * 24 * time.Hour)},
		})
	}))
	defer srv.Close()

	orig := releasesURLOverrideForTest
	releasesURLOverrideForTest = srv.URL
	defer func() { releasesURLOverrideForTest = orig }()

	version, err := LatestVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if version != "0.32.1" {
		t.Fatalf("version = %q, want %q (leading v must be stripped)", version, "0.32.1")
	}
}
