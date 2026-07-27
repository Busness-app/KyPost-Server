// Package ollamaupdate checks whether the Ollama release bundled in this
// container is behind the latest one published upstream, so operators can be
// told when a rebuild/redeploy would pick up a newer, better-patched Ollama.
package ollamaupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// releasesURLOverrideForTest lets tests point LatestVersion at a local
// httptest server instead of the real GitHub API; production code never
// changes it.
var releasesURLOverrideForTest = ""

// SetReleasesURLForTest overrides the GitHub releases URL LatestVersion
// queries, for use by other packages' tests (e.g. api's monitor test). Pass
// "" to restore the real GitHub API URL.
func SetReleasesURLForTest(url string) {
	releasesURLOverrideForTest = url
}

// releasesURL is the LIST endpoint, not /releases/latest, because the newest
// release is not necessarily the one to report — see MinReleaseAge.
const releasesURL = "https://api.github.com/repos/ollama/ollama/releases"

// MinReleaseAge is how long an upstream release must have been public before
// this checker will mention it.
//
// It exists to match .github/workflows/ollama-bump.yml's MIN_RELEASE_AGE_DAYS.
// The Dockerfile pins Ollama to a specific tarball and SHA-256, and that pin is
// only ever advanced to a release that has soaked for this long — so a release
// younger than this is one no rebuild can deliver, because the project has not
// pinned it and will not for days.
//
// Without the match, the check reported an upgrade within minutes of every
// upstream release and told the operator to rebuild, which changed nothing.
// A notification that is guaranteed to be premature on every single release
// teaches people to ignore it, and this one shares a mailbox with the security
// notices.
//
// Keep in step with the workflow. TestSoakWindowMatchesTheBumpWorkflow fails if
// one moves without the other.
const MinReleaseAge = 3 * 24 * time.Hour

// LatestVersion queries GitHub for the most recently published Ollama
// release and returns its version with any leading "v" stripped — GitHub
// tags this repo as e.g. "v0.32.1", while Ollama's own /api/version reports
// "0.32.1" with no prefix, so both sides compare on the same form.
func LatestVersion(ctx context.Context) (string, error) {
	url := releasesURL
	if releasesURLOverrideForTest != "" {
		url = releasesURLOverrideForTest
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// GitHub's REST API rejects unauthenticated requests with no User-Agent.
	req.Header.Set("User-Agent", "kypost-server-ollama-update-check")
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("github releases lookup failed: status %d", resp.StatusCode)
	}

	var releases []struct {
		TagName     string    `json:"tag_name"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}

	// Releases come back newest-first; take the first that has soaked. An empty
	// return means "nothing to report yet", not a failure — every release being
	// too fresh is an ordinary state, and reporting it as an error would put a
	// spurious checkError in front of the operator.
	cutoff := time.Now().UTC().Add(-MinReleaseAge)
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		if r.PublishedAt.IsZero() || r.PublishedAt.After(cutoff) {
			continue
		}
		version := strings.TrimPrefix(strings.TrimSpace(r.TagName), "v")
		if version == "" {
			continue
		}
		return version, nil
	}
	return "", nil
}

// IsNewer reports whether latest is a strictly newer dotted-numeric version
// than installed. Any component that doesn't parse as a number makes the
// comparison fail safe (false) rather than risk a false "update available"
// from an unexpected version format on either side.
func IsNewer(latest, installed string) bool {
	l, lok := parseVersion(latest)
	i, iok := parseVersion(installed)
	if !lok || !iok {
		return false
	}
	for idx := 0; idx < len(l) || idx < len(i); idx++ {
		var lv, iv int
		if idx < len(l) {
			lv = l[idx]
		}
		if idx < len(i) {
			iv = i[idx]
		}
		if lv != iv {
			return lv > iv
		}
	}
	return false
}

func parseVersion(v string) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return nil, false
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
