// Package ghrelease reads the published releases of a GitHub repository and
// compares dotted-numeric versions, so the update checks can tell an operator
// that something they run is behind upstream.
//
// It is deliberately generic: two callers use it — ollamaupdate (the Ollama
// release pinned in the Dockerfile) and the api package's KyPost-Server
// self-update check — and they differ only in the repository they read and
// how long a release must have soaked before it counts.
package ghrelease

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Latest returns the newest published release of the repository behind
// releasesURL (the /repos/<owner>/<repo>/releases LIST endpoint), with any
// leading "v" stripped from the tag — GitHub tags releases "v0.32.1" while
// the versions they are compared against are written "0.32.1", so both sides
// end up in the same form.
//
// Drafts and prereleases are skipped, as is anything published less than
// minAge ago. An empty return means "nothing to report", not a failure: every
// release being too fresh (or the repo having none at all) is an ordinary
// state, and reporting it as an error would put a spurious check error in
// front of the operator.
func Latest(ctx context.Context, releasesURL string, minAge time.Duration) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return "", err
	}
	// GitHub's REST API rejects unauthenticated requests with no User-Agent.
	req.Header.Set("User-Agent", "kypost-server-update-check")
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
	const maxReleaseResponseBytes = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseResponseBytes+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxReleaseResponseBytes {
		return "", fmt.Errorf("github releases response exceeds %d bytes", maxReleaseResponseBytes)
	}
	if err := json.Unmarshal(body, &releases); err != nil {
		return "", err
	}

	// Releases come back newest-first; take the first that qualifies.
	cutoff := time.Now().UTC().Add(-minAge)
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
