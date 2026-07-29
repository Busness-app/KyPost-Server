// Package ollamaupdate checks whether the Ollama release bundled in this
// container is behind the latest one published upstream, so operators can be
// told when a rebuild/redeploy would pick up a newer, better-patched Ollama.
//
// The GitHub reading and version comparison live in ghrelease, which the
// KyPost-Server self-update check shares; what is Ollama-specific is the
// repository read and the soak window below.
package ollamaupdate

import (
	"context"
	"time"

	"kypost-server/backend/internal/ghrelease"
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

// LatestVersion returns the most recently published Ollama release that has
// soaked for MinReleaseAge, or "" when none has yet. See ghrelease.Latest.
func LatestVersion(ctx context.Context) (string, error) {
	url := releasesURL
	if releasesURLOverrideForTest != "" {
		url = releasesURLOverrideForTest
	}
	return ghrelease.Latest(ctx, url, MinReleaseAge)
}

// IsNewer reports whether latest is a strictly newer dotted-numeric version
// than installed, failing safe on anything that doesn't parse.
func IsNewer(latest, installed string) bool { return ghrelease.IsNewer(latest, installed) }
