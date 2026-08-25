package api

import (
	"context"
	"time"

	"kypost-server/backend/internal/ghrelease"
)

// linuxClientReleasesURL is the LIST endpoint for the Linux client's own
// releases. A var, not a const, only so tests can point it at an httptest
// server — the same reason serverReleasesURL is one.
//
// This URL is compiled into every client that asks for it and is permanent
// for the life of those installs. It was read from the Linux repository's
// git remote rather than assumed.
var linuxClientReleasesURL = "https://api.github.com/repos/Busness-app/KyPost-for-Linux/releases"

// linuxClientReleaseMinAge is six hours where serverReleaseMinAge is zero.
//
// A KyPost-Server release is installable the moment it is published, so it
// has nothing to wait for. A Linux tag is not: flatpak.yml builds the x86_64
// and aarch64 bundles AFTER the tag exists, and the aarch64 job has already
// died twice on Flathub CDN faults (flatpak.yml:172-180). Without a soak
// window we would tell an aarch64 user about a release that has no bundle
// they can install.
const linuxClientReleaseMinAge = 6 * time.Hour

// linuxClientStatus is the last completed Linux-client release check.
//
// It holds no "upgradeAvailable" field on purpose. This server does not know
// what version any given client is running, and must not: the comparison
// belongs on the client, where the installed version is a compiled-in
// constant and is the LEFT-HAND SIDE. server_version.go:12-28 explains what
// a wrong left-hand side costs.
type linuxClientStatus struct {
	latestVersion string
	checkedAt     time.Time
	checkErr      string
}

func (s *Server) getLinuxClientStatus() linuxClientStatus {
	s.linuxClientMu.Lock()
	defer s.linuxClientMu.Unlock()
	return s.linuxClientStatus
}

func (s *Server) setLinuxClientStatus(status linuxClientStatus) {
	s.linuxClientMu.Lock()
	defer s.linuxClientMu.Unlock()
	s.linuxClientStatus = status
}

// checkForLinuxClientUpdate refreshes the cached newest Linux client release.
// Run from StartVersionMonitor alongside checkForServerUpdate.
//
// Unlike checkForServerUpdate this emails nobody. A server upgrade is the
// admin's to apply, so mailing them is actionable; a Linux client upgrade is
// applied by whoever is sitting at the Linux machine, who is usually not the
// admin and cannot act on the mail.
//
// Failures are recorded and logged rather than retried here: this runs
// unattended on an hourly tick, GitHub being unreachable is routine for a
// self-hosted box, and the next tick retries.
func (s *Server) checkForLinuxClientUpdate(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	latest, err := ghrelease.Latest(checkCtx, linuxClientReleasesURL, linuxClientReleaseMinAge)
	if err != nil {
		s.logger.Error("linux client release check failed", "error", err.Error())
		s.setLinuxClientStatus(linuxClientStatus{
			checkedAt: time.Now().UTC(),
			checkErr:  "failed to check for updates",
		})
		return
	}
	// An empty latest means no release has soaked yet, or the repository has
	// published none. Both are ordinary states, not errors: the client renders
	// an empty latestVersion as "no information", never as a failure.
	s.setLinuxClientStatus(linuxClientStatus{
		latestVersion: latest,
		checkedAt:     time.Now().UTC(),
	})
}
