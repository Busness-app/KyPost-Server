package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/ghrelease"
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
		// A failed check did not check anything, so it must not clobber the
		// last known-good latestVersion or checkedAt: doing so would drop a
		// live "an update is available" back to "no information" with a
		// fresh timestamp, and the next successful tick would then look like
		// a brand-new false->true transition to the client, firing a second
		// toast mid-session for one GitHub blip.
		prev := s.getLinuxClientStatus()
		s.setLinuxClientStatus(linuxClientStatus{
			latestVersion: prev.latestVersion,
			checkedAt:     prev.checkedAt,
			checkErr:      "failed to check for updates",
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

// handleClientVersion reports the newest published Linux client release to a
// paired device, which compares it against its own compiled-in version. It
// never performs network I/O: the value comes from the hourly monitor's
// cache, so a client opening its About screen cannot make this server call
// GitHub.
//
// Device-authenticated rather than public. The body carries nothing per-user,
// but this client is always paired by the time it asks, so there is no reason
// to add an anonymous route to reach it.
func (s *Server) handleClientVersion(w http.ResponseWriter, r *http.Request) {
	_, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	status := s.getLinuxClientStatus()
	checkedAt := ""
	if !status.checkedAt.IsZero() {
		checkedAt = status.checkedAt.Format(time.RFC3339)
	}
	// latestVersion is empty until the first check completes, when nothing has
	// soaked yet, or when the repository has no releases. The client renders
	// an empty value as "no information", never as an error.
	writeJSON(w, http.StatusOK, map[string]any{
		"latestVersion": status.latestVersion,
		"checkedAt":     checkedAt,
		"error":         status.checkErr,
	})
}
