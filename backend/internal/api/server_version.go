package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"kypost-server/backend/internal/ghrelease"
)

// serverVersion is the KyPost-Server release this binary was built from, and
// the left-hand side of the self-update check below.
//
// It is a compiled-in constant rather than a build-time flag on purpose: the
// documented install is `git clone` + `docker compose up --build`, which
// passes no build args, so anything supplied through --build-arg would be
// empty for almost every operator and the check would never fire. The cost is
// that cutting a release means bumping this in the same commit as the tag —
// see backend/AGENTS.md.
//
// It must equal frontend/package.json's version and the release tag it is
// published under. That is not a convention: release-image.yml refuses to
// publish a tag that disagrees with either, because a mismatch here is not
// cosmetic. This constant is the LEFT-HAND SIDE of the update check, so a
// binary tagged v1.0.0 while this still said 0.1.0 would compare itself
// against every published release, conclude it was out of date forever, and
// email the admin of every install about an upgrade they had already applied.
const serverVersion = "0.3.0"

// serverReleasesURL is the LIST endpoint for this project's own releases. A
// var, not a const, only so tests can point it at an httptest server.
var serverReleasesURL = "https://api.github.com/repos/Yoshiofthewire/KyPost-Server/releases"

// serverReleaseMinAge is zero where the Ollama check has a three-day soak
// window: that window exists because the Dockerfile's Ollama pin lags upstream
// by days, so a fresh Ollama release is one no rebuild can deliver. A
// KyPost-Server release has no such lag — the moment it is published, `git
// pull` and a rebuild deliver it — so there is nothing to wait for.
const serverReleaseMinAge = 0

// serverVersionStatus is the last completed release check. It is cached for
// the Settings page so opening the page never creates another GitHub request.
type serverVersionStatus struct {
	installedVersion string
	latestVersion    string
	upgradeAvailable bool
	checkedAt        time.Time
	checkErr         string
}

func (s *Server) getServerStatus() serverVersionStatus {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	return s.serverStatus
}

func (s *Server) setServerStatus(status serverVersionStatus) {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	s.serverStatus = status
}

// checkForServerUpdate compares this build against the newest KyPost-Server
// release published on GitHub and, the first time a newer one appears, emails
// the admin. Run from StartVersionMonitor alongside the Ollama check.
//
// Failures are logged and dropped rather than surfaced: this runs unattended
// on a timer, GitHub being unreachable is routine for a self-hosted box, and
// the next tick retries in an hour.
func (s *Server) checkForServerUpdate(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	latest, err := ghrelease.Latest(checkCtx, serverReleasesURL, serverReleaseMinAge)
	if err != nil {
		s.logger.Error("kypost-server release check failed", "error", err.Error())
		s.setServerStatus(serverVersionStatus{installedVersion: serverVersion, checkErr: "failed to check for updates"})
		return
	}
	// Empty means the repository has published no usable release yet, which is
	// an ordinary state. Render it as installed so the UI can say it is current.
	if latest == "" {
		s.setServerStatus(serverVersionStatus{
			installedVersion: serverVersion,
			latestVersion:    serverVersion,
			checkedAt:        time.Now().UTC(),
		})
		return
	}
	upgradeAvailable := ghrelease.IsNewer(latest, serverVersion)
	s.setServerStatus(serverVersionStatus{
		installedVersion: serverVersion,
		latestVersion:    latest,
		upgradeAvailable: upgradeAvailable,
		checkedAt:        time.Now().UTC(),
	})
	if !upgradeAvailable || s.globalStore == nil {
		return
	}

	notify, err := s.globalStore.SetServerUpdateNotified(latest)
	if err != nil {
		s.logger.Error("failed to persist kypost-server update notification state", "error", err.Error())
		return
	}
	if !notify {
		return
	}

	s.logger.Info("kypost-server update available", "installed", serverVersion, "latest", latest)
	if err := s.notifyAdminServerUpdateAvailable(latest); err != nil {
		s.logger.Error("failed to email admin about kypost-server update", "error", err.Error())
	}
}

// handleServerVersion reports the cached KyPost release comparison for the
// admin-only Settings update card. It never performs network I/O itself.
func (s *Server) handleServerVersion(w http.ResponseWriter, r *http.Request) {
	status := s.getServerStatus()
	if status.installedVersion == "" && status.checkErr == "" {
		http.Error(w, "server version check has not completed yet", http.StatusServiceUnavailable)
		return
	}
	checkedAt := ""
	if !status.checkedAt.IsZero() {
		checkedAt = status.checkedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"installedVersion": status.installedVersion,
		"latestVersion":    status.latestVersion,
		"upgradeAvailable": status.upgradeAvailable,
		"checkedAt":        checkedAt,
		"error":            status.checkErr,
	})
}

// notifyAdminServerUpdateAvailable tells the admin a newer KyPost-Server has
// been released. The upgrade steps have to match the documented install
// (README "Updating KyPost"), because an operator who follows them and sees
// nothing change stops reading the next one of these.
func (s *Server) notifyAdminServerUpdateAvailable(latest string) error {
	return s.sendAdminNotice(
		"A newer KyPost-Server version is available",
		fmt.Sprintf(
			"This install is running KyPost-Server %s. Version %s has been released.\n\n"+
				"To move to it, from your checkout:\n\n"+
				"  ./scripts/update-host.sh\n\n"+
				"That pulls the published stable image, waits for its health check, and restores the previous image "+
				"if startup fails. Your named volumes "+
				"(config, private keys, logs, state) are kept — only `docker compose down -v` removes those.\n\n"+
				"Automatic updates are optional: install the systemd timer documented in README.md.\n\n"+
				"Release notes: https://github.com/Yoshiofthewire/KyPost-Server/releases/tag/v%s\n\n"+
				"You will get this message once per new release, not once per check.",
			serverVersion, latest, latest,
		),
	)
}
