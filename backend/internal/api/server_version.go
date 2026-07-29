package api

import (
	"context"
	"fmt"
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
const serverVersion = "0.1.0"

// serverReleasesURL is the LIST endpoint for this project's own releases. A
// var, not a const, only so tests can point it at an httptest server.
var serverReleasesURL = "https://api.github.com/repos/Yoshiofthewire/KyPost-Server/releases"

// serverReleaseMinAge is zero where the Ollama check has a three-day soak
// window: that window exists because the Dockerfile's Ollama pin lags upstream
// by days, so a fresh Ollama release is one no rebuild can deliver. A
// KyPost-Server release has no such lag — the moment it is published, `git
// pull` and a rebuild deliver it — so there is nothing to wait for.
const serverReleaseMinAge = 0

// checkForServerUpdate compares this build against the newest KyPost-Server
// release published on GitHub and, the first time a newer one appears, emails
// the admin. Run from StartVersionMonitor alongside the Ollama check.
//
// Failures are logged and dropped rather than surfaced: this runs unattended
// on a timer, GitHub being unreachable is routine for a self-hosted box, and
// the next tick retries in an hour.
func (s *Server) checkForServerUpdate(ctx context.Context) {
	if s.globalStore == nil {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	latest, err := ghrelease.Latest(checkCtx, serverReleasesURL, serverReleaseMinAge)
	if err != nil {
		s.logger.Error("kypost-server release check failed", "error", err.Error())
		return
	}
	// Empty means the repository has published no usable release yet, which is
	// an ordinary state and not worth logging on every tick.
	if latest == "" || !ghrelease.IsNewer(latest, serverVersion) {
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

// notifyAdminServerUpdateAvailable tells the admin a newer KyPost-Server has
// been released. The upgrade steps have to match the documented install
// (README "Quick Start": clone, then `docker compose up --build -d`), because
// an operator who follows them and sees nothing change stops reading the next
// one of these.
func (s *Server) notifyAdminServerUpdateAvailable(latest string) error {
	return s.sendAdminNotice(
		"A newer KyPost-Server version is available",
		fmt.Sprintf(
			"This install is running KyPost-Server %s. Version %s has been released.\n\n"+
				"Nothing updates itself. To move to it, from your checkout:\n\n"+
				"  git pull\n"+
				"  docker compose up --build -d\n\n"+
				"That rebuilds the image from the new source and restarts the container. Your named volumes "+
				"(config, private keys, logs, state) are kept — only `docker compose down -v` removes those.\n\n"+
				"Release notes: https://github.com/Yoshiofthewire/KyPost-Server/releases/tag/v%s\n\n"+
				"You will get this message once per new release, not once per check.",
			serverVersion, latest, latest,
		),
	)
}
