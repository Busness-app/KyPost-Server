package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/ollamaupdate"
	"kypost-server/backend/internal/users"
)

// versionPollInterval controls how often the installed Ollama and
// KyPost-Server versions are compared against the latest upstream GitHub
// releases. Both installed versions only ever change when the container image
// itself is rebuilt, so there is no benefit to polling more often than this —
// it mainly exists to pick up a freshly-published release in a timely way.
const versionPollInterval = 1 * time.Hour

// ollamaVersionStatus is the last-known result of comparing the installed
// Ollama version against the latest upstream release, cached in memory so
// handleOllamaVersion never has to make a live network call on every page
// load (both to Ollama itself and to the GitHub API, which unauthenticated
// callers should be conservative with).
type ollamaVersionStatus struct {
	installedVersion string
	latestVersion    string
	upgradeAvailable bool
	checkedAt        time.Time
	checkErr         string
}

// SetClassifier attaches the shared classifier HTTP client so the Ollama
// version monitor can query the running instance's own /api/version. Must be
// called before StartVersionMonitor for the monitor to do anything.
func (s *Server) SetClassifier(c *classifier.HTTPClient) {
	s.classifier = c
}

func (s *Server) getOllamaStatus() ollamaVersionStatus {
	s.ollamaMu.Lock()
	defer s.ollamaMu.Unlock()
	return s.ollamaStatus
}

func (s *Server) setOllamaStatus(status ollamaVersionStatus) {
	s.ollamaMu.Lock()
	defer s.ollamaMu.Unlock()
	s.ollamaStatus = status
}

// StartVersionMonitor periodically checks the installed Ollama and
// KyPost-Server versions against the latest releases published upstream, and
// emails the admin the first time either update becomes available, so a
// self-hosted operator knows to rebuild and redeploy the container. Safe to
// call even when SetClassifier was never called — the Ollama half is then a
// no-op, and the KyPost-Server half does not need it. Intended to be run in
// its own goroutine (mirrors StartPickupSweeper) and returns when ctx is
// canceled.
func (s *Server) StartVersionMonitor(ctx context.Context) {
	s.refreshOllamaVersionStatus(ctx)
	s.checkForServerUpdate(ctx)

	ticker := time.NewTicker(versionPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refreshOllamaVersionStatus(ctx)
			s.checkForServerUpdate(ctx)
		}
	}
}

func (s *Server) refreshOllamaVersionStatus(ctx context.Context) {
	if s.classifier == nil {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	installed, err := s.classifier.Version(checkCtx)
	if err != nil {
		s.logger.Error("ollama installed-version check failed", "error", err.Error())
		s.setOllamaStatus(ollamaVersionStatus{checkErr: "failed to reach ollama"})
		return
	}

	latest, err := ollamaupdate.LatestVersion(checkCtx)
	if err != nil {
		s.logger.Error("ollama upstream-release check failed", "error", err.Error())
		s.setOllamaStatus(ollamaVersionStatus{installedVersion: installed, checkErr: "failed to check for updates"})
		return
	}

	// An empty latest means every upstream release is still inside the soak
	// window (see ollamaupdate.MinReleaseAge) — nothing to report, not a
	// failure. IsNewer already fails closed on it; this keeps the empty string
	// out of the status the UI renders.
	if latest == "" {
		s.setOllamaStatus(ollamaVersionStatus{
			installedVersion: installed,
			latestVersion:    installed,
			checkedAt:        time.Now().UTC(),
		})
		return
	}

	upgradeAvailable := ollamaupdate.IsNewer(latest, installed)
	s.setOllamaStatus(ollamaVersionStatus{
		installedVersion: installed,
		latestVersion:    latest,
		upgradeAvailable: upgradeAvailable,
		checkedAt:        time.Now().UTC(),
	})

	if !upgradeAvailable || s.globalStore == nil {
		return
	}
	notify, err := s.globalStore.SetOllamaUpdateNotified(latest)
	if err != nil {
		s.logger.Error("failed to persist ollama update notification state", "error", err.Error())
		return
	}
	if !notify {
		return
	}

	s.logger.Info("ollama update available", "installed", installed, "latest", latest)
	if err := s.notifyAdminOllamaUpdateAvailable(installed, latest); err != nil {
		s.logger.Error("failed to email admin about ollama update", "error", err.Error())
	}
}

// handleOllamaVersion reports the cached installed/latest Ollama version
// comparison for the Prompt Tuning page's version block. It deliberately
// reads the in-memory cache rather than checking live on every request.
func (s *Server) handleOllamaVersion(w http.ResponseWriter, r *http.Request) {
	status := s.getOllamaStatus()
	if status.installedVersion == "" && status.checkErr == "" {
		http.Error(w, "ollama version check has not completed yet", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"installedVersion": status.installedVersion,
		"latestVersion":    status.latestVersion,
		"upgradeAvailable": status.upgradeAvailable,
		"checkedAt":        status.checkedAt.Format(time.RFC3339),
		"error":            status.checkErr,
	})
}

// notifyAdminOllamaUpdateAvailable emails the install's primary admin that a
// newer Ollama release is available upstream than the one bundled in this
// container.
//
// What this says has to be true, or the operator does it, sees no change, and
// stops believing the next one. Rebuilding your existing checkout does NOT
// change the Ollama version: the Dockerfile pins it to a specific tarball and
// SHA-256 (deliberately — an unpinned install.sh is arbitrary remote code and
// made builds unreproducible), so a rebuild reinstalls exactly the same
// release. What moves it is the pin itself moving.
func (s *Server) notifyAdminOllamaUpdateAvailable(installed, latest string) error {
	return s.sendAdminNotice(
		"A newer Ollama version is available for your kypost container",
		fmt.Sprintf(
			"Your kypost-server container is currently running Ollama %s. Version %s has been available upstream "+
				"for at least %d days.\n\n"+
				"Rebuilding your current checkout will NOT change this: the Dockerfile pins Ollama to a specific "+
				"release and checksum, so a rebuild reinstalls the same version. To pick up the newer one, either:\n\n"+
				"  1. Pull a kypost-server image built after the pin was bumped (the pin is advanced by an automated "+
				"PR that a maintainer merges), or\n"+
				"  2. Build with the pin overridden yourself:\n"+
				"     docker build --build-arg OLLAMA_VERSION=%s --build-arg OLLAMA_SHA256=<sha> .\n"+
				"     The checksum is in that release's published sha256sum.txt; the build verifies it.\n\n"+
				"This container does not update itself, and nothing here happens automatically.",
			installed, latest, int(ollamaupdate.MinReleaseAge.Hours()/24), latest,
		),
	)
}

// sendAdminNotice emails the install's primary admin (FirstAdminFrom) through
// that admin's own configured IMAP/SMTP credentials, addressed to themselves —
// the same self-notification pattern sendPickupNotification and handleMailSend
// use. It is how both update checks reach the operator.
func (s *Server) sendAdminNotice(subject, body string) error {
	all, err := s.users.List()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	admin := users.FirstAdminFrom(all)
	if admin.ID == "" {
		return fmt.Errorf("no active admin to notify")
	}

	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(admin.ID), s.imapConfigKeyPath)
	if err != nil {
		return fmt.Errorf("read admin imap config: %w", err)
	}
	if !exists {
		return fmt.Errorf("admin has no imap configuration to send through")
	}

	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		return fmt.Errorf("resolve smtp target: %w", err)
	}

	from := sanitizeHeaderValue(payload.Username)
	if from == "" {
		return fmt.Errorf("admin imap username is empty")
	}

	msg := mailmsg.Message{
		From:    from,
		To:      []string{from},
		Subject: subject,
		Body:    body,
		Mode:    "plain",
	}.Build()

	return mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, payload.Username, payload.Password, from, []string{from}, msg)
}
