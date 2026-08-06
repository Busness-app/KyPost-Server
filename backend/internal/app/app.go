package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	"kypost-server/backend/internal/api"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// Run dispatches the process mode and blocks until shutdown for long-running modes.
func Run(args []string) error {
	fs := flag.NewFlagSet("kypost-server", flag.ContinueOnError)
	mode := fs.String("mode", "all", "process mode: daemon, server, all, bootstrap-admin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Handled before any of the setup below: bootstrap-admin runs once, as
	// root, before any service starts, and its whole job is to create the
	// account store that the setup below expects to already exist.
	if *mode == "bootstrap-admin" {
		return BootstrapAdmin()
	}

	paths := config.Paths{
		ConfigFile: filepath.Join(config.ConfigDir(), "config.yaml"),
		StateDir:   config.StateDir(),
		LogDir:     config.LogDir(),
	}

	// Capture legacy notification prefs before LoadOrInit rewrites
	// config.yaml with the trimmed multi-user schema (which drops the old
	// global mode/keywords fields the migration needs).
	legacyPrefs, legacyPrefsOK := config.LoadLegacyNotificationPrefs(paths.ConfigFile)

	cfg, err := config.LoadOrInit(paths.ConfigFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Timezone == "" {
		cfg.Timezone = "America/New_York"
	}
	if _, err := time.LoadLocation(cfg.Timezone); err != nil {
		return fmt.Errorf("invalid timezone %q: %w", cfg.Timezone, err)
	}

	// Auto-populate label allowlist from TUNING.md when the config has none.
	if len(cfg.Labels.Allowlist) == 0 {
		if labels := classifier.ParseAllowedLabels(classifier.LoadTuningText()); len(labels) > 0 {
			cfg.Labels.Allowlist = labels
		}
	}

	logger, err := logging.New(paths.LogDir)
	if err != nil {
		return fmt.Errorf("create logger: %w", err)
	}
	defer logger.Close()

	configDir := config.ConfigDir()
	usersStore, store, err := openStores(logger, configDir, paths.StateDir, legacyPrefs, legacyPrefsOK)
	if err != nil {
		return err
	}

	clearAllMFAIfRequested(logger, usersStore, paths.StateDir)

	healthSvc := health.NewService()
	healthSvc.MarkHealthy()

	// wkdStore is the instance-level WKD domain-claim store. In "all" mode
	// the api server and the poller run as goroutines in one binary and
	// share this instance; under supervisord they are two separate
	// processes (`--mode server` and `--mode daemon`) and each builds its
	// own. Both are correct: wkdpublish.Store serializes every
	// read-modify-write with an inter-process file lock, not just a mutex.
	wkdStore, err := wkdpublish.New(paths.StateDir)
	if err != nil {
		return fmt.Errorf("create wkd publish store: %w", err)
	}

	deps := runDeps{
		cfg:        cfg,
		configPath: paths.ConfigFile,
		configDir:  configDir,
		stateDir:   paths.StateDir,
		logger:     logger,
		store:      store,
		users:      usersStore,
		health:     healthSvc,
		wkdStore:   wkdStore,
	}

	// Signal handling is installed exactly once, here at the real entrypoint, and
	// the run functions below observe it only as a context. os/signal registration
	// is process-global, so doing it inside runServer/runAll left a window between
	// process start and signal.Notify in which SIGTERM kept its default disposition
	// and killed the process outright. Passing a context instead of a channel also
	// lets tests drive shutdown without signalling the whole process.
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	switch *mode {
	case "daemon":
		return runDaemon(ctx, deps)
	case "server":
		return runServer(ctx, deps)
	case "all":
		return runAll(ctx, deps)
	default:
		return errors.New("invalid mode; expected daemon, server, all, or bootstrap-admin")
	}
}

type runDeps struct {
	cfg        config.Config
	configPath string
	configDir  string
	stateDir   string
	logger     *logging.Logger
	store      *state.Store
	users      *users.Store
	health     *health.Service
	wkdStore   *wkdpublish.Store
}

func runDaemon(ctx context.Context, d runDeps) error {
	classifierClient := newClassifierClient(d.cfg)
	poller, err := processor.New(d.cfg, d.logger, d.store, d.users, d.stateDir, d.configDir, d.health, classifierClient, d.wkdStore)
	if err != nil {
		return err
	}
	poller.SetConfigPath(d.configPath)
	warmupDone := warmupClassifierOnStartup(ctx, d.logger, classifierClient, poller)
	poller.Start()
	d.logger.Info("poller goroutine started")
	go monitorHealth(ctx, d.logger, d.health)
	<-ctx.Done()
	poller.Stop()
	awaitWarmup(d.logger, warmupDone)
	// Wait for the poller's own goroutines (the tick loop, plus the eager
	// recheckWKDDomains and cleanupAllUsers runs) to finish. Stop only
	// cancels; without this the process could exit, or a test could remove
	// its state directory, while those were still writing to it.
	poller.Wait()
	return nil
}

// startBackgroundSweepers launches every periodic reclaim the API process needs.
//
// One list, called from both runServer and runAll. As nine duplicated
// `go srv.StartXSweeper(ctx)` lines, a tenth added to one list and not the other
// is a leak that only appears in the run mode nobody is testing when they add it.
func startBackgroundSweepers(ctx context.Context, srv *api.Server) {
	for _, sweep := range []func(context.Context){
		srv.StartPickupSweeper,
		srv.StartContactPhotoSweeper,
		srv.StartContactsTombstoneSweeper,
		srv.StartEnvelopeSweeper,
		srv.StartCooldownSweeper,
		srv.StartMfaPushLimiterSweeper,
		srv.StartSessionSweeper,
		srv.StartMFAChallengeSweeper,
		srv.StartPoWSweeper,
		srv.StartUserStoreSweeper,
		srv.StartVersionMonitor,
	} {
		go sweep(ctx)
	}
}

func runServer(ctx context.Context, d runDeps) error {
	srv := api.NewServer(d.cfg, d.logger, d.health, d.users, nil, d.wkdStore)
	srv.SetClassifier(newClassifierClient(d.cfg))

	// Prepare constructs the *http.Server synchronously, before the Serve
	// goroutine below is even launched, so a stop signal arriving essentially
	// immediately still has a real server for Shutdown to act on (see
	// api.Server.Prepare's doc comment for the race this avoids).
	srv.Prepare()

	sweeperCtx, cancelSweepers := context.WithCancel(ctx)
	defer cancelSweepers()
	startBackgroundSweepers(sweeperCtx, srv)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve()
	}()

	select {
	case <-ctx.Done():
		cancelSweepers()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancelShutdown()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			d.logger.Error("api server shutdown error", "error", err.Error())
		}
		<-serveErr
		return nil
	case err := <-serveErr:
		return err
	}
}

// shutdownTimeout bounds how long a graceful shutdown waits for the HTTP
// server to drain in-flight requests (via api.Server.Shutdown) before
// giving up and letting the process exit anyway. 20s comfortably covers the
// slowest handlers (e.g. IMAP round-trips) without risking an orchestrator's
// own SIGKILL timeout (typically 30s) firing first.
const shutdownTimeout = 20 * time.Second

func runAll(ctx context.Context, d runDeps) error {
	// Restore the sticky AI-credits flag onto the health status so a restart
	// keeps surfacing it until a successful classify clears it.
	if exhausted, at := d.store.AICreditsExhausted(); exhausted {
		d.health.SetAICreditsExhausted(at)
	}
	classifierClient := newClassifierClient(d.cfg)
	poller, err := processor.New(d.cfg, d.logger, d.store, d.users, d.stateDir, d.configDir, d.health, classifierClient, d.wkdStore)
	if err != nil {
		return err
	}
	poller.SetConfigPath(d.configPath)
	srv := api.NewServer(d.cfg, d.logger, d.health, d.users, poller.UpdateConfig, d.wkdStore)
	srv.SetPoller(poller)
	srv.SetClassifier(classifierClient)
	warmupDone := warmupClassifierOnStartup(ctx, d.logger, classifierClient, poller)

	// Prepare constructs the *http.Server synchronously, before the Serve
	// goroutine below is launched, so a stop signal arriving essentially
	// immediately still has a real server for Shutdown to act on (see
	// api.Server.Prepare's doc comment for the race this avoids).
	srv.Prepare()

	sweeperCtx, cancelSweepers := context.WithCancel(ctx)
	defer cancelSweepers()

	poller.Start()
	d.logger.Info("poller goroutine started")
	startBackgroundSweepers(sweeperCtx, srv)
	go monitorHealth(ctx, d.logger, d.health)
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		if err := srv.Serve(); err != nil {
			d.logger.Error("api server stopped", "error", err.Error())
		}
	}()

	<-ctx.Done()
	// Cancel the sweepers right away. Draining the HTTP server before stopping the
	// poller is convention, not a correctness requirement: poller.Stop() only
	// cancels the background ticker loop in Poller.Run, which an in-flight admin
	// "poll now" request never observes — TriggerNow's tick() derives its own
	// context.Background()-based contexts. Stop is non-blocking, so its position
	// relative to Shutdown does not affect correctness.
	cancelSweepers()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		d.logger.Error("api server shutdown error", "error", err.Error())
	}
	// Wait for the Serve goroutine to actually return, exactly as runServer
	// does. Without this, runAll reported a completed shutdown while Serve was
	// still unwinding and still writing — the caller would then close the
	// logger, and the process would exit, mid-write. It surfaced as a flaky
	// "TempDir RemoveAll cleanup: directory not empty" in the shutdown test:
	// the test's temp dir was still being written after runAll had returned.
	<-serveDone
	poller.Stop()
	awaitWarmup(d.logger, warmupDone)
	// Wait for the poller's own goroutines (the tick loop, plus the eager
	// recheckWKDDomains and cleanupAllUsers runs) to finish. Stop only
	// cancels; without this the process could exit, or a test could remove
	// its state directory, while those were still writing to it.
	poller.Wait()
	return nil
}

// mfaClearAllMarkerFile is the break-glass one-shot marker: once MFA_CLEAR_ALL
// has successfully cleared every user's MFA, this file's presence in stateDir
// self-disarms the env var so leaving it set after the fact doesn't silently
// wipe out MFA that users re-enroll on every subsequent restart.
const mfaClearAllMarkerFile = "mfa-clear-all.done"

// mfaClearAllProgressFile persists, per user ID, which users MFA_CLEAR_ALL has
// already cleared during a campaign that has not yet fully succeeded and written
// mfaClearAllMarkerFile.
//
// Without it, a boot that clears users A and B but fails on C writes no marker,
// so the next boot reruns the ENTIRE user list. If A or B re-enrolled MFA in the
// meantime — exactly what the break-glass procedure expects an admin to do — the
// retry silently wipes it out again, and forever if C's failure is permanent.
// Tracking per-user completion means a retry only touches users still
// outstanding.
const mfaClearAllProgressFile = "mfa-clear-all.progress"

// mfaClearAllProgress is the on-disk schema for mfaClearAllProgressFile.
type mfaClearAllProgress struct {
	Cleared []string `json:"cleared"`
}

// loadMFAClearAllCleared reads the set of user IDs already successfully
// cleared by a previous boot's MFA_CLEAR_ALL pass. A missing file (no prior
// partial attempt) is not an error and yields an empty set.
func loadMFAClearAllCleared(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]struct{}{}, nil
	}
	if err != nil {
		return nil, err
	}
	var progress mfaClearAllProgress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil, err
	}
	cleared := make(map[string]struct{}, len(progress.Cleared))
	for _, id := range progress.Cleared {
		cleared[id] = struct{}{}
	}
	return cleared, nil
}

// saveMFAClearAllCleared atomically persists the set of user IDs cleared so
// far, so a subsequent boot (should this one fail partway) knows which users
// are already done and must not be touched again.
func saveMFAClearAllCleared(path string, cleared map[string]struct{}) error {
	ids := make([]string, 0, len(cleared))
	for id := range cleared {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data, err := json.Marshal(mfaClearAllProgress{Cleared: ids})
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path, data, 0o600)
}

// clearAllMFAIfRequested is a break-glass recovery path for self-hosters locked
// out by MFA with no other admin able to reach the Manage Users page. Setting
// MFA_CLEAR_ALL wipes TOTP/recovery codes/push-MFA for every user, but only
// once: a successful clear writes a marker file in stateDir that permanently
// disarms this path, so an operator who forgets to unset the env var does not
// keep re-clearing MFA on every future boot.
//
// If the clear fails partway, the marker is deliberately not written so the next
// boot retries — but only for users not yet recorded in mfaClearAllProgressFile.
func clearAllMFAIfRequested(logger *logging.Logger, usersStore *users.Store, stateDir string) {
	if raw := strings.TrimSpace(os.Getenv("MFA_CLEAR_ALL")); raw == "" {
		return
	} else if enabled, err := strconv.ParseBool(raw); err != nil || !enabled {
		return
	}

	markerPath := filepath.Join(stateDir, mfaClearAllMarkerFile)
	if _, err := os.Stat(markerPath); err == nil {
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		logger.Error("MFA_CLEAR_ALL: failed to check completion marker; skipping clear this boot", "error", err.Error())
		return
	}

	progressPath := filepath.Join(stateDir, mfaClearAllProgressFile)
	cleared, err := loadMFAClearAllCleared(progressPath)
	if err != nil {
		logger.Error("MFA_CLEAR_ALL: failed to read per-user clear progress; skipping clear this boot to avoid re-clearing already-handled users", "error", err.Error())
		return
	}

	all, err := usersStore.List()
	if err != nil {
		logger.Error("MFA_CLEAR_ALL: failed to list users", "error", err.Error())
		return
	}

	clearedThisBoot := 0
	failed := false
	for _, u := range all {
		if _, alreadyCleared := cleared[u.ID]; alreadyCleared {
			// Already successfully cleared by a previous boot of this
			// campaign. Skip unconditionally — even if they now show
			// TOTPEnabled/PushMFAEnabled again because they re-enrolled —
			// so an unrelated user's outstanding failure elsewhere doesn't
			// cause a retry to wipe out their fresh MFA a second time.
			continue
		}
		if !u.TOTPEnabled && !u.PushMFAEnabled {
			continue
		}
		if _, err := usersStore.DisableTOTP(u.ID); err != nil {
			logger.Error("MFA_CLEAR_ALL: failed to clear user", "user_id", u.ID, "error", err.Error())
			failed = true
			continue
		}
		cleared[u.ID] = struct{}{}
		clearedThisBoot++
	}

	if err := saveMFAClearAllCleared(progressPath, cleared); err != nil {
		// The clears that already happened are real and won't be undone,
		// but without a persisted record of them a later boot can't tell
		// they're done, so force a retry path rather than risk declaring
		// this campaign complete based on an unpersisted set.
		logger.Error("MFA_CLEAR_ALL: failed to persist per-user clear progress; will retry on next boot", "error", err.Error())
		failed = true
	}

	if failed {
		logger.Error("MFA_CLEAR_ALL: cleared two-factor auth for some users this boot, but at least one user failed or progress could not be saved; outstanding users will be retried on next boot", "users_cleared_this_boot", strconv.Itoa(clearedThisBoot))
		return
	}

	logger.Error("MFA_CLEAR_ALL is set: cleared two-factor auth for all users", "users_cleared_this_boot", strconv.Itoa(clearedThisBoot))

	if err := fsutil.AtomicWriteFile(markerPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		logger.Error("MFA_CLEAR_ALL: failed to write completion marker; will retry clearing MFA on next boot", "error", err.Error())
		return
	}
	logger.Error("MFA_CLEAR_ALL: cleared two-factor auth for all users and wrote a completion marker; this env var can now be left set safely, it will not clear MFA again")
}

func monitorHealth(ctx context.Context, logger *logging.Logger, healthSvc *health.Service) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	threshold := config.EnvInt("UNHEALTHY_RESTART_SECONDS", 300)
	for {
		select {
		case <-ctx.Done():
			// Stop watching once shutdown starts. Left unbounded (as
			// `for range ticker.C` was), this goroutine outlived every
			// shutdown and could still fire os.Exit(2) while the process was
			// draining — turning a clean exit into exit code 2 and a
			// supervisord "unexpected exit" restart.
			return
		case <-ticker.C:
		}
		st := healthSvc.GetStatus()
		if st.Healthy {
			continue
		}
		if st.UnhealthyFor < int64(threshold) {
			continue
		}
		// No syscall.Kill(1, SIGTERM) here. This used to call it and discard
		// the error, which was always EPERM: the process runs unprivileged and
		// PID 1 does not belong to it, so the call had never once worked. The
		// restart comes entirely from the exit below plus supervisord's
		// autorestart — api.scheduleContainerRestart already says so at its own
		// call site, and this was the sibling that kept the dead line.
		logger.Error("unhealthy threshold exceeded; exiting so supervisord restarts this process",
			"unhealthy_for_seconds", strconv.FormatInt(st.UnhealthyFor, 10))
		os.Exit(2)
	}
}

// newClassifierClient builds the one shared LLM client from the OLLAMA_* env
// vars. The config-file endpoint ("Remote LLM") was removed: it let an operator
// point classification at an arbitrary host from the web UI, which meant email
// content and an API key could be redirected by anyone who reached that form.
func newClassifierClient(cfg config.Config) *classifier.HTTPClient {
	baseURL := strings.TrimSpace(os.Getenv("OLLAMA_BASE_URL"))
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("CLASSIFIER_BASE_URL"))
	}
	if baseURL == "" {
		baseURL = "http://127.0.0.1:11434"
	}

	apiKey := strings.TrimSpace(os.Getenv("OLLAMA_API_KEY"))

	classifyPath := strings.TrimSpace(os.Getenv("OLLAMA_GENERATE_PATH"))
	if classifyPath == "" {
		classifyPath = "/api/generate"
	}

	// Reported, not enforced. The only way to arrive here with a failing base
	// URL is now an env var the operator set directly, which is not a reason to
	// refuse to start a mail server. What it is a reason for is saying so out
	// loud once per boot, because the failure mode this catches (email and the
	// API key crossing the public internet in the clear) has no symptom
	// otherwise: classification keeps working exactly as before.
	if err := classifier.ValidateBaseURL(baseURL); err != nil {
		slog.Error("classifier endpoint fails the transport policy; email content is being sent to it anyway",
			"error", err.Error())
	}

	// The default tuning text only backstops callers that pass no per-call
	// tuning (e.g. users who have not customized their prompt yet).
	tuning := classifier.LoadTuningText()
	return classifier.NewHTTPClient(baseURL, apiKey, classifyPath, tuning, 3*time.Minute)
}

// warmupClassifierOnStartup kicks off the model warmup and the post-warmup
// unread sweep in the background, returning a channel closed once that work has
// finished unwinding.
//
// The context is the caller's shutdown context, not context.Background(). As
// Background with a bare 5-minute timeout, the warmup goroutine kept issuing
// IMAP calls and writing per-user state for up to five minutes after the process
// had been told to shut down — and TriggerUnreadSweep resets every active user's
// checkpoint before it re-scans, so starting that during shutdown risks tearing
// the write.
func warmupClassifierOnStartup(ctx context.Context, logger *logging.Logger, client *classifier.HTTPClient, poller *processor.Poller) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		logger.Info("classifier startup warmup requested")
		if err := client.Warmup(ctx); err != nil {
			logger.Error("classifier startup warmup failed", "error", err.Error())
			return
		}
		logger.Info("classifier startup warmup completed")
		// Re-check before the sweep: Warmup can return nil on a context that
		// was cancelled moments later, and the sweep is the half that writes.
		if ctx.Err() != nil {
			logger.Info("skipping post-warmup unread sweep; shutting down")
			return
		}
		logger.Info("processing unread unlabeled mail after startup warmup")
		poller.TriggerUnreadSweep()
	}()
	return done
}

// awaitWarmup waits for the startup warmup goroutine to unwind, bounded so a
// sweep that is already in flight cannot hold shutdown open indefinitely.
func awaitWarmup(logger *logging.Logger, done <-chan struct{}) {
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		logger.Error("startup warmup did not finish within the shutdown timeout; exiting anyway")
	}
}
