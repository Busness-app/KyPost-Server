package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	mode := fs.String("mode", "all", "process mode: daemon, server, all")
	if err := fs.Parse(args); err != nil {
		return err
	}

	paths := config.Paths{
		ConfigFile: filepath.Join(config.EnvOrDefault("CONFIG_DIR", "/kypost/config"), "config.yaml"),
		StateDir:   config.EnvOrDefault("STATE_DIR", "/kypost/state"),
		LogDir:     config.EnvOrDefault("LOG_DIR", "/kypost/logs"),
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

	store, err := state.New(paths.StateDir)
	if err != nil {
		return fmt.Errorf("create state store: %w", err)
	}

	configDir := config.EnvOrDefault("CONFIG_DIR", "/kypost/config")
	usersStore, err := users.LoadOrMigrate(configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		return fmt.Errorf("load users store: %w", err)
	}

	if err := migrateLegacySingleUserData(logger, usersStore, configDir, paths.StateDir, legacyPrefs, legacyPrefsOK); err != nil {
		logger.Error("legacy single-user data migration failed", "error", err.Error())
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

	switch *mode {
	case "daemon":
		return runDaemon(deps)
	case "server":
		return runServer(deps)
	case "all":
		return runAll(deps)
	default:
		return errors.New("invalid mode; expected daemon, server, or all")
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

func runDaemon(d runDeps) error {
	classifierClient := newClassifierClient(d.cfg)
	poller, err := processor.New(d.cfg, d.logger, d.store, d.users, d.stateDir, d.configDir, d.health, classifierClient, d.wkdStore)
	if err != nil {
		return err
	}
	poller.SetConfigPath(d.configPath)
	warmupClassifierOnStartup(d.logger, classifierClient, poller)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go poller.Run()
	d.logger.Info("poller goroutine started")
	go monitorHealth(d.logger, d.health)
	<-stop
	poller.Stop()
	return nil
}

func runServer(d runDeps) error {
	srv := api.NewServer(d.cfg, d.logger, d.health, d.users, nil, d.wkdStore)
	srv.SetClassifier(newClassifierClient(d.cfg))

	// Prepare constructs the *http.Server synchronously, before the Serve
	// goroutine below is even launched, so a stop signal arriving essentially
	// immediately still has a real server for Shutdown to act on (see
	// api.Server.Prepare's doc comment for the race this avoids).
	srv.Prepare()

	sweeperCtx, cancelSweepers := context.WithCancel(context.Background())
	defer cancelSweepers()
	go srv.StartPickupSweeper(sweeperCtx)
	go srv.StartSendAsCooldownSweeper(sweeperCtx)
	go srv.StartSessionSweeper(sweeperCtx)
	go srv.StartOllamaVersionMonitor(sweeperCtx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve()
	}()

	select {
	case <-stop:
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

func runAll(d runDeps) error {
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
	warmupClassifierOnStartup(d.logger, classifierClient, poller)

	// Prepare constructs the *http.Server synchronously, before the Serve
	// goroutine below is launched, so a stop signal arriving essentially
	// immediately still has a real server for Shutdown to act on (see
	// api.Server.Prepare's doc comment for the race this avoids).
	srv.Prepare()

	sweeperCtx, cancelSweepers := context.WithCancel(context.Background())
	defer cancelSweepers()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go poller.Run()
	d.logger.Info("poller goroutine started")
	go srv.StartPickupSweeper(sweeperCtx)
	go srv.StartSendAsCooldownSweeper(sweeperCtx)
	go srv.StartSessionSweeper(sweeperCtx)
	go srv.StartOllamaVersionMonitor(sweeperCtx)
	go monitorHealth(d.logger, d.health)
	go func() {
		if err := srv.Serve(); err != nil {
			d.logger.Error("api server stopped", "error", err.Error())
		}
	}()

	<-stop
	// Cancel the sweepers right away. Draining the HTTP server before
	// stopping the poller is an arbitrary-but-reasonable convention, not a
	// correctness requirement: poller.Stop() only cancels the background
	// ticker loop in Poller.Run (via p.cancel), which an in-flight admin
	// "poll now" request never observes — TriggerNow's tick() (and the
	// tickUser/handleMessage calls it makes) derive their own fresh
	// context.Background()-based contexts, not p.cancel. So poller.Stop()
	// is non-blocking and fire-and-forget, and its position relative to
	// Shutdown doesn't affect correctness; this order is just kept for
	// readability (network-facing shutdown first, background work last).
	cancelSweepers()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		d.logger.Error("api server shutdown error", "error", err.Error())
	}
	poller.Stop()
	return nil
}

// mfaClearAllMarkerFile is the break-glass one-shot marker: once MFA_CLEAR_ALL
// has successfully cleared every user's MFA, this file's presence in stateDir
// self-disarms the env var so leaving it set after the fact doesn't silently
// wipe out MFA that users re-enroll on every subsequent restart.
const mfaClearAllMarkerFile = "mfa-clear-all.done"

// mfaClearAllProgressFile persists, per user ID, which users MFA_CLEAR_ALL has
// already successfully cleared during an in-progress break-glass campaign —
// one that has not yet fully succeeded and written mfaClearAllMarkerFile.
//
// Without this, a boot that clears users A and B but fails on C would have no
// marker at all (since the campaign as a whole didn't finish), so the next
// boot would rerun the ENTIRE user list, including A and B. If either of them
// re-enrolled MFA in the meantime (exactly what the break-glass procedure
// expects an admin to do), that retry would silently wipe it out again — and
// forever, if C's failure is permanent. Tracking per-user completion means a
// retry only ever touches users still outstanding: once a user is recorded
// here, no later boot (with the env var still set) will clear their MFA again,
// even if they've since re-enrolled.
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

// clearAllMFAIfRequested is a break-glass recovery path for self-hosters
// locked out by MFA with no other admin able to reach the Manage Users page.
// Setting MFA_CLEAR_ALL wipes TOTP/recovery codes/push-MFA for every user,
// but only once: a successful clear writes a marker file in stateDir that
// permanently disarms this path, so an operator who forgets to unset the env
// var afterward does not keep re-clearing MFA on every future boot.
//
// If the clear fails partway (any single user's write errors), the marker is
// deliberately not written so the operator's next boot retries it — but the
// retry only reprocesses users not yet recorded in mfaClearAllProgressFile, so
// users already cleared (and possibly re-enrolled since) are left alone.
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

func monitorHealth(logger *logging.Logger, healthSvc *health.Service) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	threshold := config.EnvInt("UNHEALTHY_RESTART_SECONDS", 300)
	for range ticker.C {
		st := healthSvc.GetStatus()
		if st.Healthy {
			continue
		}
		if st.UnhealthyFor < int64(threshold) {
			continue
		}
		logger.Error("unhealthy threshold exceeded, requesting container restart", "unhealthy_for_seconds", strconv.FormatInt(st.UnhealthyFor, 10))
		_ = syscall.Kill(1, syscall.SIGTERM)
		os.Exit(2)
	}
}

// newClassifierClient builds the one shared LLM client. config.yaml wins when it
// points somewhere real; the OLLAMA_* env vars are the fallback so existing
// env-only deployments keep working. The persisted legacy config default
// ("http://127.0.0.1:3333" with path "/") predates the Ollama runtime and
// is treated as unset.
func newClassifierClient(cfg config.Config) *classifier.HTTPClient {
	const legacyDeadDefault = "http://127.0.0.1:3333"

	baseURL := strings.TrimSpace(cfg.Classifier.BaseURL)
	fromConfig := baseURL != "" && baseURL != legacyDeadDefault
	if !fromConfig {
		baseURL = strings.TrimSpace(os.Getenv("OLLAMA_BASE_URL"))
		if baseURL == "" {
			baseURL = strings.TrimSpace(os.Getenv("CLASSIFIER_BASE_URL"))
		}
		if baseURL == "" {
			baseURL = "http://127.0.0.1:11434"
		}
	}

	apiKey := strings.TrimSpace(cfg.Classifier.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("OLLAMA_API_KEY"))
	}

	classifyPath := ""
	if fromConfig {
		classifyPath = strings.TrimSpace(cfg.Classifier.ClassifyPath)
	}
	if classifyPath == "" || classifyPath == "/" {
		classifyPath = strings.TrimSpace(os.Getenv("OLLAMA_GENERATE_PATH"))
	}
	if classifyPath == "" {
		classifyPath = "/api/generate"
	}

	// The default tuning text only backstops callers that pass no per-call
	// tuning (e.g. users who have not customized their prompt yet).
	tuning := classifier.LoadTuningText()
	return classifier.NewHTTPClient(baseURL, apiKey, classifyPath, tuning, 3*time.Minute)
}

func warmupClassifierOnStartup(logger *logging.Logger, client *classifier.HTTPClient, poller *processor.Poller) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		logger.Info("classifier startup warmup requested")
		if err := client.Warmup(ctx); err != nil {
			logger.Error("classifier startup warmup failed", "error", err.Error())
			return
		}
		logger.Info("classifier startup warmup completed")
		logger.Info("processing unread unlabeled mail after startup warmup")
		poller.TriggerUnreadSweep()
	}()
}
