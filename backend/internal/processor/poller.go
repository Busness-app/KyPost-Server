package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/redaction"
	"kypost-server/backend/internal/retry"
	"kypost-server/backend/internal/rules"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// maxConcurrentUserTicks bounds how many user mailboxes are polled in
// parallel. The shared classifier client serializes classify calls anyway, so
// this mainly overlaps IMAP fetch latency across users.
const maxConcurrentUserTicks = 4

// Poller polls every active user's mailbox each tick. Global config (scan
// interval, rate-limit policy, labels, redaction) is shared; IMAP
// credentials, checkpoint/processed state, tuning prompt, and notification
// preferences are loaded per user.
type Poller struct {
	cfg     config.Config
	cfgMu   sync.RWMutex
	cfgPath string

	log   *logging.Logger
	users *users.Store
	// globalStore holds install-wide state: the sticky AI-credits flag for
	// the one shared LLM backend. Per-user mailbox state lives in stores.
	globalStore          *state.Store
	health               *health.Service
	classifier           *classifier.HTTPClient
	redaction            *redaction.Engine
	nativePushDispatcher *NativePushDispatcher
	// ctx/cancel bound the background tick loop. They are established exactly
	// once, via ctxOnce, and never reassigned afterwards. Previously cancel
	// was assigned inside Run — which executes in its own goroutine — and
	// read by Stop, which raced; when Stop won the read, cancel was still nil
	// and Stop silently did nothing, leaving the poller running through a
	// shutdown that believed it had stopped.
	//
	// New primes them, but Run and Stop prime them too: several tests build a
	// Poller as a struct literal rather than through New, and the zero value
	// has to stay usable.
	ctxOnce sync.Once
	ctx     context.Context
	cancel  context.CancelFunc
	// wg tracks the tick loop and the eager startup goroutines it spawns, so
	// a caller can wait for all poller-owned work to unwind before tearing
	// down the state directory underneath it. Start seeds the counter before
	// Run begins, which is what makes the children's Add calls inside Run
	// legal against a concurrent Wait.
	wg      sync.WaitGroup
	tickSem chan struct{}

	// wkdStore is the single instance-level WKD domain-claim store, shared
	// with (the same *wkdpublish.Store instance as) the API server — see
	// wkdpublish.Store's doc comment for why a shared instance matters.
	wkdStore *wkdpublish.Store

	stateDir    string
	configDir   string
	imapKeyPath string
	// pgpKeyPath is the master key sealing users' PGP private keys — the
	// same PGP_PRIVATE_KEY_FILE the api server resolves — needed here so a
	// send-as verification can add the newly proven address to the user's
	// existing key (see addAliasUserIDToPGPKey).
	pgpKeyPath string

	userMu         sync.Mutex
	stores         map[string]*state.Store
	mailClients    map[string]*mailClientEntry
	mailCaches     map[string]*mailcache.Store
	rulesStores    map[string]*rules.Store
	sendAsStores   map[string]*sendas.Store
	contactsStores map[string]*contacts.Store
	rate           map[string][]time.Time
}

type mailClientEntry struct {
	client  imapadapter.Client
	modTime time.Time
}

// userCtx bundles one user's per-tick dependencies.
type userCtx struct {
	id       string
	username string
	store    *state.Store
	mail     imapadapter.Client
	tuning   string
	settings config.UserNotificationSettings
	// autoLabelEnabled mirrors settings.Labels.AutoApplyEnabled at the time
	// this tick's userCtx was built. When false, handleMessage skips AI
	// classification entirely and tags every message with the account's
	// default label instead (disabledLabelingFallback).
	autoLabelEnabled bool
	// rules holds every filter rule (enabled and disabled) loaded for this
	// tick; rules.Evaluate skips disabled rules and rules out of Scope for
	// the evaluated folder itself, so no pre-filtering happens here.
	rules []rules.Rule
}

func New(cfg config.Config, log *logging.Logger, globalStore *state.Store, usersStore *users.Store, stateDir, configDir string, healthSvc *health.Service, classifierClient *classifier.HTTPClient, wkdStore *wkdpublish.Store) (*Poller, error) {
	re, err := redaction.New(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	p := &Poller{
		cfg:                  cfg,
		log:                  log,
		users:                usersStore,
		globalStore:          globalStore,
		health:               healthSvc,
		classifier:           classifierClient,
		redaction:            re,
		nativePushDispatcher: NewNativePushDispatcher(log),
		wkdStore:             wkdStore,
		stateDir:             stateDir,
		configDir:            configDir,
		imapKeyPath:          config.SecretFile("IMAP_CONFIG_KEY_FILE", "imap-config.key"),
		pgpKeyPath:           config.SecretFile("PGP_PRIVATE_KEY_FILE", "pgp-private-key.key"),
		stores:               map[string]*state.Store{},
		mailClients:          map[string]*mailClientEntry{},
		mailCaches:           map[string]*mailcache.Store{},
		rulesStores:          map[string]*rules.Store{},
		sendAsStores:         map[string]*sendas.Store{},
		contactsStores:       map[string]*contacts.Store{},
		rate:                 map[string][]time.Time{},
	}
	p.tickSem = make(chan struct{}, 1)
	p.tickSem <- struct{}{}
	p.initCtx()
	return p, nil
}

// initCtx establishes the tick loop's context exactly once. Called from New so
// the common path has it before any goroutine starts, and from both Run and
// Stop so a directly-constructed Poller (as several tests build) still works
// and still cannot race.
func (p *Poller) initCtx() {
	p.ctxOnce.Do(func() {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	})
}

func (p *Poller) userStateDir(userID string) string {
	return filepath.Join(p.stateDir, "users", userID)
}

func (p *Poller) userConfigDir(userID string) string {
	return filepath.Join(p.configDir, "users", userID)
}

func (p *Poller) userIMAPConfigPath(userID string) string {
	return filepath.Join(p.userConfigDir(userID), "imap-config.json")
}

func (p *Poller) userTuningPath(userID string) string {
	return filepath.Join(p.userConfigDir(userID), "tuning.md")
}

func (p *Poller) userSettingsPath(userID string) string {
	return filepath.Join(p.userConfigDir(userID), "config.yaml")
}

func (p *Poller) userStore(userID string) (*state.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.stores[userID]; ok {
		return st, nil
	}
	st, err := state.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.stores[userID] = st
	return st, nil
}

// userMailClient returns the cached IMAP client for a user, rebuilding it
// when their encrypted credential file changed on disk.
// The evicted client is closed rather than dropped: it holds a live,
// authenticated IMAP session that nothing else reclaims, and the api process
// keeps its own identical cache — so a credential change leaked one connection
// per process until the far end timed it out. See api.closeMailClient for why
// this is an io.Closer assertion and not a Client interface method.
func (p *Poller) userMailClient(userID string, configModTime time.Time) imapadapter.Client {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if entry, ok := p.mailClients[userID]; ok {
		if entry.modTime.Equal(configModTime) {
			return entry.client
		}
		if c, isCloser := entry.client.(io.Closer); isCloser {
			_ = c.Close()
		}
	}
	client := imapadapter.NewAPIClientFromStoredConfig(p.userIMAPConfigPath(userID), p.imapKeyPath)
	p.mailClients[userID] = &mailClientEntry{client: client, modTime: configModTime}
	return client
}

// userMailCacheStore returns the cached mail-cache store for a user,
// mirroring userStore — the api process independently constructs its own
// mailcache.Store over the same on-disk file (see server_userscope.go's
// userMailCacheStore); refreshFromDiskLocked is what keeps the two
// processes' in-memory views coherent, exactly as with state.Store.
func (p *Poller) userMailCacheStore(userID string) (*mailcache.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.mailCaches[userID]; ok {
		return st, nil
	}
	st, err := mailcache.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.mailCaches[userID] = st
	return st, nil
}

// userRulesStore returns the cached rules store for a user, mirroring
// userMailCacheStore — the api process independently constructs its own
// rules.Store over the same on-disk rules.json (see server_userscope.go's
// userRulesStore); refreshFromDiskLocked is what keeps the two processes'
// in-memory views coherent, exactly as with state.Store.
func (p *Poller) userRulesStore(userID string) (*rules.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.rulesStores[userID]; ok {
		return st, nil
	}
	st, err := rules.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.rulesStores[userID] = st
	return st, nil
}

// userContactsStore returns the cached contacts store for a user, mirroring
// userRulesStore — the api process independently constructs its own
// contacts.Store over the same on-disk contacts.json, so
// refreshFromDiskLocked keeps the two processes' in-memory views coherent,
// exactly as with state.Store.
func (p *Poller) userContactsStore(userID string) (*contacts.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.contactsStores[userID]; ok {
		return st, nil
	}
	st, err := contacts.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.contactsStores[userID] = st
	return st, nil
}

func (p *Poller) SetConfigPath(path string) {
	p.cfgMu.Lock()
	p.cfgPath = strings.TrimSpace(path)
	p.cfgMu.Unlock()
}

func (p *Poller) Run() {
	p.initCtx()
	ctx := p.ctx
	interval := time.Duration(p.cfg.Scan.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 90 * time.Second
	}

	p.log.Info("poller started", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	wkdTicker := time.NewTicker(recheckWKDInterval)
	defer wkdTicker.Stop()

	// time.NewTicker only fires after the first full interval elapses, so
	// without this, a host that restarts more often than every
	// recheckWKDInterval (12h) would never actually run recheckWKDDomains —
	// silently disabling the revocation half of the WKD DNS-proof control.
	// recheckWKDDomains is idempotent and cheap (its per-claim LastCheckedAt
	// due-guard skips anything checked recently), so running it once eagerly
	// here is safe. Backgrounded so it never delays the tick/select loop
	// below from starting.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.recheckWKDDomains()
	}()

	// Retention housekeeping, not per-tick work. Eager first run for the same
	// reason recheckWKDDomains has one: a host restarting more often than the
	// interval would otherwise never run it.
	cleanupTicker := time.NewTicker(stateCleanupInterval)
	defer cleanupTicker.Stop()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.cleanupAllUsers()
	}()

	for {
		select {
		case <-ctx.Done():
			p.log.Info("poller stopped")
			return
		case <-ticker.C:
			p.tick()
		case <-wkdTicker.C:
			p.recheckWKDDomains()
		case <-cleanupTicker.C:
			p.cleanupAllUsers()
		}
	}
}

const (
	// stateCleanupInterval is how often processed-message IDs and decisions are
	// trimmed. Against a 30-day window, a longer gap only means state.json
	// carries a few extra hours of entries past the cutoff.
	stateCleanupInterval = 6 * time.Hour
	// stateRetentionDays bounds both the audit view's history and the size of
	// the two files every mutation rewrites.
	stateRetentionDays = 30
)

// cleanupAllUsers trims expired state for every active user. Errors are logged
// per user and never abort the sweep — one unreadable state directory must not
// stop the others being trimmed.
func (p *Poller) cleanupAllUsers() {
	if p.users == nil {
		// Defensive only, as in recheckWKDDomains: guards Poller values built
		// without New(). Needed here and not in tick() because this also runs
		// eagerly at Run(), before any ticker has fired.
		return
	}
	all, err := p.users.List()
	if err != nil {
		p.log.Error("failed to list users for state cleanup", "error", err.Error())
		return
	}
	for _, u := range all {
		if !u.Active {
			continue
		}
		store, err := p.userStore(u.ID)
		if err != nil {
			p.log.Error("failed to open user state store for cleanup", "user_id", u.ID, "error", err.Error())
			continue
		}
		if err := store.Cleanup(stateRetentionDays); err != nil {
			p.log.Error("state cleanup failed", "user_id", u.ID, "error", err.Error())
		}
	}
}

// Start runs the tick loop in its own goroutine, tracked so Wait can observe
// it. Prefer this over `go p.Run()`: Run spawns further goroutines that write
// per-user state, and only work started through Start is covered by Wait.
func (p *Poller) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.Run()
	}()
}

// Stop cancels the background tick loop. It is safe to call before Run, after
// Run, or concurrently with it, and safe to call more than once
// (context.CancelFunc is idempotent). Stop only signals; use Wait to block
// until the work has actually finished.
func (p *Poller) Stop() {
	p.initCtx()
	p.cancel()
}

// Wait blocks until the tick loop and its startup goroutines have returned.
// Callers that tear down the state directory after shutdown must call this:
// Run eagerly launches recheckWKDDomains and cleanupAllUsers, both of which
// write per-user state, and both of which used to outlive Stop entirely.
// Safe to call on a Poller that was never started — the counter is zero.
func (p *Poller) Wait() {
	p.wg.Wait()
}

func (p *Poller) TriggerNow() {
	p.tick()
}

// TriggerUnreadSweep resets every active user's checkpoint so the next tick
// reconsiders all unread mail, then runs a tick.
func (p *Poller) TriggerUnreadSweep() {
	all, err := p.users.List()
	if err != nil {
		p.log.Error("failed to list users for unread sweep", "error", err.Error())
	} else {
		for _, u := range all {
			if !u.Active {
				continue
			}
			store, err := p.userStore(u.ID)
			if err != nil {
				p.log.Error("failed to open user store for unread sweep", "user_id", u.ID, "error", err.Error())
				continue
			}
			if err := store.SetCheckpoint(""); err != nil {
				p.log.Error("failed to reset checkpoint for unread sweep", "user_id", u.ID, "error", err.Error())
			}
		}
	}
	p.tick()
}

// UpdateConfig swaps the global config and rebuilds the shared redaction
// engine when the patterns changed (previously edits to redaction patterns
// never took effect until restart).
func (p *Poller) UpdateConfig(cfg config.Config) {
	p.cfgMu.Lock()
	patternsChanged := !slices.Equal(p.cfg.Redaction.Patterns, cfg.Redaction.Patterns)
	p.cfg = cfg
	if patternsChanged {
		if re, err := redaction.New(cfg.Redaction.Patterns); err == nil {
			p.redaction = re
		} else {
			p.log.Error("failed to rebuild redaction engine after config update", "error", err.Error())
		}
	}
	p.cfgMu.Unlock()
}

func (p *Poller) currentConfig() config.Config {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.cfg
}

func (p *Poller) currentRedaction() *redaction.Engine {
	p.cfgMu.RLock()
	defer p.cfgMu.RUnlock()
	return p.redaction
}

func (p *Poller) tick() {
	p.reloadConfigIfNeeded()

	// acquire semaphore; if another tick is running, log that we're waiting
	select {
	case <-p.tickSem:
		// acquired immediately
	default:
		p.log.Info("poll tick waiting for previous tick to finish")
		<-p.tickSem
	}
	defer func() { p.tickSem <- struct{}{} }()

	all, err := p.users.List()
	if err != nil {
		p.log.Error("failed to list users for poll tick", "error", err.Error())
		p.health.MarkUnhealthy("users store unreadable")
		return
	}

	sem := make(chan struct{}, maxConcurrentUserTicks)
	var wg sync.WaitGroup
	var resMu sync.Mutex
	usersPolled := 0
	usersFailed := 0

	for _, u := range all {
		if !u.Active {
			continue
		}
		fi, err := os.Stat(p.userIMAPConfigPath(u.ID))
		if err != nil {
			// No mailbox configured for this user yet — nothing to poll.
			continue
		}
		usersPolled++
		wg.Add(1)
		sem <- struct{}{}
		go func(u users.User, modTime time.Time) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					p.log.Error("user poll tick panic", "user_id", u.ID, "panic", fmt.Sprint(r))
					resMu.Lock()
					usersFailed++
					resMu.Unlock()
				}
			}()
			if err := p.tickUser(u, modTime); err != nil {
				resMu.Lock()
				usersFailed++
				resMu.Unlock()
			}
		}(u, fi.ModTime())
	}
	wg.Wait()

	tickFields := []string{"users_polled", strconv.Itoa(usersPolled), "users_failed", strconv.Itoa(usersFailed)}
	// Carry classifier admission depth onto the tick line. A tick that
	// "completed" while messages are still queued behind the model looks
	// identical to a healthy one otherwise, which is how a backlog that never
	// drains stays invisible.
	if p.classifier != nil {
		st := p.classifier.Stats()
		tickFields = append(tickFields,
			"classify_inflight", strconv.Itoa(st.InFlight),
			"classify_queued", strconv.Itoa(st.Queued))
	}
	p.log.Info("poll tick completed", tickFields...)

	// Fault isolation: one broken mailbox must not restart the container.
	// Only flip global health when every polled mailbox failed.
	if usersPolled > 0 && usersFailed == usersPolled {
		p.health.MarkUnhealthy("imap unreachable for all users")
		return
	}
	p.health.MarkHealthy()
}

// tickUser polls one user's mailbox. Errors are logged with the user id and
// reported to the caller for the all-users-failed health check; they never
// affect other users.
// mailCacheEntriesFromMessages converts freshly fetched UNSEEN messages into
// mail-cache entries. Status is always "unread": ListUnreadInbox only ever
// returns messages matching an IMAP UNSEEN search, so there's nothing to
// infer from flags here (unlike the live overview-sync path).
func mailCacheEntriesFromMessages(messages []imapadapter.Message) []mailcache.Entry {
	entries := make([]mailcache.Entry, 0, len(messages))
	for _, msg := range messages {
		uid, err := strconv.Atoi(strings.TrimSpace(msg.ID))
		if err != nil {
			continue
		}
		entries = append(entries, mailcache.Entry{
			UID:            uid,
			MessageID:      msg.ID,
			Subject:        msg.Subject,
			Sender:         msg.Sender,
			SentTo:         msg.SentTo,
			CC:             msg.CC,
			BCC:            msg.BCC,
			Keywords:       msg.Keywords,
			Status:         "unread",
			AtUTC:          msg.AtUTC,
			Body:           msg.Body,
			HasAttachments: msg.HasAttachments,
		})
	}
	return entries
}

func (p *Poller) tickUser(u users.User, imapConfigModTime time.Time) error {
	store, err := p.userStore(u.ID)
	if err != nil {
		p.log.Error("failed to open user state store", "user_id", u.ID, "error", err.Error())
		return err
	}
	// Cleanup runs on its own ticker (cleanupAllUsers), NOT here: it takes both
	// file locks and rewrites and fsyncs both state.json and decisions.json in
	// full, against a 30-day retention window.

	settings, err := config.LoadUserSettings(p.userSettingsPath(u.ID))
	if err != nil {
		p.log.Error("failed to load user settings, using defaults", "user_id", u.ID, "error", err.Error())
		settings = config.DefaultUserSettings()
	}

	tuning := ""
	if b, err := os.ReadFile(p.userTuningPath(u.ID)); err == nil {
		tuning = strings.TrimSpace(string(b))
	}

	rulesStore, err := p.userRulesStore(u.ID)
	var activeRules []rules.Rule
	if err != nil {
		p.log.Error("failed to open user rules store, skipping rule evaluation", "user_id", u.ID, "error", err.Error())
	} else {
		activeRules = rulesStore.List()
	}

	uc := userCtx{
		id:               u.ID,
		username:         u.Username,
		store:            store,
		mail:             p.userMailClient(u.ID, imapConfigModTime),
		tuning:           tuning,
		settings:         settings.Notifications,
		autoLabelEnabled: settings.Labels.AutoApplyEnabled,
		rules:            activeRules,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	checkpoint, err := store.Checkpoint()
	if err != nil {
		// Refuse the tick rather than proceeding with an empty checkpoint. An
		// unreadable checkpoint used to look identical to "never polled", and
		// the response to that is to re-scan the whole mailbox — on every tick,
		// for as long as the read keeps failing.
		p.log.Error("cannot read poll checkpoint; skipping this tick", "user_id", u.ID, "error", err.Error())
		return err
	}
	messages, nextCheckpoint, err := uc.mail.ListUnreadInbox(ctx, checkpoint)
	if err != nil {
		p.log.Error("fetch unread inbox failed", "user_id", u.ID, "error", err.Error())
		return err
	}

	// Opportunistically warm the mail cache with what was just fetched for
	// classification below — reuses the same IMAP round trip and bodies, no
	// extra IMAP calls. Done before classification, and independent of its
	// outcome, so a slow or rate-limited classification run never delays
	// cache freshness. INBOX only, matching ListUnreadInbox's scope — see
	// mailcache/AGENTS.md for why other folders are warmed lazily instead.
	// Hoisted out of the block below so the per-message loop can also mirror an
	// anti-phishing flag into the cache — the warm here runs before that loop,
	// so a message flagged inside it would otherwise carry stale keywords in
	// the cache until the next tick. Stays nil when the store won't open, which
	// mirrorPhishKeyword tolerates.
	var mailCache *mailcache.Store
	if len(messages) > 0 {
		var err error
		if mailCache, err = p.userMailCacheStore(u.ID); err != nil {
			p.log.Error("failed to open mail cache store", "user_id", u.ID, "error", err.Error())
			mailCache = nil
		} else if err := mailCache.Upsert("INBOX", mailCacheEntriesFromMessages(messages)); err != nil {
			p.log.Error("failed to warm mail cache", "user_id", u.ID, "error", err.Error())
		}
	}

	harvestEnabled, harvestSuppressed := p.autocryptHarvestConfig(u.ID)

	// Resolved once per tick rather than per message: it reads and decrypts the
	// sealed IMAP config, and every message in this batch belongs to the same
	// account. Empty is a valid answer — see flagAppImpersonation.
	ownAddress := p.accountAddress(u.ID)

	processedCount := 0
	skippedSeenCount := 0
	failedCount := 0
	rateLimitedCount := 0
	for _, msg := range messages {
		seen, err := store.Seen(msg.ID)
		if err != nil {
			// Unknown is not unprocessed. Reprocessing re-labels the message and
			// re-notifies every paired device; skipping costs one poll interval
			// and the next tick retries.
			p.log.Error("cannot determine processed state; skipping message this tick",
				"user_id", u.ID, "message_id", msg.ID, "error", err.Error())
			skippedSeenCount++
			continue
		}
		if seen {
			skippedSeenCount++
			continue
		}
		// Anti-phishing runs here, ahead of everything below, and the ordering
		// is the point:
		//   - before allowByRate, which breaks this loop once the classifier
		//     budget is spent. A security verdict must not be rationed by an
		//     LLM quota.
		//   - before handleMessage, whose rules engine can move or delete the
		//     message and whose "stop" action returns early, and whose
		//     classifier failure returns before any keyword is applied. Any of
		//     those would silently suppress the flag.
		// Flagging first also means the keyword travels with the message if a
		// user rule subsequently moves it.
		if p.flagAppImpersonation(ctx, uc, msg, ownAddress) {
			p.mirrorPhishKeyword(mailCache, msg)
		}
		if harvestEnabled {
			p.harvestAutocrypt(ctx, uc, msg, harvestSuppressed)
		}
		if !p.allowByRate(u.ID) {
			p.log.Info("rate limit reached, deferring remaining emails", "user_id", u.ID)
			rateLimitedCount = len(messages) - processedCount - skippedSeenCount - failedCount
			break
		}
		messageCtx, messageCancel := context.WithTimeout(context.Background(), 4*time.Minute)
		err = p.handleMessage(messageCtx, uc, msg)
		messageCancel()
		if err != nil {
			failedCount++
			p.recordMessageFailure(store, u.ID, uc, msg, err)
			continue
		}
		processedCount++
	}

	if nextCheckpoint != "" {
		if err := store.SetCheckpoint(nextCheckpoint); err != nil {
			p.log.Error("failed to persist checkpoint", "user_id", u.ID, "error", err.Error())
		}
	}

	p.checkPendingSendAsAliases(ctx, u.ID, uc.mail)
	// Must follow the check above, so it sees the freshest verdict for the
	// account's own address and doesn't probe an address just proven.
	p.ensureOwnAddressProven(u.ID)
	// Must follow the check above, so an alias verified in this very tick
	// gets its PGP User ID without waiting for the next one.
	p.reconcilePGPUserIDs(u.ID)

	p.log.Info(
		"user poll tick summary",
		"user_id", u.ID,
		"username", u.Username,
		"fetched", strconv.Itoa(len(messages)),
		"processed", strconv.Itoa(processedCount),
		"skipped_seen", strconv.Itoa(skippedSeenCount),
		"failed", strconv.Itoa(failedCount),
		"deferred_rate_limited", strconv.Itoa(rateLimitedCount),
	)
	return nil
}

// classifierErr marks an error returned by classifyWithRetry so tickUser's
// message loop (via shouldMarkProcessedOnError) can distinguish classifier
// failures from every other handleMessage failure mode (rule-matching
// errors, IMAP errors), which must keep marking messages processed exactly
// as they did before this gating was introduced.
type classifierErr struct {
	err error
}

func (e *classifierErr) Error() string { return e.err.Error() }
func (e *classifierErr) Unwrap() error { return e.err }

// shouldMarkProcessedOnError reports whether tickUser should mark a message
// processed after handleMessage returned err. A classifier error only marks
// processed when the underlying failure is permanent (bad input / AI
// credits exhausted, per isPermanentClassifierError) — a transient
// classifier outage leaves the message unmarked so it is retried on the
// next poll tick, instead of being silently and permanently skipped. Any
// non-classifier error (rule-matching, IMAP) always marks processed,
// unchanged from prior behavior.
func shouldMarkProcessedOnError(err error) bool {
	var cerr *classifierErr
	if errors.As(err, &cerr) {
		return isPermanentClassifierError(cerr.err)
	}
	return true
}

// maxLoggedLabelBytes bounds a raw model output before it reaches the log.
//
// A well-behaved model answers with one label from the allowlist — a few bytes.
// A misbehaving one can echo back whatever it was fed, which is attacker-
// controlled email content, and app.log is served to any admin by
// GET /api/logs. Truncating means a diagnostic stays a diagnostic instead of
// becoming a channel for message content to escape the owning user's state.db.
const maxLoggedLabelBytes = 64

// clipForLog trims and bounds a model-produced string for logging, and strips
// the newlines that would otherwise let attacker-influenced text forge whole
// log records for anything parsing app.log line by line.
func clipForLog(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
	if len(s) > maxLoggedLabelBytes {
		return s[:maxLoggedLabelBytes] + "...(truncated)"
	}
	return s
}

// recordMessageFailure is what tickUser's message loop runs on every
// handleMessage failure: it logs the failure, records it as a "failed"
// Decision, and marks the message processed — except for a transient
// classifier error, which is deliberately left unmarked so it retries next
// poll tick. Push notifications still fire exactly as before this change;
// only the MarkProcessed gating is new.
func (p *Poller) recordMessageFailure(store *state.Store, userID string, uc userCtx, msg imapadapter.Message, err error) {
	p.log.Error("message processing failed", "user_id", userID, "message_id", msg.ID, "error", err.Error())
	_ = store.AddDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Status:    "failed",
		Detail:    err.Error(),
	})
	if shouldMarkProcessedOnError(err) {
		// Retire the message so it is not retried on the next tick.
		_ = store.MarkProcessed(msg.ID)
	} else {
		p.log.Info("transient classifier error; leaving message unmarked so it is retried next poll tick", "user_id", userID, "message_id", msg.ID)
	}
	p.maybeSendPushNotification(uc, msg, "", nil)
	p.maybeSendNativePushNotification(uc, msg, "", nil)
}

// sendRejectionNotice matches mailmsg.SMTPDeliver's signature. A
// package-level var — rather than calling mailmsg.SMTPDeliver directly — so
// tests can substitute a fake SMTP sender and verify the reject-and-notify
// path without standing up a live SMTP server, the same test-seam idiom
// mailmsg.MaxInboundMessageBytes uses for the size cap itself.
var sendRejectionNotice = mailmsg.SMTPDeliver

// rejectOversizedMessage is handleMessage's branch for a message
// ListUnreadInbox flagged as TooLarge: instead of the normal rule/classify/
// label pipeline (which has no real content to act on — Body was
// deliberately left empty), it best-effort emails a rejection notice to the
// account's own address and records a distinct "rejected_too_large"
// Decision, then marks the message processed so it isn't retried every poll
// tick. A failure to send the notice is logged and folded into the
// Decision's Detail, but never blocks recording the decision or marking the
// message processed — an SMTP misconfiguration must not leave the same
// oversized message retried forever.
func (p *Poller) rejectOversizedMessage(uc userCtx, msg imapadapter.Message) error {
	detail := fmt.Sprintf("message from %q exceeded the %d MiB inbound size limit and was not processed", msg.Sender, mailmsg.MaxInboundMessageBytes/(1<<20))
	if err := p.notifyMessageTooLarge(uc, msg); err != nil {
		p.log.Error("failed to send too-large rejection notice", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
		detail += "; rejection notice could not be sent: " + err.Error()
	}
	if err := uc.store.AddDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Status:    "rejected_too_large",
		Detail:    detail,
	}); err != nil {
		return err
	}
	return uc.store.MarkProcessed(msg.ID)
}

// notifyMessageTooLarge emails a rejection notice to the mailbox owner's own
// address — the IMAP username, the same "this account's address" convention
// api.handleMailSend uses for accountAddr — using the poller's per-user IMAP/
// SMTP config and the mailmsg SMTP-send helpers from Task 16. The notice
// deliberately carries only the sender and subject the rejected message
// already exposed in its IMAP overview (cheap header metadata fetched
// without ever reading the oversized body — see ListUnreadInbox), plus the
// size limit itself: never the message's own content, which this server
// never read into memory in the first place, so there's nothing sensitive
// left to leak.
func (p *Poller) notifyMessageTooLarge(uc userCtx, msg imapadapter.Message) error {
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(p.userIMAPConfigPath(uc.id), p.imapKeyPath)
	if err != nil {
		return fmt.Errorf("read imap config: %w", err)
	}
	if !exists {
		return errors.New("no imap configuration on file for this account")
	}
	accountAddr := mailmsg.SanitizeHeaderValue(payload.Username)
	if accountAddr == "" {
		return errors.New("imap username is required to notify the account")
	}
	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		return err
	}

	notice := mailmsg.Message{
		From:    accountAddr,
		To:      []string{accountAddr},
		Subject: "Message rejected: too large to process",
		Body: fmt.Sprintf(
			"An incoming message was rejected because it exceeded the %d MiB size limit this server enforces, and was not read, classified, or filtered.\n\n"+
				"From: %s\nSubject: %s\n\n"+
				"The message itself was left on the server exactly as delivered — check your mailbox directly to read it — but no label or rule was applied to it.",
			mailmsg.MaxInboundMessageBytes/(1<<20), msg.Sender, msg.Subject,
		),
		Mode: "plain",
	}.Build()

	return sendRejectionNotice(smtpHost, smtpPort, addr, payload.Username, payload.Password, accountAddr, []string{accountAddr}, notice)
}

func (p *Poller) reloadConfigIfNeeded() {
	p.cfgMu.RLock()
	path := p.cfgPath
	p.cfgMu.RUnlock()
	if strings.TrimSpace(path) == "" {
		return
	}
	next, err := config.Load(path)
	if err != nil {
		p.log.Error("failed to reload config for poll tick", "error", err.Error())
		return
	}
	p.UpdateConfig(next)
}

func (p *Poller) handleMessage(ctx context.Context, uc userCtx, msg imapadapter.Message) error {
	// A message ListUnreadInbox flagged as too large to safely fetch (see
	// imapadapter.Message.TooLarge and mailmsg.MaxInboundMessageBytes) skips
	// every ordinary step below — rule matching, classification, labeling —
	// none of which have real content to act on anyway, since Body was
	// deliberately left empty rather than populated with an oversized read.
	if msg.TooLarge {
		return p.rejectOversizedMessage(uc, msg)
	}

	cfg := p.currentConfig()

	// Filter rules run first, before classification (below), and skip it
	// entirely when a matched rule's actions include "stop" — mirrors
	// Sieve's delivery-time semantics and avoids burning a rate-limited
	// Ollama call on mail a rule will immediately delete/spam. Rule
	// matching is local and never leaves the system, so the raw
	// (unredacted) message is used here, unlike the redacted body handed to
	// classifyWithRetry further down.
	uid, _ := strconv.Atoi(strings.TrimSpace(msg.ID))
	ruleInput := rules.EvalInput{
		UID:       uid,
		MessageID: msg.ID,
		From:      msg.Sender,
		To:        msg.SentTo,
		CC:        msg.CC,
		BCC:       msg.BCC,
		Subject:   msg.Subject,
		Body:      msg.Body,
		Keywords:  msg.Keywords,
		Folder:    "INBOX",
	}
	outcome := rules.Evaluate(ruleInput, uc.rules)
	if len(outcome.Matched) > 0 {
		results := rules.ApplyOutcome(ctx, uc.mail, "INBOX", ruleInput, outcome)
		detail := "rule(s) applied: " + strings.Join(outcome.Matched, ", ")
		var failures []string
		for _, r := range results {
			if r.Err == nil {
				continue
			}
			p.log.Error(
				"rule action failed",
				"user_id", uc.id,
				"message_id", msg.ID,
				"rules_matched", strings.Join(outcome.Matched, ", "),
				"action", r.Action.Type,
				"error", r.Err.Error(),
			)
			failures = append(failures, fmt.Sprintf("%s: %s", r.Action.Type, r.Err.Error()))
		}
		if len(failures) > 0 {
			detail += fmt.Sprintf("; %d action(s) failed: %s", len(failures), strings.Join(failures, "; "))
		}
		if err := uc.store.AddDecision(state.Decision{
			MessageID: msg.ID,
			Sender:    msg.Sender,
			SentTo:    msg.SentTo,
			Subject:   msg.Subject,
			Status:    "applied",
			Detail:    detail,
		}); err != nil {
			return err
		}
		if outcome.Stopped {
			if err := uc.store.MarkProcessed(msg.ID); err != nil {
				return err
			}
			p.maybeSendPushNotification(uc, msg, "", nil)
			p.maybeSendNativePushNotification(uc, msg, "", nil)
			return nil
		}
	}

	if !uc.autoLabelEnabled {
		defaultLabel := disabledLabelingFallback(cfg.Labels.Allowlist)
		keywords := keywordsForSelectedLabel(defaultLabel, cfg.Labels.KeywordMappings)
		p.log.Info(
			"auto-labeling disabled; tagging default label",
			"user_id", uc.id,
			"message_id", msg.ID,
			"selected_label", defaultLabel,
			"keywords", strings.Join(keywords, ","),
		)
		if err := applyKeywordsWithRetry(ctx, uc.mail, msg.ID, keywords); err != nil {
			p.log.Error("label apply failed", "user_id", uc.id, "message_id", msg.ID, "selected_label", defaultLabel, "error", err.Error())
			return err
		}
		if err := uc.store.MarkProcessed(msg.ID); err != nil {
			return err
		}
		if err := uc.store.AddDecision(state.Decision{
			MessageID: msg.ID,
			Sender:    msg.Sender,
			SentTo:    msg.SentTo,
			Subject:   msg.Subject,
			Label:     defaultLabel,
			Status:    "applied",
			Detail:    "automatic keyword labeling disabled; tagged " + defaultLabel,
		}); err != nil {
			return err
		}
		p.maybeSendPushNotification(uc, msg, defaultLabel, keywords)
		p.maybeSendNativePushNotification(uc, msg, defaultLabel, keywords)
		return nil
	}

	body := strings.TrimSpace(msg.Body)
	if len(body) > 2000 {
		body = body[:2000]
	}
	redacted := p.currentRedaction().Apply(body)

	// Clamp the headers too. The prompt builder puts the instruction block, the
	// nonced fence and the tuning document BEFORE the email text, and Ollama
	// truncates from the front — so an unbounded Subject pushes the fence out
	// of num_ctx and the model sees attacker text with no instructions. The
	// classifier's own num_ctx note assumes a bounded worst-case prompt; only
	// the body was actually bounded. Rune-wise so a multi-byte character is
	// never split.
	sender := truncateRunes(strings.TrimSpace(msg.Sender), maxClassifySenderRunes)
	subject := truncateRunes(strings.TrimSpace(msg.Subject), maxClassifySubjectRunes)

	label, err := classifyWithRetry(ctx, p.classifier, cfg.Labels.Allowlist, sender, subject, redacted, uc.tuning)
	// The model answering with something that isn't an allowed label is a
	// normal outcome, not a classifier failure: fall through to the
	// "no known label returned" skip path below (which retires the message
	// and still notifies) rather than treating it as an error worth
	// retrying or worth blocking MarkProcessed on.
	var noLabel *classifier.NoAllowedLabelError
	if errors.As(err, &noLabel) {
		label, err = noLabel.Output, nil
	}
	if err != nil {
		if isAICreditsExhaustedError(err) {
			p.flagAICreditsExhausted()
		}
		// Wrapped so the caller (tickUser, via shouldMarkProcessedOnError)
		// can tell a classifier failure apart from rule/IMAP errors and gate
		// MarkProcessed on isPermanentClassifierError instead of always
		// retiring the message — see recordMessageFailure.
		return &classifierErr{err: err}
	}
	// A successful classification means the classifier has credits again; clear any flag.
	p.clearAICreditsExhausted()
	// No sender and no subject. This logger writes to the instance-wide app.log
	// that GET /api/logs serves to ANY admin, so anything put here leaves every
	// user's correspondence metadata readable by an account that is not theirs —
	// on a server whose whole premise is that only the recipient can read their
	// mail. Sender and subject are already recorded in the state.Decision row
	// below, which lives in the user's own state.db and is served only to them.
	// The message id is enough to join the two when debugging.
	p.log.Info("classification result", "user_id", uc.id, "message_id", msg.ID, "raw_label", clipForLog(label))
	selected := classifier.SelectLabelFromText(cfg.Labels.Allowlist, label)
	if selected == "" {
		p.log.Info("classification skipped", "user_id", uc.id, "message_id", msg.ID, "reason", "no known label returned", "raw_label", clipForLog(label), "allowlist_count", strconv.Itoa(len(cfg.Labels.Allowlist)))
		_ = uc.store.AddDecision(state.Decision{
			MessageID: msg.ID,
			Sender:    msg.Sender,
			SentTo:    msg.SentTo,
			Subject:   msg.Subject,
			Status:    "skipped",
			Detail:    "no known label returned",
		})
		if err := uc.store.MarkProcessed(msg.ID); err != nil {
			return err
		}
		p.maybeSendPushNotification(uc, msg, "", nil)
		p.maybeSendNativePushNotification(uc, msg, "", nil)
		return nil
	}
	keywords := keywordsForSelectedLabel(selected, cfg.Labels.KeywordMappings)
	p.log.Info(
		"applying label",
		"user_id", uc.id,
		"message_id", msg.ID,
		"selected_label", selected,
		"keywords", strings.Join(keywords, ","),
	)
	if err := applyKeywordsWithRetry(ctx, uc.mail, msg.ID, keywords); err != nil {
		p.log.Error("label apply failed", "user_id", uc.id, "message_id", msg.ID, "selected_label", selected, "error", err.Error())
		return err
	}
	p.log.Info("label applied", "user_id", uc.id, "message_id", msg.ID, "selected_label", selected, "keywords", strings.Join(keywords, ","))
	if err := uc.store.MarkProcessed(msg.ID); err != nil {
		return err
	}
	if err := uc.store.AddDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Label:     selected,
		Status:    "applied",
		Detail:    "label applied successfully",
	}); err != nil {
		return err
	}
	p.maybeSendPushNotification(uc, msg, selected, keywords)
	p.maybeSendNativePushNotification(uc, msg, selected, keywords)
	return nil
}

func (p *Poller) maybeSendPushNotification(uc userCtx, msg imapadapter.Message, selectedLabel string, messageKeywords []string) {
	cfg := p.currentConfig()
	if !shouldSendNotification(uc.settings, selectedLabel, messageKeywords) {
		p.log.Info(
			"new-email push notification skipped",
			"reason", "notification mode/keywords did not match",
			"user_id", uc.id,
			"message_id", msg.ID,
			"mode", strings.ToLower(strings.TrimSpace(uc.settings.Mode)),
			"selected_label", strings.TrimSpace(selectedLabel),
			"message_keywords", strings.Join(messageKeywords, ","),
			"configured_keywords", strings.Join(uc.settings.Keywords, ","),
		)
		return
	}

	subs := uc.store.ListNotificationSubscriptions()
	if len(subs) == 0 {
		p.log.Info(
			"new-email push notification skipped",
			"reason", "no active push subscriptions",
			"user_id", uc.id,
			"message_id", msg.ID,
		)
		return
	}

	privateKeyPath := strings.TrimSpace(cfg.Notifications.PrivateKeyPath)
	publicKey := strings.TrimSpace(cfg.Notifications.PublicKey)
	if privateKeyPath == "" || publicKey == "" {
		p.log.Error("notifications enabled but vapid key material missing")
		return
	}

	// Web push payloads are encrypted to the browser's own subscription keys
	// (RFC 8291), so unlike the native relay path the push service sees only
	// ciphertext and there is no third-party disclosure here. The
	// ContentPreview setting is still honored, because a user who asked not
	// to see senders and subjects in notifications means on their lock
	// screen too, not just in transit.
	title := "New Email"
	body := "You have a new email."
	if uc.settings.ContentPreview {
		body = buildNotificationBody(msg)
	}

	// Deep-link straight to the email that triggered the notification
	// instead of the generic inbox view, so tapping the notification opens
	// the message rather than dropping the user on whatever tab happens to
	// be active.
	linkParams := url.Values{}
	linkParams.Set("message", strings.TrimSpace(msg.ID))
	if tab := strings.TrimSpace(selectedLabel); tab != "" {
		linkParams.Set("tab", tab)
	}

	payloadBytes, err := json.Marshal(map[string]any{
		"title": title,
		"body":  body,
		"url":   "/read?" + linkParams.Encode(),
		"tag":   fmt.Sprintf("kypost-email-%s", strings.TrimSpace(msg.ID)),
	})
	if err != nil {
		p.log.Error("failed to marshal notification payload", "error", err.Error())
		return
	}

	outcome, err := SendWebPush(uc.store, publicKey, privateKeyPath, 300, payloadBytes)
	if err != nil {
		p.log.Error("failed to load notification private key", "error", err.Error())
		return
	}

	p.log.Info(
		"new-email push notification attempt",
		"user_id", uc.id,
		"message_id", msg.ID,
		"subscriptions", strconv.Itoa(outcome.Subscriptions),
		"sent", strconv.Itoa(outcome.Sent),
		"failed", strconv.Itoa(outcome.Failed),
		"removed_stale", strconv.Itoa(outcome.Removed),
	)
}

func (p *Poller) maybeSendNativePushNotification(uc userCtx, msg imapadapter.Message, selectedLabel string, messageKeywords []string) {
	if !shouldSendNotification(uc.settings, selectedLabel, messageKeywords) {
		return
	}

	devices := uc.store.ListNativeDevices()
	if len(devices) == 0 {
		return
	}

	includeContent := uc.settings.ContentPreview
	title, body := buildNativeNotificationText(msg, includeContent)
	data := buildNativePushData(msg, messageKeywords, title, body, includeContent)

	// title/body are duplicated into data so a mobile client that renders its
	// own notification from the data payload shows the sender and subject
	// instead of a generic fallback.
	notification := NativePushMessage{Title: title, Body: body, Data: data}

	outcome, err := SendNativePush(context.Background(), p.nativePushDispatcher, p.health, uc.store, notification, func(device state.NativeDevice, platform string, sendErr error) {
		// TODO(server-side management): a failed send (relay unreachable,
		// upstream 5xx, or a 429 when the relay's per-server rate limit is
		// exceeded) currently drops the push — the email still syncs in-app,
		// but no notification fires. Add server-side handling: honor the
		// relay's Retry-After, queue and re-attempt over-limit / transient
		// failures with backoff, and surface persistent failures to the user.
		p.log.Error(
			"native notification failed",
			"user_id", uc.id,
			"message_id", msg.ID,
			"device_id", strings.TrimSpace(device.DeviceID),
			"platform", platform,
			// "sent_via", not "sender": this names the delivery path, and
			// overloading "sender" — which everywhere else in this package means
			// an email's From address — is how a field that must never be logged
			// ends up looking like one that already is.
			"sent_via", "relay",
			"error", sendErr.Error(),
		)
	})

	// App Pull mode bypasses the relay and Firebase: queue the notification
	// server-side for the paired device to fetch over plain HTTP.
	if outcome.Queued {
		if err != nil {
			p.log.Error("failed to queue native pull notification", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
			return
		}
		p.log.Info("new-email native notification queued for pull", "user_id", uc.id, "message_id", msg.ID)
		return
	}

	p.log.Info(
		"new-email native notification attempt",
		"user_id", uc.id,
		"message_id", msg.ID,
		"devices", strconv.Itoa(outcome.Devices),
		"sent", strconv.Itoa(outcome.Sent),
		"failed", strconv.Itoa(outcome.Failed),
		"removed_stale", strconv.Itoa(outcome.Removed),
	)
}

func shouldSendNotification(settings config.UserNotificationSettings, selectedLabel string, messageKeywords []string) bool {
	mode := strings.ToLower(strings.TrimSpace(settings.Mode))
	switch mode {
	case "none", "":
		return false
	case "all":
		return true
	case "keywords":
		selected := strings.TrimSpace(selectedLabel)
		if selected != "" {
			messageKeywords = append([]string{selected}, messageKeywords...)
		}

		enabled := map[string]bool{}
		for _, keyword := range settings.Keywords {
			clean := strings.ToLower(strings.TrimSpace(keyword))
			if clean != "" {
				enabled[clean] = true
			}
		}
		if len(enabled) == 0 {
			return false
		}

		for _, keyword := range messageKeywords {
			key := strings.ToLower(strings.TrimSpace(keyword))
			if key != "" && enabled[key] {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func buildNotificationBody(msg imapadapter.Message) string {
	from := strings.TrimSpace(msg.Sender)
	subject := strings.TrimSpace(msg.Subject)
	if from == "" && subject == "" {
		return "You have a new email."
	}
	if from == "" {
		return fmt.Sprintf("Subject: %s", subject)
	}
	if subject == "" {
		return fmt.Sprintf("From: %s", from)
	}
	return fmt.Sprintf("From %s: %s", from, subject)
}

// buildNativeNotificationText renders a mobile push. With includeContent it
// reads as a mail app's does — sender as the title, subject as the body.
// Without it, the notification is generic and carries no message metadata at
// all.
//
// includeContent is off unless the user turned on
// UserNotificationSettings.ContentPreview, because a native push is not
// delivered by this server: it goes backend -> relay Worker -> FCM/APNs, in
// cleartext to every hop. See that field's doc comment.
func buildNativeNotificationText(msg imapadapter.Message, includeContent bool) (title, body string) {
	if !includeContent {
		return "KyPost", "You have a new email."
	}
	from := strings.TrimSpace(msg.Sender)
	subject := strings.TrimSpace(msg.Subject)
	title = from
	if title == "" {
		title = "New Email"
	}
	body = subject
	if body == "" {
		body = "You have a new email."
	}
	return title, body
}

// buildNativePushData builds the data payload accompanying a native push.
//
// Without includeContent it carries only the message id (so tapping the
// notification can open the right message once the app syncs over its own
// authenticated connection) and the deep link. No sender, no subject, no
// keywords — keywords leak the classification, which is itself a statement
// about the message.
//
// The sender appears under both "sender" and "senderName", and the subject
// under both "subject" and "emailSubject". That is not redundancy to clean
// up: the mobile client reads senderName/emailSubject on the FCM path and
// falls back to sender/subject on the App Pull path, so removing either pair
// breaks one of them. The client already renders generic text when they are
// absent, which is exactly what this function produces when previews are off.
func buildNativePushData(msg imapadapter.Message, messageKeywords []string, title, body string, includeContent bool) map[string]string {
	data := map[string]string{
		"messageId": strings.TrimSpace(msg.ID),
		"url":       "/read",
	}
	if !includeContent {
		return data
	}
	data["sender"] = strings.TrimSpace(msg.Sender)
	data["subject"] = strings.TrimSpace(msg.Subject)
	data["senderName"] = strings.TrimSpace(msg.Sender)
	data["emailSubject"] = strings.TrimSpace(msg.Subject)
	data["Keywords"] = strings.Join(messageKeywords, ",")
	data["title"] = title
	data["body"] = body
	return data
}

func classifyWithRetry(ctx context.Context, c *classifier.HTTPClient, labels []string, sender, subject, body, tuning string) (string, error) {
	return retry.Loop(ctx, 3, func(attempt int) time.Duration {
		return 5 * time.Second
	}, func(attempt int) (string, error, bool) {
		out, err := c.Classify(ctx, labels, sender, subject, body, tuning)
		if err == nil && out != "" {
			return out, nil, false
		}
		if err != nil && isPermanentClassifierError(err) {
			return "", err, false
		}
		if err == nil {
			// Classify returned no error but an empty label — treat as retryable.
			err = fmt.Errorf("classifier returned empty label")
		}
		return "", err, true
	})
}

func isPermanentClassifierError(err error) bool {
	if err == nil {
		return false
	}
	// The model gave a real answer that just isn't on the allowlist. Asking
	// the same question two more times, five seconds apart, is not going to
	// change that — and the caller handles it as a skip, not a failure.
	var noLabel *classifier.NoAllowedLabelError
	if errors.As(err, &noLabel) {
		return true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "422") {
		return true
	}
	if strings.Contains(msg, "invalid input") || strings.Contains(msg, "unprocessable") {
		return true
	}
	// Out of AI credits will not recover on retry; stop hammering the classifier.
	if isAICreditsExhaustedError(err) {
		return true
	}
	return false
}

// isAICreditsExhaustedError reports whether a classify error is the classifier signalling
// that the weekly chat limit / AI credits have been exhausted.
func isAICreditsExhaustedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "out of ai credits") ||
		strings.Contains(msg, "weekly chat limit")
}

// flagAICreditsExhausted persists the AI-credits flag, mirrors it onto the
// health status, and logs once on the false->true transition.
func (p *Poller) flagAICreditsExhausted() {
	now := time.Now().UTC().Format(time.RFC3339)
	newly, err := p.globalStore.SetAICreditsExhausted(now)
	if err != nil {
		p.log.Error("failed to persist ai credits exhausted flag", "error", err.Error())
	}
	p.health.SetAICreditsExhausted(now)
	if newly {
		p.log.Error("AI credits exhausted; email classification paused until credits reset",
			"detail", "classifier returned the weekly chat limit response")
	}
}

// clearAICreditsExhausted resets the AI-credits flag after a successful classify.
func (p *Poller) clearAICreditsExhausted() {
	if exhausted, _ := p.globalStore.AICreditsExhausted(); !exhausted {
		return
	}
	cleared, err := p.globalStore.ClearAICreditsExhausted()
	if err != nil {
		p.log.Error("failed to clear ai credits exhausted flag", "error", err.Error())
	}
	p.health.ClearAICreditsExhausted()
	if cleared {
		p.log.Info("AI credits restored; email classification resumed")
	}
}

func applyKeywordsWithRetry(ctx context.Context, c imapadapter.Client, messageID string, keywords []string) error {
	for _, keyword := range keywords {
		if err := applySingleKeywordWithRetry(ctx, c, messageID, keyword); err != nil {
			return err
		}
	}
	return nil
}

// maxClassifySenderRunes/maxClassifySubjectRunes bound the two header values
// that reach the classification prompt. Generous for real headers, and small
// enough that neither can push the instruction block out of the model's
// context window.
const (
	maxClassifySenderRunes  = 256
	maxClassifySubjectRunes = 512
)

// truncateRunes clips s to at most n runes, never splitting a character.
func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func applySingleKeywordWithRetry(ctx context.Context, c imapadapter.Client, messageID, keyword string) error {
	_, err := retry.Loop(ctx, 3, func(attempt int) time.Duration {
		return 30 * time.Second
	}, func(attempt int) (struct{}, error, bool) {
		err := c.EnsureLabel(ctx, keyword)
		if err == nil {
			err = c.ApplyLabel(ctx, messageID, keyword)
		}
		if err == nil {
			return struct{}{}, nil, false
		}
		// A keyword the IMAP grammar cannot express fails the same way every
		// time, before any network I/O. Retrying it bought nothing and cost
		// two 30s sleeps per message inside the instance-wide tick semaphore,
		// stalling classification for every user. Config can hand us one:
		// mailbox names may contain spaces, keywords may not, and the label
		// allowlist is populated from mailbox names by the UI.
		if errors.Is(err, imapadapter.ErrUnsafeKeyword) {
			return struct{}{}, err, false
		}
		return struct{}{}, err, true
	})
	return err
}

// disabledLabelingFallback picks the label applied when auto-labeling is
// off. "Primary" is preferred for backward compatibility, but it only
// matches a tab the frontend actually shows by default
// (server.go's bucket()/firstMatchingKeyword, ReadPage.tsx's tabs[0]
// default) when it's genuinely one of the account's configured labels. If
// it isn't, falling back to the literal string leaves mail silently
// stranded in the Uncategorized tab, which looks like mail vanishing
// (effectively an unrequested auto-archive) rather than being sorted.
func disabledLabelingFallback(allowlist []string) string {
	for _, label := range allowlist {
		if strings.EqualFold(strings.TrimSpace(label), "Primary") {
			return strings.TrimSpace(label)
		}
	}
	if len(allowlist) > 0 {
		return strings.TrimSpace(allowlist[0])
	}
	return "Primary"
}

func keywordsForSelectedLabel(label string, mappings map[string][]string) []string {
	base := strings.TrimSpace(label)
	if base == "" {
		return []string{}
	}

	out := []string{base}
	for mappedLabel, mappedKeywords := range mappings {
		if !strings.EqualFold(strings.TrimSpace(mappedLabel), base) {
			continue
		}
		for _, keyword := range mappedKeywords {
			if cleaned := strings.TrimSpace(keyword); cleaned != "" {
				out = append(out, cleaned)
			}
		}
		break
	}

	seen := map[string]bool{}
	unique := make([]string, 0, len(out))
	for _, keyword := range out {
		key := strings.ToLower(strings.TrimSpace(keyword))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, strings.TrimSpace(keyword))
	}
	return unique
}

// allowByRate applies the global rate-limit policy as an independent budget
// per user, so one busy mailbox cannot starve the others.
func (p *Poller) allowByRate(userID string) bool {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	cfg := p.currentConfig()
	now := time.Now()
	minuteCutoff := now.Add(-1 * time.Minute)
	hourCutoff := now.Add(-1 * time.Hour)
	window := p.rate[userID]
	trimmed := make([]time.Time, 0, len(window))
	for _, t := range window {
		if t.After(hourCutoff) {
			trimmed = append(trimmed, t)
		}
	}
	minuteCount := 0
	for _, t := range trimmed {
		if t.After(minuteCutoff) {
			minuteCount++
		}
	}
	if minuteCount >= cfg.RateLimits.PerMinute || len(trimmed) >= cfg.RateLimits.PerHour {
		p.rate[userID] = trimmed
		return false
	}
	p.rate[userID] = append(trimmed, now)
	return true
}
