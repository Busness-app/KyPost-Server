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
	// ctx/cancel bound the background tick loop. They are established exactly once,
	// via ctxOnce, and never reassigned. Assigning cancel inside Run — which runs in
	// its own goroutine — raced with Stop, which could read a nil cancel and
	// silently do nothing, leaving the poller running through a shutdown that
	// believed it had stopped.
	//
	// New primes them, but Run and Stop prime them too: several tests build a Poller
	// as a struct literal, and the zero value has to stay usable.
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

	// newMailClient builds one user's IMAP client from their sealed credential
	// file. A field rather than a direct call to
	// imapadapter.NewAPIClientFromStoredConfig — the same test-seam idiom as
	// sendRejectionNotice — so a test can drive a whole tickUser against a
	// scripted mailbox and assert what the checkpoint, the processed set and
	// the audit log look like afterwards. Those are the contracts that decide
	// whether mail is retried or thrown away, and until this existed they could
	// only be tested a piece at a time. nil means the real client.
	newMailClient func(configPath, keyPath string) imapadapter.Client

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

// lifetimeCtx is the poller's own context: cancelled by Stop, and by nothing
// else. Notification delivery uses it rather than context.Background() so a
// shutdown can actually interrupt a relay that is timing out — three attempts
// at a 12s timeout apiece, per device, otherwise runs to completion with
// nothing able to stop it. It is not the per-message context, which is
// cancelled as soon as handleMessage returns and so would abort the very
// notification the message just earned (and is already cancelled by the time
// recordMessageFailure notifies).
//
// It calls initCtx for the same reason Run and Stop do: a directly-constructed
// Poller, as several tests build, has never been through New.
func (p *Poller) lifetimeCtx() context.Context {
	p.initCtx()
	return p.ctx
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

// userMailClient returns the cached IMAP client for a user, rebuilding it when
// their encrypted credential file changed on disk. The evicted client is closed
// rather than dropped: it holds a live, authenticated IMAP session that nothing
// else reclaims, and the api process keeps its own identical cache. See
// api.closeMailClient for why this is an io.Closer assertion.
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
	build := p.newMailClient
	if build == nil {
		build = func(configPath, keyPath string) imapadapter.Client {
			return imapadapter.NewAPIClientFromStoredConfig(configPath, keyPath)
		}
	}
	client := build(p.userIMAPConfigPath(userID), p.imapKeyPath)
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

	// time.NewTicker only fires after the first full interval, so a host that
	// restarts more often than recheckWKDInterval (12h) would never run
	// recheckWKDDomains — silently disabling the revocation half of the WKD
	// DNS-proof control. It is idempotent and cheap (its per-claim LastCheckedAt
	// guard skips anything checked recently), so one eager run is safe. Backgrounded
	// so it never delays the tick loop from starting.
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
	// trimmed. Against a 30-day window, a longer gap only means state.db
	// carries a few extra hours of entries past the cutoff.
	stateCleanupInterval = 6 * time.Hour
	// stateRetentionDays bounds both the audit view's history and the growth of
	// the processed and decisions tables.
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
	if patternsChanged {
		re, err := redaction.New(cfg.Redaction.Patterns)
		if err != nil {
			// Refuse the update rather than committing it. Assigning p.cfg
			// first meant a pattern set that failed to compile was still
			// recorded as current, so every later diff said "unchanged", the
			// rebuild never retried, and redaction silently kept enforcing the
			// OLD set while the API reported the new one as live — a privacy
			// control failing open and quietly.
			p.log.Error("refusing config update: redaction patterns do not compile", "error", err.Error())
			p.cfgMu.Unlock()
			return
		}
		p.redaction = re
	}
	p.cfg = cfg
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

// mailCacheEntriesFromMessages converts freshly fetched UNSEEN messages into
// mail-cache entries. Status is always "unread": ListUnreadInbox only returns
// messages matching an IMAP UNSEEN search, so there is nothing to infer from
// flags here (unlike the live overview-sync path).
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
	// Cleanup runs on its own ticker (cleanupAllUsers), NOT here: it is two
	// DELETEs in one transaction against a 30-day retention window, and there
	// is no reason to pay them on the poll path.

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
	} else if activeRules, err = rulesStore.List(); err != nil {
		// Same answer as a store that won't open: rules move, mark as spam and
		// delete, so a list this cycle cannot confirm is not one to act on.
		p.log.Error("failed to read user rules, skipping rule evaluation", "user_id", u.ID, "error", err.Error())
		activeRules = nil
	} else {
		// rules.json predates ValidateRule and is a plain file in the user's
		// state directory, so the API's write boundaries cannot be the only
		// gate — see rules.FilterRunnable. An unexecutable rule skipped here
		// with one log line per tick is the alternative to it failing on every
		// matching message, which the error taxonomy below treats as retryable
		// and therefore defers each of them for the full maxDeferralAttempts
		// window before retiring them unlabelled.
		var rejected []string
		activeRules, rejected = rules.FilterRunnable(activeRules)
		for _, why := range rejected {
			p.log.Error("skipping unexecutable rule", "user_id", u.ID, "reason", why)
		}
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
	// classification below — same IMAP round trip and bodies, no extra calls. Run
	// before classification and independent of its outcome, so a slow or
	// rate-limited classification never delays cache freshness. INBOX only, matching
	// ListUnreadInbox's scope; see mailcache/AGENTS.md for why other folders are
	// warmed lazily.
	//
	// Hoisted above the per-message loop so that loop can mirror an anti-phishing
	// flag into the cache. Stays nil when the store won't open, which
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
	// deferredIDs are the messages this tick is leaving for a later one. Every
	// "the next tick retries it" below is only true if the checkpoint stays
	// below them — ListUnreadInbox filters on UID > checkpoint and advances its
	// returned value to the highest UID it fetched regardless of outcome, so an
	// unclamped write here retires exactly the messages these branches meant to
	// keep. See imapadapter.ClampCheckpoint.
	var deferredIDs []string
	// ledgerErr records that the deferral counter could not be written for at
	// least one message this tick. The tick's own work still completes — the
	// checkpoint clamp below is the part that matters — but the tick is
	// reported as failed so a state-store outage reaches health instead of
	// showing up only as mail that quietly stopped being processed.
	var ledgerErr error
	for i, msg := range messages {
		seen, err := store.Seen(msg.ID)
		if err != nil {
			// Unknown is not unprocessed. Reprocessing re-labels the message and
			// re-notifies every paired device; skipping costs one poll interval
			// and the next tick retries.
			p.log.Error("cannot determine processed state; skipping message this tick",
				"user_id", u.ID, "message_id", msg.ID, "error", err.Error())
			deferredIDs = append(deferredIDs, msg.ID)
			skippedSeenCount++
			continue
		}
		if seen {
			skippedSeenCount++
			continue
		}
		// Anti-phishing runs ahead of everything below, and the ordering is the point:
		//   - before allowByRate, which breaks this loop once the classifier budget is
		//     spent. A security verdict must not be rationed by an LLM quota.
		//   - before handleMessage, whose rules engine can move or delete the message,
		//     whose "stop" action returns early, and whose classifier failure returns
		//     before any keyword is applied.
		// Flagging first also means the keyword travels with the message if a user rule
		// subsequently moves it.
		if p.flagAppImpersonation(ctx, uc, msg, ownAddress) {
			p.mirrorPhishKeyword(mailCache, msg)
		}
		if harvestEnabled {
			p.harvestAutocrypt(ctx, uc, msg, harvestSuppressed)
		}
		if !p.allowByRate(u.ID) {
			p.log.Info("rate limit reached, deferring remaining emails", "user_id", u.ID)
			rateLimitedCount = len(messages) - processedCount - skippedSeenCount - failedCount
			// "Deferring" is the whole point of the break: this message and
			// everything after it are untouched, so the checkpoint must not
			// advance past them. Any already-processed message swept up here is
			// filtered by the Seen gate above on the next tick.
			for _, deferred := range messages[i:] {
				deferredIDs = append(deferredIDs, deferred.ID)
			}
			break
		}
		messageCtx, messageCancel := context.WithTimeout(context.Background(), 4*time.Minute)
		err = p.handleMessage(messageCtx, uc, msg)
		messageCancel()
		if err != nil {
			failedCount++
			// Decided ONCE, here, and handed to recordMessageFailure rather than
			// re-derived there: retiring the message and advancing the checkpoint
			// past it are the same decision, and two copies of the predicate are
			// how they drift apart.
			retire := shouldMarkProcessedOnError(err)
			if !retire {
				// A deferral holds the checkpoint below this message, so every
				// later message is re-fetched next tick too. That is affordable
				// while the failure is genuinely transient and ruinous if it
				// never clears, which is what the attempt cap decides.
				attempts, cerr := store.RecordDeferral(msg.ID)
				switch {
				case cerr != nil:
					// Fail CLOSED: the message stays deferred and the checkpoint
					// stays below it, exactly as if the counter had been written.
					//
					// This used to retire the message, reasoning that a counter
					// which cannot be written cannot enforce the cap, and an
					// uncappable deferral holds the checkpoint forever. The
					// premise is right and the conclusion does not follow:
					// retiring is RecordProcessedDecision, another write to the
					// same state.Store that just failed, and the Seen() read at
					// the top of this loop fails too. A state store broken enough
					// to lose RecordDeferral cannot retire the message either —
					// it advances the checkpoint past unfinished mail with
					// neither the label nor the audit row. So retiring bought no
					// progress and paid for it in lost mail.
					//
					// Held below alongside the rest of this tick's deferrals, and
					// surfaced by failing the tick (see ledgerErr) so an operator
					// sees a state-store outage rather than a quiet backlog.
					p.log.Error("cannot count deferral attempts; holding message for retry and failing the tick",
						"user_id", u.ID, "message_id", msg.ID, "error", cerr.Error())
					deferredIDs = append(deferredIDs, msg.ID)
					if ledgerErr == nil {
						ledgerErr = fmt.Errorf("deferral ledger unwritable: %w", cerr)
					}
				case attempts >= maxDeferralAttempts:
					p.log.Error("deferral limit reached; retiring message",
						"user_id", u.ID, "message_id", msg.ID,
						"attempts", strconv.Itoa(attempts),
						"limit", strconv.Itoa(maxDeferralAttempts),
						"error", err.Error())
					retire = true
					// Wrapped so the recorded Decision says the message was given
					// up on, not merely that it failed once — the audit log is
					// the only place an operator learns mail was abandoned.
					err = fmt.Errorf("gave up after %d deferred attempts: %w", attempts, err)
				default:
					deferredIDs = append(deferredIDs, msg.ID)
				}
			}
			p.recordMessageFailure(store, u.ID, uc, msg, err, retire)
			continue
		}
		// No ClearDeferral here on purpose: every success path in handleMessage
		// ends in RecordProcessedDecision, which drops the deferral row in the
		// same transaction that retires the message. Clearing it again from the
		// caller would be a second copy of an invariant the store already owns.
		processedCount++
	}

	checkpointHeld := false
	if nextCheckpoint != "" {
		clamped := imapadapter.ClampCheckpoint(checkpoint, nextCheckpoint, deferredIDs)
		checkpointHeld = clamped != nextCheckpoint
		if checkpointHeld {
			p.log.Info("holding poll checkpoint below deferred messages so they are retried",
				"user_id", u.ID, "deferred", strconv.Itoa(len(deferredIDs)),
				"checkpoint", clamped, "fetched_through", nextCheckpoint)
		}
		if err := store.SetCheckpoint(clamped); err != nil {
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

	// The same summary, persisted, because the log line above answers "is mail
	// being polled?" only for someone already reading logs. Recorded at the END
	// of a completed tick: every early return above leaves the previous record
	// alone so its age keeps growing, which is the outage signal.
	//
	// A failure here is logged and not returned — the tick genuinely succeeded,
	// and failing it would restart work that is already done.
	if err := store.RecordPollTick(state.PollTick{
		AtUTC:          time.Now().UTC().Format(time.RFC3339),
		Fetched:        len(messages),
		Processed:      processedCount,
		SkippedSeen:    skippedSeenCount,
		Failed:         failedCount,
		Deferred:       len(deferredIDs),
		RateLimited:    rateLimitedCount > 0,
		CheckpointHeld: checkpointHeld,
	}); err != nil {
		p.log.Error("failed to record poll tick", "user_id", u.ID, "error", err.Error())
	}
	// Returned last, after the checkpoint clamp and the tick record: the work
	// this tick did do is real and must be persisted. What the error changes is
	// only the tick's reported outcome — see tick's usersFailed accounting.
	return ledgerErr
}

// classifierErr marks an error returned by classifyWithRetry so tickUser's
// message loop (via shouldMarkProcessedOnError) can apply the classifier's own
// permanent/transient split (isPermanentClassifierError) rather than the
// blanket judgement below.
type classifierErr struct {
	err error
}

func (e *classifierErr) Error() string { return e.err.Error() }
func (e *classifierErr) Unwrap() error { return e.err }

// retryableErr marks a handleMessage failure that a LATER TICK MAY SUCCEED AT:
// an IMAP action that timed out or lost its connection, a state write that lost
// a lock race. The message is left unmarked and the poll checkpoint is held
// below it, so the next tick tries again.
//
// This exists because the opposite was the default. Every non-classifier error
// used to retire the message it belonged to — deliberately, to preserve the
// behaviour that predated classifier gating — which meant an IMAP reset while
// applying a keyword recorded the message as handled, advanced the checkpoint
// past it, and never applied the label. The message was classified correctly
// and the result was silently thrown away, which is the one thing this program
// exists to do.
//
// Not everything is retryable, and the default stays "retire": a rule
// referencing a folder that does not exist, or a malformed action, fails
// identically forever, and retrying it only holds the checkpoint back. Wrapping
// is therefore opt-in at the call site that knows the failure is an outage
// rather than a mistake. The attempt cap in tickUser is the backstop for
// getting that judgement wrong in the retryable direction.
type retryableErr struct {
	err error
}

func (e *retryableErr) Error() string { return e.err.Error() }
func (e *retryableErr) Unwrap() error { return e.err }

// shouldMarkProcessedOnError reports whether tickUser should mark a message
// processed after handleMessage returned err — that is, whether to RETIRE the
// message or leave it for a later tick.
//
//   - a classifier error retires only when permanent (bad input / AI credits
//     exhausted, per isPermanentClassifierError); a transient outage defers.
//   - a retryableErr (transient IMAP, transient state-store) always defers.
//   - anything else retires, because an unrecognised failure that repeats
//     forever must not hold the checkpoint forever.
//
// Deferral is not unbounded: tickUser counts attempts per message and retires
// one that has exhausted them, whatever this says.
func shouldMarkProcessedOnError(err error) bool {
	var cerr *classifierErr
	if errors.As(err, &cerr) {
		return isPermanentClassifierError(cerr.err)
	}
	// Retryable defers; everything else retires.
	var rerr *retryableErr
	return !errors.As(err, &rerr)
}

// maxDeferralAttempts caps how many consecutive ticks may defer one message
// before it is retired with a recorded failure.
//
// Deferring holds the poll checkpoint below the message, and every tick
// re-fetches the whole batch above it, so an unbounded deferral degrades from
// "retry" into "re-fetch this mailbox forever and never make progress". The cap
// converts a permanent failure that was mistaken for a transient one back into
// a retirement.
//
// 120 against the default 90-second scan interval is about three hours of
// retries. The asymmetry is deliberate: deferring costs one re-fetched batch
// per tick, while retiring too early permanently loses the label for mail that
// was classified correctly. Three hours rides out an IMAP server restart, a
// classifier model re-pull, or a network partition, and still stops a genuinely
// poisoned message from holding the checkpoint for a whole day.
const maxDeferralAttempts = 120

// maxLoggedLabelBytes bounds a raw model output before it reaches the log.
//
// A well-behaved model answers with one label from the allowlist. A misbehaving
// one can echo back attacker-controlled email content, and app.log is served to
// any admin by GET /api/logs — so truncating keeps a diagnostic from becoming a
// channel for message content to escape the owning user's state.db.
const maxLoggedLabelBytes = 64

// maxDecisionDetailBytes bounds the Detail of a recorded Decision.
//
// Detail is an error string from anywhere in handleMessage — a classifier
// reply, an IMAP server's response, a rule action — none of which the message
// pipeline controls the size of. It lands in state.db and is served back
// through the decisions API, so an unbounded one is a row (and a response)
// sized by whatever a remote endpoint felt like returning. 4 KiB holds any
// diagnostic worth reading.
const maxDecisionDetailBytes = 4096

// clipDetail bounds an error string for storage as a Decision's Detail. Like
// clipForLog it strips newlines and keeps the result valid UTF-8; unlike
// clipForLog it is generous, because this is the audit record rather than a
// log line.
func clipDetail(s string) string {
	s = strings.TrimSpace(s)
	truncated := false
	if len(s) > maxDecisionDetailBytes {
		s = s[:maxDecisionDetailBytes]
		truncated = true
	}
	s = strings.ToValidUTF8(strings.NewReplacer("\n", " ", "\r", " ").Replace(s), "")
	if truncated {
		s += "...(truncated)"
	}
	return s
}

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
// handleMessage failure: it logs the failure and records it as a "failed"
// Decision, retiring the message (marking it processed) only when retire says
// so. A deferred message is deliberately left unmarked so it retries next poll
// tick — which also requires tickUser to hold the poll checkpoint below it, or
// the retry cannot happen at all.
//
// retire is passed in rather than re-derived from err. tickUser has to make the
// same call to decide the checkpoint, and it also applies the deferral attempt
// cap, which err alone cannot express: a message given up on after 40 attempts
// carries an error that still looks perfectly transient.
//
// A retired message reaches this exactly once, so its Decision and its push
// notification are unconditional. A DEFERRED one reaches it on every tick
// until the outage clears, so both are gated on not having been reported
// already — the audit log is per message, not per attempt, and a user gets one
// notification for one email.
func (p *Poller) recordMessageFailure(store *state.Store, userID string, uc userCtx, msg imapadapter.Message, err error, retire bool) {
	p.log.Error("message processing failed", "user_id", userID, "message_id", msg.ID, "error", err.Error())
	decision := state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Status:    "failed",
		Detail:    clipDetail(err.Error()),
	}
	// Both writes together when the message is being retired, so a failure
	// cannot leave it retired-but-unrecorded — see RecordProcessedDecision.
	// A deferred message records the decision only: it is deliberately left
	// unmarked so the next tick retries it.
	var writeErr error
	if retire {
		writeErr = store.RecordProcessedDecision(decision)
	} else {
		p.log.Info("transient failure; leaving message unmarked so it is retried next poll tick", "user_id", userID, "message_id", msg.ID)
		// Record and notify ONCE per message, not once per attempt. A deferred
		// message really does come back every tick (the checkpoint is held
		// below it), so an unconditional write here would append an audit row
		// and push a notification every ~90 seconds for the whole length of a
		// classifier outage, multiplied by every affected message. "I don't
		// know" counts as reported: duplicating on an unreadable audit log is
		// the unbounded direction, and the failure is logged at Error above
		// regardless.
		reported, readErr := store.HasDecisionWithStatus(msg.ID, "failed")
		if readErr != nil {
			p.log.Error("cannot determine whether this failure was already recorded; not repeating it",
				"user_id", userID, "message_id", msg.ID, "error", readErr.Error())
		}
		if reported || readErr != nil {
			return
		}
		writeErr = store.AddDecision(decision)
	}
	// This is already the failure path, so there is nothing above to abort;
	// logged rather than swallowed because a dropped write here means the
	// audit log is missing a message the poller reports as handled.
	if writeErr != nil {
		p.log.Error("failed to record message failure", "user_id", userID, "message_id", msg.ID, "error", writeErr.Error())
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

// rejectOversizedMessage is handleMessage's branch for a message ListUnreadInbox
// flagged as TooLarge. Instead of the normal rule/classify/label pipeline (which
// has no content to act on — Body was deliberately left empty), it best-effort
// emails a rejection notice to the account's own address, records a distinct
// "rejected_too_large" Decision, and marks the message processed so it is not
// retried every tick. A failed notice is folded into the Decision's Detail but
// never blocks either step: an SMTP misconfiguration must not leave the same
// oversized message retried forever.
func (p *Poller) rejectOversizedMessage(uc userCtx, msg imapadapter.Message) error {
	detail := fmt.Sprintf("message from %q exceeded the %d MiB inbound size limit and was not processed", msg.Sender, mailmsg.MaxInboundMessageBytes/(1<<20))
	if err := p.notifyMessageTooLarge(uc, msg); err != nil {
		p.log.Error("failed to send too-large rejection notice", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
		detail += "; rejection notice could not be sent: " + err.Error()
	}
	return uc.store.RecordProcessedDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Status:    "rejected_too_large",
		Detail:    detail,
	})
}

// notifyMessageTooLarge emails a rejection notice to the mailbox owner's own
// address — the IMAP username, the same convention api.handleMailSend uses for
// accountAddr — via the poller's per-user IMAP/SMTP config and the mailmsg SMTP
// helpers. The notice carries only the sender and subject the rejected message
// already exposed in its IMAP overview, plus the size limit: never the message's
// own content, which this server never read into memory.
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

	// Filter rules run first, before classification, and skip it entirely when a
	// matched rule's actions include "stop" — mirroring Sieve's delivery-time
	// semantics and avoiding a rate-limited Ollama call on mail a rule will delete.
	// Rule matching is local and never leaves the system, so the raw (unredacted)
	// message is used here, unlike the redacted body handed to classifyWithRetry.
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
		// An action that failed did not happen, so the message has not been
		// handled and must not be recorded as if it had.
		//
		// This used to append the failures to the Detail of an "applied"
		// decision and carry on — which, for the "stop" rule below, retired the
		// message in the same breath. An IMAP reset during "archive and stop"
		// therefore left the mail sitting in the inbox, an audit row claiming it
		// was archived, and no tick that would ever look at it again.
		//
		// Retryable rather than fatal because the overwhelmingly common cause is
		// an outage: a dropped connection, a timeout, a server that went away
		// mid-command. A rule that fails for a permanent reason — moving to a
		// folder that does not exist — fails identically on every retry and is
		// retired by tickUser's deferral cap instead of holding the checkpoint
		// forever.
		//
		// Retrying is safe because the action set is idempotent in effect
		// (keyword/unkeyword/read set state; move/archive/spam/delete are
		// terminal on a UID, and a message whose move DID succeed is no longer
		// in INBOX for the next ListUnreadInbox to return). There is no forward
		// or reply action that a retry could duplicate.
		if len(failures) > 0 {
			return &retryableErr{err: fmt.Errorf(
				"%s; %d action(s) failed: %s", detail, len(failures), strings.Join(failures, "; "))}
		}
		decision := state.Decision{
			MessageID: msg.ID,
			Sender:    msg.Sender,
			SentTo:    msg.SentTo,
			Subject:   msg.Subject,
			Status:    "applied",
			Detail:    detail,
		}
		// A "stop" rule is a terminal path — the decision and the processed
		// marker are one state change and are written as one. Without "stop"
		// the message carries on to classification, which will retire it, so
		// only the decision is recorded here.
		if outcome.Stopped {
			// Retryable: the actions succeeded and only the bookkeeping failed,
			// which under api/daemon contention means SQLITE_BUSY past the busy
			// timeout. Retiring the message on a failed write would lose the
			// audit row for work that really happened.
			if err := uc.store.RecordProcessedDecision(decision); err != nil {
				return &retryableErr{err: err}
			}
			p.maybeSendPushNotification(uc, msg, "", nil)
			p.maybeSendNativePushNotification(uc, msg, "", nil)
			return nil
		}
		if err := uc.store.AddDecision(decision); err != nil {
			return &retryableErr{err: err}
		}
	}

	if !uc.autoLabelEnabled {
		return p.tagWithFallbackLabel(ctx, uc, cfg, msg, "automatic keyword labeling disabled")
	}

	// A PGP-encrypted message carries no body to classify. GetEmails only sets
	// PGPEncryptedPayload *because* the parse produced no text (imap
	// client.go's `if body == ""` guard) — goimap cannot render
	// multipart/encrypted — and the poller never decrypts. Sending it to the
	// classifier anyway spends an Ollama call on an empty body and hands the
	// model the sender plus, for third-party PGP/MIME that does not use
	// protected headers, the real subject in the clear. Nothing useful comes
	// back for that: the model answers off metadata alone or answers nothing,
	// and the "no known label returned" path below retires the message
	// unlabeled.
	//
	// Tagging the fallback label instead of leaving it unlabeled is
	// deliberate. Mail stranded in the Uncategorized tab reads as vanished
	// rather than sorted (see disabledLabelingFallback), and a growing pile of
	// permanently-unlabeled mail is itself a statement about which messages
	// matter.
	//
	// Do NOT "improve" this with an `Encrypted` keyword. IMAP keywords are
	// stored on the mail server in the clear, so that keyword would hand
	// whoever runs that server a precise index of which messages are worth
	// attacking — the exact adversary client-protected custody exists to
	// defend against — while looking to the user like a security feature. It
	// would break the published contract in both directions at once: keywords
	// are a sorting hint and never a security boundary (README.md, SECURITY.md),
	// so such a keyword would be simultaneously not trustworthy enough to rely
	// on and harmful merely by existing. The reader's encryption column is
	// derived from the message bytes at render time and stores nothing.
	if msg.PGPEncrypted {
		return p.tagWithFallbackLabel(ctx, uc, cfg, msg, "message is encrypted; no readable content to classify")
	}

	body := strings.TrimSpace(msg.Body)
	if len(body) > 2000 {
		body = body[:2000]
	}
	redacted := p.currentRedaction().Apply(body)

	// Clamp the headers too. The prompt builder puts the instruction block, the
	// nonced fence and the tuning document BEFORE the email text and Ollama
	// truncates from the front, so an unbounded Subject pushes the fence out of
	// num_ctx and the model sees attacker text with no instructions. Rune-wise so a
	// multi-byte character is never split.
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
		// Surfaced in /api/health without touching Healthy: a model that never
		// installed (the container's pull can fail while everything else comes
		// up fine) otherwise showed up nowhere an operator looks.
		p.health.RecordClassifierFailure()
		// Wrapped so the caller (tickUser, via shouldMarkProcessedOnError)
		// can tell a classifier failure apart from rule/IMAP errors and gate
		// MarkProcessed on isPermanentClassifierError instead of always
		// retiring the message — see recordMessageFailure.
		return &classifierErr{err: err}
	}
	// A successful classification means the classifier has credits again; clear any flag.
	p.clearAICreditsExhausted()
	p.health.RecordClassifierSuccess()
	// No sender and no subject. This logger writes to the instance-wide app.log that
	// GET /api/logs serves to ANY admin, so anything here leaves one user's
	// correspondence metadata readable by an account that is not theirs. Sender and
	// subject are recorded in the state.Decision row below, which lives in the
	// user's own state.db; the message id joins the two when debugging.
	p.log.Info("classification result", "user_id", uc.id, "message_id", msg.ID, "raw_label", clipForLog(label))
	selected := classifier.SelectLabelFromText(cfg.Labels.Allowlist, label)
	if selected == "" {
		p.log.Info("classification skipped", "user_id", uc.id, "message_id", msg.ID, "reason", "no known label returned", "raw_label", clipForLog(label), "allowlist_count", strconv.Itoa(len(cfg.Labels.Allowlist)))
		if err := uc.store.RecordProcessedDecision(state.Decision{
			MessageID: msg.ID,
			Sender:    msg.Sender,
			SentTo:    msg.SentTo,
			Subject:   msg.Subject,
			Status:    "skipped",
			Detail:    "no known label returned",
		}); err != nil {
			return &retryableErr{err: err}
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
	// The core promise of the product, and the one failure that used to be
	// discarded silently: applyKeywordsWithRetry has already exhausted its own
	// retries, so reaching here means the IMAP session is genuinely unwell.
	// Retiring the message would record a correct classification whose label
	// was never written and never will be.
	if err := applyKeywordsWithRetry(ctx, uc.mail, msg.ID, keywords); err != nil {
		p.log.Error("label apply failed", "user_id", uc.id, "message_id", msg.ID, "selected_label", selected, "error", err.Error())
		return &retryableErr{err: err}
	}
	p.log.Info("label applied", "user_id", uc.id, "message_id", msg.ID, "selected_label", selected, "keywords", strings.Join(keywords, ","))
	if err := uc.store.RecordProcessedDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Label:     selected,
		Status:    "applied",
		Detail:    "label applied successfully",
	}); err != nil {
		return &retryableErr{err: err}
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

	subs, err := uc.store.ListNotificationSubscriptionsStrict()
	if err != nil {
		p.log.Error("failed to list notification subscriptions", "user_id", uc.id, "error", err.Error())
		return
	}
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

	outcome, err := SendWebPush(p.lifetimeCtx(), uc.store, publicKey, privateKeyPath, 300, payloadBytes)
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

	devices, err := uc.store.ListNativeDevicesStrict()
	if err != nil {
		p.log.Error("failed to list native devices", "user_id", uc.id, "error", err.Error())
		return
	}
	if len(devices) == 0 {
		return
	}

	includeContent := nativePushIncludesContent(uc.settings, msg)
	title, body := buildNativeNotificationText(msg, includeContent)
	data := buildNativePushData(msg, messageKeywords, title, body, includeContent)

	// title/body are duplicated into data so a mobile client that renders its
	// own notification from the data payload shows the sender and subject
	// instead of a generic fallback.
	notification := NativePushMessage{Title: title, Body: body, Data: data}

	outcome, err := SendNativePush(p.lifetimeCtx(), p.nativePushDispatcher, p.health, uc.store, notification, func(device state.NativeDevice, platform string, sendErr error) {
		// This fires only after sendWithRetry has spent its attempts — transient
		// failures (relay unreachable, upstream 5xx, 429) are retried with backoff,
		// honouring the relay's Retry-After. What reaches here is a relay that stayed
		// down for the whole window, and the notification is dropped: the email still
		// syncs in-app, and health.RecordNativePushFailure surfaces the relay as
		// failing. Re-attempt ACROSS requests would be a queue, not a retry; see
		// sendWithRetry.
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

// nativePushIncludesContent decides whether a native push may carry the
// message's sender and subject.
//
// ContentPreview is the user's setting, but an encrypted message overrides it.
// The outer subject is the KyPost placeholder only for KyPost-to-KyPost mail;
// third-party PGP/MIME that does not use protected headers leaves the real
// subject in the clear, and this path is cleartext to the relay Worker and to
// FCM/APNs. Shipping the subject of an end-to-end encrypted message through
// Google or Apple undoes the point of having encrypted it, and the user cannot
// see it happening, so it is not theirs to opt into by accident.
//
// Web push is deliberately not held to this: RFC 8291 encrypts that payload to
// the browser's own subscription keys, so there is no third party to withhold
// it from and ContentPreview stays the user's call there.
func nativePushIncludesContent(settings config.UserNotificationSettings, msg imapadapter.Message) bool {
	return settings.ContentPreview && !msg.PGPEncrypted
}

// buildNativeNotificationText renders a mobile push. With includeContent it
// reads as a mail app's does — sender as the title, subject as the body.
// Without it the notification is generic and carries no message metadata.
//
// includeContent is off unless the user turned on
// UserNotificationSettings.ContentPreview, because a native push goes backend ->
// relay Worker -> FCM/APNs, in cleartext to every hop.
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
// notification opens the right message once the app syncs over its own
// authenticated connection) and the deep link. No sender, no subject, no
// keywords — keywords leak the classification, which is itself a statement about
// the message.
//
// The sender appears under both "sender" and "senderName", the subject under
// both "subject" and "emailSubject": the mobile client reads
// senderName/emailSubject on the FCM path and falls back to sender/subject on
// App Pull, so removing either pair breaks one of them.
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

// keywordRetryDelay is the wait between keyword-write attempts. A var rather
// than a const only so the full-tick tests, which deliberately fail this call,
// do not spend two 30-second sleeps per message proving it.
var keywordRetryDelay = 30 * time.Second

func applySingleKeywordWithRetry(ctx context.Context, c imapadapter.Client, messageID, keyword string) error {
	_, err := retry.Loop(ctx, 3, func(attempt int) time.Duration {
		return keywordRetryDelay
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

// tagWithFallbackLabel retires a message the classifier is not going to be
// asked about: it applies the account's fallback label, records the decision
// with reason as its Detail, and notifies. Shared by the two paths that skip
// classification for reasons that are not failures — auto-labeling turned off,
// and an encrypted message with no readable body — so the two cannot drift
// apart in what they write to the mailbox or to the decision log.
func (p *Poller) tagWithFallbackLabel(ctx context.Context, uc userCtx, cfg config.Config, msg imapadapter.Message, reason string) error {
	defaultLabel := disabledLabelingFallback(cfg.Labels.Allowlist)
	keywords := keywordsForSelectedLabel(defaultLabel, cfg.Labels.KeywordMappings)
	p.log.Info(
		"classification skipped; tagging default label",
		"user_id", uc.id,
		"message_id", msg.ID,
		"reason", reason,
		"selected_label", defaultLabel,
		"keywords", strings.Join(keywords, ","),
	)
	if err := applyKeywordsWithRetry(ctx, uc.mail, msg.ID, keywords); err != nil {
		p.log.Error("label apply failed", "user_id", uc.id, "message_id", msg.ID, "selected_label", defaultLabel, "error", err.Error())
		return &retryableErr{err: err}
	}
	if err := uc.store.RecordProcessedDecision(state.Decision{
		MessageID: msg.ID,
		Sender:    msg.Sender,
		SentTo:    msg.SentTo,
		Subject:   msg.Subject,
		Label:     defaultLabel,
		Status:    "applied",
		Detail:    reason + "; tagged " + defaultLabel,
	}); err != nil {
		return &retryableErr{err: err}
	}
	p.maybeSendPushNotification(uc, msg, defaultLabel, keywords)
	p.maybeSendNativePushNotification(uc, msg, defaultLabel, keywords)
	return nil
}

// disabledLabelingFallback picks the label applied when auto-labeling is off.
// "Primary" is preferred for backward compatibility, but it only matches a tab
// the frontend shows by default (server.go's bucket()/firstMatchingKeyword,
// ReadPage.tsx's tabs[0]) when it is genuinely one of the account's configured
// labels. Otherwise falling back to the literal string strands mail in the
// Uncategorized tab, which looks like mail vanishing rather than being sorted.
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
