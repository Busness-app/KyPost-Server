package api

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/captcha"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/groups"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/rules"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/totp"
	"kypost-server/backend/internal/users"

	goimap "github.com/BrianLeishman/go-imap"
)

// Session tracks who a live session token belongs to. Role is deliberately
// not stored here: currentUser looks the user up live from the users store
// on every request so a role change or deactivation take effect on the very
// next request rather than only at next login. CSRFToken backs the
// double-submit CSRF check (see csrfCheckOK) — minted alongside the session
// and mirrored into the non-HttpOnly csrf_token cookie so the frontend can
// read and echo it back as a header.
type Session struct {
	UserID    string
	ExpiresAt time.Time
	CSRFToken string
}

// AuthContext identifies the caller of an authenticated request.
type AuthContext struct {
	UserID             string
	Username           string
	Role               users.Role
	MustChangePassword bool
}

type Server struct {
	mu                     sync.RWMutex
	cfg                    config.Config
	onConfigUpdated        func(config.Config)
	logger                 *logging.Logger
	health                 *health.Service
	users                  *users.Store
	configDir              string
	stateDir               string
	configPath             string
	logPath                string
	imapConfigKeyPath      string
	totpSecretKeyPath      string
	pgpPrivateKeyPath      string
	sessions               map[string]Session
	mfaChallenges          *mfa.Store
	pairingSecret          string
	serverBaseURL          string
	baseURLFallbackWarn    sync.Once
	pairingSecretWarn      sync.Once
	nativePushDispatcher   *processor.NativePushDispatcher
	pickupStore            *pgpmail.PickupStore
	poller                 *processor.Poller
	loginLockout           *failureLockout
	davLockout             *failureLockout
	mfaLockout             *failureLockout
	deviceLockout          *failureLockout
	mfaPushCooldown        *mfaPushCooldown
	sendAsCooldown         *sendAsVerificationCooldown
	classifierTestCooldown *classifierTestCooldown
	nativePairingNonces    *consumedNativePairingNonces
	captchaVerifier        captcha.Verifier
	captchaProvider        captcha.Provider
	captchaSiteKey         string

	// classifier and globalStore back the Ollama version/update-check block on
	// the Prompt Tuning page and its admin-notification email. classifier is
	// nil until SetClassifier is called (see app.go); globalStore is the
	// install-wide (not per-user) state.Store rooted at stateDir itself, used
	// only to dedupe the upgrade-available email to one per newly-seen
	// upstream release.
	classifier   *classifier.HTTPClient
	globalStore  *state.Store
	ollamaMu     sync.Mutex
	ollamaStatus ollamaVersionStatus

	// Per-user resources, lazily created and cached. userMu also guards the
	// subscriberID -> userID index used by the unauthenticated native
	// pairing registration endpoint, and the deviceID -> userID index used
	// by ongoing per-device auth (deviceAuthFromRequest).
	userMu         sync.Mutex
	userStores     map[string]*state.Store
	userContacts   map[string]*contacts.Store
	userSendAs     map[string]*sendas.Store
	userGroups     map[string]*groups.Store
	userRules      map[string]*rules.Store
	userMailCache  map[string]*mailcache.Store
	userMail       map[string]*serverMailEntry
	subIndex       map[string]string
	deviceIndex    map[string]string
	davCredentials davCredentialCache

	// httpServer is the live *http.Server backing Run/Serve, constructed by
	// Prepare so that a Shutdown call arriving before Serve's goroutine has
	// even been scheduled still has a real server to act on instead of racing
	// a lazy initialization (see Prepare's doc comment).
	httpServer *http.Server
}

func NewServer(cfg config.Config, logger *logging.Logger, healthSvc *health.Service, usersStore *users.Store, onConfigUpdated func(config.Config)) *Server {
	configDir := config.EnvOrDefault("CONFIG_DIR", "/kypost/config")
	stateDir := config.EnvOrDefault("STATE_DIR", "/kypost/state")
	logPath := filepath.Join(config.EnvOrDefault("LOG_DIR", "/kypost/logs"), "app.log")
	imapConfigKeyPath := config.EnvOrDefault("IMAP_CONFIG_KEY_FILE", "/kypost/private/imap-config.key")
	totpSecretKeyPath := config.EnvOrDefault("TOTP_SECRET_KEY_FILE", "/kypost/private/totp-secret.key")
	pgpPrivateKeyPath := config.EnvOrDefault("PGP_PRIVATE_KEY_FILE", "/kypost/private/pgp-private-key.key")
	pickupStoreKeyPath := config.EnvOrDefault("PICKUP_STORE_KEY_FILE", "/kypost/private/pickup-store.key")
	pairingSecret := strings.TrimSpace(os.Getenv("PAIRING_SECRET"))

	captchaProvider := captcha.Provider(strings.ToLower(strings.TrimSpace(os.Getenv("CAPTCHA_PROVIDER"))))
	captchaSiteKey := strings.TrimSpace(os.Getenv("CAPTCHA_SITE_KEY"))
	captchaVerifier, err := captcha.NewVerifier(captcha.Config{
		Provider:  captchaProvider,
		SiteKey:   captchaSiteKey,
		SecretKey: strings.TrimSpace(os.Getenv("CAPTCHA_SECRET_KEY")),
	})
	if err != nil {
		// Misconfigured CAPTCHA must fail closed on login (see handleLogin)
		// rather than silently running unprotected, but must not prevent the
		// server itself from starting.
		logger.Error("captcha misconfigured; login CAPTCHA will reject all attempts until fixed", "error", err.Error())
		captchaVerifier = misconfiguredCaptchaVerifier{err: err}
	}

	globalStore, err := state.New(stateDir)
	if err != nil {
		// Only the Ollama-update-notification dedup relies on this; losing it
		// just means a possible duplicate email, never a reason to fail startup.
		logger.Error("failed to open global state store; ollama update emails may repeat", "error", err.Error())
		globalStore = nil
	}

	return &Server{
		cfg:                    cfg,
		onConfigUpdated:        onConfigUpdated,
		logger:                 logger,
		health:                 healthSvc,
		users:                  usersStore,
		configDir:              configDir,
		stateDir:               stateDir,
		configPath:             filepath.Join(configDir, "config.yaml"),
		logPath:                logPath,
		imapConfigKeyPath:      imapConfigKeyPath,
		totpSecretKeyPath:      totpSecretKeyPath,
		pgpPrivateKeyPath:      pgpPrivateKeyPath,
		sessions:               map[string]Session{},
		mfaChallenges:          mfa.NewStore(),
		pairingSecret:          pairingSecret,
		serverBaseURL:          strings.TrimRight(strings.TrimSpace(os.Getenv("SERVER_BASE_URL")), "/"),
		nativePushDispatcher:   processor.NewNativePushDispatcher(logger),
		pickupStore:            pgpmail.NewPickupStore(filepath.Join(stateDir, "pickup"), pickupStoreKeyPath),
		userStores:             map[string]*state.Store{},
		userContacts:           map[string]*contacts.Store{},
		userSendAs:             map[string]*sendas.Store{},
		userGroups:             map[string]*groups.Store{},
		userRules:              map[string]*rules.Store{},
		userMailCache:          map[string]*mailcache.Store{},
		userMail:               map[string]*serverMailEntry{},
		subIndex:               map[string]string{},
		deviceIndex:            map[string]string{},
		davCredentials:         newDAVCredentialCache(),
		loginLockout:           newLoginLockout(),
		davLockout:             newFailureLockout(davMaxFailures, davLockoutFor),
		mfaLockout:             newFailureLockout(mfaMaxFailures, mfaLockoutFor),
		deviceLockout:          newFailureLockout(deviceMaxFailures, deviceLockoutFor),
		mfaPushCooldown:        newMfaPushCooldown(),
		sendAsCooldown:         newSendAsVerificationCooldown(),
		classifierTestCooldown: newClassifierTestCooldown(),
		nativePairingNonces:    newConsumedNativePairingNonces(),
		captchaVerifier:        captchaVerifier,
		captchaProvider:        captchaProvider,
		captchaSiteKey:         captchaSiteKey,
		globalStore:            globalStore,
	}
}

// misconfiguredCaptchaVerifier stands in for a Verifier that failed to
// construct (e.g. CAPTCHA_PROVIDER set but CAPTCHA_SECRET_KEY missing), so
// login fails closed with a clear error instead of silently running with no
// CAPTCHA check at all.
type misconfiguredCaptchaVerifier struct{ err error }

func (m misconfiguredCaptchaVerifier) Verify(context.Context, string, string) (bool, error) {
	return false, m.err
}

// SetPoller wires the background mail poller into the server so admin
// endpoints (e.g. a manual "poll now" trigger) can reach it. Set once at
// startup, alongside the poller's own construction in app.go.
func (s *Server) SetPoller(p *processor.Poller) {
	s.poller = p
}

// routes builds the API's route table. Split out from Run so tests can
// dispatch through the exact same registration (middleware included)
// instead of calling handlers directly and assuming the wiring matches.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("POST /api/health/repair", s.withAdmin(s.handleRepair))
	mux.HandleFunc("POST /api/admin/mail/poll-now", s.withAdmin(s.handlePollNow))
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/auth/captcha-config", s.handleCaptchaConfig)
	mux.HandleFunc("POST /api/auth/mfa/totp", s.handleMFATOTP)
	mux.HandleFunc("POST /api/auth/mfa/recovery-code", s.handleMFARecoveryCode)
	mux.HandleFunc("POST /api/auth/mfa/push/poll", s.handlePushPoll)
	mux.HandleFunc("POST /api/auth/mfa/push/finish", s.handlePushFinish)
	mux.HandleFunc("POST /api/mfa/push/respond", s.handlePushRespond)
	mux.HandleFunc("GET /api/mfa/status", s.withAuth(s.handleMFAStatus))
	mux.HandleFunc("POST /api/mfa/totp/setup", s.withAuth(s.handleMFASetup))
	mux.HandleFunc("POST /api/mfa/totp/confirm", s.withAuth(s.handleMFAConfirm))
	mux.HandleFunc("POST /api/mfa/totp/disable", s.withAuth(s.handleMFADisable))
	mux.HandleFunc("POST /api/mfa/recovery-codes/regenerate", s.withAuth(s.handleMFARecoveryCodesRegenerate))
	mux.HandleFunc("PUT /api/mfa/push/enabled", s.withAuth(s.handleMFAPushEnabled))
	mux.HandleFunc("PUT /api/notifications/native/devices/{deviceId}/mfa", s.withAuth(s.handleNativeDeviceMFA))
	mux.HandleFunc("GET /api/auth/me", s.handleMe)
	mux.HandleFunc("GET /api/auth/csrf", s.handleCSRFToken)
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.withAuth(s.handleChangePassword))
	mux.HandleFunc("/api/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("GET /api/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("PUT /api/config", s.withAdmin(s.handleConfig))
	mux.HandleFunc("GET /api/labels", s.withAuth(s.handleLabels))
	mux.HandleFunc("GET /api/decisions", s.withAuth(s.handleDecisions))
	mux.HandleFunc("GET /api/inbox", s.withMailAuth(s.handleInbox))
	mux.HandleFunc("GET /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("POST /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("PUT /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("DELETE /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("POST /api/inbox/actions", s.withMailAuth(s.handleInboxActions))
	mux.HandleFunc("GET /api/mail/search", s.withMailAuth(s.handleMailSearch))
	mux.HandleFunc("GET /api/logs", s.withAdmin(s.handleLogs))
	mux.HandleFunc("GET /api/logs/list", s.withAdmin(s.handleLogsList))
	mux.HandleFunc("GET /api/users", s.withAdmin(s.handleUsersList))
	mux.HandleFunc("POST /api/users", s.withAdmin(s.handleUsersCreate))
	mux.HandleFunc("PUT /api/users/{id}", s.withAdmin(s.handleUsersUpdate))
	mux.HandleFunc("POST /api/users/{id}/reset-password", s.withAdmin(s.handleUsersResetPassword))
	mux.HandleFunc("POST /api/users/{id}/deactivate", s.withAdmin(s.handleUsersDeactivate))
	mux.HandleFunc("POST /api/users/{id}/reactivate", s.withAdmin(s.handleUsersReactivate))
	mux.HandleFunc("POST /api/users/{id}/clear-mfa", s.withAdmin(s.handleUsersClearMFA))
	mux.HandleFunc("GET /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("POST /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("DELETE /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("POST /api/imap/test", s.withAuth(s.handleIMAPTest))
	mux.HandleFunc("POST /api/mail/draft", s.withMailAuth(s.handleMailDraft))
	mux.HandleFunc("POST /api/mail/send", s.withMailAuth(s.handleMailSend))
	mux.HandleFunc("GET /api/mail/send-as", s.withAuth(s.handleSendAs))
	mux.HandleFunc("POST /api/mail/send-as", s.withAuth(s.handleSendAs))
	mux.HandleFunc("DELETE /api/mail/send-as/{id}", s.withAuth(s.handleSendAsByID))
	mux.HandleFunc("GET /api/mail/attachments", s.withMailAuth(s.handleMailAttachmentList))
	mux.HandleFunc("GET /api/mail/attachment", s.withMailAuth(s.handleMailAttachmentDownload))
	mux.HandleFunc("POST /api/classifier/test", s.withAdmin(s.handleClassifierTest))
	mux.HandleFunc("GET /api/ollama/version", s.withAuth(s.handleOllamaVersion))
	mux.HandleFunc("GET /api/tuning", s.withAuth(s.handleTuning))
	mux.HandleFunc("PUT /api/tuning", s.withAuth(s.handleTuning))
	mux.HandleFunc("GET /api/notifications/preferences", s.withAuth(s.handleNotificationPreferences))
	mux.HandleFunc("PUT /api/notifications/preferences", s.withAuth(s.handleNotificationPreferences))
	mux.HandleFunc("GET /api/labels/preferences", s.withAuth(s.handleLabelPreferences))
	mux.HandleFunc("PUT /api/labels/preferences", s.withAuth(s.handleLabelPreferences))
	mux.HandleFunc("GET /api/notifications/vapid-public-key", s.withAuth(s.handleNotificationVAPIDPublicKey))
	mux.HandleFunc("POST /api/notifications/subscriptions", s.withAuth(s.handleNotificationSubscriptions))
	mux.HandleFunc("DELETE /api/notifications/subscriptions", s.withAuth(s.handleNotificationSubscriptions))
	mux.HandleFunc("POST /api/notifications/test", s.withAuth(s.handleNotificationTest))
	mux.HandleFunc("GET /api/notifications/pairing", s.withAuth(s.handleNotificationPairing))
	mux.HandleFunc("POST /api/notifications/native/register", s.handleNotificationNativeRegister)
	mux.HandleFunc("GET /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("DELETE /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("POST /api/notifications/native/unpair", s.withAuth(s.handleNotificationNativeUnpair))
	mux.HandleFunc("POST /api/notifications/native/deregister", s.handleNotificationNativeDeregister)
	mux.HandleFunc("PUT /api/notifications/native/mode", s.withAuth(s.handleNotificationNativeMode))
	mux.HandleFunc("GET /api/notifications/native/pull", s.handleNotificationNativePull)
	mux.HandleFunc("POST /api/notifications/desktop/pair", s.withAuth(s.handleDesktopPair))
	mux.HandleFunc("GET /api/contacts", s.withAuth(s.handleContacts))
	mux.HandleFunc("POST /api/contacts", s.withAuth(s.handleContacts))
	mux.HandleFunc("POST /api/contacts/dedupe", s.withMailAuth(s.handleContactsDedupe))
	mux.HandleFunc("GET /api/contacts/search", s.withAuth(s.handleContactsSearch))
	mux.HandleFunc("POST /api/contacts/bulk-delete", s.withAuth(s.handleContactsBulkDelete))
	mux.HandleFunc("GET /api/contacts/export", s.withAuth(s.handleContactsExport))
	mux.HandleFunc("POST /api/contacts/import", s.withAuth(s.handleContactsImport))
	mux.HandleFunc("GET /api/contacts/dav-password", s.withAuth(s.handleContactsDAVPassword))
	mux.HandleFunc("POST /api/contacts/dav-password", s.withAuth(s.handleContactsDAVPassword))
	mux.HandleFunc("DELETE /api/contacts/dav-password", s.withAuth(s.handleContactsDAVPassword))
	mux.HandleFunc("GET /api/contacts/carddav-client/config", s.withAuth(s.handleContactsCardDAVClientConfig))
	mux.HandleFunc("POST /api/contacts/carddav-client/config", s.withAuth(s.handleContactsCardDAVClientConfig))
	mux.HandleFunc("DELETE /api/contacts/carddav-client/config", s.withAuth(s.handleContactsCardDAVClientConfig))
	mux.HandleFunc("POST /api/contacts/carddav-client/sync", s.withAuth(s.handleContactsCardDAVClientSync))
	mux.HandleFunc("GET /api/contacts/{id}", s.withAuth(s.handleContactByID))
	mux.HandleFunc("PUT /api/contacts/{id}", s.withAuth(s.handleContactByID))
	mux.HandleFunc("DELETE /api/contacts/{id}", s.withAuth(s.handleContactByID))
	mux.HandleFunc("GET /api/contacts/sync", s.handleContactsSync)
	mux.HandleFunc("POST /api/contacts/sync", s.handleContactsSync)
	mux.HandleFunc("POST /api/contacts/{id}/photo", s.withAuth(s.handleContactPhoto))
	mux.HandleFunc("GET /api/contacts/{id}/photo", s.withMailAuth(s.handleContactPhoto))
	mux.HandleFunc("DELETE /api/contacts/{id}/photo", s.withAuth(s.handleContactPhoto))
	mux.HandleFunc("POST /api/contacts/{id}/self", s.withAuth(s.handleContactSelf))
	mux.HandleFunc("POST /api/pgp/identity/generate", s.withAuth(s.handlePGPIdentityGenerate))
	mux.HandleFunc("POST /api/pgp/identity/import", s.withAuth(s.handlePGPIdentityImport))
	mux.HandleFunc("GET /api/pgp/identity", s.withAuth(s.handlePGPIdentity))
	mux.HandleFunc("DELETE /api/pgp/identity", s.withAuth(s.handlePGPIdentity))
	mux.HandleFunc("GET /api/pgp/keyserver/lookup", s.withAuth(s.handlePGPKeyserverLookup))
	mux.HandleFunc("POST /api/pgp/recipients/check", s.withAuth(s.handlePGPRecipientsCheck))
	mux.HandleFunc("GET /api/pgp/discovery/settings", s.withAuth(s.handlePGPDiscoverySettings))
	mux.HandleFunc("PUT /api/pgp/discovery/settings", s.withAuth(s.handlePGPDiscoverySettings))
	mux.HandleFunc("GET /api/pgp/discovery/suppressions", s.withAuth(s.handlePGPDiscoverySuppressions))
	mux.HandleFunc("DELETE /api/pgp/discovery/suppressions/{email}", s.withAuth(s.handlePGPDiscoverySuppressionByEmail))
	mux.HandleFunc("POST /api/pgp/discovery/suppress-contact", s.withAuth(s.handlePGPDiscoverySuppressContact))
	mux.HandleFunc("GET /api/pgp/wkd/domains", s.withAuth(s.handleWKDDomains))
	mux.HandleFunc("POST /api/pgp/wkd/domains", s.withAuth(s.handleWKDDomains))
	mux.HandleFunc("POST /api/pgp/wkd/domains/{domain}/verify", s.withAuth(s.handleWKDDomainVerify))
	mux.HandleFunc("DELETE /api/pgp/wkd/domains/{domain}", s.withAuth(s.handleWKDDomainDelete))
	mux.HandleFunc("GET /api/pgp/qr/token", s.withMailAuth(s.handlePGPQRToken))
	mux.HandleFunc("GET /api/pgp/qr/key", s.handlePGPQRKey)
	mux.HandleFunc("GET /api/groups", s.withMailAuth(s.handleGroups))
	mux.HandleFunc("POST /api/groups", s.withAuth(s.handleGroups))
	mux.HandleFunc("PUT /api/groups/{id}", s.withAuth(s.handleGroupByID))
	mux.HandleFunc("DELETE /api/groups/{id}", s.withAuth(s.handleGroupByID))
	mux.HandleFunc("GET /api/rules", s.withMailAuth(s.handleRules))
	mux.HandleFunc("POST /api/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("PUT /api/rules/{id}", s.withAuth(s.handleRuleByID))
	mux.HandleFunc("DELETE /api/rules/{id}", s.withAuth(s.handleRuleByID))
	mux.HandleFunc("POST /api/rules/reorder", s.withAuth(s.handleRulesReorder))
	mux.HandleFunc("GET /api/rules/{id}/sieve", s.withMailAuth(s.handleRuleSieve))
	mux.HandleFunc("PUT /api/rules/{id}/sieve", s.withAuth(s.handleRuleSieve))
	mux.HandleFunc("POST /api/rules/run", s.withMailAuth(s.handleRulesRun))
	mux.Handle("/.well-known/carddav", s.withDAVBasicAuth(http.HandlerFunc(s.handleCardDAV)))
	mux.Handle(davPrefix+"/", s.withDAVBasicAuth(http.HandlerFunc(s.handleCardDAV)))
	mux.HandleFunc("GET /.well-known/openpgpkey/", s.handleWKD)
	mux.HandleFunc("GET /api/setup", s.handleSetup)
	mux.HandleFunc("GET /pickup/{id}", s.handlePickup)
	mux.HandleFunc("/", s.handleFrontend)

	return withSecurityHeaders(mux)
}

// Prepare constructs the underlying *http.Server (Addr + Handler) without
// starting it. Callers that need to coordinate a graceful Shutdown with a
// signal handler (see runServer/runAll in internal/app/app.go) MUST call
// Prepare synchronously — before launching any goroutine that calls Serve —
// so that a shutdown signal arriving essentially immediately after startup
// always has a non-nil *http.Server to call Shutdown on. Constructing the
// *http.Server lazily inside the goroutine that calls Serve would instead
// race: Shutdown could run before that goroutine is even scheduled, either
// panicking on a nil server or silently doing nothing.
//
// Serve and Run call Prepare automatically if it wasn't already called, so
// simple callers that don't need external shutdown coordination can still
// just call Run.
func (s *Server) Prepare() {
	port := config.EnvInt("WEB_PORT", 5866)
	s.httpServer = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: s.routes(),
	}
}

// Serve binds the address configured on the prepared *http.Server and blocks
// serving requests until Shutdown (or Close) stops it, at which point it
// returns nil (the underlying http.ErrServerClosed is not an error from the
// caller's point of view — it's the expected result of a graceful stop).
// Prepare is called automatically if it hasn't been already, but callers
// that need race-free Shutdown coordination should call Prepare themselves
// first (see Prepare's doc comment).
func (s *Server) Serve() error {
	if s.httpServer == nil {
		s.Prepare()
	}
	s.logger.Info("api server starting", "addr", s.httpServer.Addr)
	err := s.httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Run is a convenience wrapper for callers that don't need to call Shutdown
// from elsewhere: it prepares and serves in one blocking call.
func (s *Server) Run() error {
	s.Prepare()
	return s.Serve()
}

// Shutdown gracefully stops the HTTP server: it stops accepting new
// connections immediately and waits for active requests to finish on their
// own, up to ctx's deadline, before returning. Safe to call even if Prepare
// was never invoked (a no-op then, since there is nothing to shut down) or
// before Serve's goroutine has started (the eventual Serve call will observe
// the server is already shutting down and return promptly instead of ever
// blocking on Accept — see net/http.Server's shuttingDown/trackListener).
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// StartPickupSweeper runs PickupStore.Sweep on an interval for the process
// lifetime, mirroring processor.Poller's ticker/cancel pattern
// (backend/internal/processor/poller.go). Call once after NewServer, e.g.
// `go srv.StartPickupSweeper(context.Background())` alongside wherever the
// existing background poller is started.
func (s *Server) StartPickupSweeper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.pickupStore.Sweep(30 * 24 * time.Hour); err != nil {
				s.logger.Error("pickup sweep failed", "error", err.Error())
			}
		}
	}
}

// sendAsCooldownSweepInterval is a var rather than an inline literal (unlike
// StartPickupSweeper's ticker) solely so tests can shrink it to observe a
// real tick without waiting out the production interval; production always
// runs with the 1-hour default below.
var sendAsCooldownSweepInterval = 1 * time.Hour

// StartSendAsCooldownSweeper runs sendAsCooldown.sweep on an interval for the
// process lifetime, mirroring StartPickupSweeper's ticker/select pattern
// exactly. Call once after NewServer, e.g.
// `go srv.StartSendAsCooldownSweeper(context.Background())` alongside
// StartPickupSweeper.
func (s *Server) StartSendAsCooldownSweeper(ctx context.Context) {
	ticker := time.NewTicker(sendAsCooldownSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendAsCooldown.sweep(sendAsCooldownSweepMaxAge)
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	st := s.health.GetStatus()
	status := http.StatusOK
	if !st.Healthy {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, st)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	processedSince := time.Now().UTC().Add(-1 * time.Hour)
	resp := map[string]any{
		"scanIntervalSeconds":     cfg.Scan.IntervalSeconds,
		"rateLimits":              cfg.RateLimits,
		"checkpoint":              store.Checkpoint(),
		"emailsProcessedLastHour": store.ProcessedSince(processedSince),
		"serverTimeUtc":           time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// imapConfigPayload is an alias for mailmsg.IMAPConfigPayload: the type
// moved to package mailmsg (Task 16) so the mail poller can read stored IMAP/
// SMTP credentials without an api->processor->api import cycle. Kept as an
// alias here (rather than rewriting every reference in this package) since
// it's the identical type, just relocated.
type imapConfigPayload = mailmsg.IMAPConfigPayload

func (s *Server) handleIMAPConfig(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	imapConfigPath := s.userIMAPConfigPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		payload, exists, err := mailmsg.ReadIMAPConfigPayload(imapConfigPath, s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to read imap configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, map[string]any{"configured": false, "path": imapConfigPath, "keyPath": s.imapConfigKeyPath})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"configured":      true,
			"path":            imapConfigPath,
			"keyPath":         s.imapConfigKeyPath,
			"host":            payload.Host,
			"port":            payload.Port,
			"username":        payload.Username,
			"mailbox":         payload.Mailbox,
			"smtpHost":        payload.SMTPHost,
			"smtpPort":        payload.SMTPPort,
			"updatedAt":       payload.UpdatedAt,
			"encryptedAtRest": true,
		})
	case http.MethodPost:
		var payload imapConfigPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}

		payload = mailmsg.NormalizeIMAPPayload(payload)
		if payload.Host == "" || payload.Username == "" || payload.Password == "" {
			http.Error(w, "host, username, and password are required", http.StatusBadRequest)
			return
		}
		payload.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

		if err := os.MkdirAll(filepath.Dir(imapConfigPath), 0o700); err != nil {
			http.Error(w, "failed to create imap configuration directory", http.StatusInternalServerError)
			return
		}
		if err := writeIMAPConfigPayload(imapConfigPath, s.imapConfigKeyPath, payload); err != nil {
			http.Error(w, "failed to save imap configuration", http.StatusInternalServerError)
			return
		}
		s.invalidateUserMail(ac.UserID)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"configured":      true,
			"path":            imapConfigPath,
			"keyPath":         s.imapConfigKeyPath,
			"host":            payload.Host,
			"port":            payload.Port,
			"username":        payload.Username,
			"mailbox":         payload.Mailbox,
			"smtpHost":        payload.SMTPHost,
			"smtpPort":        payload.SMTPPort,
			"updatedAt":       payload.UpdatedAt,
			"encryptedAtRest": true,
		})
	case http.MethodDelete:
		if err := os.Remove(imapConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "failed to remove imap configuration", http.StatusInternalServerError)
			return
		}
		s.invalidateUserMail(ac.UserID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": false})
	}
}

func (s *Server) handleIMAPTest(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req imapConfigPayload
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)

	if strings.TrimSpace(req.Host) == "" || strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		stored, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to load imap configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "host, username, and password are required (or store IMAP config first)", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Host) == "" {
			req.Host = stored.Host
		}
		if req.Port <= 0 {
			req.Port = stored.Port
		}
		if strings.TrimSpace(req.Username) == "" {
			req.Username = stored.Username
		}
		if strings.TrimSpace(req.Password) == "" {
			req.Password = stored.Password
		}
		if strings.TrimSpace(req.Mailbox) == "" {
			req.Mailbox = stored.Mailbox
		}
	}

	req = mailmsg.NormalizeIMAPPayload(req)

	client, err := goimap.New(req.Username, req.Password, req.Host, req.Port)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()

	if err := client.SelectFolder(req.Mailbox); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "host": req.Host, "port": req.Port, "mailbox": req.Mailbox})
}

func parseRecipientList(raw string) ([]string, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(raw, ";", ","))
	if normalized == "" {
		return []string{}, nil
	}
	addresses, err := mail.ParseAddressList(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if addr == nil {
			continue
		}
		clean := strings.TrimSpace(addr.Address)
		if clean == "" {
			continue
		}
		out = append(out, clean)
	}
	return out, nil
}

type mailRequest struct {
	Subject     string
	Body        string
	Mode        string
	To          []string
	CC          []string
	BCC         []string
	Attachments []mailmsg.Attachment
	Encrypt     bool
	Sign        bool
	From        string
}

// Attachment budget for one outgoing message (decoded bytes); the request
// body limit leaves headroom for the ~4/3 base64 overhead plus the JSON.
const (
	maxMailAttachmentBytes = 25 << 20
	maxMailRequestBytes    = 40 << 20
)

// decodeMailRequest decodes and validates the shared to/cc/bcc/subject/body/
// mode/attachments JSON body used by both the send and draft-save endpoints.
// On error it returns the client-facing error message alongside the error.
func decodeMailRequest(r *http.Request) (mailRequest, string, error) {
	var raw struct {
		To          string `json:"to"`
		CC          string `json:"cc"`
		BCC         string `json:"bcc"`
		Subject     string `json:"subject"`
		Body        string `json:"body"`
		Mode        string `json:"mode"`
		From        string `json:"from"`
		Attachments []struct {
			Name       string `json:"name"`
			MimeType   string `json:"mimeType"`
			DataBase64 string `json:"dataBase64"`
		} `json:"attachments"`
		Encrypt bool `json:"encrypt"`
		Sign    bool `json:"sign"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMailRequestBytes)).Decode(&raw); err != nil {
		return mailRequest{}, "invalid request", err
	}

	attachments := make([]mailmsg.Attachment, 0, len(raw.Attachments))
	attachmentTotal := 0
	for _, a := range raw.Attachments {
		content, err := base64.StdEncoding.DecodeString(a.DataBase64)
		if err != nil {
			return mailRequest{}, "invalid attachment encoding", err
		}
		attachmentTotal += len(content)
		if attachmentTotal > maxMailAttachmentBytes {
			return mailRequest{}, "attachments too large (max 25 MB total)",
				errors.New("attachment size limit exceeded")
		}
		attachments = append(attachments, mailmsg.Attachment{
			Name:     a.Name,
			MimeType: a.MimeType,
			Content:  content,
		})
	}

	toList, err := parseRecipientList(raw.To)
	if err != nil || len(toList) == 0 {
		if err == nil {
			err = errors.New("missing to recipient")
		}
		return mailRequest{}, "valid TO recipient is required", err
	}
	ccList, err := parseRecipientList(raw.CC)
	if err != nil {
		return mailRequest{}, "invalid CC recipients", err
	}
	bccList, err := parseRecipientList(raw.BCC)
	if err != nil {
		return mailRequest{}, "invalid BCC recipients", err
	}

	return mailRequest{
		Subject:     raw.Subject,
		Body:        raw.Body,
		Mode:        raw.Mode,
		To:          toList,
		CC:          ccList,
		BCC:         bccList,
		Attachments: attachments,
		Encrypt:     raw.Encrypt,
		Sign:        raw.Sign,
		From:        raw.From,
	}, "", nil
}

func sanitizeHeaderValue(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
}

// findContactPGPKey looks up email among the store's contacts (case-
// insensitive) and returns its armored PGP public key, if the matching
// contact has one on file.
func findContactPGPKey(store *contacts.Store, email string) (string, bool) {
	target := strings.ToLower(strings.TrimSpace(email))
	if target == "" {
		return "", false
	}
	for _, c := range store.List() {
		if c.PGPKey == "" {
			continue
		}
		for _, e := range c.Emails {
			if strings.ToLower(strings.TrimSpace(e.Value)) == target {
				return c.PGPKey, true
			}
		}
	}
	return "", false
}

// pgpRecipientPlan splits an encrypted send's To/CC/BCC recipients by PGP
// key availability and status. To/CC recipients with a usable key share one
// ciphertext, matching how a normal email is visible to every To/CC
// recipient. BCC recipients are kept separate so each can be encrypted
// individually in buildPGPDeliveries — sharing a ciphertext (and its
// embedded recipient key IDs) with anyone else would deanonymize them.
// Recipients with no key on file, or whose key is revoked or expired, land
// in withoutKeyEmails and fall back to the existing plaintext pickup-link
// notification.
type pgpRecipientPlan struct {
	toCCEmails       []string
	toCCKeys         []string
	bccEmails        []string
	bccKeys          []string
	withoutKeyEmails []string
}

// buildPGPRecipientPlan resolves each recipient's contact PGP key and
// builds a pgpRecipientPlan. Recipients are deduplicated case-insensitively
// across To+CC+BCC combined, keeping only the first occurrence — an address
// listed in both To and BCC is treated as a To recipient.
func buildPGPRecipientPlan(ctx context.Context, toList, ccList, bccList []string, resolver *keyResolver) pgpRecipientPlan {
	var plan pgpRecipientPlan
	seen := map[string]bool{}

	resolve := func(recipient string) (armoredKey string, usable bool) {
		rk := resolver.resolve(ctx, recipient)
		return rk.Armored, rk.Usable
	}

	toCC := append(append([]string{}, toList...), ccList...)
	for _, recipient := range toCC {
		lower := strings.ToLower(strings.TrimSpace(recipient))
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		if key, ok := resolve(recipient); ok {
			plan.toCCEmails = append(plan.toCCEmails, recipient)
			plan.toCCKeys = append(plan.toCCKeys, key)
		} else {
			plan.withoutKeyEmails = append(plan.withoutKeyEmails, recipient)
		}
	}
	for _, recipient := range bccList {
		lower := strings.ToLower(strings.TrimSpace(recipient))
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		if key, ok := resolve(recipient); ok {
			plan.bccEmails = append(plan.bccEmails, recipient)
			plan.bccKeys = append(plan.bccKeys, key)
		} else {
			plan.withoutKeyEmails = append(plan.withoutKeyEmails, recipient)
		}
	}
	return plan
}

// pgpDelivery is one PGP/MIME ciphertext and the SMTP recipient(s) it
// should be delivered to in a single transaction.
type pgpDelivery struct {
	Recipients []string
	Ciphertext []byte
}

// buildPGPDeliveries encrypts msg once for plan's shared To/CC recipients
// (if any) and once individually for each of plan's BCC recipients, so no
// BCC recipient's key ID ever appears in a ciphertext another recipient can
// inspect. signer is passed straight through to EncryptMIME for every
// delivery (nil if the caller didn't request signing).
func buildPGPDeliveries(msg []byte, plan pgpRecipientPlan, signer *pgpmail.Identity) ([]pgpDelivery, error) {
	var deliveries []pgpDelivery
	if len(plan.toCCEmails) > 0 {
		ciphertext, err := pgpmail.EncryptMIME(msg, plan.toCCKeys, signer)
		if err != nil {
			return nil, fmt.Errorf("encrypt to/cc recipients: %w", err)
		}
		deliveries = append(deliveries, pgpDelivery{Recipients: plan.toCCEmails, Ciphertext: ciphertext})
	}
	for i, recipient := range plan.bccEmails {
		ciphertext, err := pgpmail.EncryptMIME(msg, []string{plan.bccKeys[i]}, signer)
		if err != nil {
			return nil, fmt.Errorf("encrypt bcc recipient %s: %w", recipient, err)
		}
		deliveries = append(deliveries, pgpDelivery{Recipients: []string{recipient}, Ciphertext: ciphertext})
	}
	return deliveries, nil
}

// resolveMailFrom decides the From header value handleMailSend should use,
// given the account's own IMAP username (accountAddr — already sanitized
// and confirmed non-empty by the caller) and the client-requested From
// address (requestedFrom, exactly as decoded from the JSON body — not yet
// trimmed or validated).
//
// If requestedFrom is empty, or names the account's own address
// (case-insensitively), it resolves to accountAddr and aliasStoreFn is
// never called — this preserves today's zero-lookup behavior exactly for
// every existing caller (which never sends `from` at all) and for a caller
// that explicitly re-submits their own address.
//
// Otherwise requestedFrom is parsed as an RFC 5322 address, and
// aliasStoreFn (typically s.sendAsFor(r), passed lazily so it's only
// invoked when actually needed) is consulted for a verified alias matching
// it. A verified alias's stored DisplayName is used to format the
// resolved From via mail.Address.String(), so a display name with special
// characters gets properly quoted/encoded.
//
// On success it returns the resolved header-From and envelope-From values
// and status 0. On failure it returns empty values, along with the exact
// HTTP status code and client-facing message handleMailSend should respond
// with — malformed address (400), alias store unavailable (500), or
// address not a verified alias (403).
//
// headerFrom and envelopeFrom MUST be kept separate by every caller:
// headerFrom may carry a display name (RFC 5322 formatted, for the MIME
// From: header) while envelopeFrom is always a bare addr-spec. net/smtp's
// Mail()/SendMail() never parses the from string it's given — it only
// wraps it verbatim as MAIL FROM:<%s> — so passing a display-name-formatted
// or already-angle-bracketed value as the envelope sender produces a
// malformed SMTP command that real servers reject.
func resolveMailFrom(accountAddr, requestedFrom string, aliasStoreFn func() (*sendas.Store, error)) (headerFrom, envelopeFrom string, status int, msg string) {
	requested := strings.TrimSpace(requestedFrom)
	if requested == "" {
		return accountAddr, accountAddr, 0, ""
	}
	parsed, perr := mail.ParseAddress(requested)
	if perr != nil {
		return "", "", http.StatusBadRequest, "invalid from address"
	}
	candidate := strings.ToLower(parsed.Address)
	if strings.EqualFold(candidate, accountAddr) {
		return accountAddr, accountAddr, 0, ""
	}
	aliasStore, aerr := aliasStoreFn()
	if aerr != nil {
		return "", "", http.StatusInternalServerError, "failed to check send-as aliases"
	}
	alias, ok := aliasStore.FindVerifiedByEmail(candidate)
	if !ok {
		return "", "", http.StatusForbidden, "the from address is not a verified send-as alias for this account"
	}
	headerFrom = sanitizeHeaderValue((&mail.Address{Name: alias.DisplayName, Address: alias.Email}).String())
	envelopeFrom = sanitizeHeaderValue(alias.Email)
	return headerFrom, envelopeFrom, 0, ""
}

func (s *Server) handleMailSend(w http.ResponseWriter, r *http.Request) {
	req, errMsg, err := decodeMailRequest(r)
	if err != nil {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	toList, ccList, bccList := req.To, req.CC, req.BCC

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read mail credentials", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "imap configuration is required before sending", http.StatusBadRequest)
		return
	}

	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		http.Error(w, "smtp host is not configured", http.StatusBadRequest)
		return
	}

	accountAddr := sanitizeHeaderValue(payload.Username)
	if accountAddr == "" {
		http.Error(w, "imap username is required for sender", http.StatusBadRequest)
		return
	}
	headerFrom, envelopeFrom, fromStatus, fromMsg := resolveMailFrom(accountAddr, req.From, func() (*sendas.Store, error) {
		return s.sendAsFor(r)
	})
	if fromStatus != 0 {
		http.Error(w, fromMsg, fromStatus)
		return
	}

	autocryptHeader := s.outboundAutocryptHeader(ac.UserID, envelopeFrom)

	msg := mailmsg.Message{
		From:        headerFrom,
		To:          toList,
		CC:          ccList,
		Subject:     req.Subject,
		Body:        req.Body,
		Mode:        req.Mode,
		Attachments: req.Attachments,
		Autocrypt:   autocryptHeader,
	}.Build()

	var signer *pgpmail.Identity
	if req.Sign || req.Encrypt {
		u, uerr := s.users.Get(ac.UserID)
		if uerr == nil && u.PGPPrivateKeyEnc != "" {
			signer, err = pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, s.pgpPrivateKeyPath)
			if err != nil {
				http.Error(w, "failed to load pgp identity", http.StatusInternalServerError)
				return
			}
		} else if req.Sign {
			http.Error(w, "signing requires a pgp identity — generate or import one first", http.StatusBadRequest)
			return
		}
	}
	if req.Sign && signer != nil {
		if status := signer.Status(); !status.Usable() {
			http.Error(w, "cannot sign — your pgp identity is revoked or expired, generate or import a new one", http.StatusBadRequest)
			return
		}
	}

	if !req.Encrypt {
		if req.Sign {
			signed, serr := pgpmail.SignMIME(msg, signer)
			if serr != nil {
				http.Error(w, "failed to sign message", http.StatusInternalServerError)
				return
			}
			msg = signed
		}
		recipients := append(append(append([]string{}, toList...), ccList...), bccList...)
		s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, recipients, msg, req)
		return
	}

	contactsStore, cerr := s.userContactsStore(ac.UserID)
	if cerr != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	discoverySettings, derr := pgpdiscovery.Load(s.userStateDir(ac.UserID))
	if derr != nil {
		http.Error(w, "failed to load pgp discovery settings", http.StatusInternalServerError)
		return
	}
	suppressed, serr := pgpdiscovery.SuppressedSet(s.userStateDir(ac.UserID))
	if serr != nil {
		http.Error(w, "failed to load pgp discovery suppressions", http.StatusInternalServerError)
		return
	}
	resolver := &keyResolver{store: contactsStore, settings: discoverySettings, discover: req.Encrypt, suppressed: suppressed}
	plan := buildPGPRecipientPlan(r.Context(), toList, ccList, bccList, resolver)
	if len(plan.toCCEmails) == 0 && len(plan.bccEmails) == 0 {
		http.Error(w, "none of the recipients have a known pgp key — disable encryption or add keys to your contacts first", http.StatusBadRequest)
		return
	}

	deliveries, eerr := buildPGPDeliveries(msg, plan, encryptSigner(signer, req.Sign))
	if eerr != nil {
		http.Error(w, "failed to encrypt message", http.StatusInternalServerError)
		return
	}

	// deliveries[0] is always the correct hard-error-gated send: buildPGPDeliveries
	// guarantees the shared To/CC ciphertext (if any) comes first, otherwise the
	// first BCC recipient's ciphertext is deliveries[0]. deliveries is guaranteed
	// non-empty here because we already returned a 400 above when both
	// plan.toCCEmails and plan.bccEmails were empty. Treating index 0 uniformly
	// (rather than special-casing on len(plan.toCCEmails) > 0) avoids a BCC-only
	// send picking an empty "main" delivery, which previously let finishMailSend
	// report ok:true via its empty-recipient-list guard before any of the actual
	// best-effort BCC sends had even been attempted.
	mainRecipients, mainCiphertext := deliveries[0].Recipients, deliveries[0].Ciphertext
	bccDeliveries := deliveries[1:]

	if !s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, mainRecipients, mainCiphertext, req) {
		return
	}

	for _, delivery := range bccDeliveries {
		if err := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, delivery.Recipients, delivery.Ciphertext); err != nil {
			s.logger.Error("bcc pgp send failed", "recipient", delivery.Recipients[0], "error", err.Error())
		}
	}

	for _, recipient := range plan.withoutKeyEmails {
		if err := s.sendPickupNotification(ac.UserID, envelopeFrom, recipient, req.Subject, req.Body, smtpHost, smtpPort, addr, payload.Username, payload.Password); err != nil {
			s.logger.Error("pickup notification send failed", "recipient", recipient, "error", err.Error())
		}
	}
}

// encryptSigner decides which signer identity (if any) should be embedded
// into an encrypted message. Encrypt and Sign are independent per-email
// toggles: an identity being loaded (because Encrypt requires checking
// whether one exists, or because Sign itself was requested) must not imply
// the message gets signed. Only pass a signer through to EncryptMIME when
// the caller explicitly asked to sign — otherwise Encrypt=true, Sign=false
// would silently produce a signed-and-encrypted message whenever the sender
// happens to have a PGP identity configured, costing them deniability they
// never asked to give up.
func encryptSigner(signer *pgpmail.Identity, sign bool) *pgpmail.Identity {
	if !sign {
		return nil
	}
	return signer
}

// finishMailSend sends msg over SMTP to recipients and best-effort saves it
// to the Sent folder (as plaintext — see the plan's Global Constraints on
// why the Sent copy isn't PGP-wrapped), writing the JSON response. Returns
// false if the send itself failed (response already written), so callers
// with follow-up work (e.g. pickup notifications) know not to proceed.
func (s *Server) finishMailSend(w http.ResponseWriter, r *http.Request, userID, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, toList, ccList, bccList, recipients []string, msg []byte, req mailRequest) bool {
	s.logger.Info("mail send requested", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "recipientCount", strconv.Itoa(len(recipients)))

	if len(recipients) > 0 {
		if sendErr := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, smtpUsername, smtpPassword, from, recipients, msg); sendErr != nil {
			s.logger.Error("mail send failed", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "error", sendErr.Error())
			http.Error(w, fmt.Sprintf("failed to send email: %s", sendErr.Error()), http.StatusBadGateway)
			return false
		}
	}

	warning := ""
	sentSaved := true
	if mailClient, mailErr := s.userMailClient(userID); mailErr == nil {
		if err := mailClient.SaveSent(r.Context(), imapadapter.DraftMessage{
			To:          toList,
			CC:          ccList,
			BCC:         bccList,
			Subject:     req.Subject,
			Body:        req.Body,
			Mode:        req.Mode,
			Attachments: req.Attachments,
		}); err != nil {
			sentSaved = false
			warning = "email sent but could not be saved to Sent folder"
			s.logger.Error("mail sent but save-sent failed", "error", err.Error())
		}
	}
	s.logger.Info("mail send completed", "sentSaved", strconv.FormatBool(sentSaved))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sentSaved": sentSaved, "warning": warning})
	return true
}

func (s *Server) handleMailDraft(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required before saving drafts", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	req, errMsg, err := decodeMailRequest(r)
	if err != nil {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	if err := mailClient.SaveDraft(r.Context(), imapadapter.DraftMessage{
		To:          req.To,
		CC:          req.CC,
		BCC:         req.BCC,
		Subject:     req.Subject,
		Body:        req.Body,
		Mode:        req.Mode,
		Attachments: req.Attachments,
	}); err != nil {
		http.Error(w, "failed to save draft", http.StatusBadGateway)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// attachmentRequestParams reads the shared mailbox/messageId query params of
// the two attachment endpoints. messageId is an IMAP UID, the same id shape
// /api/inbox and /api/inbox/actions use.
func attachmentRequestParams(r *http.Request) (mailbox string, uid int, err error) {
	mailbox = strings.TrimSpace(r.URL.Query().Get("mailbox"))
	uid, err = strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("messageId")))
	if err != nil || uid <= 0 {
		return "", 0, errors.New("valid messageId is required")
	}
	return mailbox, uid, nil
}

// handleMailAttachmentList returns attachment metadata for one message.
// GET /api/mail/attachments?sub=&hash=&mailbox=&messageId=
func (s *Server) handleMailAttachmentList(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}
	s.serveAttachmentList(w, r, mailClient)
}

func (s *Server) serveAttachmentList(w http.ResponseWriter, r *http.Request, mailClient imapadapter.Client) {
	mailbox, uid, err := attachmentRequestParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	infos, err := mailClient.ListAttachments(r.Context(), mailbox, uid)
	if err != nil {
		s.logger.Error("attachment list failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		http.Error(w, "failed to list attachments", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "attachments": infos})
}

// handleMailAttachmentDownload streams one attachment's bytes.
// GET /api/mail/attachment?sub=&hash=&mailbox=&messageId=&index=
func (s *Server) handleMailAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}
	s.serveAttachmentDownload(w, r, mailClient)
}

func (s *Server) serveAttachmentDownload(w http.ResponseWriter, r *http.Request, mailClient imapadapter.Client) {
	mailbox, uid, err := attachmentRequestParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	index, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("index")))
	if err != nil || index < 0 {
		http.Error(w, "valid index is required", http.StatusBadRequest)
		return
	}
	info, content, err := mailClient.GetAttachment(r.Context(), mailbox, uid, index)
	if errors.Is(err, imapadapter.ErrAttachmentNotFound) {
		http.Error(w, "attachment not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.logger.Error("attachment fetch failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		http.Error(w, "failed to fetch attachment", http.StatusBadGateway)
		return
	}

	contentType := strings.TrimSpace(info.MimeType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	name := mailmsg.SanitizeHeaderValue(info.Name)
	if name == "" {
		name = "attachment"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(
		"attachment", map[string]string{"filename": name},
	))
	w.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func writeIMAPConfigPayload(path, keyPath string, payload imapConfigPayload) error {
	plain, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return writeEncryptedPayload(path, keyPath, plain)
}

func writeEncryptedPayload(path, keyPath string, payload []byte) error {
	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		return err
	}

	env, err := cryptutil.Seal(payload, key)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	return fsutil.AtomicWriteFile(path, b, 0o600)
}

func decryptEncryptedPayload(raw []byte, keyPath string) ([]byte, error) {
	env, ok := cryptutil.ParseEnvelope(raw)
	if !ok {
		// Backward-compatibility with plaintext credentials.
		return raw, nil
	}

	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return cryptutil.Open(env, key)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.RLock()
		cfg := s.cfg
		s.mu.RUnlock()
		// The remote LLM API key is a live secret: never echo it back to
		// any caller, admin included. Report only whether one is set, on
		// this response copy — the live s.cfg is never mutated.
		cfg.Classifier.APIKeySet = cfg.Classifier.APIKey != ""
		cfg.Classifier.APIKey = ""
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodPut:
		var next config.Config
		if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
			http.Error(w, "invalid config payload", http.StatusBadRequest)
			return
		}
		s.mu.RLock()
		// APIKeySet is a response-only computed field (see GET above) and is
		// never meaningful in a PUT payload. Reset it unconditionally before
		// the change-detection diff so a naive round-trip of a GET response
		// (which echoes apiKeySet=true when a key is configured) doesn't
		// spuriously register as a Classifier change.
		next.Classifier.APIKeySet = false
		// GET always zeroes APIKey on the wire, so a naive round-trip PUT
		// will carry apiKey="". Preserve the live key in that case rather
		// than wiping it, and do so before the diff so that round-trip
		// isn't misread as the user clearing the key.
		if next.Classifier.APIKey == "" {
			next.Classifier.APIKey = s.cfg.Classifier.APIKey
		}
		classifierChanged := next.Classifier != s.cfg.Classifier
		// VAPID key material is server-owned and json:"-" on the wire;
		// carry it across the round-trip.
		next.Notifications = s.cfg.Notifications
		s.mu.RUnlock()
		// Remote LLM settings are admin-only. Reject (rather than silently
		// drop) a non-admin change so a broken save is never masked.
		if ac, ok := authFromContext(r); classifierChanged && (!ok || ac.Role != users.RoleAdmin) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "remote llm settings require admin access"})
			return
		}
		if err := config.Save(s.configPath, next); err != nil {
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		s.cfg = next
		s.mu.Unlock()
		if classifierChanged {
			classifier.ResetWarmupState()
		}
		if s.onConfigUpdated != nil {
			s.onConfigUpdated(next)
		}
		s.logger.Info("config updated via api")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// handleNotificationPreferences reads/writes the calling user's delivery
// preferences (mode/keywords), which moved out of the global config.
func (s *Server) handleNotificationPreferences(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	path := s.userSettingsPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		settings, err := config.LoadUserSettings(path)
		if err != nil {
			http.Error(w, "failed to read notification preferences", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, settings.Notifications)
	case http.MethodPut:
		var prefs config.UserNotificationSettings
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&prefs); err != nil {
			http.Error(w, "invalid preferences payload", http.StatusBadRequest)
			return
		}
		settings, err := config.LoadUserSettings(path)
		if err != nil {
			settings = config.DefaultUserSettings()
		}
		if prefs.Keywords == nil {
			prefs.Keywords = []string{}
		}
		settings.Notifications = prefs
		if err := config.SaveUserSettings(path, settings); err != nil {
			http.Error(w, "failed to save notification preferences", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// handleLabelPreferences reads/writes the calling user's preference for
// whether the AI classifier automatically applies keyword labels.
func (s *Server) handleLabelPreferences(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	path := s.userSettingsPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		settings, err := config.LoadUserSettings(path)
		if err != nil {
			http.Error(w, "failed to read label preferences", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, settings.Labels)
	case http.MethodPut:
		var prefs config.UserLabelSettings
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&prefs); err != nil {
			http.Error(w, "invalid preferences payload", http.StatusBadRequest)
			return
		}
		settings, err := config.LoadUserSettings(path)
		if err != nil {
			settings = config.DefaultUserSettings()
		}
		settings.Labels = prefs
		if err := config.SaveUserSettings(path, settings); err != nil {
			http.Error(w, "failed to save label preferences", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

type notificationSubscriptionPayload struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		Auth   string `json:"auth"`
		P256DH string `json:"p256dh"`
	} `json:"keys"`
}

type notificationTestPayload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func (s *Server) handleNotificationVAPIDPublicKey(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	publicKey := strings.TrimSpace(s.cfg.Notifications.PublicKey)
	s.mu.RUnlock()
	if publicKey == "" {
		http.Error(w, "notification public key not configured", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"publicKey": publicKey})
}

func (s *Server) handleNotificationSubscriptions(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var payload notificationSubscriptionPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid subscription payload", http.StatusBadRequest)
			return
		}
		payload.Endpoint = strings.TrimSpace(payload.Endpoint)
		payload.Keys.Auth = strings.TrimSpace(payload.Keys.Auth)
		payload.Keys.P256DH = strings.TrimSpace(payload.Keys.P256DH)
		if payload.Endpoint == "" || payload.Keys.Auth == "" || payload.Keys.P256DH == "" {
			http.Error(w, "endpoint and keys are required", http.StatusBadRequest)
			return
		}

		sub := state.NotificationSubscription{
			Endpoint:  payload.Endpoint,
			Auth:      payload.Keys.Auth,
			P256DH:    payload.Keys.P256DH,
			UserAgent: strings.TrimSpace(r.Header.Get("User-Agent")),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := store.UpsertNotificationSubscription(sub); err != nil {
			http.Error(w, "failed to persist notification subscription", http.StatusInternalServerError)
			return
		}
		count := len(store.ListNotificationSubscriptions())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "subscriptions": count})
	case http.MethodDelete:
		var payload struct {
			Endpoint string `json:"endpoint"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid unsubscribe payload", http.StatusBadRequest)
			return
		}
		endpoint := strings.TrimSpace(payload.Endpoint)
		if endpoint == "" {
			http.Error(w, "endpoint is required", http.StatusBadRequest)
			return
		}
		removed, err := store.RemoveNotificationSubscription(endpoint)
		if err != nil {
			http.Error(w, "failed to remove notification subscription", http.StatusInternalServerError)
			return
		}
		count := len(store.ListNotificationSubscriptions())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "subscriptions": count})
	}
}

func (s *Server) handleNotificationTest(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	var payload notificationTestPayload
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload)
	title := strings.TrimSpace(payload.Title)
	body := strings.TrimSpace(payload.Body)
	if title == "" {
		title = "KyPost Test Notification"
	}
	if body == "" {
		body = "Push delivery is working across all subscribed devices."
	}

	message := map[string]any{
		"title": title,
		"body":  body,
		"url":   "/notifications",
		"tag":   "kypost-test",
	}
	payloadBytes, err := json.Marshal(message)
	if err != nil {
		http.Error(w, "failed to serialize notification payload", http.StatusInternalServerError)
		return
	}

	subs := store.ListNotificationSubscriptions()
	sent := 0
	failed := 0
	removed := 0
	if len(subs) > 0 {
		outcome, err := processor.SendWebPush(store, s.cfg.Notifications.PublicKey, s.cfg.Notifications.PrivateKeyPath, 3600, payloadBytes)
		if err != nil {
			http.Error(w, "failed to load notification private key", http.StatusInternalServerError)
			return
		}
		sent = outcome.Sent
		failed = outcome.Failed
		removed = outcome.Removed
	}

	nativeDevices := store.ListNativeDevices()
	nativeSent := 0
	nativeFailed := 0
	nativeRemoved := 0
	nativeError := ""
	if len(nativeDevices) > 0 {
		nativeMessage := processor.NativePushMessage{
			Title: title,
			Body:  body,
			Data:  map[string]string{"url": "/notifications"},
		}
		outcome, err := processor.SendNativePush(r.Context(), s.nativePushDispatcher, s.health, store, nativeMessage, func(device state.NativeDevice, platform string, sendErr error) {
			s.logger.Error("test native notification failed", "device_id", strings.TrimSpace(device.DeviceID), "platform", platform, "sender", "relay", "error", sendErr.Error())
		})
		if outcome.Queued {
			// App Pull mode: queue the test for the device to fetch over HTTP
			// instead of dispatching through the relay/Firebase.
			if err != nil {
				nativeError = "failed to queue pull notification: " + err.Error()
				s.logger.Error("test native pull notification failed", "error", err.Error())
			} else {
				nativeSent = outcome.Sent
			}
		} else {
			nativeSent = outcome.Sent
			nativeFailed = outcome.Failed
			nativeRemoved = outcome.Removed
		}
	}

	resp := map[string]any{
		"ok":                  failed == 0 && nativeFailed == 0 && nativeError == "",
		"subscriptions":       len(subs),
		"sent":                sent,
		"failed":              failed,
		"removedStale":        removed,
		"activeSubscriptions": len(store.ListNotificationSubscriptions()),
		"nativeDevices":       len(nativeDevices),
		"nativeSent":          nativeSent,
		"nativeFailed":        nativeFailed,
		"nativeRemovedStale":  nativeRemoved,
	}
	if nativeError != "" {
		resp["nativeError"] = nativeError
	}
	writeJSON(w, http.StatusOK, resp)
}

// nativePairingTokenTTL is the validity window for a native-device pairing
// token, shared by the token-minting call site (handleNotificationPairing)
// and the nonce-consumption TTL in handleNotificationNativeRegister — a
// single constant so the two can't drift out of sync.
const nativePairingTokenTTL = 90 * time.Second

func (s *Server) handleNotificationPairing(w http.ResponseWriter, r *http.Request) {
	ac, okAuth := authFromContext(r)
	if !okAuth {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	store, err := s.userStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	subscriberID, err := store.GetOrCreateSubscriberID()
	if err != nil {
		http.Error(w, "failed to load subscriber id", http.StatusInternalServerError)
		return
	}
	// Keep the unauthenticated register endpoint's subscriber -> user index
	// warm so a device pairing right after this call resolves immediately.
	s.userMu.Lock()
	s.subIndex[subscriberID] = ac.UserID
	s.userMu.Unlock()
	configured := s.pairingSecret != ""
	configurationError := ""
	if !configured {
		configurationError = "pairing is not configured on the server; set PAIRING_SECRET"
	}
	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	registerEndpoint := ""
	pullEndpoint := ""
	if serverBaseURL != "" {
		registerEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/register"
		pullEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/pull"
	}
	pairingTTLSeconds := int64(nativePairingTokenTTL.Seconds())
	resp := map[string]any{
		"subscriberId":      subscriberID,
		"serverBaseUrl":     serverBaseURL,
		"registerEndpoint":  registerEndpoint,
		"pullEndpoint":      pullEndpoint,
		"deliveryMode":      store.NativeDeliveryMode(),
		"pairingTtlSeconds": pairingTTLSeconds,
		"configured":        configured,
	}
	if configurationError != "" {
		resp["configurationError"] = configurationError
	}
	if configured {
		token, expiresAt, err := s.createPairingToken(subscriberID, pairingPurposeNativeDevice, time.Duration(pairingTTLSeconds)*time.Second)
		if err != nil {
			s.logger.Error("failed to create pairing token", "subscriber_id", subscriberID, "error", err.Error())
			http.Error(w, "failed to prepare mobile pairing", http.StatusInternalServerError)
			return
		}
		resp["pairingToken"] = token
		resp["pairingExpiresAt"] = expiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

type nativeRegisterRequest struct {
	SubscriberID string `json:"subscriberId"`
	PairingToken string `json:"pairingToken"`
	DeviceToken  string `json:"deviceToken"`
	DeviceID     string `json:"deviceId,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Transport    string `json:"transport,omitempty"`
	DeviceName   string `json:"deviceName,omitempty"`
	AppVersion   string `json:"appVersion,omitempty"`
}

func (s *Server) handleNotificationNativeRegister(w http.ResponseWriter, r *http.Request) {
	if s.pairingSecret == "" {
		http.Error(w, "pairing is not configured", http.StatusServiceUnavailable)
		return
	}

	var req nativeRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	subscriberID := strings.TrimSpace(req.SubscriberID)
	pairingToken := strings.TrimSpace(req.PairingToken)
	deviceToken := strings.TrimSpace(req.DeviceToken)
	if subscriberID == "" || pairingToken == "" || deviceToken == "" {
		http.Error(w, "subscriberId, pairingToken, and deviceToken are required", http.StatusBadRequest)
		return
	}

	platform := normalizeNativePlatform(req.Platform)
	transport, err := normalizeNativeTransport(req.Transport, req.Platform)
	if err != nil {
		http.Error(w, "invalid transport: "+err.Error(), http.StatusBadRequest)
		return
	}

	// For UnifiedPush, the deviceToken is an HTTPS endpoint URL the client
	// fully controls, not an opaque token — reject anything that could be used
	// for SSRF against internal services (private/loopback/link-local hosts).
	// The sender re-checks at send time too, against DNS rebinding.
	if transport == "unifiedpush" {
		if err := processor.ValidateUnifiedPushEndpointURL(deviceToken); err != nil {
			http.Error(w, "invalid unifiedpush deviceToken: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	claims, err := s.decodeAndVerifyPairingToken(pairingToken, pairingPurposeNativeDevice, time.Now().UTC())
	if err != nil {
		http.Error(w, "invalid or expired pairing token", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(claims.Sub)), []byte(subscriberID)) != 1 {
		http.Error(w, "invalid or expired pairing token", http.StatusUnauthorized)
		return
	}
	// Native pairing tokens are meant to be redeemed exactly once — the
	// QR/deep-link a user scans to pair a new device. Without this, the same
	// captured token stays valid for its full TTL and could register an
	// unlimited number of devices.
	if !s.nativePairingNonces.consume(claims.Nonce, nativePairingTokenTTL) {
		http.Error(w, "pairing token already used", http.StatusConflict)
		return
	}

	// The pairing token proved this device was handed a QR minted by a
	// signed-in user; resolve which user's device list to write into.
	ownerID, okOwner := s.lookupUserBySubscriber(subscriberID)
	if !okOwner {
		http.Error(w, "unknown subscriber", http.StatusUnauthorized)
		return
	}
	store, err := s.userStore(ownerID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	// A device id is global (the deviceIndex maps it to exactly one owner), but
	// the id is client-supplied. Reserve it atomically (check-and-set under
	// one lock, not a separate check followed by a later write) so a caller
	// can't hijack a victim's device-index entry and deny that device
	// service, even under concurrent registration requests.
	if !s.reserveDeviceID(ownerID, strings.TrimSpace(req.DeviceID)) {
		http.Error(w, "device id already registered", http.StatusConflict)
		return
	}

	// Mint this device's own pairing secret. Only its hash is ever persisted
	// (see state.NativeDevice.SecretHash); the raw value is returned once
	// below and never retrievable again.
	rawSecret, err := randomToken(24)
	if err != nil {
		http.Error(w, "failed to mint device secret", http.StatusInternalServerError)
		return
	}
	secretHash, err := users.HashPassword(rawSecret)
	if err != nil {
		http.Error(w, "failed to mint device secret", http.StatusInternalServerError)
		return
	}

	device := state.NativeDevice{
		DeviceID:    strings.TrimSpace(req.DeviceID),
		Platform:    platform,
		Transport:   transport,
		PushToken:   deviceToken,
		DeviceName:  strings.TrimSpace(req.DeviceName),
		AppVersion:  strings.TrimSpace(req.AppVersion),
		UserAgent:   strings.TrimSpace(r.Header.Get("User-Agent")),
		UserID:      ownerID,
		MFAApprover: true,
		SecretHash:  secretHash,
	}
	if err := store.UpsertNativeDevice(device); err != nil {
		http.Error(w, "failed to persist native device", http.StatusInternalServerError)
		return
	}

	// Resolve the canonical device ID by token: the upsert may have merged
	// this registration into an existing row (same token + platform), whose
	// ID wins over whatever the request carried.
	devices := store.ListNativeDevices()
	registeredDeviceID := device.DeviceID
	for i := len(devices) - 1; i >= 0; i-- {
		if strings.TrimSpace(devices[i].PushToken) == deviceToken && devices[i].Platform == device.Platform {
			registeredDeviceID = devices[i].DeviceID
			break
		}
	}

	s.userMu.Lock()
	s.deviceIndex[registeredDeviceID] = ownerID
	s.userMu.Unlock()

	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	pullEndpoint := ""
	if serverBaseURL != "" {
		pullEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/native/pull"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"synced":       true,
		"deviceId":     registeredDeviceID,
		"deviceSecret": rawSecret,
		"devices":      len(devices),
		"deliveryMode": store.NativeDeliveryMode(),
		"pullEndpoint": pullEndpoint,
		"transport":    transport,
	})
}

func (s *Server) handleNotificationNativeDevices(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		devices := store.ListNativeDevices()
		redacted := make([]state.NativeDevice, len(devices))
		for i, d := range devices {
			redacted[i] = d.Redacted()
		}
		writeJSON(w, http.StatusOK, map[string]any{"devices": redacted})
	case http.MethodDelete:
		var payload struct {
			DeviceID string `json:"deviceId"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		deviceID := strings.TrimSpace(payload.DeviceID)
		if deviceID == "" {
			http.Error(w, "deviceId is required", http.StatusBadRequest)
			return
		}
		removed, err := store.RemoveNativeDevice(deviceID)
		if err != nil {
			http.Error(w, "failed to remove native device", http.StatusInternalServerError)
			return
		}
		s.userMu.Lock()
		delete(s.deviceIndex, deviceID)
		s.userMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "devices": len(store.ListNativeDevices())})
	}
}

func normalizeNativePlatform(platform string) string {
	clean := strings.ToLower(strings.TrimSpace(platform))
	if clean == "" {
		// Legacy clients that omit platform entirely default to android.
		return "android"
	}
	// Pass any other platform name through unchanged so a new client isn't
	// silently mislabeled as android — it just shows up under its own name.
	return clean
}

func normalizeNativeTransport(transport, platform string) (string, error) {
	clean := strings.ToLower(strings.TrimSpace(transport))
	switch clean {
	case "fcm", "apns", "unifiedpush":
		return clean, nil
	case "":
		// Derive from platform if transport not specified (legacy behavior).
		switch strings.ToLower(strings.TrimSpace(platform)) {
		case "ios", "macos":
			return "apns", nil
		case "linux":
			return "unifiedpush", nil
		default:
			return "fcm", nil
		}
	default:
		return "", fmt.Errorf("unrecognized transport %q", clean)
	}
}

func (s *Server) handleNotificationNativeUnpair(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	devices := store.ListNativeDevices()
	removed := 0
	for _, device := range devices {
		if strings.TrimSpace(device.DeviceID) == "" {
			continue
		}
		ok, err := store.RemoveNativeDevice(device.DeviceID)
		if err != nil {
			http.Error(w, "failed to revoke paired devices", http.StatusInternalServerError)
			return
		}
		if ok {
			removed++
			s.userMu.Lock()
			delete(s.deviceIndex, device.DeviceID)
			s.userMu.Unlock()
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed, "devices": len(store.ListNativeDevices())})
}

// handleNotificationNativeDeregister lets a paired device remove itself —
// e.g. on app logout/uninstall — without going through a web session. It
// authenticates with the device's own X-Kypost-Device-Id/
// X-Kypost-Device-Secret credentials (deviceAuthFromRequest), so a device can
// only ever remove itself, never another device on the account.
func (s *Server) handleNotificationNativeDeregister(w http.ResponseWriter, r *http.Request) {
	userID, device, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	if _, err := store.RemoveNativeDevice(device.DeviceID); err != nil {
		http.Error(w, "failed to remove device", http.StatusInternalServerError)
		return
	}
	s.userMu.Lock()
	delete(s.deviceIndex, device.DeviceID)
	s.userMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleNotificationNativeMode switches native delivery between the relay-backed
// push mode and App Pull mode for the signed-in user.
func (s *Server) handleNotificationNativeMode(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != state.DeliveryModePush && mode != state.DeliveryModePull {
		http.Error(w, "mode must be \"push\" or \"pull\"", http.StatusBadRequest)
		return
	}
	if err := store.SetNativeDeliveryMode(mode); err != nil {
		http.Error(w, "failed to persist delivery mode", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deliveryMode": store.NativeDeliveryMode()})
}

// handleNotificationNativePull serves queued notifications to a paired mobile
// app polling over plain HTTP — the App Pull path that bypasses the Cloudflare
// relay and Firebase entirely. It is unauthenticated by web session; the
// device proves it is that specific still-paired device with its own
// deviceId + deviceSecret (minted at registration), sent via the
// X-Kypost-Device-Id/X-Kypost-Device-Secret headers (see device_auth.go). The
// client passes ?after=<cursor> to fetch only notifications newer than its
// last poll.
func (s *Server) handleNotificationNativePull(w http.ResponseWriter, r *http.Request) {
	userID, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	store, err := s.userStore(userID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	var after int64
	if raw := strings.TrimSpace(r.URL.Query().Get("after")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			after = parsed
		}
	}
	notifications, cursor := store.PullNotificationsAfter(after)
	if notifications == nil {
		notifications = []state.PullNotification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deliveryMode":  store.NativeDeliveryMode(),
		"cursor":        cursor,
		"notifications": notifications,
	})
}

func (s *Server) handleDesktopPair(w http.ResponseWriter, r *http.Request) {
	ac, okAuth := authFromContext(r)
	if !okAuth {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	store, err := s.userStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}

	// Check rate limit: max 5 failed attempts per hour
	allowed, remaining, err := store.CheckDesktopPairingRateLimit()
	if err != nil {
		s.logger.Error("rate limit check failed", "user_id", ac.UserID, "error", err.Error())
		http.Error(w, "failed to check rate limit", http.StatusInternalServerError)
		return
	}
	if !allowed {
		s.logger.Error("desktop pairing rate limit exceeded", "user_id", ac.UserID)
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "rate limit exceeded: too many pairing attempts. Try again later.",
		})
		return
	}

	// Generate 16 bytes (128 bits) of cryptographically secure random data
	codeBytes := make([]byte, 16)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "failed to generate pairing code", http.StatusInternalServerError)
		return
	}

	// Return as 32-character hex string (no formatting, delivered via API/QR only)
	pairingCode := strings.ToUpper(hex.EncodeToString(codeBytes))

	// Store pairing code with 5-minute expiration
	if err := store.SetDesktopPairingCode(pairingCode, 5*time.Minute); err != nil {
		s.logger.Error("failed to store desktop pairing code", "user_id", ac.UserID, "error", err.Error())
		http.Error(w, "failed to create pairing code", http.StatusInternalServerError)
		return
	}

	// Record successful pairing initiation
	_ = store.RecordDesktopPairingAttempt(pairingCode, true)

	// Log pairing event without exposing the full code (only hash for correlation)
	s.logger.Info("desktop pairing initiated", "user_id", ac.UserID, "code_hash", pairingCode[:8])

	// Build server URL and register endpoint for desktop app
	serverBaseURL := s.serverBaseURL
	if serverBaseURL == "" {
		serverBaseURL = externalBaseURL(r)
	}
	registerEndpoint := ""
	if serverBaseURL != "" {
		registerEndpoint = strings.TrimRight(serverBaseURL, "/") + "/api/notifications/desktop/register"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"pairingCode":      pairingCode,
		"ttlSeconds":       300,
		"rateLimit":        remaining,
		"serverBaseUrl":    serverBaseURL,
		"registerEndpoint": registerEndpoint,
	})
}

// Pairing tokens are minted for exactly one of these purposes and are only
// ever valid for that same purpose. Without this separation, a token minted
// for one flow (e.g. a low-stakes pickup link, mailed in plaintext to a
// recipient with no account) could be replayed against a different, more
// sensitive flow (e.g. native device pairing, which grants full mail sync
// and push-MFA-approval rights) if an attacker obtained it.
const (
	pairingPurposeNativeDevice = "native-device"
	pairingPurposePGPQRKey     = "pgp-qr-key"
	pairingPurposePickupLink   = "pickup-link"
)

type pairingTokenClaims struct {
	Sub     string `json:"sub"`
	Exp     int64  `json:"exp"`
	Nonce   string `json:"n"`
	Purpose string `json:"purpose"`
}

func (s *Server) createPairingToken(subscriberID, purpose string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", time.Time{}, err
	}

	expiresAt := time.Now().UTC().Add(ttl)
	claims := pairingTokenClaims{
		Sub:     strings.TrimSpace(subscriberID),
		Exp:     expiresAt.Unix(),
		Nonce:   hex.EncodeToString(nonceBytes),
		Purpose: purpose,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	mac := hmac.New(sha256.New, []byte(s.pairingSecret))
	mac.Write(payload)
	sig := mac.Sum(nil)

	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
	return token, expiresAt, nil
}

// decodeAndVerifyPairingToken decodes token (in the shape produced by
// createPairingToken), verifies its HMAC signature, checks expiry, and
// checks that the token's purpose matches wantPurpose, returning its claims.
// The purpose check is a plain != — the purpose isn't secret, unlike the
// HMAC signature and (in validatePairingToken) the subject, which correctly
// stay constant-time comparisons. Shared by validatePairingToken (which
// additionally checks the subject against a caller-supplied expectation) and
// parsePairingTokenUserID (which returns the subject to the caller instead).
func (s *Server) decodeAndVerifyPairingToken(token, wantPurpose string, now time.Time) (pairingTokenClaims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return pairingTokenClaims{}, errors.New("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return pairingTokenClaims{}, errors.New("invalid token payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return pairingTokenClaims{}, errors.New("invalid token signature")
	}

	mac := hmac.New(sha256.New, []byte(s.pairingSecret))
	mac.Write(payload)
	expectedSig := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, expectedSig) != 1 {
		return pairingTokenClaims{}, errors.New("signature mismatch")
	}

	var claims pairingTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return pairingTokenClaims{}, errors.New("invalid token claims")
	}
	if claims.Exp <= 0 || now.UTC().Unix() > claims.Exp {
		return pairingTokenClaims{}, errors.New("token expired")
	}
	if claims.Purpose != wantPurpose {
		return pairingTokenClaims{}, errors.New("purpose mismatch")
	}

	return claims, nil
}

func (s *Server) validatePairingToken(subscriberID, token, wantPurpose string, now time.Time) error {
	claims, err := s.decodeAndVerifyPairingToken(token, wantPurpose, now)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(claims.Sub)), []byte(strings.TrimSpace(subscriberID))) != 1 {
		return errors.New("subscriber mismatch")
	}
	return nil
}

// parsePairingTokenUserID decodes and HMAC-verifies token without requiring
// the caller to already know the expected subject, returning the subject
// the token was minted for. Used by the QR key-fetch endpoint, which must
// learn which user a token belongs to rather than confirm a known one —
// unlike validatePairingToken (used for pickup links, where the URL path
// already carries the expected ID to check against).
func (s *Server) parsePairingTokenUserID(token, wantPurpose string, now time.Time) (string, error) {
	claims, err := s.decodeAndVerifyPairingToken(token, wantPurpose, now)
	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}

// trustProxyHeaders reports whether X-Forwarded-Proto/Host/For may be
// believed. Defaults to false (fail closed) — the shipped docker-compose.yml
// exposes the container directly with no reverse proxy in front, so trusting
// these headers by default would let any client forge its own IP and defeat
// the login/CardDAV lockouts. Deployments that do put a TLS-terminating
// reverse proxy in front must explicitly set TRUST_PROXY_HEADERS=true.
func trustProxyHeaders() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")), "true")
}

func externalBaseURL(r *http.Request) string {
	var proto, host string
	if trustProxyHeaders() {
		proto = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		host = strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0])
	}
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host
}

// clientIP best-effort resolves the caller's IP for logging, CAPTCHA
// context, and lockout keying: X-Forwarded-For's first hop when proxy
// headers are trusted (see trustProxyHeaders — this app then also trusts
// X-Forwarded-* for scheme/host in externalBaseURL/isRequestSecure), falling
// back to the raw connection address with its port stripped. When used as a
// lockout key, a client forging X-Forwarded-For on a directly-exposed
// deployment could dodge or misdirect lockouts — set TRUST_PROXY_HEADERS=false
// there.
func clientIP(r *http.Request) string {
	if trustProxyHeaders() {
		// Use the RIGHT-most hop — the address the nearest trusted proxy
		// appended — not the left-most one. A client can prepend arbitrary
		// values to X-Forwarded-For (an appending proxy like nginx's
		// $proxy_add_x_forwarded_for turns a client-sent "a" into "a, <realip>"),
		// so keying the login lockout on the left-most hop let a client rotate
		// it and evade the lockout. This assumes a single trusted proxy in
		// front; multi-proxy deployments should set TRUST_PROXY_HEADERS=false
		// and rely on RemoteAddr, or terminate the chain at a known hop.
		if xff := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(xff) != "" {
			parts := strings.Split(xff, ",")
			if fwd := strings.TrimSpace(parts[len(parts)-1]); fwd != "" {
				return fwd
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

// isRequestSecure reports whether r was received over HTTPS, either
// directly or (per X-Forwarded-Proto) via a TLS-terminating reverse proxy.
// Used to decide whether the session cookie can carry the Secure attribute
// without breaking plain-HTTP local/dev deployments.
func isRequestSecure(r *http.Request) bool {
	if trustProxyHeaders() {
		if proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); proto != "" {
			return strings.EqualFold(proto, "https")
		}
	}
	return r.TLS != nil
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	writeJSON(w, http.StatusOK, store.Decisions(limit))
}

type inboxEmail struct {
	MessageID string `json:"messageId"`
	Sender    string `json:"sender"`
	SentTo    string `json:"sentTo,omitempty"`
	CC        string `json:"cc,omitempty"`
	BCC       string `json:"bcc,omitempty"`
	Subject   string `json:"subject"`
	Body      string `json:"body,omitempty"`
	Label     string `json:"label,omitempty"`
	// Keywords is every raw IMAP keyword flag on the message (unlike Label,
	// which is just the first one matching an allowlisted tab). Stamped in
	// bucket() alongside Label so every code path that builds an inboxEmail
	// gets it for free.
	Keywords []string `json:"keywords,omitempty"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	AtUTC    string   `json:"atUtc"`
	// HasAttachments is a warm-path hint for the inbox paperclip badge; see
	// mailcache.Entry.HasAttachments. Absent when false.
	HasAttachments bool `json:"hasAttachments,omitempty"`
	// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint/
	// PGPDecryptError mirror imapadapter.MessageContent's PGP fields once
	// decryptPGPMessageContent/decryptPGPUnreadMessage has run.
	PGPEncrypted         bool   `json:"pgpEncrypted,omitempty"`
	PGPSigned            bool   `json:"pgpSigned,omitempty"`
	PGPVerified          bool   `json:"pgpVerified,omitempty"`
	PGPSignerFingerprint string `json:"pgpSignerFingerprint,omitempty"`
	PGPDecryptError      string `json:"pgpDecryptError,omitempty"`
	// ChangeType is only ever set on a delta (since=) response: "new" (Body
	// populated, client should insert) or "updated" (flags/label changed,
	// Body intentionally empty — the client already has it cached). Absent
	// entirely on classic responses, so old clients see no shape change.
	ChangeType string `json:"changeType,omitempty"`
}

type inboxFolder struct {
	Path      string `json:"path"`
	Deletable bool   `json:"deletable"`
}

func mailboxLeaf(path string) string {
	clean := strings.TrimSpace(path)
	if clean == "" {
		return ""
	}
	if idx := strings.LastIndexAny(clean, "/."); idx >= 0 && idx+1 < len(clean) {
		return strings.TrimSpace(clean[idx+1:])
	}
	return clean
}

func mailboxParentPath(path string) string {
	clean := strings.TrimSpace(path)
	idx := strings.LastIndexAny(clean, "/.")
	if idx <= 0 {
		return ""
	}
	return clean[:idx]
}

func isBuiltinMailbox(path string) bool {
	leaf := strings.ToLower(mailboxLeaf(path))
	switch leaf {
	case "inbox", "archive", "drafts", "draft", "sent", "sent items", "spam", "junk", "trash", "deleted items":
		return true
	default:
		return false
	}
}

func toInboxFolders(paths []string) []inboxFolder {
	folders := make([]inboxFolder, 0, len(paths))
	for _, folder := range paths {
		clean := strings.TrimSpace(folder)
		if clean == "" {
			continue
		}
		folders = append(folders, inboxFolder{
			Path:      clean,
			Deletable: mailboxParentPath(clean) != "" && !isBuiltinMailbox(clean),
		})
	}
	return folders
}

func firstMatchingKeyword(keywords []string, allowed []string) string {
	if len(keywords) == 0 || len(allowed) == 0 {
		return ""
	}
	seen := map[string]string{}
	for _, keyword := range keywords {
		clean := strings.TrimSpace(keyword)
		if clean == "" {
			continue
		}
		seen[strings.ToLower(clean)] = clean
	}
	for _, allowedKeyword := range allowed {
		key := strings.ToLower(strings.TrimSpace(allowedKeyword))
		if key == "" {
			continue
		}
		if matched, ok := seen[key]; ok {
			return matched
		}
	}
	return ""
}

func collectAllowedKeywords(cfg config.Config) []string {
	out := []string{}
	seen := map[string]bool{}
	appendKeyword := func(value string) {
		clean := strings.TrimSpace(value)
		if clean == "" {
			return
		}
		key := strings.ToLower(clean)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, clean)
	}

	for _, label := range cfg.Labels.Allowlist {
		appendKeyword(label)
	}
	for _, mappedKeywords := range cfg.Labels.KeywordMappings {
		for _, keyword := range mappedKeywords {
			appendKeyword(keyword)
		}
	}
	return out
}

// inboxCacheMailboxKey normalizes the mailbox query param into a stable
// mailcache window key: empty (account default) is aliased to "INBOX" so
// omitting the param and passing it explicitly share one window — both
// already resolve to the same selected IMAP folder. The raw (possibly
// empty) mailbox string is still passed to mailClient calls unchanged; this
// normalization is cache-key-only.
func inboxCacheMailboxKey(mailbox string) string {
	trimmed := strings.TrimSpace(mailbox)
	if trimmed == "" || strings.EqualFold(trimmed, "INBOX") {
		return "INBOX"
	}
	return trimmed
}

func mailCacheEntryFromOverview(ov imapadapter.Overview) mailcache.Overview {
	return mailcache.Overview{
		UID:      ov.UID,
		Subject:  ov.Subject,
		Sender:   ov.Sender,
		SentTo:   ov.SentTo,
		CC:       ov.CC,
		BCC:      ov.BCC,
		Keywords: ov.Keywords,
		Status:   ov.Status,
		AtUTC:    ov.AtUTC,
	}
}

func mailCacheEntryFromUnreadMessage(msg imapadapter.UnreadMessage, status string) mailcache.Entry {
	uid, _ := strconv.Atoi(strings.TrimSpace(msg.MessageID))
	return mailcache.Entry{
		UID:                  uid,
		MessageID:            msg.MessageID,
		Subject:              msg.Subject,
		Sender:               msg.Sender,
		SentTo:               msg.SentTo,
		CC:                   msg.CC,
		BCC:                  msg.BCC,
		Keywords:             msg.Keywords,
		Status:               status,
		AtUTC:                msg.AtUTC,
		Body:                 msg.Body,
		HasAttachments:       msg.HasAttachments,
		PGPEncrypted:         msg.PGPEncrypted,
		PGPSigned:            msg.PGPSigned,
		PGPVerified:          msg.PGPVerified,
		PGPSignerFingerprint: msg.PGPSignerFingerprint,
		PGPProtectedSubject:  msg.PGPProtectedSubject,
	}
}

// inboxSubject returns the subject to display for a message: the real subject
// recovered from an encrypted message's protected headers when present,
// otherwise the plaintext envelope/overview subject (which for an encrypted
// message is pgpmail.OuterPlaceholderSubject).
func inboxSubject(envelopeSubject, protectedSubject string) string {
	if protectedSubject != "" {
		return protectedSubject
	}
	return envelopeSubject
}

// inboxUncategorizedTab is the fallback tab for messages matching none of
// the configured label keywords.
const inboxUncategorizedTab = "Uncategorized"

// buildInboxTabScaffold seeds the tabs/byTab response shape from the
// account's configured label keywords, before any messages are bucketed in
// — shared by handleInbox's no-mail-client empty scaffold and serveInbox's
// populated response, so both start from identical tab ordering.
func buildInboxTabScaffold(allowedKeywords []string) ([]string, map[string][]inboxEmail) {
	tabs := make([]string, 0, len(allowedKeywords)+1)
	byTab := map[string][]inboxEmail{}
	seenTab := map[string]bool{}

	for _, keyword := range allowedKeywords {
		name := strings.TrimSpace(keyword)
		if name == "" {
			continue
		}
		if seenTab[strings.ToLower(name)] {
			continue
		}
		seenTab[strings.ToLower(name)] = true
		tabs = append(tabs, name)
		byTab[name] = []inboxEmail{}
	}

	byTab[inboxUncategorizedTab] = []inboxEmail{}
	return tabs, byTab
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	limit := 500
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 5000 {
			limit = v
		}
	}
	mailbox := strings.TrimSpace(r.URL.Query().Get("mailbox"))
	useDelta := strings.TrimSpace(r.URL.Query().Get("since")) != ""
	since := parseNonNegativeInt64Query(r, "since")

	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	mailClient, err := s.mailFor(r)
	if err != nil {
		// No mailbox configured yet — show the empty tab scaffold rather
		// than an error so the page still renders.
		tabs, byTab := buildInboxTabScaffold(collectAllowedKeywords(cfg))
		tabs = append(tabs, inboxUncategorizedTab)
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
		return
	}

	cache, err := s.mailCacheFor(r)
	if err != nil {
		http.Error(w, "failed to open mail cache", http.StatusInternalServerError)
		return
	}

	s.serveInbox(w, r.Context(), ac.UserID, mailClient, cache, cfg, mailbox, limit, since, useDelta)
}

// serveInbox contains handleInbox's core logic once a mail client and cache
// store are resolved — split out from handleInbox (which only does
// param/auth/store resolution) so it can be exercised directly in tests
// against a fake imapadapter.Client, without a real IMAP connection.
func (s *Server) serveInbox(w http.ResponseWriter, ctx context.Context, userID string, mailClient imapadapter.Client, cache *mailcache.Store, cfg config.Config, mailbox string, limit int, since int64, useDelta bool) {
	allowedKeywords := collectAllowedKeywords(cfg)
	tabs, byTab := buildInboxTabScaffold(allowedKeywords)

	// bucket appends entry into the tab its keywords match (or
	// Uncategorized), stamping Label and registering any newly-seen tab —
	// shared by every path below (cache-warmed classic, live-fallback
	// classic, and delta) so bucketing stays identical regardless of where
	// the data came from.
	bucket := func(keywords []string, entry inboxEmail) {
		tab := firstMatchingKeyword(keywords, allowedKeywords)
		if tab == "" {
			tab = inboxUncategorizedTab
		}
		if _, ok := byTab[tab]; !ok {
			byTab[tab] = []inboxEmail{}
			if tab != inboxUncategorizedTab {
				tabs = append(tabs, tab)
			}
		}
		entry.Label = tab
		entry.Keywords = keywords
		byTab[tab] = append(byTab[tab], entry)
	}

	cacheKey := inboxCacheMailboxKey(mailbox)

	if !useDelta {
		// Cache-first: if the background poller (or an earlier request)
		// has already warmed a full window of `limit` messages with
		// bodies, serve it with zero IMAP calls.
		if entries, warmed := cache.Snapshot(cacheKey, limit); warmed {
			for _, e := range entries {
				bucket(e.Keywords, inboxEmail{
					MessageID:            e.MessageID,
					Sender:               e.Sender,
					SentTo:               e.SentTo,
					CC:                   e.CC,
					BCC:                  e.BCC,
					Subject:              inboxSubject(e.Subject, e.PGPProtectedSubject),
					Body:                 e.Body,
					Status:               e.Status,
					AtUTC:                e.AtUTC,
					HasAttachments:       e.HasAttachments,
					PGPEncrypted:         e.PGPEncrypted,
					PGPSigned:            e.PGPSigned,
					PGPVerified:          e.PGPVerified,
					PGPSignerFingerprint: e.PGPSignerFingerprint,
				})
			}
			tabs = append(tabs, inboxUncategorizedTab)
			writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
			return
		}

		// Cold or partial cache (new user, non-INBOX folder the poller
		// never touches, or fewer entries than requested) — fall back to a
		// live fetch exactly as before, then self-warm the cache so the
		// next load for this user+mailbox+limit can be served from it.
		unread, err := mailClient.ListUnreadMessages(ctx, mailbox, limit)
		if err != nil {
			http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
			return
		}

		for i, msg := range unread {
			if msg.PGPEncryptedPayload != "" {
				unread[i] = s.decryptPGPUnreadMessage(userID, msg)
			} else if msg.PGPSignaturePayload != "" {
				unread[i] = s.verifySignedOnlyUnreadMessage(userID, msg)
			}
		}

		warmEntries := make([]mailcache.Entry, 0, len(unread))
		for _, msg := range unread {
			status := strings.TrimSpace(msg.Status)
			if status == "" {
				status = "unread"
			}
			bucket(msg.Keywords, inboxEmail{
				MessageID:            msg.MessageID,
				Sender:               msg.Sender,
				SentTo:               msg.SentTo,
				CC:                   msg.CC,
				BCC:                  msg.BCC,
				Subject:              inboxSubject(msg.Subject, msg.PGPProtectedSubject),
				Body:                 msg.Body,
				Status:               status,
				AtUTC:                msg.AtUTC,
				HasAttachments:       msg.HasAttachments,
				PGPEncrypted:         msg.PGPEncrypted,
				PGPSigned:            msg.PGPSigned,
				PGPVerified:          msg.PGPVerified,
				PGPSignerFingerprint: msg.PGPSignerFingerprint,
				PGPDecryptError:      msg.PGPDecryptError,
			})
			warmEntries = append(warmEntries, mailCacheEntryFromUnreadMessage(msg, status))
		}
		if len(warmEntries) > 0 {
			if err := cache.Upsert(cacheKey, warmEntries); err != nil {
				s.logger.Error("failed to warm mail cache", "error", err.Error())
			}
		}

		tabs = append(tabs, inboxUncategorizedTab)
		writeJSON(w, http.StatusOK, map[string]any{"tabs": tabs, "byTab": byTab})
		return
	}

	// Delta path: cheap overview fetch (no bodies), diff against the cache,
	// and only pay for a body fetch on genuinely new messages the cache
	// (and the daemon's opportunistic warming) hasn't already seen.
	overviews, err := mailClient.ListOverviews(ctx, mailbox, limit)
	if err != nil {
		http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
		return
	}
	live := make([]mailcache.Overview, 0, len(overviews))
	for _, ov := range overviews {
		live = append(live, mailCacheEntryFromOverview(ov))
	}

	result, err := cache.Sync(cacheKey, limit, live, since)
	if err != nil {
		http.Error(w, "failed to sync mail cache", http.StatusInternalServerError)
		return
	}

	needBodies := make([]int, 0, len(result.New))
	for _, e := range result.New {
		if e.Body == "" {
			needBodies = append(needBodies, e.UID)
		}
	}
	contents := map[int]imapadapter.MessageContent{}
	if len(needBodies) > 0 {
		contents, err = mailClient.GetMessageBodies(ctx, mailbox, needBodies)
		if err != nil {
			http.Error(w, "failed to fetch inbox", http.StatusBadGateway)
			return
		}
		for uid, c := range contents {
			if c.PGPEncryptedPayload != "" {
				contents[uid] = s.decryptPGPMessageContent(userID, c)
			} else if c.PGPSignaturePayload != "" {
				contents[uid] = s.verifySignedOnlyMessageContent(userID, c)
			}
		}
		// Attach the freshly fetched bodies back onto the cache (metadata
		// is unchanged from what Sync just stored, so this only warms
		// Body/HasAttachments without bumping Rev) so a subsequent
		// classic-path load doesn't re-fetch them live.
		warmEntries := make([]mailcache.Entry, 0, len(needBodies))
		for i, e := range result.New {
			if c, ok := contents[e.UID]; ok && c.Body != "" {
				e.Body = c.Body
				e.HasAttachments = c.HasAttachments
				e.PGPEncrypted = c.PGPEncrypted
				e.PGPSigned = c.PGPSigned
				e.PGPVerified = c.PGPVerified
				e.PGPSignerFingerprint = c.PGPSignerFingerprint
				e.PGPProtectedSubject = c.PGPProtectedSubject
				result.New[i] = e
				warmEntries = append(warmEntries, e)
			}
		}
		if len(warmEntries) > 0 {
			if err := cache.Upsert(cacheKey, warmEntries); err != nil {
				s.logger.Error("failed to warm mail cache from delta fetch", "error", err.Error())
			}
		}
	}

	for _, e := range result.New {
		body := e.Body
		hasAttachments := e.HasAttachments
		pgpEncrypted, pgpSigned, pgpVerified := e.PGPEncrypted, e.PGPSigned, e.PGPVerified
		pgpSignerFingerprint := e.PGPSignerFingerprint
		pgpProtectedSubject := e.PGPProtectedSubject
		var pgpDecryptError string
		if body == "" {
			if c, ok := contents[e.UID]; ok {
				body = c.Body
				hasAttachments = c.HasAttachments
				pgpEncrypted = c.PGPEncrypted
				pgpSigned = c.PGPSigned
				pgpVerified = c.PGPVerified
				pgpSignerFingerprint = c.PGPSignerFingerprint
				pgpProtectedSubject = c.PGPProtectedSubject
				pgpDecryptError = c.PGPDecryptError
			}
		}
		bucket(e.Keywords, inboxEmail{
			MessageID:            e.MessageID,
			Sender:               e.Sender,
			SentTo:               e.SentTo,
			CC:                   e.CC,
			BCC:                  e.BCC,
			Subject:              inboxSubject(e.Subject, pgpProtectedSubject),
			Body:                 body,
			Status:               e.Status,
			AtUTC:                e.AtUTC,
			HasAttachments:       hasAttachments,
			PGPEncrypted:         pgpEncrypted,
			PGPSigned:            pgpSigned,
			PGPVerified:          pgpVerified,
			PGPSignerFingerprint: pgpSignerFingerprint,
			PGPDecryptError:      pgpDecryptError,
			ChangeType:           "new",
		})
	}
	for _, e := range result.Updated {
		bucket(e.Keywords, inboxEmail{
			MessageID:            e.MessageID,
			Sender:               e.Sender,
			SentTo:               e.SentTo,
			CC:                   e.CC,
			BCC:                  e.BCC,
			Subject:              inboxSubject(e.Subject, e.PGPProtectedSubject),
			Status:               e.Status,
			AtUTC:                e.AtUTC,
			HasAttachments:       e.HasAttachments,
			PGPEncrypted:         e.PGPEncrypted,
			PGPSigned:            e.PGPSigned,
			PGPVerified:          e.PGPVerified,
			PGPSignerFingerprint: e.PGPSignerFingerprint,
			ChangeType:           "updated",
		})
	}

	removed := make([]string, 0, len(result.Removed))
	for _, e := range result.Removed {
		removed = append(removed, e.MessageID)
	}

	tabs = append(tabs, inboxUncategorizedTab)
	writeJSON(w, http.StatusOK, map[string]any{
		"tabs":    tabs,
		"byTab":   byTab,
		"delta":   true,
		"cursor":  result.Cursor,
		"removed": removed,
	})
}

func (s *Server) handleInboxFolders(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		parent := strings.TrimSpace(r.URL.Query().Get("parent"))

		folders, err := mailClient.ListSubfolders(r.Context(), parent)
		if err != nil {
			http.Error(w, "failed to fetch inbox folders", http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"parent":  parent,
			"folders": toInboxFolders(folders),
		})
	case http.MethodPost:
		var req struct {
			Parent string `json:"parent"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		parent := strings.TrimSpace(req.Parent)
		name := strings.TrimSpace(req.Name)
		if name == "" {
			http.Error(w, "folder name is required", http.StatusBadRequest)
			return
		}

		folder, err := mailClient.CreateFolder(r.Context(), parent, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"parent": parent,
			"name":   name,
			"folder": folder,
		})
	case http.MethodPut:
		var req struct {
			Folder string `json:"folder"`
			Name   string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		folder := strings.TrimSpace(req.Folder)
		name := strings.TrimSpace(req.Name)
		if folder == "" || name == "" {
			http.Error(w, "folder and name are required", http.StatusBadRequest)
			return
		}
		if isBuiltinMailbox(folder) {
			http.Error(w, "built-in folders cannot be renamed", http.StatusBadRequest)
			return
		}
		if mailboxParentPath(folder) == "" {
			http.Error(w, "folder must have a parent mailbox", http.StatusBadRequest)
			return
		}

		renamed, err := mailClient.RenameFolder(r.Context(), folder, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"folder":  folder,
			"renamed": renamed,
			"parent":  mailboxParentPath(renamed),
		})
	case http.MethodDelete:
		folder := strings.TrimSpace(r.URL.Query().Get("folder"))
		if folder == "" {
			http.Error(w, "folder is required", http.StatusBadRequest)
			return
		}
		if isBuiltinMailbox(folder) {
			http.Error(w, "built-in folders cannot be deleted", http.StatusBadRequest)
			return
		}
		if mailboxParentPath(folder) == "" {
			http.Error(w, "folder must have a parent mailbox", http.StatusBadRequest)
			return
		}
		if err := mailClient.DeleteFolder(r.Context(), folder); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"folder": folder,
			"parent": mailboxParentPath(folder),
		})
	}
}

func (s *Server) handleInboxActions(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		Action        string   `json:"action"`
		MessageIDs    []string `json:"messageIds"`
		Mailbox       string   `json:"mailbox"`
		TargetMailbox string   `json:"targetMailbox"`
		Keyword       string   `json:"keyword"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	mailbox := strings.TrimSpace(req.Mailbox)
	targetMailbox := strings.TrimSpace(req.TargetMailbox)
	keyword := strings.TrimSpace(req.Keyword)
	switch action {
	case "delete", "archive", "spam", "read", "move", "label", "unlabel":
	default:
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	if action == "move" && targetMailbox == "" {
		http.Error(w, "targetMailbox is required for move action", http.StatusBadRequest)
		return
	}
	if (action == "label" || action == "unlabel") && keyword == "" {
		http.Error(w, "keyword is required for label/unlabel action", http.StatusBadRequest)
		return
	}

	uniqueIDs := make([]string, 0, len(req.MessageIDs))
	seen := map[string]bool{}
	for _, messageID := range req.MessageIDs {
		clean := strings.TrimSpace(messageID)
		if clean == "" {
			continue
		}
		if seen[clean] {
			continue
		}
		seen[clean] = true
		uniqueIDs = append(uniqueIDs, clean)
	}
	if len(uniqueIDs) == 0 {
		http.Error(w, "at least one messageId is required", http.StatusBadRequest)
		return
	}

	type inboxActionFailure struct {
		MessageID string `json:"messageId"`
		Error     string `json:"error"`
	}
	failures := make([]inboxActionFailure, 0)
	processed := 0
	for _, messageID := range uniqueIDs {
		// label/unlabel bypass ApplyInboxAction's switch entirely (it has no
		// concept of a keyword parameter) and call the dedicated keyword
		// methods directly, keeping ApplyInboxAction's folder-fallback logic
		// for the other actions untouched.
		var err error
		switch action {
		case "label":
			err = mailClient.ApplyLabel(r.Context(), messageID, keyword)
		case "unlabel":
			err = mailClient.RemoveLabel(r.Context(), messageID, keyword)
		default:
			err = mailClient.ApplyInboxAction(r.Context(), messageID, action, mailbox, targetMailbox)
		}
		if err != nil {
			failures = append(failures, inboxActionFailure{MessageID: messageID, Error: err.Error()})
			continue
		}
		processed++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            len(failures) == 0,
		"action":        action,
		"processed":     processed,
		"failed":        failures,
		"targetMailbox": targetMailbox,
	})
}

func (s *Server) handleMailSearch(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		http.Error(w, "q parameter is required", http.StatusBadRequest)
		return
	}

	field := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("field")))
	if field == "" {
		field = "all"
	}
	if field != "subject" && field != "sender" && field != "from" && field != "body" && field != "all" {
		http.Error(w, "invalid field parameter", http.StatusBadRequest)
		return
	}

	mailbox := strings.TrimSpace(r.URL.Query().Get("mailbox"))
	if mailbox == "" {
		mailbox = "INBOX"
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 200 {
		limit = 200
	}

	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	allowedKeywords := collectAllowedKeywords(cfg)

	results, err := mailClient.SearchMessages(r.Context(), mailbox, field, q, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("search failed: %v", err), http.StatusServiceUnavailable)
		return
	}

	// Convert Overview to inboxEmail wire format, mirroring handleInbox's label-bucketing
	out := make([]any, 0, len(results))
	for _, overview := range results {
		label := firstMatchingKeyword(overview.Keywords, allowedKeywords)
		if label == "" {
			label = inboxUncategorizedTab
		}
		out = append(out, inboxEmail{
			MessageID:      overview.MessageID,
			Subject:        overview.Subject,
			Sender:         overview.Sender,
			SentTo:         overview.SentTo,
			CC:             overview.CC,
			BCC:            overview.BCC,
			Label:          label,
			Keywords:       overview.Keywords,
			Status:         overview.Status,
			AtUTC:          overview.AtUTC,
			HasAttachments: false,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": out,
	})
}

func (s *Server) handleLabels(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	configured := append([]string{}, s.cfg.Labels.Allowlist...)
	s.mu.RUnlock()

	imapLabels := []string{}
	if mailClient, err := s.mailFor(r); err == nil {
		found, err := mailClient.ListLabels(r.Context())
		if err == nil {
			imapLabels = found
		}
	}
	sort.Strings(imapLabels)
	writeJSON(w, http.StatusOK, map[string]any{"configured": configured, "imap": imapLabels})
}

func (s *Server) handleTuning(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	tuningPath := s.userTuningPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(tuningPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// New users start from the install's default tuning prompt.
				fallback := strings.TrimSpace(classifier.LoadTuningText())
				if fallback != "" {
					writeJSON(w, http.StatusOK, map[string]any{"content": fallback, "path": tuningPath})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"content": ""})
				return
			}
			http.Error(w, "failed to read tuning file", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"content": string(b), "path": tuningPath})
	case http.MethodPut:
		var req struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := os.MkdirAll(filepath.Dir(tuningPath), 0o755); err != nil {
			http.Error(w, "failed to create tuning directory", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(tuningPath, []byte(req.Content), 0o600); err != nil {
			http.Error(w, "failed to save tuning file", http.StatusInternalServerError)
			return
		}
		// Tuning is now passed to the model per classify call, so no classifier
		// process restart is needed for edits to take effect.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": tuningPath, "restartOk": true, "restartError": ""})
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if raw := r.URL.Query().Get("lines"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 5000 {
			lines = v
		}
	}
	logDir := config.EnvOrDefault("LOG_DIR", "/kypost/logs")
	// Resolve requested file — default to app.log, allow any *.log in logDir
	filename := filepath.Base(r.URL.Query().Get("file"))
	if filename == "" || filename == "." {
		filename = "app.log"
	}
	// Security: only allow .log files, no path traversal
	if filepath.Ext(filename) != ".log" || strings.Contains(filename, "/") || strings.Contains(filename, "..") {
		http.Error(w, "invalid log file", http.StatusBadRequest)
		return
	}
	target := filepath.Join(logDir, filename)
	out, err := tailLines(target, lines)
	if err != nil {
		http.Error(w, "failed to read logs", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": out, "file": filename})
}

func (s *Server) handleLogsList(w http.ResponseWriter, r *http.Request) {
	logDir := config.EnvOrDefault("LOG_DIR", "/kypost/logs")
	entries, err := os.ReadDir(logDir)
	if err != nil {
		http.Error(w, "failed to list logs", http.StatusInternalServerError)
		return
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".log" {
			files = append(files, e.Name())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files})
}

// handleSetup is unauthenticated by necessity (the frontend's first-run
// wizard needs to know whether setup is needed before anyone can log in), so
// it must never return more than the boolean it exists to answer. It used to
// also return the real admin username and must-change-password state; the
// frontend never actually consumed those fields, and returning them let any
// anonymous caller learn the admin's username indefinitely — defeating the
// hardening value of an operator choosing a non-default admin username.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	all, err := s.users.List()
	if err != nil {
		http.Error(w, "failed to read setup state", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": len(all) > 0})
}

func (s *Server) handleRepair(w http.ResponseWriter, r *http.Request) {
	s.logger.Error("manual repair requested")
	scheduleContainerRestart(s.logger, "manual repair", 250*time.Millisecond)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "restart requested"})
}

// handlePollNow forces an immediate mail poll tick instead of waiting for
// the poller's regular interval, for admins who want to check "is new mail
// here yet" without the usual delay.
func (s *Server) handlePollNow(w http.ResponseWriter, r *http.Request) {
	if s.poller == nil {
		http.Error(w, "poller not available", http.StatusServiceUnavailable)
		return
	}
	s.logger.Info("manual mail poll requested")
	s.poller.TriggerNow()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		CaptchaToken string `json:"captchaToken,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Three-strikes/15-minute lockout, keyed by the exact username
	// submitted regardless of whether it belongs to a real account (so
	// lockout behavior can't be used to enumerate valid usernames) plus the
	// client IP (so an attacker hammering a known username can't lock the
	// real owner out from their own machine).
	lockoutKey := req.Username + "\x00" + clientIP(r)
	if allowed, retryAfter := s.loginLockout.allowed(lockoutKey); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many failed attempts, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return
	}

	// CAPTCHA, when an operator has configured a provider, is required on
	// every login attempt and checked before the password is verified so a
	// failed/missing solution never pays scrypt's cost.
	if s.captchaVerifier != nil {
		ok, err := s.captchaVerifier.Verify(r.Context(), req.CaptchaToken, clientIP(r))
		if err != nil {
			s.logger.Error("captcha verification failed", "error", err.Error())
			http.Error(w, "captcha verification unavailable", http.StatusServiceUnavailable)
			return
		}
		if !ok {
			http.Error(w, "captcha verification failed", http.StatusUnauthorized)
			return
		}
	}

	u, err := s.users.GetByUsername(req.Username)
	if err != nil || !u.Active {
		// Pay the same scrypt cost a real password check would, so response
		// timing doesn't reveal whether the username exists (or is inactive).
		equalizeLoginTiming(req.Password)
		s.loginLockout.recordFailure(lockoutKey)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if !users.VerifyPassword(u, req.Password) {
		s.loginLockout.recordFailure(lockoutKey)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.loginLockout.recordSuccess(lockoutKey)

	// Second-factor users must clear a challenge before a session exists. No
	// cookie is set here; the client receives a challenge id plus the methods it
	// may use. A push-enabled challenge additionally fans a notification out to
	// the user's approver devices (asynchronously — see dispatchPushChallenge).
	if u.TOTPEnabled || u.PushMFAEnabled {
		ch, err := s.mfaChallenges.Create(u.ID)
		if err != nil {
			http.Error(w, "session creation failed", http.StatusInternalServerError)
			return
		}
		methods := make([]string, 0, 2)
		if u.TOTPEnabled {
			methods = append(methods, "totp")
		}
		if u.PushMFAEnabled {
			methods = append(methods, "push")
			// Rate-limit the push itself, not challenge creation or login: a user who
			// mistyped a TOTP code must still be able to retry, but repeated logins
			// within the cooldown window reuse the existing push rather than fanning
			// another one out — see mfaPushCooldown's doc for why.
			if allowed, _ := s.mfaPushCooldown.tryConsume(u.ID); allowed {
				go s.dispatchPushChallenge(u.ID, ch.ID)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mfaRequired": true,
			"challengeId": ch.ID,
			"methods":     methods,
		})
		return
	}

	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

// handleCaptchaConfig is public (pre-login) and tells the frontend which
// CAPTCHA widget, if any, to render on the login form. provider=="" means
// CAPTCHA is disabled. siteKey is the provider's public site key — safe to
// expose, unlike the secret key used server-side for verification.
func (s *Server) handleCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": s.captchaProvider,
		"siteKey":  s.captchaSiteKey,
	})
}

// handleCSRFToken returns the CSRF token paired with the caller's session,
// for same-origin JS that cannot read the non-HttpOnly csrf_token cookie —
// specifically the service worker's pushsubscriptionchange handler, which
// must send X-CSRF-Token on its resubscription POST but has no access to
// document.cookie. The response carries no CORS headers, so a cross-origin
// page can trigger this GET but never read the token; possession of the
// session cookie remains the only way to obtain it, which is exactly the
// double-submit invariant csrfCheckOK enforces.
func (s *Server) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentUser(r); !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrfToken": sess.CSRFToken})
}

// startSession mints a session token for userID, records it, and sets the
// kypost_session cookie with exactly the flags the legacy password-only login
// used. Shared by handleLogin and the second-factor endpoints.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID string) error {
	token, err := randomToken(24)
	if err != nil {
		return err
	}
	csrfToken, err := randomToken(24)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions[token] = Session{UserID: userID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: csrfToken}
	s.mu.Unlock()
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{Name: "kypost_session", Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	// Deliberately NOT HttpOnly: the frontend must be able to read this and
	// echo it back as the X-CSRF-Token header (double-submit pattern) — see
	// csrfCheckOK. It carries no authority on its own without the paired
	// HttpOnly session cookie, so JS-readability doesn't weaken the session.
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: csrfToken, Path: "/", HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode})
	return nil
}

// handleMFATOTP completes a login challenge with a TOTP code. It is
// authenticated solely by possession of a valid challengeId (no session
// cookie). On success it mints the real session.
func (s *Server) handleMFATOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ch, ok := s.mfaChallenges.Get(strings.TrimSpace(req.ChallengeID))
	if !ok {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Per-account throttle spanning challenges: the per-challenge attempt cap
	// alone can be reset by minting a new challenge, so a password-holding
	// attacker could otherwise brute force TOTP online.
	if allowed, _ := s.mfaLockout.allowed(ch.UserID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}

	u, err := s.users.Get(ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled || u.TOTPSecretEnc == "" {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	secret, err := mfa.OpenTOTPSecret(u.TOTPSecretEnc, s.totpSecretKeyPath)
	if err != nil {
		http.Error(w, "failed to load second factor", http.StatusInternalServerError)
		return
	}

	step, valid := totp.Validate(secret, req.Code, time.Now())
	if !valid {
		s.mfaLockout.recordFailure(ch.UserID)
		if err := s.mfaChallenges.RecordTOTPAttempt(ch.ID); errors.Is(err, mfa.ErrTooManyAttempts) {
			http.Error(w, "too many attempts", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}

	// A challenge is single-use: ConsumeTOTPStep atomically checks-and-marks
	// consumption under a single lock, so two concurrent requests bearing the
	// same still-valid code cannot both win (closes the TOCTOU window a
	// separate Get + later RecordTOTPStep would leave open).
	if err := s.mfaChallenges.ConsumeTOTPStep(ch.ID, step); err != nil {
		if errors.Is(err, mfa.ErrChallengeAlreadyUsed) {
			http.Error(w, "challenge already used", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	// Per-account replay guard: a password-holding attacker can mint any
	// number of challenges, so single-use protection on the challenge alone
	// (above) is not enough — it would let one captured valid code be
	// replayed once per freshly minted challenge. SetLastUsedTOTPStep
	// atomically rejects any step that is not strictly newer than the last
	// one accepted for this account, persisted across challenges. It runs
	// only after every other check has passed (a wrong/rejected code never
	// reaches here, so it never advances the recorded step), and a rejection
	// here gets the exact same generic response as a wrong code so it cannot
	// be distinguished from one over the wire.
	//
	// recordSuccess (which clears the account's brute-force lockout throttle)
	// is deliberately deferred until after this guard passes: a replayed code
	// is a rejected attempt, exactly like a wrong code, and must count against
	// the lockout (recordFailure) rather than clearing it — otherwise a
	// captured valid code let an attacker keep the lockout counter at zero
	// indefinitely while brute-forcing the real, still-unknown current code.
	if _, err := s.users.SetLastUsedTOTPStep(u.ID, step); err != nil {
		s.mfaLockout.recordFailure(ch.UserID)
		s.mfaChallenges.Delete(ch.ID)
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	s.mfaLockout.recordSuccess(ch.UserID)

	s.mfaChallenges.Delete(ch.ID)
	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

// handleMFARecoveryCode completes a login challenge with a one-time recovery
// code. The matched code is consumed (removed) on success.
func (s *Server) handleMFARecoveryCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	ch, ok := s.mfaChallenges.Get(strings.TrimSpace(req.ChallengeID))
	if !ok {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}
	if allowed, _ := s.mfaLockout.allowed(ch.UserID); !allowed {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	u, err := s.users.Get(ch.UserID)
	if err != nil || !u.Active || !u.TOTPEnabled {
		http.Error(w, "invalid or expired challenge", http.StatusUnauthorized)
		return
	}

	_, matched, err := s.users.ConsumeRecoveryCode(u.ID, strings.TrimSpace(req.Code))
	if err != nil {
		http.Error(w, "failed to verify recovery code", http.StatusInternalServerError)
		return
	}
	if !matched {
		s.mfaLockout.recordFailure(ch.UserID)
		if err := s.mfaChallenges.RecordTOTPAttempt(ch.ID); errors.Is(err, mfa.ErrTooManyAttempts) {
			http.Error(w, "too many attempts", http.StatusUnauthorized)
			return
		}
		http.Error(w, "invalid code", http.StatusUnauthorized)
		return
	}
	s.mfaLockout.recordSuccess(ch.UserID)

	s.mfaChallenges.Delete(ch.ID)
	if err := s.startSession(w, r, u.ID); err != nil {
		http.Error(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mustChangePassword": u.MustChangePassword})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("kypost_session")
	if err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	secure := isRequestSecure(r)
	http.SetCookie(w, &http.Cookie{Name: "kypost_session", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Path: "/", Expires: time.Unix(0, 0), MaxAge: -1, HttpOnly: false, Secure: secure, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// currentSessionToken returns the kypost_session cookie value on r, or "" if
// absent — used alongside revokeUserSessions so a self-service credential
// change revokes every *other* session without also logging out the request
// that made the change.
func currentSessionToken(r *http.Request) string {
	if c, err := r.Cookie("kypost_session"); err == nil {
		return c.Value
	}
	return ""
}

// revokeUserSessions deletes every live session belonging to userID, except
// keepToken if non-empty (the caller's own session, when the caller and the
// affected account are the same — e.g. a user changing their own password).
// Called after a password change/reset or MFA disable/regeneration so a
// stolen session cookie for that account is cut off from continued access
// as soon as the legitimate user (or an admin, on their behalf) takes one of
// those recovery actions, rather than remaining valid for up to the
// remaining 24h sliding-expiry window.
func (s *Server) revokeUserSessions(userID, keepToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, sess := range s.sessions {
		if sess.UserID == userID && token != keepToken {
			delete(s.sessions, token)
		}
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.currentUser(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	subscriberID := ""
	if store, err := s.userStore(ac.UserID); err == nil {
		subscriberID, _ = store.GetOrCreateSubscriberID()
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "subscriberId": subscriberID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":      true,
		"userId":             u.ID,
		"username":           u.Username,
		"role":               u.Role,
		"mustChangePassword": u.MustChangePassword,
		"subscriberId":       subscriberID,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		http.Error(w, "new password required", http.StatusBadRequest)
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if !u.MustChangePassword && !users.VerifyPassword(u, req.OldPassword) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if u.MustChangePassword && strings.TrimSpace(req.OldPassword) != "" && !users.VerifyPassword(u, req.OldPassword) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	if _, err := s.users.SetPassword(u.ID, req.NewPassword, false); err != nil {
		http.Error(w, "failed to update password", http.StatusInternalServerError)
		return
	}
	// A password change should cut off any other session on this account —
	// e.g. a stolen cookie the legitimate user is trying to lock out by
	// changing their password — while leaving the session making this very
	// request (presumably the legitimate user) logged in.
	s.revokeUserSessions(u.ID, currentSessionToken(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleClassifierTest(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// This handler deliberately builds its own ad-hoc classifier client (see
	// below) rather than reusing the server's shared, paced instance, so this
	// cooldown is the substitute guard against an admin (or a compromised
	// admin session) firing unpaced concurrent requests at the shared
	// classifier/Ollama backend.
	if allowed, retryAfter := s.classifierTestCooldown.tryConsume(ac.UserID); !allowed {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "classifier test already in progress or recently run; try again shortly",
			"retryAfterSeconds": int(retryAfter.Seconds()) + 1,
		})
		return
	}

	var req struct {
		Prompt string `json:"prompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	baseURL := strings.TrimSpace(cfg.Classifier.BaseURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("CLASSIFIER_BASE_URL"))
	}
	if baseURL == "" {
		http.Error(w, "classifier base url is not configured", http.StatusBadRequest)
		return
	}

	path := strings.TrimSpace(cfg.Classifier.ClassifyPath)
	if path == "" {
		path = "/"
	}
	apiKey := strings.TrimSpace(cfg.Classifier.APIKey)
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("CLASSIFIER_API_KEY"))
	}

	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		prompt = "Email Address: test@example.com  Subject Line: Classifier connectivity test Return only the label Updates"
	}

	allowed := cfg.Labels.Allowlist
	if len(allowed) == 0 {
		allowed = []string{"Questionable", "Important"}
	}

	tuning := classifier.LoadTuningText()
	client := classifier.NewHTTPClient(baseURL, apiKey, path, tuning, 120*time.Second)
	defer client.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	result, err := client.Classify(ctx, allowed, "", "", prompt, tuning)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"response": result,
		"baseUrl":  baseURL,
		"path":     path,
	})
}

func (s *Server) handleFrontend(w http.ResponseWriter, r *http.Request) {
	frontendDir := config.EnvOrDefault("FRONTEND_DIR", "/opt/kypost/frontend")
	indexPath := filepath.Join(frontendDir, "index.html")

	requestPath := path.Clean("/" + r.URL.Path)
	relPath := strings.TrimPrefix(requestPath, "/")

	if relPath != "" {
		assetPath := filepath.Join(frontendDir, relPath)
		rootPrefix := filepath.Clean(frontendDir) + string(os.PathSeparator)
		if strings.HasPrefix(filepath.Clean(assetPath)+string(os.PathSeparator), rootPrefix) {
			if info, err := os.Stat(assetPath); err == nil && !info.IsDir() {
				http.ServeFile(w, r, assetPath)
				return
			}
		}
	}

	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}

	http.Error(w, "frontend assets not found; build frontend and set FRONTEND_DIR", http.StatusNotFound)
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, ok := s.currentUser(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !s.csrfCheckOK(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Enforce the first-login password change server-side: a user who still
		// owes a password change (e.g. the bootstrap admin) gets a full session
		// but may reach nothing except the change/logout endpoints until they
		// rotate it. Without this the flag is merely advisory and a default
		// credential grants full access.
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

// csrfCheckOK enforces a double-submit CSRF check on cookie-authenticated,
// state-changing (non-GET/HEAD/OPTIONS) requests: the X-CSRF-Token header
// must match the csrf_token minted alongside the caller's session (see
// startSession). It intentionally does nothing when no kypost_session cookie
// is present — mobile clients (X-Kypost-Device-Id/X-Kypost-Device-Secret
// headers, see resolveMailAuthContext) and CardDAV (HTTP Basic Auth) never send that
// cookie, so they carry no ambient, forgeable credential for CSRF to exploit
// in the first place and are structurally exempt rather than specially
// carved out here.
func (s *Server) csrfCheckOK(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		return true
	}
	s.mu.RLock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.RUnlock()
	if !ok {
		// No matching session for this cookie value: either it's stale (the
		// caller-visible auth check elsewhere will already reject the
		// request) or this request actually authenticated via a different,
		// cookie-free path (e.g. withMailAuth's mobile fallback) despite an
		// unrelated cookie being present. Either way there's no session CSRF
		// token to check against.
		return true
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && subtle.ConstantTimeCompare([]byte(header), []byte(sess.CSRFToken)) == 1
}

// withMailAuth gates endpoints mobile clients need to reach without a web
// session — mail read/act-on (inbox, folders, actions, draft, send), contacts
// dedupe/groups/photo-get, and the PGP QR token mint — for either a web
// session cookie or a paired device's own X-Kypost-Device-Id/
// X-Kypost-Device-Secret credentials — see resolveMailAuthContext. Despite
// the name, it's no longer mail-exclusive; IMAP/SMTP account setup
// (/api/imap/config, /api/imap/test) and other web-UI-only writes
// intentionally stay on withAuth only.
func (s *Server) withMailAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac, err := s.resolveMailAuthContext(r)
		if err != nil {
			var lockErr *mailLockedOutError
			if errors.As(err, &lockErr) {
				w.Header().Set("Retry-After", strconv.Itoa(int(lockErr.retryAfter.Seconds())+1))
				writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many failed attempts, try again later"})
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if !s.csrfCheckOK(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "missing or invalid csrf token"})
			return
		}
		// Session users still owing a first-login password change are blocked
		// here too (device-auth contexts never set this flag).
		if ac.MustChangePassword && !mustChangePasswordExemptPaths[r.URL.Path] {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "password change required", "mustChangePassword": true})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	}
}

type authContextKey struct{}

// authFromContext retrieves the AuthContext injected by withAuth or
// withDAVBasicAuth. It only returns ok=false if called on a request that
// never passed through either (a programming error), since both already
// reject the request before next() runs otherwise.
func authFromContext(r *http.Request) (AuthContext, bool) {
	return authContextFromContext(r.Context())
}

func authContextFromContext(ctx context.Context) (AuthContext, bool) {
	ac, ok := ctx.Value(authContextKey{}).(AuthContext)
	return ac, ok
}

// currentUser validates the session cookie and looks the owning user up
// live from the users store (not snapshotted into the session), so a role
// change or deactivation take effect on the request immediately following
// it rather than only at next login.
func (s *Server) currentUser(r *http.Request) (AuthContext, bool) {
	cookie, err := r.Cookie("kypost_session")
	if err != nil {
		return AuthContext{}, false
	}

	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	if !ok {
		s.mu.Unlock()
		return AuthContext{}, false
	}
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		return AuthContext{}, false
	}
	// Sliding window session expiry for active users.
	s.sessions[cookie.Value] = Session{UserID: sess.UserID, ExpiresAt: time.Now().Add(24 * time.Hour), CSRFToken: sess.CSRFToken}
	s.mu.Unlock()

	u, err := s.users.Get(sess.UserID)
	if err != nil || !u.Active {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		return AuthContext{}, false
	}
	return AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role, MustChangePassword: u.MustChangePassword}, true
}

// mustChangePasswordExemptPaths are the only authenticated routes a user with
// an unsatisfied first-login password-change requirement may reach: the
// change endpoint itself and logout. Everything else is refused until the
// password is rotated, so a known/default bootstrap credential cannot be used
// for anything but changing it.
var mustChangePasswordExemptPaths = map[string]bool{
	"/api/auth/password": true,
	"/api/auth/logout":   true,
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func scheduleContainerRestart(logger *logging.Logger, reason string, delay time.Duration) {
	go func() {
		time.Sleep(delay)
		if logger != nil {
			logger.Error("container restart requested", "reason", reason)
		}
		_ = syscall.Kill(1, syscall.SIGTERM)
		os.Exit(2)
	}()
}

func tailLines(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]string, 0, limit)
	s := bufio.NewScanner(f)
	for s.Scan() {
		buf = append(buf, s.Text())
		if len(buf) > limit {
			buf = buf[1:]
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return buf, nil
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
