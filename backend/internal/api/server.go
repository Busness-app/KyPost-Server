package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/adapters/classifier"
	"kypost-server/backend/internal/captcha"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/groups"
	"kypost-server/backend/internal/health"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/mfa"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/processor"
	"kypost-server/backend/internal/rules"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"
)

// Server holds the HTTP surface and its process-wide state.
//
// LOCK ORDER: cfgMu before sessMu before userMu before ollamaMu. Never the
// reverse. Enforced by TestLockOrderIsRespected, which reads this package's
// source and fails on a function that takes one while holding a higher-ranked
// one — directly, or through any call chain inside this package. Adding a mutex
// here means adding it to lockRank in lock_order_test.go; one that is missing
// from that map is not checked.
//
// The rule used to be stated here and enforced nowhere, with the note that
// "nothing currently takes more than one, which is the only reason there is no
// deadlock to find today". The failure it warns about — one handler reading
// s.cfg inside a userMu critical section while another does the reverse — is an
// ABBA deadlock that appears only under concurrent load, in production, and that
// no unit test would provoke. It needed a checker, not a paragraph.
//
// cfgMu and sessMu are separate because currentUser slides a session's idle
// expiry, which is a WRITE: as one mutex, every authenticated request took it
// exclusively and every s.cfg reader queued behind it.
//
// httpServer is unguarded. Prepare, Serve, Run and Shutdown all touch it with no
// lock held, which is safe only because Prepare is called synchronously before
// any goroutine can reach the others — see Prepare's doc comment.
type Server struct {
	cfgMu           sync.RWMutex
	cfg             config.Config
	onConfigUpdated func(config.Config)

	// sessMu guards sessions only.
	sessMu sync.RWMutex

	logger              *logging.Logger
	health              *health.Service
	users               *users.Store
	configDir           string
	stateDir            string
	configPath          string
	logPath             string
	imapConfigKeyPath   string
	totpSecretKeyPath   string
	pgpPrivateKeyPath   string
	sessions            map[string]Session
	mfaChallenges       *mfa.Store
	pairingSecret       string
	serverBaseURL       string
	baseURLFallbackWarn sync.Once
	pairingSecretWarn   sync.Once
	// singleUse makes each one-shot token — PGP QR key exchange, native device
	// pairing nonces — redeemable exactly once. See singleUseTokens.
	singleUse            *singleUseTokens
	nativePushDispatcher *processor.NativePushDispatcher
	pickupStore          *pgpmail.PickupStore
	poller               *processor.Poller
	loginLockout         *failureLockout
	davLockout           *failureLockout
	mfaLockout           *failureLockout
	// passwordChangeLockout bounds current-credential guessing on
	// POST /api/auth/password, keyed on the acting user's ID.
	passwordChangeLockout *failureLockout
	deviceLockout         *failureLockout
	wkdLimiter            *ipRateLimiter
	// pushPollLimiter meters the two unauthenticated push-MFA endpoints per IP.
	// They were the only public routes with no meter, and both take mfa.Store's
	// process-wide lock. See withPushPollRateLimit.
	pushPollLimiter *ipRateLimiter
	// loginParamsLimiter meters GET /api/auth/login-params PER IP. Drawing a full
	// attempt's reservation from the instance-wide derivation budget below priced a
	// ~5us HMAC at 0.2 core-seconds: sixteen free requests emptied the bucket and
	// denied sign-in to the whole instance, with no per-IP proxy rule able to
	// restore it.
	loginParamsLimiter *ipRateLimiter
	// kdfSem bounds how many memory-hard derivations may run at once, process
	// wide. Each scrypt at N=1<<17 allocates 128 MiB, and the per-IP lockouts
	// bound guessing, not concurrency — so ~64 simultaneous unauthenticated
	// CardDAV auth attempts could sum past the container memory limit and get
	// the process OOM-killed. Sessions are in-memory, so that logs out everyone.
	kdfSem                 chan struct{}
	mfaPushLimiter         *mfaPushLimiter
	sendAsCooldown         *cooldown
	classifierTestCooldown *cooldown
	captchaVerifier        captcha.Verifier
	captchaProvider        captcha.Provider
	captchaSiteKey         string

	// powVerifier is the same object as captchaVerifier when the configured
	// provider is pow, held additionally under its concrete type because the
	// challenge endpoint and the sweeper need Issue/SweepExpired, which are
	// not on the Verifier interface. nil for every other provider.
	powVerifier   *captcha.PoWVerifier
	powChallenges *powChallengeLimiter
	powDifficulty *powEscalation

	// loginRateLimiter is an INSTANCE-WIDE token bucket on POST /api/auth/login,
	// not a per-IP one.
	//
	// loginLockout below is keyed on username+IP, and the username is
	// attacker-chosen with unbounded cardinality, so it bounds guessing at any one
	// account and nothing about total work. Every attempt with an unknown username
	// deliberately runs scrypt (equalizeLoginTiming), tens of milliseconds of CPU
	// for a 200-byte request, so a rotating username could peg every CPU on a box
	// that also runs an LLM.
	//
	// Instance-wide is the point: a per-IP limit is defeated by more IPs, and the
	// CPU being protected is shared.
	loginRateLimiter *ipRateLimiter
	// loginIPLockout is a second, coarser lockout keyed on the client IP ALONE,
	// so a caller cycling through usernames from one address runs out of budget.
	loginIPLockout *failureLockout

	// classifier and globalStore back the Ollama version/update-check block on the
	// Prompt Tuning page and its admin-notification email. classifier is nil until
	// SetClassifier is called (see app.go); globalStore is the install-wide (not
	// per-user) state.Store rooted at stateDir itself, used only to dedupe the
	// upgrade-available email to one per newly-seen upstream release.
	classifier   *classifier.HTTPClient
	globalStore  *state.Store
	ollamaMu     sync.Mutex
	ollamaStatus ollamaVersionStatus

	// Per-user resources, lazily created and cached. userMu also guards the
	// subscriberID -> userID index used by the unauthenticated native
	// pairing registration endpoint, and the deviceID -> userID index used
	// by ongoing per-device auth (deviceAuthFromRequest).
	userMu        sync.Mutex
	userStores    map[string]*state.Store
	userContacts  map[string]*contacts.Store
	userSendAs    map[string]*sendas.Store
	userGroups    map[string]*groups.Store
	userRules     map[string]*rules.Store
	userMailCache map[string]*mailcache.Store
	// userLastSeen stamps the last request that touched each user's cached
	// stores above, so sweepIdleUserStores knows what to reclaim.
	userLastSeen map[string]time.Time
	userMail     map[string]*serverMailEntry
	subIndex     map[string]string
	deviceIndex  map[string]string
	// deviceReserving counts registrations that have reserved a device ID but
	// not yet written its row, so sweepDeviceIndex — which decides what is
	// residue by looking at disk — does not delete a reservation that simply
	// has not reached disk yet. Guarded by userMu, like deviceIndex.
	deviceReserving map[string]int
	// deviceRescan throttles full device-index rebuilds. A rebuild opens every
	// account's SQLite store, and an unauthenticated caller can force a cache
	// miss on every request just by varying the device id.
	deviceRescan   *intervalGate
	davCredentials davCredentialCache

	// wkdStore is the single instance-level WKD domain-claim store, injected
	// once at construction (NewServer) and shared with the poller process —
	// see wkdPublishStore's doc comment below and wkdpublish.Store's doc
	// comment for why sharing one instance matters.
	wkdStore *wkdpublish.Store

	// TLS state, resolved by Prepare from TLS_CERT_FILE/TLS_KEY_FILE. tlsConfig
	// is nil for a plain-HTTP listener; tlsErr is non-nil when the configuration
	// is broken, and Serve refuses to start rather than falling back to
	// cleartext. See tls.go.
	tlsConfig   *tls.Config
	tlsErr      error
	tlsCertFile string
	tlsKeyFile  string

	// httpServer is the live *http.Server backing Run/Serve, constructed by
	// Prepare so that a Shutdown call arriving before Serve's goroutine has
	// even been scheduled still has a real server to act on instead of racing
	// a lazy initialization (see Prepare's doc comment).
	httpServer *http.Server
}

func NewServer(cfg config.Config, logger *logging.Logger, healthSvc *health.Service, usersStore *users.Store, onConfigUpdated func(config.Config), wkdStore *wkdpublish.Store) *Server {
	configDir := config.ConfigDir()
	stateDir := config.StateDir()
	logPath := filepath.Join(config.LogDir(), "app.log")
	imapConfigKeyPath := config.SecretFile("IMAP_CONFIG_KEY_FILE", "imap-config.key")
	totpSecretKeyPath := config.SecretFile("TOTP_SECRET_KEY_FILE", "totp-secret.key")
	pgpPrivateKeyPath := config.SecretFile("PGP_PRIVATE_KEY_FILE", "pgp-private-key.key")
	pickupStoreKeyPath := config.SecretFile("PICKUP_STORE_KEY_FILE", "pickup-store.key")
	// Generated and persisted like every other key above when PAIRING_SECRET is
	// unset; the env var still wins so a multi-replica deployment can share one.
	// See resolvePairingSecret.
	pairingSecretKeyPath := config.SecretFile("PAIRING_SECRET_FILE", "pairing.key")
	pairingSecret := resolvePairingSecret(pairingSecretKeyPath, logger)

	warnOnRetiredProxyEnv(logger)

	// Pay the login timing-equalization derivation here, in the api process,
	// before anything can serve — see warmLoginTimingHash.
	warmLoginTimingHash()

	captchaProvider := resolveCaptchaProvider(os.Getenv("CAPTCHA_PROVIDER"))
	warnIfPoWDefaultMayLockOutPlainHTTP(logger, captchaProvider, os.Getenv("CAPTCHA_PROVIDER"))
	captchaSiteKey := strings.TrimSpace(os.Getenv("CAPTCHA_SITE_KEY"))
	captchaCfg := captcha.Config{
		Provider:  captchaProvider,
		SiteKey:   captchaSiteKey,
		SecretKey: strings.TrimSpace(os.Getenv("CAPTCHA_SECRET_KEY")),
	}
	if captchaProvider == captcha.ProviderPoW {
		captchaCfg.HMACKey = resolvePoWSecret(
			config.SecretFile("POW_SECRET_FILE", "pow.key"), logger)
		captchaCfg.MaxNumber = config.EnvInt("POW_MAX_NUMBER", 0)
	}
	captchaVerifier, err := captcha.NewVerifier(captchaCfg)
	if err != nil {
		// Misconfigured CAPTCHA must fail closed on login (see handleLogin)
		// rather than silently running unprotected, but must not prevent the
		// server itself from starting.
		logger.Error("captcha misconfigured; login CAPTCHA will reject all attempts until fixed", "error", err.Error())
		captchaVerifier = misconfiguredCaptchaVerifier{err: err}
	}
	// Held under its concrete type too — see the powVerifier field comment.
	powVerifier, _ := captchaVerifier.(*captcha.PoWVerifier)

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
		singleUse:              newSingleUseTokens(),
		serverBaseURL:          strings.TrimRight(strings.TrimSpace(os.Getenv("SERVER_BASE_URL")), "/"),
		nativePushDispatcher:   processor.NewNativePushDispatcher(logger),
		pickupStore:            pgpmail.NewPickupStore(filepath.Join(stateDir, "pickup"), pickupStoreKeyPath),
		userStores:             map[string]*state.Store{},
		userContacts:           map[string]*contacts.Store{},
		userSendAs:             map[string]*sendas.Store{},
		userGroups:             map[string]*groups.Store{},
		userRules:              map[string]*rules.Store{},
		userMailCache:          map[string]*mailcache.Store{},
		userLastSeen:           map[string]time.Time{},
		userMail:               map[string]*serverMailEntry{},
		subIndex:               map[string]string{},
		deviceIndex:            map[string]string{},
		deviceReserving:        map[string]int{},
		davCredentials:         newDAVCredentialCache(),
		loginLockout:           newLoginLockout(),
		davLockout:             newFailureLockout(davMaxFailures, davLockoutFor),
		mfaLockout:             newFailureLockout(mfaMaxFailures, mfaLockoutFor),
		passwordChangeLockout:  newFailureLockout(passwordChangeMaxFailures, passwordChangeLockoutFor),
		deviceLockout:          newFailureLockout(deviceMaxFailures, deviceLockoutFor),
		wkdLimiter:             newIPRateLimiter(wkdRateBurst, wkdRateRefillPerSec),
		pushPollLimiter:        newIPRateLimiter(pushPollBurst, pushPollRefillPerSec),
		loginParamsLimiter:     newIPRateLimiter(loginParamsBurst, loginParamsRefillPerSec),
		kdfSem:                 make(chan struct{}, maxConcurrentKDF),
		deviceRescan:           newIntervalGate(deviceRescanInterval),
		mfaPushLimiter:         newMfaPushLimiter(),
		sendAsCooldown:         newCooldown(sendAsVerificationCooldownFor),
		classifierTestCooldown: newCooldown(classifierTestCooldownFor),
		captchaVerifier:        captchaVerifier,
		captchaProvider:        captchaProvider,
		captchaSiteKey:         captchaSiteKey,
		powVerifier:            powVerifier,
		powChallenges:          newPowChallengeLimiter(),
		powDifficulty:          newPowEscalation(),
		loginRateLimiter:       newIPRateLimiter(loginKDFBurstSeconds, loginKDFDutyCycle),
		loginIPLockout:         newFailureLockout(loginIPMaxFailures, loginIPLockoutFor),
		globalStore:            globalStore,
		wkdStore:               wkdStore,
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

// wkdPublishStore returns the instance-level WKD domain-claim store. Domain
// ownership is a property of the domain, not of a user, so there is exactly one
// store (and one TXT record) per domain for the whole instance, rooted at the
// state directory itself. s.wkdStore is set once at construction to the SAME
// *wkdpublish.Store instance the poller process uses — both built once in
// app.go and injected — so the store's own mutex serializes every
// read-modify-write across both processes. An error here only means "not wired"
// (e.g. a test server built without a wkdStore), not an I/O failure.
func (s *Server) wkdPublishStore() (*wkdpublish.Store, error) {
	if s.wkdStore == nil {
		return nil, fmt.Errorf("wkd publish store not configured")
	}
	return s.wkdStore, nil
}

// routes builds the API's full HTTP surface, split into one function per area
// rather than one 130-line block so the auth posture of a group — which
// middleware wraps it, and which endpoints deliberately have none — can be read
// at a glance. Tests dispatch through this same registration, middleware
// included, instead of calling handlers directly.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	s.routesAuth(mux)
	s.routesAdmin(mux)
	s.routesMail(mux)
	s.routesContacts(mux)
	s.routesPGP(mux)
	s.routesNotifications(mux)
	s.routesRules(mux)
	s.routesFrontend(mux)

	return withSecurityHeaders(mux, buildContentSecurityPolicy(s.captchaProvider))
}

// routesAuth registers sign-in, session, and second-factor endpoints.
// The pre-session ones (login, the MFA challenge completions, captcha
// config, the proof-of-work challenge) are deliberately unwrapped: they run
// before a session exists.
func (s *Server) routesAuth(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", withPublicRoute(s.handleLogin))
	mux.HandleFunc("GET /api/auth/captcha-config", withPublicRoute(s.handleCaptchaConfig))
	// Pre-login, unauthenticated: tells the browser how to derive its auth
	// secret so the password never has to be transmitted. See login_params.go
	// for why the response cannot reveal whether the account exists.
	mux.HandleFunc("GET /api/auth/login-params", withPublicRoute(s.handleLoginParams))
	mux.HandleFunc("GET /api/auth/pow-challenge", withPublicRoute(s.handlePoWChallenge))
	mux.HandleFunc("POST /api/auth/mfa/totp", withPublicRoute(s.handleMFATOTP))
	mux.HandleFunc("POST /api/auth/mfa/recovery-code", withPublicRoute(s.handleMFARecoveryCode))
	mux.HandleFunc("POST /api/auth/mfa/push/poll", withPublicRoute(s.withPushPollRateLimit(s.handlePushPoll)))
	mux.HandleFunc("POST /api/auth/mfa/push/finish", withPublicRoute(s.withPushPollRateLimit(s.handlePushFinish)))
	mux.HandleFunc("POST /api/mfa/push/respond", withDeviceAuth(s.handlePushRespond))
	mux.HandleFunc("GET /api/mfa/status", s.withAuth(s.handleMFAStatus))
	mux.HandleFunc("POST /api/mfa/totp/setup", s.withAuth(s.handleMFASetup))
	mux.HandleFunc("POST /api/mfa/totp/confirm", s.withAuth(s.handleMFAConfirm))
	mux.HandleFunc("POST /api/mfa/totp/disable", s.withAuth(s.handleMFADisable))
	mux.HandleFunc("POST /api/mfa/recovery-codes/regenerate", s.withAuth(s.handleMFARecoveryCodesRegenerate))
	mux.HandleFunc("PUT /api/mfa/push/enabled", s.withAuth(s.handleMFAPushEnabled))
	mux.HandleFunc("GET /api/auth/me", withSelfAuth(s.handleMe))
	mux.HandleFunc("GET /api/auth/csrf", withSelfAuth(s.handleCSRFToken))
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.withAuth(s.handleChangePassword))
}

// routesAdmin registers instance administration and observability:
// health, users, config, logs, tuning, the classifier/Ollama controls, and
// the pre-login setup hint.
func (s *Server) routesAdmin(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", withPublicRoute(s.handleHealth))
	mux.HandleFunc("POST /api/health/repair", s.withAdmin(s.handleRepair))
	mux.HandleFunc("POST /api/admin/mail/poll-now", s.withAdmin(s.handlePollNow))
	mux.HandleFunc("/api/status", s.withAuth(s.handleStatus))
	mux.HandleFunc("GET /api/config", s.withAuth(s.handleConfig))
	mux.HandleFunc("PUT /api/config", s.withAdmin(s.handleConfig))
	mux.HandleFunc("GET /api/labels", s.withAuth(s.handleLabels))
	mux.HandleFunc("GET /api/decisions", s.withAuth(s.handleDecisions))
	mux.HandleFunc("GET /api/logs", s.withAdmin(s.handleLogs))
	mux.HandleFunc("GET /api/logs/list", s.withAdmin(s.handleLogsList))
	mux.HandleFunc("GET /api/users", s.withAdmin(s.handleUsersList))
	mux.HandleFunc("POST /api/users", s.withAdmin(s.handleUsersCreate))
	mux.HandleFunc("PUT /api/users/{id}", s.withAdmin(s.handleUsersUpdate))
	mux.HandleFunc("POST /api/users/{id}/reset-password", s.withAdmin(s.handleUsersResetPassword))
	mux.HandleFunc("POST /api/users/{id}/deactivate", s.withAdmin(s.handleUsersDeactivate))
	mux.HandleFunc("POST /api/users/{id}/reactivate", s.withAdmin(s.handleUsersReactivate))
	mux.HandleFunc("POST /api/users/{id}/clear-mfa", s.withAdmin(s.handleUsersClearMFA))
	mux.HandleFunc("POST /api/classifier/test", s.withAdmin(s.handleClassifierTest))
	mux.HandleFunc("GET /api/ollama/version", s.withAuth(s.handleOllamaVersion))
	mux.HandleFunc("GET /api/tuning", s.withAuth(s.handleTuning))
	mux.HandleFunc("PUT /api/tuning", s.withAuth(s.handleTuning))
	mux.HandleFunc("GET /api/labels/preferences", s.withAuth(s.handleLabelPreferences))
	mux.HandleFunc("PUT /api/labels/preferences", s.withAuth(s.handleLabelPreferences))
	mux.HandleFunc("GET /api/setup", withPublicRoute(s.handleSetup))
}

// routesMail registers mailbox reading and sending, plus IMAP/SMTP
// account setup. The read/act paths use withMailAuth so paired mobile
// devices reach them without a web session; credential setup stays on
// withAuth (web UI only).
func (s *Server) routesMail(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/inbox", s.withMailAuth(s.handleInbox))
	mux.HandleFunc("GET /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("POST /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("PUT /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("DELETE /api/inbox/folders", s.withMailAuth(s.handleInboxFolders))
	mux.HandleFunc("POST /api/inbox/actions", s.withMailAuth(s.handleInboxActions))
	mux.HandleFunc("GET /api/mail/search", s.withMailAuth(s.handleMailSearch))
	mux.HandleFunc("GET /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("POST /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("DELETE /api/imap/config", s.withAuth(s.handleIMAPConfig))
	mux.HandleFunc("POST /api/imap/test", s.withAuth(s.handleIMAPTest))
	mux.HandleFunc("POST /api/mail/draft", withUploadDeadline(s.withMailAuth(s.handleMailDraft)))
	mux.HandleFunc("POST /api/mail/send", withUploadDeadline(s.withMailAuth(s.handleMailSend)))
	// Send path for end-to-end keys: the browser has already encrypted and
	// signed, the server only relays over SMTP. See pgp_send_client.go.
	mux.HandleFunc("POST /api/mail/send-pgp", withUploadDeadline(s.withMailAuth(s.handleMailSendPGP)))
	// Read path for end-to-end keys: lazy per-message ciphertext fetch, since
	// the inbox DTO cannot carry it. See pgp_client_read.go.
	mux.HandleFunc("GET /api/mail/pgp-payload", s.withMailAuth(s.handlePGPPayload))
	mux.HandleFunc("GET /api/mail/send-as", s.withAuth(s.handleSendAs))
	mux.HandleFunc("POST /api/mail/send-as", s.withAuth(s.handleSendAs))
	mux.HandleFunc("DELETE /api/mail/send-as/{id}", s.withAuth(s.handleSendAsByID))
	mux.HandleFunc("GET /api/mail/attachments", s.withMailAuth(s.handleMailAttachmentList))
	mux.HandleFunc("GET /api/mail/attachment", s.withMailAuth(s.handleMailAttachmentDownload))
}

// routesContacts registers the address book, groups, and the CardDAV
// server surface (which authenticates via HTTP Basic, not a session).
func (s *Server) routesContacts(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/contacts", s.withAuth(s.handleContacts))
	mux.HandleFunc("POST /api/contacts", s.withAuth(s.handleContacts))
	mux.HandleFunc("POST /api/contacts/dedupe", s.withMailAuth(s.handleContactsDedupe))
	mux.HandleFunc("GET /api/contacts/search", s.withAuth(s.handleContactsSearch))
	mux.HandleFunc("POST /api/contacts/bulk-delete", s.withAuth(s.handleContactsBulkDelete))
	mux.HandleFunc("GET /api/contacts/export", s.withAuth(s.handleContactsExport))
	mux.HandleFunc("POST /api/contacts/import", withUploadDeadline(s.withAuth(s.handleContactsImport)))
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
	mux.HandleFunc("GET /api/contacts/sync", withDeviceAuth(s.handleContactsSync))
	mux.HandleFunc("POST /api/contacts/sync", withDeviceAuth(s.handleContactsSync))
	mux.HandleFunc("POST /api/contacts/{id}/photo", withUploadDeadline(s.withAuth(s.handleContactPhoto)))
	mux.HandleFunc("GET /api/contacts/{id}/photo", s.withMailAuth(s.handleContactPhoto))
	mux.HandleFunc("DELETE /api/contacts/{id}/photo", s.withAuth(s.handleContactPhoto))
	mux.HandleFunc("POST /api/contacts/{id}/self", s.withAuth(s.handleContactSelf))
	mux.HandleFunc("GET /api/groups", s.withMailAuth(s.handleGroups))
	mux.HandleFunc("POST /api/groups", s.withAuth(s.handleGroups))
	mux.HandleFunc("PUT /api/groups/{id}", s.withAuth(s.handleGroupByID))
	mux.HandleFunc("DELETE /api/groups/{id}", s.withAuth(s.handleGroupByID))
	mux.Handle("/.well-known/carddav", s.withDAVBasicAuth(http.HandlerFunc(s.handleCardDAV)))
	mux.Handle(davPrefix+"/", s.withDAVBasicAuth(http.HandlerFunc(s.handleCardDAV)))
}

// routesPGP registers key management, recipient/keyserver lookup,
// discovery settings, WKD publishing, and the two token-gated public
// endpoints (QR key exchange and one-time pickup links).
func (s *Server) routesPGP(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/pgp/identity/generate", s.withAuth(s.handlePGPIdentityGenerate))
	mux.HandleFunc("POST /api/pgp/identity/import", s.withAuth(s.handlePGPIdentityImport))
	mux.HandleFunc("GET /api/pgp/identity", s.withAuth(s.handlePGPIdentity))
	// End-to-end key handling: the browser wraps and unwraps the private half, the
	// server only stores an opaque envelope. See pgp_client_keys.go.
	//
	// These are withMailAuth, not withAuth: a paired mobile device authenticates
	// with per-device credentials and no session cookie, and it needs to unwrap its
	// own key exactly as much as the browser does. Session-only gating here locked
	// every native client out of the feature built for it.
	mux.HandleFunc("GET /api/pgp/bootstrap", s.withMailAuth(s.handlePGPBootstrap))
	mux.HandleFunc("GET /api/pgp/identity/wrapped", s.withMailAuth(s.handlePGPWrappedKey))
	// These two WRITE key material: identity/client replaces the account's public
	// key (and clears the server-sealed private half), and rewrap replaces the
	// wrapped envelope. They are session-only for the same reason export-legacy
	// below is — a device secret is not a re-verified password — and a stolen
	// device secret could otherwise substitute the key all future mail is encrypted
	// to, or wipe the private half irrecoverably.
	mux.HandleFunc("POST /api/pgp/identity/client", s.withAuth(s.handlePGPIdentityClient))
	mux.HandleFunc("POST /api/pgp/identity/rewrap", s.withAuth(s.handlePGPRewrapKey))
	// export-legacy stays session-only on purpose. It is the one endpoint
	// that returns a private key in the clear, and it re-verifies the account
	// password before doing so — a device secret is not that password, and a
	// paired device must not be able to exchange itself for the key.
	mux.HandleFunc("POST /api/pgp/identity/export-legacy", s.withAuth(s.handlePGPExportLegacyKey))
	mux.HandleFunc("DELETE /api/pgp/identity", s.withAuth(s.handlePGPIdentity))
	mux.HandleFunc("GET /api/pgp/keyserver/lookup", s.withAuth(s.handlePGPKeyserverLookup))
	// withMailAuth: mobile compose calls this to warn about keyless recipients
	// before sending. It reads the caller's own contacts to answer the same
	// question the send path answers by refusing, only asked earlier.
	// (recipients/resolve below stays unusable here — it 409s for anything but a
	// client-protected account.)
	mux.HandleFunc("POST /api/pgp/recipients/check", s.withMailAuth(s.handlePGPRecipientsCheck))
	// Returns the recipients' actual public keys, for client-protected
	// accounts whose browser does the encrypting. See pgp_resolve_handler.go.
	mux.HandleFunc("POST /api/pgp/recipients/resolve", s.withMailAuth(s.handlePGPRecipientsResolve))
	// GET is withMailAuth so a paired device can honor autoEncryptWhenKeyKnown;
	// the PUT below stays session-only because a device secret is not a
	// re-verified password and this is a policy write.
	mux.HandleFunc("GET /api/pgp/discovery/settings", s.withMailAuth(s.handlePGPDiscoverySettings))
	mux.HandleFunc("PUT /api/pgp/discovery/settings", s.withAuth(s.handlePGPDiscoverySettings))
	mux.HandleFunc("GET /api/pgp/discovery/suppressions", s.withAuth(s.handlePGPDiscoverySuppressions))
	mux.HandleFunc("DELETE /api/pgp/discovery/suppressions/{email}", s.withAuth(s.handlePGPDiscoverySuppressionByEmail))
	mux.HandleFunc("POST /api/pgp/discovery/suppress-contact", s.withAuth(s.handlePGPDiscoverySuppressContact))
	mux.HandleFunc("GET /api/pgp/wkd/domains", s.withAdmin(s.handleWKDDomains))
	mux.HandleFunc("POST /api/pgp/wkd/domains", s.withAdmin(s.handleWKDDomains))
	mux.HandleFunc("POST /api/pgp/wkd/domains/{domain}/verify", s.withAdmin(s.handleWKDDomainVerify))
	mux.HandleFunc("DELETE /api/pgp/wkd/domains/{domain}", s.withAdmin(s.handleWKDDomainDelete))
	mux.HandleFunc("GET /api/pgp/qr/token", s.withMailAuth(s.handlePGPQRToken))
	mux.HandleFunc("GET /api/pgp/qr/key", withTokenAuth(s.handlePGPQRKey))
	// Public by protocol: Web Key Directory exists so any sender's client can
	// fetch a published key without credentials. withWKDRateLimit bounds it,
	// but a rate limit is not an auth model, which is why the marker is here.
	mux.HandleFunc("GET /.well-known/openpgpkey/", withPublicRoute(s.withWKDRateLimit(s.handleWKD)))
	mux.HandleFunc("GET /pickup/{id}", withTokenAuth(s.handlePickup))
	// Client-sealed pickup: the browser encrypts, the server stores an opaque
	// blob, and the key travels in the link fragment it never receives.
	// See pickup_client_sealed.go.
	mux.HandleFunc("POST /pickup/{id}/open", withTokenAuth(s.handlePickupOpen))
	mux.HandleFunc("GET /pickup/{id}/blob", withTokenAuth(s.handlePickupBlob))
	mux.HandleFunc("POST /api/pgp/pickup", withUploadDeadline(s.withMailAuth(s.handlePickupCreate)))
}

// routesNotifications registers web push, native device pairing, and the
// App Pull queue. The register/deregister/pull endpoints authenticate with
// per-device credentials rather than a session, so they carry no middleware
// here and check inside the handler.
func (s *Server) routesNotifications(mux *http.ServeMux) {
	mux.HandleFunc("PUT /api/notifications/native/devices/{deviceId}/mfa", s.withAuth(s.handleNativeDeviceMFA))
	mux.HandleFunc("GET /api/notifications/preferences", s.withAuth(s.handleNotificationPreferences))
	mux.HandleFunc("PUT /api/notifications/preferences", s.withAuth(s.handleNotificationPreferences))
	mux.HandleFunc("GET /api/notifications/vapid-public-key", s.withAuth(s.handleNotificationVAPIDPublicKey))
	mux.HandleFunc("POST /api/notifications/subscriptions", s.withAuth(s.handleNotificationSubscriptions))
	mux.HandleFunc("DELETE /api/notifications/subscriptions", s.withAuth(s.handleNotificationSubscriptions))
	mux.HandleFunc("POST /api/notifications/test", s.withAuth(s.handleNotificationTest))
	mux.HandleFunc("GET /api/notifications/pairing", s.withAuth(s.handleNotificationPairing))
	// withTokenAuth, not withDeviceAuth: registration creates the device, so
	// there is no device secret to authenticate with yet. The credential is the
	// single-use signed pairing token from the scanned QR, verified by
	// decodeAndVerifyPairingToken.
	mux.HandleFunc("POST /api/notifications/native/register", withTokenAuth(s.handleNotificationNativeRegister))
	mux.HandleFunc("GET /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("DELETE /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("POST /api/notifications/native/unpair", s.withAuth(s.handleNotificationNativeUnpair))
	mux.HandleFunc("POST /api/notifications/native/deregister", withDeviceAuth(s.handleNotificationNativeDeregister))
	mux.HandleFunc("PUT /api/notifications/native/mode", s.withAuth(s.handleNotificationNativeMode))
	mux.HandleFunc("GET /api/notifications/native/pull", withDeviceAuth(s.handleNotificationNativePull))
	mux.HandleFunc("POST /api/notifications/desktop/pair", s.withAuth(s.handleDesktopPair))
}

// routesRules registers the filter-rule builder and the Sieve editor.
func (s *Server) routesRules(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/rules", s.withMailAuth(s.handleRules))
	mux.HandleFunc("POST /api/rules", s.withAuth(s.handleRules))
	mux.HandleFunc("PUT /api/rules/{id}", s.withAuth(s.handleRuleByID))
	mux.HandleFunc("DELETE /api/rules/{id}", s.withAuth(s.handleRuleByID))
	mux.HandleFunc("POST /api/rules/reorder", s.withAuth(s.handleRulesReorder))
	mux.HandleFunc("GET /api/rules/{id}/sieve", s.withMailAuth(s.handleRuleSieve))
	mux.HandleFunc("PUT /api/rules/{id}/sieve", s.withAuth(s.handleRuleSieve))
	mux.HandleFunc("POST /api/rules/run", s.withMailAuth(s.handleRulesRun))
}

// routesFrontend registers the SPA fallback. "/" is the least specific
// pattern, so Go's mux only reaches it when nothing else matches.
func (s *Server) routesFrontend(mux *http.ServeMux) {
	mux.HandleFunc("/", withPublicRoute(s.handleFrontend))
}

// Prepare constructs the underlying *http.Server (Addr + Handler) without
// starting it. Callers that coordinate a graceful Shutdown with a signal
// handler (see runServer/runAll in internal/app/app.go) MUST call Prepare
// synchronously — before launching any goroutine that calls Serve — so a
// shutdown signal arriving immediately after startup always has a non-nil
// *http.Server to call Shutdown on. Constructing it lazily inside the Serve
// goroutine races instead: Shutdown could run first and either panic on a nil
// server or silently do nothing.
//
// Serve and Run call Prepare automatically if it wasn't already called.
func (s *Server) Prepare() {
	port := config.EnvInt("WEB_PORT", 5866)
	// Timeouts are set explicitly because net/http's zero values mean "no limit":
	// without them a connection that dribbles one header line every few seconds is
	// held open indefinitely, and the shipped compose file publishes this port
	// directly with no reverse proxy in front to absorb it. WriteTimeout is
	// deliberately generous rather than absent — large attachment downloads stream
	// through this same server.
	//
	// ReadTimeout stays tight because it covers the whole request INCLUDING the
	// body, and almost every route reads at most a few KB. The handful that accept
	// a multi-megabyte upload extend it per-request via withUploadDeadline.
	s.httpServer = &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	// Optional inbound TLS — see tls.go. The error is stashed rather than returned
	// because Prepare has no error return; Serve surfaces it and refuses to start.
	// It must NOT degrade to plain HTTP: an operator who configured a certificate
	// believes this port is encrypted, and quietly serving cleartext is worse than
	// not starting.
	certFile, keyFile, err := tlsFilesFromEnv()
	if err == nil {
		s.tlsConfig, err = newTLSConfig(certFile, keyFile)
	}
	if err != nil {
		s.tlsErr = err
		return
	}
	if s.tlsConfig != nil {
		s.httpServer.TLSConfig = s.tlsConfig
		s.tlsCertFile, s.tlsKeyFile = certFile, keyFile
	}
}

// Serve binds the address configured on the prepared *http.Server and blocks
// until Shutdown (or Close) stops it, at which point it returns nil —
// http.ErrServerClosed is the expected result of a graceful stop. Prepare is
// called automatically if it hasn't been already, but callers that need
// race-free Shutdown coordination should call Prepare themselves first.
func (s *Server) Serve() error {
	if s.httpServer == nil {
		s.Prepare()
	}
	// A TLS misconfiguration is fatal here rather than a fallback to cleartext.
	if s.tlsErr != nil {
		return fmt.Errorf("tls configuration: %w", s.tlsErr)
	}

	var err error
	if s.tlsConfig != nil {
		s.logger.Info("api server starting", "addr", s.httpServer.Addr, "scheme", "https")
		// Paths are already in TLSConfig.GetCertificate; passing empty strings
		// tells net/http to use it, which is what makes renewal reload work.
		err = s.httpServer.ListenAndServeTLS("", "")
	} else {
		s.logger.Info("api server starting", "addr", s.httpServer.Addr, "scheme", "http")
		err = s.httpServer.ListenAndServe()
	}
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

// Shutdown gracefully stops the HTTP server: it stops accepting new connections
// immediately and waits for active requests to finish, up to ctx's deadline.
// Safe to call even if Prepare was never invoked (a no-op) or before Serve's
// goroutine has started — the eventual Serve call observes the server is
// already shutting down and returns promptly instead of blocking on Accept.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// StartPickupSweeper runs PickupStore.Sweep on an interval for the process
// lifetime, mirroring processor.Poller's ticker/cancel pattern. Call once after
// NewServer, e.g. `go srv.StartPickupSweeper(context.Background())`.
func (s *Server) StartPickupSweeper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// pickupLinkTTL, not a separate longer number. The notification email tells the
			// recipient the link "expires in 7 days or as soon as it's opened", and a
			// record is unusable past its ExpiresAt anyway — so a 30-day sweep only meant
			// the message sat on disk for 23 days after the last moment anyone could read
			// it.
			if err := s.pickupStore.Sweep(pickupLinkTTL); err != nil {
				s.logger.Error("pickup sweep failed", "error", err.Error())
			}
		}
	}
}

// StartContactPhotoSweeper reclaims contact-photo files no live contact
// references, for every user, on the same hourly cadence as the pickup sweep.
//
// Photo filenames are content hashes, so two contacts with the same picture
// share one file and no handler can safely delete on unlink — clearing one
// contact's photo would blank the other's. DELETE .../photo therefore only
// clears the reference, and the bytes come back only through this sweep.
//
// One user's failure is logged and skipped rather than aborting the pass, so a
// single corrupt contacts file cannot stop every other account being reclaimed.
func (s *Server) StartContactPhotoSweeper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			users, err := s.users.List()
			if err != nil {
				s.logger.Error("contact photo sweep could not list users", "error", err.Error())
				continue
			}
			for _, u := range users {
				if err := s.sweepContactPhotos(u.ID); err != nil {
					s.logger.Error("contact photo sweep failed",
						"user_id", u.ID, "error", err.Error())
				}
			}
		}
	}
}

// StartSessionSweeper reclaims sessions that passed their idle timeout or
// absolute lifetime without anyone presenting them again. Call once after
// NewServer.
//
// Without it, s.sessions only ever shrinks when a token is presented again
// (currentUser), logged out, or revoked — so every session belonging to a user
// who simply closed the tab is pinned for the process lifetime. Every other
// bounded map in this package already has a sweep; the one holding live
// credentials was the exception.
func (s *Server) StartSessionSweeper(ctx context.Context) {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepSessions(time.Now())
			s.logSaturatedLockouts()
		}
	}
}

// logSaturatedLockouts reports any lockout table that has hit
// loginLockoutHardCap and started shedding new keys.
//
// A saturated table refuses to track keys it has not seen before, which the
// caller experiences as a 429 on a perfectly good credential. That is the
// deliberate trade — shedding rather than evicting live lockouts, see
// loginLockoutHardCap — but it must not be silent: from the outside it is
// indistinguishable from "login is broken", and it means tens of thousands of
// distinct keys are locked out at once, which is an attack in progress.
func (s *Server) logSaturatedLockouts() {
	if s.logger == nil {
		return
	}
	for name, lockout := range map[string]*failureLockout{
		"login":           s.loginLockout,
		"login_ip":        s.loginIPLockout,
		"dav":             s.davLockout,
		"mfa":             s.mfaLockout,
		"password_change": s.passwordChangeLockout,
		"device":          s.deviceLockout,
	} {
		if lockout != nil && lockout.Saturated() {
			s.logger.Error("lockout table saturated; new keys are being shed",
				"table", name,
				"hard_cap", strconv.Itoa(loginLockoutHardCap),
				"effect", "callers not already tracked receive 429; lockouts already in force are preserved")
		}
	}
}

// sweepSessions drops every session dead as of now. Split out so tests can
// drive it directly instead of waiting on the ticker.
func (s *Server) sweepSessions(now time.Time) int {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	removed := 0
	for token, sess := range s.sessions {
		if now.After(sess.ExpiresAt) || now.Sub(sess.IssuedAt) >= sessionMaxLifetime {
			delete(s.sessions, token)
			removed++
		}
	}
	return removed
}

// mfaChallengeSweepInterval is a var rather than an inline literal so tests can
// shrink it, mirroring sendAsCooldownSweepInterval below. Challenges live five
// minutes (mfa.challengeTTL), so sweeping every minute keeps the map's steady
// state to roughly one interval's worth of abandonments.
var mfaChallengeSweepInterval = time.Minute

// StartMFAChallengeSweeper reclaims login challenges that expired without
// anyone completing (or abandoning through) them. Call once after NewServer.
//
// Without it, mfa.Store only ever shrank when a challenge was presented again,
// consumed, or explicitly purged — so every login that reached the
// second-factor prompt and stopped there was pinned for the process lifetime.
func (s *Server) StartMFAChallengeSweeper(ctx context.Context) {
	ticker := time.NewTicker(mfaChallengeSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mfaChallenges.SweepExpired(time.Now())
		}
	}
}

// sendAsCooldownSweepInterval is a var rather than an inline literal (unlike
// StartPickupSweeper's ticker) solely so tests can shrink it to observe a
// real tick without waiting out the production interval; production always
// runs with the 1-hour default below.
var cooldownSweepInterval = 1 * time.Hour

// StartCooldownSweeper runs sweep on every cooldown map for the process
// lifetime, mirroring StartPickupSweeper. Call once after NewServer.
//
// Both instances, from one ticker. It used to sweep only sendAsCooldown, because
// that was the instance whose bug prompted the sweep; classifierTestCooldown was
// a copy of the same type made before the sweep existed and never got one.
func (s *Server) StartCooldownSweeper(ctx context.Context) {
	ticker := time.NewTicker(cooldownSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, c := range []*cooldown{s.sendAsCooldown, s.classifierTestCooldown} {
				c.sweep(cooldownSweepMaxAge)
			}
		}
	}
}

// StartMfaPushLimiterSweeper runs mfaPushLimiter.sweep on an interval for the
// process lifetime, mirroring StartSendAsCooldownSweeper's ticker/select pattern
// exactly. Call once after NewServer.
func (s *Server) StartMfaPushLimiterSweeper(ctx context.Context) {
	ticker := time.NewTicker(mfaPushLimiterSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mfaPushLimiter.sweep(mfaPushLimiterSweepMaxAge)
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
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	store, err := s.storeFor(r)
	if err != nil {
		http.Error(w, "failed to open user state", http.StatusInternalServerError)
		return
	}
	processedSince := time.Now().UTC().Add(-1 * time.Hour)
	// A failed checkpoint read is reported as such rather than rendered as an
	// empty string, which on this page is indistinguishable from "never polled".
	checkpoint, err := store.Checkpoint()
	if err != nil {
		s.logger.Error("status: checkpoint read failed", "error", err.Error())
		checkpoint = ""
	}
	resp := map[string]any{
		"scanIntervalSeconds":     cfg.Scan.IntervalSeconds,
		"rateLimits":              cfg.RateLimits,
		"checkpoint":              checkpoint,
		"checkpointReadFailed":    err != nil,
		"emailsProcessedLastHour": store.ProcessedSince(processedSince),
		"serverTimeUtc":           time.Now().UTC().Format(time.RFC3339),
	}
	// Classifier admission depth. Without this the only symptom of a backlog
	// the model cannot drain is mail that quietly classifies late — the poll
	// tick reports success either way, and the health check only watches IMAP.
	if s.classifier != nil {
		resp["classifier"] = s.classifier.Stats()
	}

	// How this server resolved the caller's address, and whether it believed the
	// forwarded headers to do it.
	//
	// Nothing logs the client IP (deliberately — see log_privacy_test.go), so an
	// operator standing up a reverse proxy has no other way to confirm the lockouts
	// key off real callers. Getting it wrong is silent and cuts both ways: a
	// forgeable value defeats every rate limit, and a CONSTANT value makes the
	// per-IP lockout one shared bucket where 50 failures from anyone locks out
	// sign-in for everyone.
	//
	// Safe to return: the caller's own address, plus a deployment property. Behind a
	// correct proxy clientIp is YOUR public address and proxyHeadersTrusted is true;
	// a loopback or bridge address means every user shares one lockout key.
	resp["clientIp"] = clientIP(r)
	resp["proxyHeadersTrusted"] = proxyHeadersTrusted(r)

	writeJSON(w, http.StatusOK, resp)
}

// imapConfigPayload aliases mailmsg.IMAPConfigPayload, which moved to package
// mailmsg so the mail poller can read stored IMAP/SMTP credentials without an
// api->processor->api import cycle.
type imapConfigPayload = mailmsg.IMAPConfigPayload

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
	// AllowPickupFallback opts in to the one-time pickup link for recipients
	// with no usable PGP key. Absent means refuse: that fallback stores the
	// message's plaintext server-side for seven days and mails the link in
	// the clear, so it is a downgrade the sender has to choose out loud.
	AllowPickupFallback bool
	From                string
}

// Size limits for one outgoing message.
//
// maxMailRequestBytes is the hard cap on the request body — what a user
// experiences as "how big an upload is allowed" — and is the one fixed by hand.
// maxMailAttachmentBytes is DERIVED from it: attachments travel base64-encoded
// inside the JSON body, so a decoded budget above (request cap × 3/4) can never
// be reached and only produces a confusing error at the wrong layer.
// mailRequestOverheadBytes reserves 1 MiB for JSON scaffolding, recipients,
// subject and body, far more than those need.
//
// The client-side-encrypted paths (maxClientCiphertextBytes,
// maxSealedPickupBytes) deliberately track the INBOUND message cap instead: they
// carry an already-armored ciphertext sized by what the browser produced, and
// are bounded so a send cannot exceed what a receive can handle.
const (
	maxMailRequestBytes      = 25 << 20
	mailRequestOverheadBytes = 1 << 20
	// 3/4 undoes base64's 4/3 expansion.
	maxMailAttachmentBytes = (maxMailRequestBytes - mailRequestOverheadBytes) / 4 * 3
)

// The two size-refusal messages, derived from the constants above rather than
// written out. The attachment message previously read "max 25 MB total" as a
// hardcoded string while the constant it described was a separate literal —
// so changing one silently made the other a lie to the user's face.
var (
	mailTooLargeMessage = fmt.Sprintf(
		"message too large (max %d MB including attachments)", maxMailRequestBytes>>20)
	attachmentsTooLargeMessage = fmt.Sprintf(
		"attachments too large (max %d MB total)", maxMailAttachmentBytes>>20)
)

// pgpRecipientPlan splits an encrypted send's To/CC/BCC recipients by PGP key
// availability and status. To/CC recipients with a usable key share one
// ciphertext, matching how a normal email is visible to every To/CC recipient.
// BCC recipients are kept separate so each can be encrypted individually in
// buildPGPDeliveries — sharing a ciphertext, and its embedded recipient key IDs,
// would deanonymize them. Recipients with no key on file, or whose key is
// revoked or expired, land in withoutKeyEmails and fall back to the plaintext
// pickup-link notification.
type pgpRecipientPlan struct {
	toCCEmails       []string
	toCCKeys         []string
	bccEmails        []string
	bccKeys          []string
	withoutKeyEmails []string
}

// pgpDelivery is one PGP/MIME ciphertext and the SMTP recipient(s) it
// should be delivered to in a single transaction.
type pgpDelivery struct {
	Recipients []string
	Ciphertext []byte
}

func (s *Server) handleFrontend(w http.ResponseWriter, r *http.Request) {
	// An /api/ path that reached the catch-all is one the mux did not
	// register. Serving index.html for it — 200, a page of HTML — makes a
	// mistyped endpoint indistinguishable from a working one, and forces every
	// client to sniff the body to find out which it got.
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "unknown api endpoint",
			"path":  r.URL.Path,
		})
		return
	}

	frontendDir := config.EnvOrDefault("FRONTEND_DIR", "/opt/kypost/frontend")
	indexPath := filepath.Join(frontendDir, "index.html")

	requestPath := path.Clean("/" + r.URL.Path)
	relPath := strings.TrimPrefix(requestPath, "/")

	if relPath != "" {
		// os.Root, not a lexical prefix check: os.Stat and http.ServeFile
		// follow symlinks, so a link under frontendDir pointing at
		// /kypost/private satisfies any string comparison you can write.
		if root, err := os.OpenRoot(frontendDir); err == nil {
			defer root.Close()
			if info, err := root.Stat(relPath); err == nil && !info.IsDir() {
				if f, err := root.Open(relPath); err == nil {
					defer f.Close()
					// Vite content-hashes asset filenames, so anything under
					// assets/ is immutable by construction.
					if strings.HasPrefix(relPath, "assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					http.ServeContent(w, r, info.Name(), info.ModTime(), f)
					return
				}
			}
		}
	}

	if _, err := os.Stat(indexPath); err == nil {
		http.ServeFile(w, r, indexPath)
		return
	}

	http.Error(w, "frontend assets not found; build frontend and set FRONTEND_DIR", http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scheduleContainerRestart exits this process after delay so supervisord's
// autorestart brings it back with fresh state. It restarts THIS PROCESS, not
// the container: this process is unprivileged and PID 1 is not ours, so
// signalling PID 1 only ever returns EPERM.
func scheduleContainerRestart(logger *logging.Logger, reason string, delay time.Duration) {
	go func() {
		time.Sleep(delay)
		if logger != nil {
			logger.Error("restarting process; supervisord will bring it back", "reason", reason)
		}
		os.Exit(2)
	}()
}

func randomToken(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
