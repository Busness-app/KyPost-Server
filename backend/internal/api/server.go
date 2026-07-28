package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"

	goimap "github.com/BrianLeishman/go-imap"
)

// Server holds the HTTP surface and its process-wide state.
//
// LOCK ORDER: mu before userMu. Never the reverse.
//
// These are two independent mutexes guarding two independent groups of
// fields — mu covers cfg/sessions/httpServer, userMu covers the per-user
// store caches and the subscriber/device indexes. Nothing currently takes
// both, which is the only reason there is no deadlock to find today. The
// moment one handler reads s.cfg (mu) inside a userMu critical section
// while another does the reverse, that becomes an ABBA deadlock that only
// shows up under concurrent load in production. Stating the order here is
// cheaper than discovering it there.
type Server struct {
	mu                  sync.RWMutex
	cfg                 config.Config
	onConfigUpdated     func(config.Config)
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
	// qrTokens makes each PGP QR key-exchange token redeemable exactly once.
	qrTokens               *qrTokenGuard
	nativePushDispatcher   *processor.NativePushDispatcher
	pickupStore            *pgpmail.PickupStore
	poller                 *processor.Poller
	loginLockout           *failureLockout
	davLockout             *failureLockout
	mfaLockout             *failureLockout
	deviceLockout          *failureLockout
	wkdLimiter             *ipRateLimiter
	mfaPushCooldown        *mfaPushCooldown
	sendAsCooldown         *sendAsVerificationCooldown
	classifierTestCooldown *classifierTestCooldown
	nativePairingNonces    *consumedNativePairingNonces
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

	// wkdStore is the single instance-level WKD domain-claim store, injected
	// once at construction (NewServer) and shared with the poller process —
	// see wkdPublishStore's doc comment below and wkdpublish.Store's doc
	// comment for why sharing one instance matters.
	wkdStore *wkdpublish.Store

	// httpServer is the live *http.Server backing Run/Serve, constructed by
	// Prepare so that a Shutdown call arriving before Serve's goroutine has
	// even been scheduled still has a real server to act on instead of racing
	// a lazy initialization (see Prepare's doc comment).
	httpServer *http.Server
}

func NewServer(cfg config.Config, logger *logging.Logger, healthSvc *health.Service, usersStore *users.Store, onConfigUpdated func(config.Config), wkdStore *wkdpublish.Store) *Server {
	configDir := config.EnvOrDefault("CONFIG_DIR", "/kypost/config")
	stateDir := config.EnvOrDefault("STATE_DIR", "/kypost/state")
	logPath := filepath.Join(config.EnvOrDefault("LOG_DIR", "/kypost/logs"), "app.log")
	imapConfigKeyPath := config.EnvOrDefault("IMAP_CONFIG_KEY_FILE", "/kypost/private/imap-config.key")
	totpSecretKeyPath := config.EnvOrDefault("TOTP_SECRET_KEY_FILE", "/kypost/private/totp-secret.key")
	pgpPrivateKeyPath := config.EnvOrDefault("PGP_PRIVATE_KEY_FILE", "/kypost/private/pgp-private-key.key")
	pickupStoreKeyPath := config.EnvOrDefault("PICKUP_STORE_KEY_FILE", "/kypost/private/pickup-store.key")
	// Generated and persisted like every other key above when PAIRING_SECRET is
	// unset; the env var still wins so a multi-replica deployment can share one.
	// See resolvePairingSecret.
	pairingSecretKeyPath := config.EnvOrDefault("PAIRING_SECRET_FILE", "/kypost/private/pairing.key")
	pairingSecret := resolvePairingSecret(pairingSecretKeyPath, logger)

	captchaProvider := captcha.Provider(strings.ToLower(strings.TrimSpace(os.Getenv("CAPTCHA_PROVIDER"))))
	captchaSiteKey := strings.TrimSpace(os.Getenv("CAPTCHA_SITE_KEY"))
	captchaCfg := captcha.Config{
		Provider:  captchaProvider,
		SiteKey:   captchaSiteKey,
		SecretKey: strings.TrimSpace(os.Getenv("CAPTCHA_SECRET_KEY")),
	}
	if captchaProvider == captcha.ProviderPoW {
		captchaCfg.HMACKey = resolvePoWSecret(
			config.EnvOrDefault("POW_SECRET_FILE", "/kypost/private/pow.key"), logger)
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
		qrTokens:               newQRTokenGuard(),
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
		wkdLimiter:             newIPRateLimiter(wkdRateBurst, wkdRateRefillPerSec),
		mfaPushCooldown:        newMfaPushCooldown(),
		sendAsCooldown:         newSendAsVerificationCooldown(),
		classifierTestCooldown: newClassifierTestCooldown(),
		nativePairingNonces:    newConsumedNativePairingNonces(),
		captchaVerifier:        captchaVerifier,
		captchaProvider:        captchaProvider,
		captchaSiteKey:         captchaSiteKey,
		powVerifier:            powVerifier,
		powChallenges:          newPowChallengeLimiter(),
		powDifficulty:          newPowEscalation(),
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
// ownership is a property of the domain, not of a user, so there is exactly
// one store (and one TXT record) per domain for the whole instance, rooted
// at the state directory itself rather than under stateDir/users/<id>/.
// s.wkdStore is set once at construction (NewServer) to the SAME
// *wkdpublish.Store instance the poller process uses (both are built once in
// app.go and injected) — not a second Store independently opened over the
// same file — so wkdpublish.Store's own internal mutex actually serializes
// every read-modify-write call across both the API and the poller, rather
// than each process only ever serializing against itself. An error return
// here only means "not wired" (e.g. a test server built without a wkdStore);
// it does not indicate an I/O failure, since construction already happened
// up front.
func (s *Server) wkdPublishStore() (*wkdpublish.Store, error) {
	if s.wkdStore == nil {
		return nil, fmt.Errorf("wkd publish store not configured")
	}
	return s.wkdStore, nil
}

// routes builds the API's route table. Split out from Run so tests can
// dispatch through the exact same registration (middleware included)
// instead of calling handlers directly and assuming the wiring matches.
// routes builds the full HTTP surface. It is split into one function per
// area rather than one 130-line block so the auth posture of a given
// group -- which middleware wraps it, and which endpoints deliberately
// have none -- can be read at a glance instead of scanned for.
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
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/auth/captcha-config", s.handleCaptchaConfig)
	mux.HandleFunc("GET /api/auth/pow-challenge", s.handlePoWChallenge)
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
	mux.HandleFunc("GET /api/auth/me", s.handleMe)
	mux.HandleFunc("GET /api/auth/csrf", s.handleCSRFToken)
	mux.HandleFunc("POST /api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("POST /api/auth/password", s.withAuth(s.handleChangePassword))
}

// routesAdmin registers instance administration and observability:
// health, users, config, logs, tuning, the classifier/Ollama controls, and
// the pre-login setup hint.
func (s *Server) routesAdmin(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", s.handleHealth)
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
	mux.HandleFunc("GET /api/setup", s.handleSetup)
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
	mux.HandleFunc("POST /api/mail/draft", s.withMailAuth(s.handleMailDraft))
	mux.HandleFunc("POST /api/mail/send", s.withMailAuth(s.handleMailSend))
	// Send path for end-to-end keys: the browser has already encrypted and
	// signed, the server only relays over SMTP. See pgp_send_client.go.
	mux.HandleFunc("POST /api/mail/send-pgp", s.withMailAuth(s.handleMailSendPGP))
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
	// End-to-end key handling: the browser wraps and unwraps the private
	// half, the server only stores an opaque envelope. See pgp_client_keys.go.
	//
	// These are withMailAuth, not withAuth: a paired mobile device
	// authenticates with per-device credentials and no session cookie, and it
	// needs to unwrap its own key exactly as much as the browser does. They
	// were session-only when first added, which locked every native client
	// out of the feature built for it.
	mux.HandleFunc("GET /api/pgp/bootstrap", s.withMailAuth(s.handlePGPBootstrap))
	mux.HandleFunc("GET /api/pgp/identity/wrapped", s.withMailAuth(s.handlePGPWrappedKey))
	// These two WRITE key material: identity/client replaces the account's
	// public key (and clears the server-sealed private half), and rewrap
	// replaces the wrapped envelope. They are session-only for the same reason
	// export-legacy below is — a device secret is not a re-verified password —
	// and the asymmetry of gating the endpoint that *reads* a key while
	// leaving the two that *destroy* one open to a device secret was a real
	// hole: a stolen device secret could substitute the key all future mail is
	// encrypted to, or wipe the private half irrecoverably.
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
	// before sending. It is a read of the caller's own contacts answering the
	// same question the send path answers by refusing, only asked earlier.
	// (recipients/resolve below stays unusable here — it 409s for anything but
	// a client-protected account.)
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
	mux.HandleFunc("GET /api/pgp/qr/key", s.handlePGPQRKey)
	mux.HandleFunc("GET /.well-known/openpgpkey/", s.withWKDRateLimit(s.handleWKD))
	mux.HandleFunc("GET /pickup/{id}", s.handlePickup)
	// Client-sealed pickup: the browser encrypts, the server stores an opaque
	// blob, and the key travels in the link fragment it never receives.
	// See pickup_client_sealed.go.
	mux.HandleFunc("POST /pickup/{id}/open", s.handlePickupOpen)
	mux.HandleFunc("GET /pickup/{id}/blob", s.handlePickupBlob)
	mux.HandleFunc("POST /api/pgp/pickup", s.withMailAuth(s.handlePickupCreate))
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
	mux.HandleFunc("POST /api/notifications/native/register", s.handleNotificationNativeRegister)
	mux.HandleFunc("GET /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("DELETE /api/notifications/native/devices", s.withAuth(s.handleNotificationNativeDevices))
	mux.HandleFunc("POST /api/notifications/native/unpair", s.withAuth(s.handleNotificationNativeUnpair))
	mux.HandleFunc("POST /api/notifications/native/deregister", s.handleNotificationNativeDeregister)
	mux.HandleFunc("PUT /api/notifications/native/mode", s.withAuth(s.handleNotificationNativeMode))
	mux.HandleFunc("GET /api/notifications/native/pull", s.handleNotificationNativePull)
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
	mux.HandleFunc("/", s.handleFrontend)
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
	// Timeouts are set explicitly because net/http's zero values mean "no
	// limit": without them a connection that dribbles one header line every
	// few seconds is held open indefinitely, and the shipped compose file
	// publishes this port directly with no reverse proxy in front to absorb
	// it. WriteTimeout is deliberately generous rather than absent — large
	// attachment downloads stream through this same server.
	s.httpServer = &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
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
			// pickupLinkTTL, not a separate longer number. The notification
			// email tells the recipient the link "expires in 7 days or as soon
			// as it's opened", and a record is unusable past its ExpiresAt
			// anyway — so a 30-day sweep only meant the message sat on disk for
			// 23 days after the last moment anyone could read it, contradicting
			// what the recipient was told.
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
// contact's photo would blank the other's. That is why DELETE .../photo only
// clears the reference, and why the bytes need a reference-based sweep to come
// back at all. Without this they never did.
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
// absolute lifetime without anyone presenting them again, mirroring
// StartPickupSweeper's ticker/select pattern. Call once after NewServer.
//
// Without it, s.sessions only ever shrinks when a token is presented again
// (currentUser), logged out, or revoked — so every session belonging to a
// user who simply closed the tab is pinned for the process lifetime. Every
// other bounded map in this package already has a sweep (loginLockout,
// nativePairingNonces, sendAsCooldown, pickupStore); the one holding live
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
		}
	}
}

// sweepSessions drops every session dead as of now. Split out so tests can
// drive it directly instead of waiting on the ticker.
func (s *Server) sweepSessions(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
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
// anyone completing (or abandoning through) them, mirroring
// StartSessionSweeper's ticker/select pattern. Call once after NewServer.
//
// Without it, mfa.Store only ever shrank when a challenge was presented again,
// consumed, or explicitly purged — so every login that reached the second-factor
// prompt and stopped there was pinned for the process lifetime. See mfa.Store's
// doc comment for why "swept lazily on access" was not the same as swept.
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

	// All-or-nothing, deliberately. The fallback used to be applied per field,
	// so a caller who supplied only a host — leaving username and password
	// blank — got the *stored* credentials filled in around their chosen
	// destination, and the server then performed an IMAP LOGIN with the
	// victim's real mail password against a server the caller controlled.
	// GET /api/imap/config never returns that password precisely because it is
	// the account's most durable secret (it is the SMTP password too, and it
	// survives every KyPost-side revocation), and this was the one path that
	// handed it out. A caller-chosen destination must never be paired with a
	// server-held secret.
	suppliedHost := strings.TrimSpace(req.Host) != ""
	suppliedUser := strings.TrimSpace(req.Username) != ""
	suppliedPass := strings.TrimSpace(req.Password) != ""
	switch {
	case !suppliedHost && !suppliedUser && !suppliedPass:
		stored, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to load imap configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "host, username, and password are required (or store IMAP config first)", http.StatusBadRequest)
			return
		}
		mailbox := strings.TrimSpace(req.Mailbox)
		req = stored
		if mailbox != "" {
			req.Mailbox = mailbox
		}
	case !(suppliedHost && suppliedUser && suppliedPass):
		http.Error(w, "supply host, username, and password together, or none of them", http.StatusBadRequest)
		return
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
	// AllowPickupFallback opts in to the one-time pickup link for recipients
	// with no usable PGP key. Absent means refuse: that fallback stores the
	// message's plaintext server-side for seven days and mails the link in
	// the clear, so it is a downgrade the sender has to choose out loud.
	AllowPickupFallback bool
	From                string
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
		Encrypt             bool `json:"encrypt"`
		Sign                bool `json:"sign"`
		AllowPickupFallback bool `json:"allowPickupFallback"`
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
		Subject:             raw.Subject,
		Body:                raw.Body,
		Mode:                raw.Mode,
		To:                  toList,
		CC:                  ccList,
		BCC:                 bccList,
		Attachments:         attachments,
		Encrypt:             raw.Encrypt,
		Sign:                raw.Sign,
		AllowPickupFallback: raw.AllowPickupFallback,
		From:                raw.From,
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
		// An end-to-end key cannot be used here: the server has no way to
		// open it, by design. Refuse loudly and point at the browser path
		// rather than falling through to sending the message unsigned and
		// unencrypted, which is the one outcome a user who ticked those
		// boxes must never silently get.
		if uerr == nil && u.PGPProtection() == users.PGPProtectionClient {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":            "this account's PGP key is end-to-end protected, so the server cannot sign or encrypt on your behalf",
				"clientSideNeeded": true,
			})
			return
		}
		if uerr == nil && u.HasServerReadableKey() {
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
		s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, recipients, msg, req, "")
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

	// Refuse before any delivery when a recipient has no usable key and the
	// caller did not opt in. The pickup fallback stores this message's
	// plaintext server-side for seven days and mails the link in the clear,
	// so it is a downgrade the sender chooses, not one they discover later.
	//
	// Ordering matters: nothing has been sent at this point, so a client may
	// re-send with allowPickupFallback set once the user confirms, with no
	// risk of a duplicate or half-delivered message.
	if len(plan.withoutKeyEmails) > 0 && !req.AllowPickupFallback {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                   "some recipients have no usable PGP key; sending them a one-time link stores this message's plaintext on the server for 7 days",
			"keylessRecipients":       plan.withoutKeyEmails,
			"pickupFallbackAvailable": true,
		})
		return
	}

	if len(plan.toCCEmails) == 0 && len(plan.bccEmails) == 0 {
		if !req.AllowPickupFallback {
			http.Error(w, "none of the recipients have a known pgp key — disable encryption or add keys to your contacts first", http.StatusBadRequest)
			return
		}
		// Opted in with nothing to encrypt to: the pickup notifications ARE the
		// entire delivery, so unlike the mixed keyed/keyless path below, their
		// outcome has to be checked before answering, not logged best-effort
		// after. If PAIRING_SECRET is unset, sendPickupNotification fails every
		// recipient immediately (pickup_handlers.go) and nothing goes out at
		// all — answering 200 in that case would silently convert a hard
		// failure into a lie, which is exactly the failure mode a hard 400 used
		// to prevent before this opt-in existed.
		failed := s.sendPickupNotifications(ac.UserID, envelopeFrom, plan.withoutKeyEmails, req.Subject, req.Body, req.Mode, smtpHost, smtpPort, addr, payload.Username, payload.Password)
		total := len(plan.withoutKeyEmails)
		if total > 0 && failed == total {
			http.Error(w, "failed to deliver a pickup link to any recipient; nothing was sent", http.StatusBadGateway)
			return
		}
		extraWarning := ""
		if failed > 0 {
			extraWarning = fmt.Sprintf("failed to deliver a pickup link to %d of %d recipient(s)", failed, total)
		}
		// Passing no recipients is safe — finishMailSend skips SMTP on an empty
		// list and still saves the plaintext Sent copy.
		if !s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, nil, nil, req, extraWarning) {
			return
		}
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
	// non-empty here because the branch above already returned early whenever
	// both plan.toCCEmails and plan.bccEmails were empty, so at least one of
	// them is non-empty by the time buildPGPDeliveries runs. Treating index 0
	// uniformly (rather than special-casing on len(plan.toCCEmails) > 0) avoids
	// a BCC-only send picking an empty "main" delivery, which previously let
	// finishMailSend report ok:true via its empty-recipient-list guard before
	// any of the actual best-effort BCC sends had even been attempted.
	mainRecipients, mainCiphertext := deliveries[0].Recipients, deliveries[0].Ciphertext
	bccDeliveries := deliveries[1:]

	if !s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, mainRecipients, mainCiphertext, req, "") {
		return
	}

	for _, delivery := range bccDeliveries {
		if err := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, delivery.Recipients, delivery.Ciphertext); err != nil {
			s.logger.Error("bcc pgp send failed", "recipient", delivery.Recipients[0], "error", err.Error())
		}
	}

	// Best-effort here (failures only logged, never surfaced) is deliberate and
	// unlike the all-keyless branch above: the keyed recipients above already
	// received the message, so this loop is topping up delivery to the
	// keyless subset, not carrying the entire send.
	s.sendPickupNotifications(ac.UserID, envelopeFrom, plan.withoutKeyEmails, req.Subject, req.Body, req.Mode, smtpHost, smtpPort, addr, payload.Username, payload.Password)
}

// sendPickupNotifications mails a pickup link to every keyless recipient,
// logging each individual failure and returning how many failed. Shared by
// the all-keyless opt-in path and the mixed keyed/keyless path so the two
// call sites can't drift apart on the notification loop's behavior — the two
// differ only in what they do with the failure count: the all-keyless path
// has nothing else to fall back on and must check it, the mixed path already
// delivered to the keyed recipients and treats this as best-effort logging.
func (s *Server) sendPickupNotifications(userID, envelopeFrom string, recipients []string, subject, body, mode, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword string) int {
	failed := 0
	for _, recipient := range recipients {
		if err := s.sendPickupNotification(userID, envelopeFrom, recipient, subject, body, mode, smtpHost, smtpPort, addr, smtpUsername, smtpPassword); err != nil {
			s.logger.Error("pickup notification send failed", "recipient", recipient, "error", err.Error())
			failed++
		}
	}
	return failed
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
//
// extraWarning is folded into the response's warning field alongside any
// save-to-Sent warning generated here — the all-keyless opt-in path uses it
// to report partial pickup-notification failures the caller would otherwise
// never see; every other caller passes "".
func (s *Server) finishMailSend(w http.ResponseWriter, r *http.Request, userID, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, toList, ccList, bccList, recipients []string, msg []byte, req mailRequest, extraWarning string) bool {
	s.logger.Info("mail send requested", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "recipientCount", strconv.Itoa(len(recipients)))

	if len(recipients) > 0 {
		if sendErr := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, smtpUsername, smtpPassword, from, recipients, msg); sendErr != nil {
			s.logger.Error("mail send failed", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "error", sendErr.Error())
			http.Error(w, fmt.Sprintf("failed to send email: %s", sendErr.Error()), http.StatusBadGateway)
			return false
		}
	}

	warning := extraWarning
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
			if warning != "" {
				warning += "; "
			}
			warning += "email sent but could not be saved to Sent folder"
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

// decryptEncryptedPayload reverses writeEncryptedPayload. It is a thin
// alias for cryptutil.OpenBytes, kept so the several call sites in this
// package read symmetrically with their write side; see OpenBytes for why
// there is no plaintext fallback.
func decryptEncryptedPayload(raw []byte, keyPath string) ([]byte, error) {
	return cryptutil.OpenBytes(raw, keyPath)
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
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&next); err != nil {
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
		if prefs.Keywords == nil {
			prefs.Keywords = []string{}
		}
		// One locked read-modify-write, not Load+Save: the label handler below
		// writes the same file, and interleaving the two lost whichever section
		// landed first — including the contentPreview privacy opt-out.
		if err := config.UpdateUserSettings(path, func(settings *config.UserSettings) error {
			settings.Notifications = prefs
			return nil
		}); err != nil {
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
		if err := config.UpdateUserSettings(path, func(settings *config.UserSettings) error {
			settings.Labels = prefs
			return nil
		}); err != nil {
			http.Error(w, "failed to save label preferences", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
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
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
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
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
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
		// The model answered but off-allowlist: that is a successful round
		// trip as far as connectivity goes, which is all this endpoint
		// tests. Show the operator what it actually said.
		var noLabel *classifier.NoAllowedLabelError
		if errors.As(err, &noLabel) {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":             true,
				"response":       noLabel.Output,
				"matchedAllowed": false,
				"baseUrl":        baseURL,
				"path":           path,
				"allowedLabels":  allowed,
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"response":       result,
		"matchedAllowed": true,
		"baseUrl":        baseURL,
		"path":           path,
	})
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scheduleContainerRestart exits this process after delay so supervisord's
// autorestart brings it back with fresh state.
//
// It does NOT signal PID 1. The previous version called
// syscall.Kill(1, SIGTERM) and discarded the error — which was always EPERM,
// because this process runs unprivileged while PID 1 does not belong to it.
// The call had never once worked; the restart came entirely from the
// os.Exit below plus supervisord's autorestart. Naming that honestly beats
// keeping a line that implies the whole container gets recycled.
func scheduleContainerRestart(logger *logging.Logger, reason string, delay time.Duration) {
	go func() {
		time.Sleep(delay)
		if logger != nil {
			logger.Error("restarting process; supervisord will bring it back", "reason", reason)
		}
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
