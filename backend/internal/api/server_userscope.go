package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/groups"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/rules"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/state"
	"kypost-server/backend/internal/users"
)

// getOrCreateUserStore returns the cached per-user store, constructing and
// caching it on first access, and stamps the user as recently seen so
// sweepIdleUserStores can reclaim them. Shared by the userStore/
// userContactsStore/userGroupsStore/userRulesStore/userMailCacheStore getters
// below, which otherwise differ only in which map and constructor they use.
func getOrCreateUserStore[T any](mu *sync.Mutex, cache map[string]T, lastSeen map[string]time.Time, userID string, construct func() (T, error)) (T, error) {
	mu.Lock()
	defer mu.Unlock()
	lastSeen[userID] = time.Now()
	if st, ok := cache[userID]; ok {
		return st, nil
	}
	st, err := construct()
	if err != nil {
		var zero T
		return zero, err
	}
	cache[userID] = st
	return st, nil
}

// userStoreIdleTTL is how long a user's cached stores survive with no requests
// before sweepIdleUserStores reclaims them. Without a bound, every user who
// ever authenticates pins their full processed-message set and decision history
// in RAM for the process lifetime.
//
// Eviction is safe because these stores hold no state a reopen cannot rebuild:
// state.Store owns a SQLite handle, the rest are file-backed JSON. A dropped
// store costs one reopen. Anything added here that holds a live resource MUST
// release it on becoming unreachable (state.New's runtime cleanup is the
// pattern) — never by closing it in sweepIdleUserStores, which cannot tell
// whether a caller is still using it.
const userStoreIdleTTL = 2 * time.Hour

// userStoreSweepInterval is how often idle per-user stores are reclaimed. A
// var so tests can drive it.
var userStoreSweepInterval = 30 * time.Minute

// StartUserStoreSweeper reclaims per-user stores idle past userStoreIdleTTL.
// Follows StartSessionSweeper's ticker/select pattern; call once after
// NewServer.
func (s *Server) StartUserStoreSweeper(ctx context.Context) {
	ticker := time.NewTicker(userStoreSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepIdleUserStores(time.Now())
		}
	}
}

// sweepIdleUserStores drops every cached store for users not seen since
// userStoreIdleTTL ago, returning how many users were reclaimed. Split out so
// tests can drive it without the ticker. All six caches are keyed by user id
// and swept together, since a request acquires them together.
func (s *Server) sweepIdleUserStores(now time.Time) int {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	removed := 0
	for userID, seen := range s.userLastSeen {
		if now.Sub(seen) < userStoreIdleTTL {
			continue
		}
		// Dropping the map entry is the whole eviction. It deliberately does NOT
		// Close the state.Store's SQLite handle.
		//
		// The caches hand out bare pointers and release userMu before the caller
		// has finished with them, and userLastSeen records when a store was
		// ACQUIRED, not when it was released — so "idle for two hours" does not
		// mean "nobody is holding it". Closing here severed the handle under any
		// caller that outlived the TTL (a stalled IMAP fetch inside the 10-minute
		// WriteTimeout, a large attachment stream, a goroutine outliving its
		// request) and turned their next query into "database is closed".
		//
		// state.New registers a runtime cleanup instead, so the fd and WAL are
		// released once the Store is genuinely unreachable. Reachability is the
		// reference count this cache never kept. Anything added here that holds a
		// live resource must arrange the same, NOT a close on eviction.
		// Pinned by TestEvictedStoreStaysUsableForItsHolder.
		delete(s.userStores, userID)
		delete(s.userContacts, userID)
		delete(s.userSendAs, userID)
		delete(s.userGroups, userID)
		delete(s.userRules, userID)
		delete(s.userMailCache, userID)
		delete(s.userLastSeen, userID)
		removed++
	}
	return removed
}

// errIMAPNotConfigured is returned when a caller has not stored IMAP
// credentials yet; handlers translate it into a 400 with a clear message.
var errIMAPNotConfigured = errors.New("imap configuration is required")

// errMailUnauthorized is returned by resolveMailAuthContext for any failed
// auth attempt (no session, no/invalid device credentials).
var errMailUnauthorized = errors.New("unauthorized")

// mailLockedOutError is returned by resolveMailAuthContext instead of
// errMailUnauthorized when device-secret auth failed specifically because
// the deviceID is currently locked out (see s.deviceLockout), rather than
// because the presented credentials were wrong. resolveMailAuthContext
// doesn't hold a http.ResponseWriter to answer 429 itself, so it hands its
// one caller (withMailAuth) this typed sentinel to distinguish the two cases
// and set Retry-After accordingly.
type mailLockedOutError struct {
	retryAfter time.Duration
}

func (e *mailLockedOutError) Error() string { return "device locked out" }

func (s *Server) userConfigDir(userID string) string {
	return filepath.Join(s.configDir, "users", userID)
}

func (s *Server) userStateDir(userID string) string {
	return filepath.Join(s.stateDir, "users", userID)
}

func (s *Server) userIMAPConfigPath(userID string) string {
	return filepath.Join(s.userConfigDir(userID), "imap-config.json")
}

func (s *Server) userTuningPath(userID string) string {
	return filepath.Join(s.userConfigDir(userID), "tuning.md")
}

func (s *Server) userSettingsPath(userID string) string {
	return filepath.Join(s.userConfigDir(userID), "config.yaml")
}

// userCardDAVAuthPath is where the user's app-specific CardDAV password hash
// is stored — separate from imap-config.json since it's a plain scrypt hash
// (not reversible credentials), so it needs no encryption-at-rest key.
func (s *Server) userCardDAVAuthPath(userID string) string {
	return filepath.Join(s.userConfigDir(userID), "carddav-auth.json")
}

// userCardDAVClientConfigPath is where the user's outbound CardDAV client
// credentials (for pulling contacts from an external CardDAV server) are
// stored, encrypted at rest the same way as imap-config.json.
func (s *Server) userCardDAVClientConfigPath(userID string) string {
	return filepath.Join(s.userConfigDir(userID), "carddav-client.json")
}

func (s *Server) userStore(userID string) (*state.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userStores, s.userLastSeen, userID, func() (*state.Store, error) {
		return state.New(s.userStateDir(userID))
	})
}

// storeFor resolves the calling user's state store from the request's
// AuthContext (requires the handler to be wrapped in withAuth).
func (s *Server) storeFor(r *http.Request) (*state.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userStore(ac.UserID)
}

func (s *Server) userContactsStore(userID string) (*contacts.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userContacts, s.userLastSeen, userID, func() (*contacts.Store, error) {
		return contacts.New(s.userStateDir(userID))
	})
}

// contactsFor resolves the calling user's contacts store from the request's
// AuthContext (requires the handler to be wrapped in withAuth or withMailAuth,
// or otherwise inject an AuthContext).
func (s *Server) contactsFor(r *http.Request) (*contacts.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userContactsStore(ac.UserID)
}

func (s *Server) userSendAsStore(userID string) (*sendas.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userSendAs, s.userLastSeen, userID, func() (*sendas.Store, error) {
		return sendas.New(s.userStateDir(userID))
	})
}

// sendAsFor resolves the calling user's send-as alias store from the
// request's AuthContext (requires the handler to be wrapped in withAuth).
func (s *Server) sendAsFor(r *http.Request) (*sendas.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userSendAsStore(ac.UserID)
}

func (s *Server) userGroupsStore(userID string) (*groups.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userGroups, s.userLastSeen, userID, func() (*groups.Store, error) {
		return groups.New(s.userStateDir(userID))
	})
}

// groupsFor resolves the calling user's groups store from the request's
// AuthContext (requires the handler to be wrapped in withAuth).
func (s *Server) groupsFor(r *http.Request) (*groups.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userGroupsStore(ac.UserID)
}

func (s *Server) userRulesStore(userID string) (*rules.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userRules, s.userLastSeen, userID, func() (*rules.Store, error) {
		return rules.New(s.userStateDir(userID))
	})
}

// rulesFor resolves the calling user's rules store from the request's
// AuthContext (requires the handler to be wrapped in withAuth or
// withMailAuth).
func (s *Server) rulesFor(r *http.Request) (*rules.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userRulesStore(ac.UserID)
}

// sanitizeGroupIDsForUser drops any group ID that isn't a real group owned
// by userID, so a stale or forged ID from a client can't create a dangling
// Contact.GroupIDs reference.
func (s *Server) sanitizeGroupIDsForUser(userID string, ids []string) []string {
	if len(ids) == 0 {
		return ids
	}
	gs, err := s.userGroupsStore(userID)
	if err != nil {
		return nil
	}
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := gs.Get(id); ok {
			kept = append(kept, id)
		}
	}
	return kept
}

// userContactPhotosDir is where a user's contact photo files live, one
// content-hashed file per uploaded photo.
func (s *Server) userContactPhotosDir(userID string) string {
	return filepath.Join(s.userStateDir(userID), "contact-photos")
}

// userContactPhotoPath resolves a photoRef to its on-disk path.
// filepath.Base guards against path traversal from a hostile ref.
func (s *Server) userContactPhotoPath(userID, ref string) string {
	return filepath.Join(s.userContactPhotosDir(userID), filepath.Base(ref))
}

func (s *Server) userMailCacheStore(userID string) (*mailcache.Store, error) {
	return getOrCreateUserStore(&s.userMu, s.userMailCache, s.userLastSeen, userID, func() (*mailcache.Store, error) {
		return mailcache.New(s.userStateDir(userID))
	})
}

// mailCacheFor resolves the calling user's mail cache store from the
// request's AuthContext (requires the handler to be wrapped in
// withMailAuth, as handleInbox already is).
func (s *Server) mailCacheFor(r *http.Request) (*mailcache.Store, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userMailCacheStore(ac.UserID)
}

type serverMailEntry struct {
	client    imapadapter.Client
	updatedAt string
}

// userMailClient returns a cached IMAP client for the user, rebuilt whenever
// their stored credential payload changes (keyed by the payload UpdatedAt).
// Returns errIMAPNotConfigured when the user has no stored credentials.
func (s *Server) userMailClient(userID string) (imapadapter.Client, error) {
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(userID), s.imapConfigKeyPath)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errIMAPNotConfigured
	}
	s.userMu.Lock()
	defer s.userMu.Unlock()
	if entry, ok := s.userMail[userID]; ok {
		if entry.updatedAt == payload.UpdatedAt {
			return entry.client, nil
		}
		closeMailClient(entry.client)
	}
	client := imapadapter.NewAPIClientFromStoredConfig(s.userIMAPConfigPath(userID), s.imapConfigKeyPath)
	s.userMail[userID] = &serverMailEntry{client: client, updatedAt: payload.UpdatedAt}
	return client, nil
}

// closeMailClient hangs up a mail client that is being dropped from a cache.
//
// An imapadapter.APIClient holds a live authenticated IMAP session for its
// whole life; nothing reclaims that when the value becomes unreachable, so an
// evicted client leaks one connection per eviction, in each of the two
// processes that keep such a cache. IMAP providers cap concurrent sessions per
// account, so the leak ends as "too many simultaneous connections" and mail
// simply stops syncing.
//
// io.Closer rather than a Close method on imapadapter.Client: the interface has
// six test fakes with nothing to close, and widening it for their sake buys
// nothing. A client that isn't a Closer is a no-op here.
func closeMailClient(client imapadapter.Client) {
	if c, ok := client.(io.Closer); ok {
		_ = c.Close()
	}
}

func (s *Server) mailFor(r *http.Request) (imapadapter.Client, error) {
	ac, ok := authFromContext(r)
	if !ok {
		return nil, errors.New("no auth context on request")
	}
	return s.userMailClient(ac.UserID)
}

// resolveMailAuthContext authenticates a mail request either by session
// cookie (web) or by per-device pairing credentials (mobile/native, reusing
// the same device trust boundary as native push and contacts sync — see
// contacts_handlers.go's handleContactsSync). Device credentials are read
// from the X-Kypost-Device-Id/X-Kypost-Device-Secret headers (see
// device_auth.go). Mobile never sees or sets raw IMAP/SMTP credentials; it
// only acts on an account already configured through the web UI.
func (s *Server) resolveMailAuthContext(r *http.Request) (AuthContext, error) {
	if ac, ok := s.currentUser(r); ok {
		return ac, nil
	}
	userID, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		if retryAfter > 0 {
			return AuthContext{}, &mailLockedOutError{retryAfter: retryAfter}
		}
		return AuthContext{}, errMailUnauthorized
	}
	return AuthContext{UserID: userID}, nil
}

func (s *Server) invalidateUserMail(userID string) {
	s.userMu.Lock()
	if entry, ok := s.userMail[userID]; ok {
		closeMailClient(entry.client)
	}
	delete(s.userMail, userID)
	s.userMu.Unlock()
}

// lookupUserBySubscriber maps a per-user subscriber ID back to its owning
// user, for the unauthenticated native-register endpoint. The in-memory
// index is lazily rebuilt on a miss so a subscriber ID minted after server
// start is still found without a restart.
func (s *Server) lookupUserBySubscriber(subscriberID string) (string, bool) {
	subscriberID = strings.TrimSpace(subscriberID)
	if subscriberID == "" {
		return "", false
	}
	s.userMu.Lock()
	if userID, ok := s.subIndex[subscriberID]; ok {
		s.userMu.Unlock()
		return userID, true
	}
	s.userMu.Unlock()

	s.rescanSubscriberIndex()

	s.userMu.Lock()
	defer s.userMu.Unlock()
	userID, ok := s.subIndex[subscriberID]
	return userID, ok
}

// knownUserIDs lists every account with a per-user state directory. The
// directory layout is the index; there is no separate registry.
func (s *Server) knownUserIDs() []string {
	entries, err := os.ReadDir(filepath.Join(s.stateDir, "users"))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// rescanSubscriberIndex rebuilds subscriberID -> userID across every per-user
// store. Cheap at this scale (a handful of accounts).
//
// It goes through state.Store rather than reading the underlying file. Parsing
// storage directly from here is how this broke once already: it hard-coded
// state.json, so the move to SQLite left it silently finding nothing and every
// device registration answering "unknown subscriber". The store is the only
// thing that knows how state is stored.
func (s *Server) rescanSubscriberIndex() {
	next := map[string]string{}
	// userStore takes s.userMu, so resolve every store BEFORE taking it below.
	for _, userID := range s.knownUserIDs() {
		store, err := s.userStore(userID)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(store.SubscriberID()); id != "" {
			next[id] = userID
		}
	}
	s.userMu.Lock()
	// Merge rather than replace, for the same reason as rescanDeviceIndex:
	// never let a rescan discard an in-memory entry a concurrent request is
	// still relying on. Both indexes are owner-resolution hints; neither
	// grants access on its own.
	for id, owner := range next {
		s.subIndex[id] = owner
	}
	s.userMu.Unlock()
}

// lookupUserByDevice maps a per-device ID back to its owning user, for the
// ongoing device-auth path (mail/contacts/pull/push-approve/deregister).
// Lazily rebuilt on a miss, mirroring lookupUserBySubscriber.
func (s *Server) lookupUserByDevice(deviceID string) (string, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return "", false
	}
	s.userMu.Lock()
	if userID, ok := s.deviceIndex[deviceID]; ok {
		s.userMu.Unlock()
		return userID, true
	}
	s.userMu.Unlock()

	// Throttled. The index is a resolution hint with no startup warm, so a miss
	// must still be able to rebuild it — but deviceID is caller-supplied with
	// unbounded cardinality, and the device lockout is keyed on it, so rotating
	// the id meant every unauthenticated request forced a full rescan that
	// opens SQLite for every account on the instance.
	if s.deviceRescan.allow() {
		s.rescanDeviceIndex()
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()
	userID, ok := s.deviceIndex[deviceID]
	return userID, ok
}

// reserveDeviceID atomically reserves deviceID for ownerID in the shared
// deviceIndex, refusing if it's already reserved by a different owner. The
// check and the reservation happen in the same critical section, so two
// concurrent registrations for the same client-chosen deviceId from two
// different owners can't both succeed — the second call returns false
// instead of both callers proceeding and leaving deviceIndex pointing at
// only one of them (silently orphaning the other's device). An empty
// deviceID is a no-op (true, nothing to reserve) since the server mints a
// fresh random UUID for those.
func (s *Server) reserveDeviceID(ownerID, deviceID string) bool {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return true
	}
	// Warm the index from disk on a miss, so a device registered before this
	// process started, or by a prior request, is still honored by the check
	// below. This runs outside the critical section because it does disk I/O
	// and takes userMu itself — which is precisely why rescanDeviceIndex
	// must merge rather than replace: a rescan triggered here by one
	// in-flight registration must not wipe the reservation another one has
	// already made but not yet persisted.
	s.lookupUserByDevice(deviceID)

	s.userMu.Lock()
	defer s.userMu.Unlock()
	if existing, ok := s.deviceIndex[deviceID]; ok && existing != ownerID {
		return false
	}
	s.deviceIndex[deviceID] = ownerID
	return true
}

// revokeAllUserCredentials cuts off every way this account can currently
// authenticate. There are three, not two:
//
//  1. web sessions      (revokeUserSessions)
//  2. paired devices    (revokeUserDevices)
//  3. CardDAV Basic Auth (davCredentials)
//
// The third one used to be missed by every admin revocation path, because
// withDAVBasicAuth consults its verified-credential cache *before* it looks the
// account up and checks u.Active. A deactivated account therefore kept full
// read/write on its contacts, over CardDAV, for up to davCredentialTTL after an
// admin cut it off — bounded at 90s, but silently, and the handlers claimed to
// have revoked everything.
//
// Exists as one function rather than three lines repeated in
// deactivate/reset-password/clear-MFA so that a fourth credential type only has
// to be added here. The DAV cache has no per-user index (its keys are salted
// hashes of username+password), so invalidation clears the whole map; that is
// cheap at this project's scale and costs other users at most one extra scrypt
// verification on their next sync.
func (s *Server) revokeAllUserCredentials(u users.User) {
	s.revokeAllUserCredentialsExcept(u, "")
}

// revokeAllUserCredentialsExcept is revokeAllUserCredentials with one session
// spared. The self-service password change needs this: it must cut off devices
// and CardDAV exactly like the admin paths do, but logging the user out of the
// tab they just changed their password in would be a surprising way to answer
// "I secured my account".
func (s *Server) revokeAllUserCredentialsExcept(u users.User, keepSessionToken string) {
	s.revokeUserSessions(u.ID, keepSessionToken)
	s.revokeUserDevices(u.ID)
	// Delete the credential, not just the cache entry. invalidateUser clears an
	// in-memory verification cache; the scrypt hash lives in carddav-auth.json,
	// so on the next request readDAVPassword loaded it again and minted a fresh
	// AuthContext. A stolen app password therefore survived admin
	// reset-password, admin clear-MFA and the self-service password change —
	// every path whose whole contract is to cut off access. Deactivate was the
	// only one that held, and only because Active is re-checked live.
	if err := os.Remove(s.userCardDAVAuthPath(u.ID)); err != nil && !os.IsNotExist(err) {
		s.logger.Error("failed to revoke carddav credential", "user_id", u.ID, "error", err.Error())
	}
	s.davCredentials.invalidateUser(u.Username)
}

// revokeUserDevices removes every paired native device for userID from both
// the per-user store and the global deviceIndex, so an admin-driven
// deactivate / password-reset / MFA-clear cuts off device access with the same
// action that cuts off web sessions (see revokeUserSessions). Best-effort:
// errors are logged, not fatal, so revocation of the primary credential still
// succeeds.
func (s *Server) revokeUserDevices(userID string) {
	store, err := s.userStore(userID)
	if err != nil {
		s.logger.Error("failed to open store to revoke devices", "user_id", userID, "error", err.Error())
		return
	}
	for _, dev := range store.ListNativeDevices() {
		if _, err := store.RemoveNativeDevice(dev.DeviceID); err != nil {
			s.logger.Error("failed to remove native device during revocation", "user_id", userID, "error", err.Error())
			continue
		}
		s.userMu.Lock()
		delete(s.deviceIndex, dev.DeviceID)
		s.userMu.Unlock()
	}
}

// rescanDeviceIndex rebuilds deviceID -> userID across every per-user store.
// Mirrors rescanSubscriberIndex, including going through state.Store rather
// than parsing storage directly.
func (s *Server) rescanDeviceIndex() {
	next := map[string]string{}
	for _, userID := range s.knownUserIDs() {
		store, err := s.userStore(userID)
		if err != nil {
			continue
		}
		for _, d := range store.ListNativeDevices() {
			if id := strings.TrimSpace(d.DeviceID); id != "" {
				next[id] = userID
			}
		}
	}
	s.userMu.Lock()
	// Merge into the live index rather than replacing it. A reservation made
	// by reserveDeviceID for an in-flight registration has not reached disk
	// yet, so replacing the map would silently drop it — and two concurrent
	// registrations racing the same client-chosen deviceId would then BOTH
	// see a free slot and both succeed, which is exactly the device-ID
	// hijack reserveDeviceID exists to prevent.
	//
	// Merging can leave an entry for a device that was since unpaired by the
	// other process. That is safe: the index only resolves deviceId -> owner
	// so the owner's store can be opened; authorization is decided by
	// state.Store.GetNativeDevice + the secret-hash check in
	// deviceAuthFromRequest, both of which read through to disk and fail
	// closed on a device that is no longer there.
	for id, owner := range next {
		s.deviceIndex[id] = owner
	}
	s.userMu.Unlock()
}
