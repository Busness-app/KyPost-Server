package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/config"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/fsutil"
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
	return acquireUserStore(mu, cache, lastSeen, userID, construct, true)
}

// acquireUserStore is getOrCreateUserStore with control over whether the access
// counts as the user being seen.
//
// touch=false exists for the server's own maintenance passes. rescanDeviceIndex
// opens EVERY user's store on every rebuild, and a rebuild is triggered — under
// a 30-second throttle — by any caller presenting an unknown device id, i.e. by
// an unauthenticated request. Stamping there meant that on any instance with
// device traffic every user looked freshly active twice a minute, so
// sweepIdleUserStores could never evict anything and the idle TTL it enforces
// was unreachable. The bookkeeping recorded the server's own polling as user
// activity.
//
// The store is still constructed and cached when absent; only the "recently
// seen" claim is withheld, because it would not be true.
func acquireUserStore[T any](mu *sync.Mutex, cache map[string]T, lastSeen map[string]time.Time, userID string, construct func() (T, error), touch bool) (T, error) {
	mu.Lock()
	defer mu.Unlock()
	if touch {
		lastSeen[userID] = time.Now()
	}
	if st, ok := cache[userID]; ok {
		return st, nil
	}
	st, err := construct()
	if err != nil {
		var zero T
		return zero, err
	}
	cache[userID] = st
	// A store this pass constructed still needs an entry, or it is invisible to
	// the sweep and leaks for the process lifetime. Stamp it only if it is new,
	// so a genuinely idle user's existing timestamp is not refreshed.
	if _, known := lastSeen[userID]; !known {
		lastSeen[userID] = time.Now()
	}
	return st, nil
}

// userStoreForMaintenance is userStore for the server's own background passes:
// it opens the store without claiming the user was active. See
// acquireUserStore.
func (s *Server) userStoreForMaintenance(userID string) (*state.Store, error) {
	return acquireUserStore(&s.userMu, s.userStores, s.userLastSeen, userID, func() (*state.Store, error) {
		return state.New(s.userStateDir(userID))
	}, false)
}

// userStoreIdleTTL is how long a user's cached stores survive with no requests
// before sweepIdleUserStores reclaims them. Without a bound, every user who ever
// authenticates pins their full processed-message set and decision history in
// RAM for the process lifetime.
//
// Eviction is safe because these stores hold no state a reopen cannot rebuild: a
// dropped store costs one reopen. Anything added here that holds a live resource
// MUST release it on becoming unreachable (state.New's runtime cleanup is the
// pattern) — never by closing it in sweepIdleUserStores, which cannot tell
// whether a caller is still using it.
const userStoreIdleTTL = 2 * time.Hour

// userStoreSweepInterval is how often idle per-user stores are reclaimed. A
// var so tests can drive it.
var userStoreSweepInterval = 30 * time.Minute

// StartUserStoreSweeper reclaims per-user stores idle past userStoreIdleTTL and
// prunes deviceIndex residue. Call once after NewServer.
//
// The device-index prune rides this ticker because it needs the same walk over
// every account's store. Order matters: prune first, while the stores are about
// to be opened anyway, then evict.
func (s *Server) StartUserStoreSweeper(ctx context.Context) {
	ticker := time.NewTicker(userStoreSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweepDeviceIndex()
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
		// Dropping the map entry is the whole eviction. It deliberately does NOT Close
		// the state.Store's SQLite handle.
		//
		// The caches hand out bare pointers and release userMu before the caller has
		// finished, and userLastSeen records when a store was ACQUIRED, not released —
		// so "idle for two hours" does not mean "nobody is holding it". Closing here
		// severs the handle under any caller that outlived the TTL (a stalled IMAP fetch
		// inside the 10-minute WriteTimeout, a large attachment stream) and turns their
		// next query into "database is closed".
		//
		// state.New registers a runtime cleanup instead, so the fd and WAL are released
		// once the Store is genuinely unreachable. Anything added here that holds a live
		// resource must arrange the same. Pinned by
		// TestEvictedStoreStaysUsableForItsHolder.
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
// errMailUnauthorized when device-secret auth failed for a reason that is
// "come back later" rather than "the credentials were wrong": the deviceID is
// locked out (see s.deviceLockout), or the secret was never compared because
// the derivation slots were saturated. resolveMailAuthContext holds no
// ResponseWriter, so it hands its one caller (withMailAuth) this typed sentinel
// to write the response.
//
// kdfBusy separates the two, because they are not the same answer: a lockout is
// 429 "too many failed attempts", which is a statement about this caller, while
// a shed derivation is 503 writeKDFBusy — the server is out of capacity and the
// caller did nothing wrong. Telling a phone syncing mail that it has failed too
// many attempts, when its secret was never even compared, is the same lie in a
// softer status code.
type mailLockedOutError struct {
	retryAfter time.Duration
	kdfBusy    bool
}

func (e *mailLockedOutError) Error() string {
	if e.kdfBusy {
		return "credential verification is busy"
	}
	return "device locked out"
}

func (s *Server) userConfigDir(userID string) string {
	return filepath.Join(s.configDir, "users", safeUserPathComponent(userID))
}

func (s *Server) userStateDir(userID string) string {
	return filepath.Join(s.stateDir, "users", safeUserPathComponent(userID))
}

// safeUserPathComponent keeps malformed or legacy user records inside the
// users directory. Valid IDs are opaque UUIDs, but path construction must not
// rely on that invariant surviving hand-edited or migrated users.json files.
func safeUserPathComponent(userID string) string {
	if fsutil.SafePathComponent(userID) {
		return userID
	}
	return "__invalid-user-id__"
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

// userLabels reads one account's label set, seeding it from the house list the
// first time the account is seen.
//
// An error is answered with the house list rather than an empty one: an empty
// allowlist means "this account labels nothing", which is a much louder wrong
// answer than "this account still has the defaults" for a read that only feeds
// the inbox tab scaffold.
func (s *Server) userLabels(userID string) config.UserLabelSettings {
	s.cfgMu.RLock()
	house := s.cfg
	s.cfgMu.RUnlock()

	settings, err := config.LoadUserLabelSettings(s.userSettingsPath(userID), house)
	if err != nil {
		s.logger.Error("failed to read label settings; falling back to the house list",
			"user_id", userID, "error", err.Error())
		return settings.Labels
	}
	return settings.Labels
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
//
// A groups read failure is returned, not answered with an empty set: every
// caller writes the result straight onto a contact, so "I could not read
// groups.json" silently became "this contact belongs to no groups" and the
// user's group memberships were erased by a transient storage fault.
func (s *Server) sanitizeGroupIDsForUser(userID string, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return ids, nil
	}
	gs, err := s.userGroupsStore(userID)
	if err != nil {
		return nil, err
	}
	all, err := gs.List()
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(all))
	for _, g := range all {
		known[g.ID] = true
	}
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if known[id] {
			kept = append(kept, id)
		}
	}
	return kept, nil
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
// An imapadapter.APIClient holds a live authenticated IMAP session for its whole
// life and nothing reclaims that when the value becomes unreachable, so an
// evicted client leaks one connection per eviction in each of the two processes
// that keep such a cache. IMAP providers cap concurrent sessions per account, so
// the leak ends as "too many simultaneous connections" and mail stops syncing.
//
// io.Closer rather than a Close method on imapadapter.Client: the interface has
// six test fakes with nothing to close. A client that isn't a Closer is a no-op.
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

// resolveMailAuthContext authenticates a mail request either by session cookie
// (web) or by per-device pairing credentials (mobile/native, the same device
// trust boundary as native push and contacts sync). Device credentials come from
// the X-Kypost-Device-Id/X-Kypost-Device-Secret headers (see device_auth.go).
// Mobile never sees or sets raw IMAP/SMTP credentials; it only acts on an
// account already configured through the web UI.
func (s *Server) resolveMailAuthContext(r *http.Request) (AuthContext, error) {
	if ac, ok := s.currentUser(r); ok {
		return ac, nil
	}
	userID, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		if retryAfter == retryAfterKDFBusy {
			// A shed secret check is "come back later" too — nothing was
			// examined and no strike was spent — so it must not fall through to
			// the 401 that tells a client its credential is dead. Same answer
			// the direct call sites give through writeDeviceAuthFailure.
			return AuthContext{}, &mailLockedOutError{retryAfter: kdfMaxQueueWait(), kdfBusy: true}
		}
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
// It goes through state.Store rather than reading the underlying file: parsing
// storage directly hard-coded state.json, so the move to SQLite left it silently
// finding nothing and every device registration answering "unknown subscriber".
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

	// Throttled. The index is a resolution hint with no startup warm, so a miss must
	// still be able to rebuild it — but deviceID is caller-supplied with unbounded
	// cardinality, so rotating the id meant every unauthenticated request forced a
	// full rescan that opens SQLite for every account on the instance.
	//
	// The rescan MERGES; sweepDeviceIndex is what removes. A rescan can be triggered
	// by an unauthenticated caller and must never delete anything, least of all a
	// reservation another registration is holding but has not yet persisted.
	if s.deviceRescan.allow() {
		s.rescanDeviceIndex()
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()
	userID, ok := s.deviceIndex[deviceID]
	return userID, ok
}

// reserveDeviceID atomically reserves deviceID for ownerID in the shared
// deviceIndex, refusing if it is already reserved by a different owner. Check
// and reservation share one critical section, so two concurrent registrations
// for the same client-chosen deviceId from different owners cannot both succeed
// and silently orphan one of them.
//
// The returned release MUST be deferred by the caller. A reservation is a
// promise to write a NativeDevice row under this ID, and a registration that
// returns without keeping it — a failed secret mint, a failed
// UpsertNativeDevice, a merge into an existing row — leaves a permanent index
// entry with nothing behind it. That entry makes the ID unregisterable by
// anyone, and every auth attempt against it burns a deviceLockout strike,
// because deviceAuthFromRequest resolves the owner and only THEN finds no
// device. One transient SQLite error during re-pairing bricks that phone against
// this server until the process restarts.
//
// Release and Commit are idempotent and mutually exclusive — whichever runs
// first wins — so the defer is safe on every return path, including the success
// path that has already committed.
//
// An empty deviceID is a no-op (ok=true); the server mints a fresh random UUID.
func (s *Server) reserveDeviceID(ownerID, deviceID string) (*deviceReservation, bool) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return &deviceReservation{srv: s, ownerID: ownerID}, true
	}
	// Warm the index from disk on a miss, so a device registered before this process
	// started is still honored by the check below. Outside the critical section
	// because it does disk I/O and takes userMu itself — which is why
	// rescanDeviceIndex must merge rather than replace: a rescan triggered here must
	// not wipe a reservation another in-flight registration has not yet persisted.
	s.lookupUserByDevice(deviceID)

	s.userMu.Lock()
	defer s.userMu.Unlock()
	if existing, exists := s.deviceIndex[deviceID]; exists && existing != ownerID {
		return nil, false
	}
	s.deviceIndex[deviceID] = ownerID
	// Mark it in-flight so sweepDeviceIndex, which decides what is residue by
	// looking at DISK, does not mistake a reservation that has not reached disk
	// yet for an orphan and delete it.
	s.deviceReserving[deviceID]++
	return &deviceReservation{srv: s, ownerID: ownerID, deviceID: deviceID}, true
}

// deviceReservation is one outstanding claim on a device ID, held from
// reserveDeviceID until Commit or Release settles it.
//
// Release and Commit share the `done` flag rather than being independent,
// because the handler arms Release with defer and then calls Commit on success:
// as separate operations the deferred Release fires afterwards and deletes the
// entry the commit just wrote. One object, one settled flag, first call wins.
type deviceReservation struct {
	srv      *Server
	ownerID  string
	deviceID string
	done     bool
}

// Release drops the reservation, for a registration that never wrote a device
// row. Safe to defer unconditionally; a no-op once Commit has run.
func (res *deviceReservation) Release() {
	if res == nil || res.deviceID == "" {
		return
	}
	res.srv.userMu.Lock()
	defer res.srv.userMu.Unlock()
	if res.done {
		return
	}
	res.done = true
	res.srv.endReservationLocked(res.deviceID)
	// Only drop an entry this owner still holds: a rescan between the
	// reservation and the failure may legitimately have re-pointed the ID at
	// whoever actually has the device on disk, and clobbering that would be the
	// hijack reserveDeviceID exists to prevent.
	if owner, exists := res.srv.deviceIndex[res.deviceID]; exists && owner == res.ownerID {
		delete(res.srv.deviceIndex, res.deviceID)
	}
}

// Commit points the index at the ID the device was actually persisted under and
// settles the reservation on the ID the request asked for. The two differ when
// UpsertNativeDevice merged this registration into an existing row (same push
// token and platform), whose ID wins; the requested ID then never got a
// NativeDevice record, so leaving its entry behind is the orphan described on
// reserveDeviceID.
func (res *deviceReservation) Commit(registeredID string) {
	if res == nil {
		return
	}
	registeredID = strings.TrimSpace(registeredID)

	res.srv.userMu.Lock()
	defer res.srv.userMu.Unlock()
	if !res.done && res.deviceID != "" {
		res.done = true
		res.srv.endReservationLocked(res.deviceID)
		if res.deviceID != registeredID {
			if owner, exists := res.srv.deviceIndex[res.deviceID]; exists && owner == res.ownerID {
				delete(res.srv.deviceIndex, res.deviceID)
			}
		}
	}
	if registeredID != "" {
		res.srv.deviceIndex[registeredID] = res.ownerID
	}
}

// endReservationLocked decrements the in-flight count for deviceID. Callers must
// hold userMu. Counted rather than a plain set because two registrations for the
// same ID from the same owner can legitimately overlap.
func (s *Server) endReservationLocked(deviceID string) {
	if n := s.deviceReserving[deviceID]; n > 1 {
		s.deviceReserving[deviceID] = n - 1
	} else {
		delete(s.deviceReserving, deviceID)
	}
}

// sweepDeviceIndex drops index entries with no device behind them, and reports
// how many went.
//
// The index is a resolution hint rebuilt from disk, so an entry matching no
// NativeDevice row is residue — from a registration that failed after reserving,
// from a device the DAEMON removed as stale in the other process, or from an
// unpair. Residue is not inert: it makes the ID unregisterable and turns every
// attempt against it into a deviceLockout strike.
//
// In-flight reservations are exempt: they legitimately have no disk row yet, and
// deleting one re-opens the concurrent-registration hijack reserveDeviceID
// closes.
//
// Driven by StartUserStoreSweeper, which already walks the user list on a timer.
// sweepDeviceIndex uses the NON-warming accessor: it runs on the line before
// sweepIdleUserStores, and touching lastSeen for every user microseconds
// earlier meant the idle sweep could never evict anything. Its sibling
// rescanDeviceIndex was switched for this reason and this one was missed.
func (s *Server) sweepDeviceIndex() int {
	live := map[string]bool{}
	unreadable := map[string]bool{}
	for _, userID := range s.knownUserIDs() {
		store, err := s.userStoreForMaintenance(userID)
		if err != nil {
			// Cannot prove this user's devices are gone. Keep their entries:
			// dropping them on a transient open error would unpair working
			// devices and cost each one a lockout strike on its next request.
			unreadable[userID] = true
			continue
		}
		devices, err := store.ListNativeDevicesStrict()
		if err != nil {
			unreadable[userID] = true
			continue
		}
		for _, d := range devices {
			if id := strings.TrimSpace(d.DeviceID); id != "" {
				live[id] = true
			}
		}
	}

	s.userMu.Lock()
	defer s.userMu.Unlock()
	removed := 0
	for id, owner := range s.deviceIndex {
		if live[id] || unreadable[owner] || s.deviceReserving[id] > 0 {
			continue
		}
		delete(s.deviceIndex, id)
		removed++
	}
	return removed
}

// revokeAllUserCredentials cuts off every way this account can currently
// authenticate. There are four, not two:
//
//  1. web sessions          (revokeUserSessions)
//  2. paired devices        (revokeUserDevices)
//  3. CardDAV Basic Auth    (davCredentials)
//  4. a linked SSO identity (users.RevokeSSOLink)
//
// The third was missed by every admin revocation path, because withDAVBasicAuth
// consults its verified-credential cache BEFORE it looks the account up and
// checks u.Active. A deactivated account therefore kept full read/write on its
// contacts over CardDAV for up to davCredentialTTL — bounded at 90s, but
// silently.
//
// The fourth was missed for the same shape of reason: handleSSOCallback
// resolves a sign-in purely through GetBySSOSub plus an Active check, so a
// stored subject is a credential and nothing here touched it. An attacker who
// bound their own directory identity to a hijacked session's account kept a
// working front door through the victim's password change, through an admin
// reset, and through clear-MFA. A reactivated account has to re-link, exactly
// as it has to re-pair its devices and re-create its CardDAV password.
//
// The fourth is also the only one revoked by FLAG rather than by erasure, and
// the only one that is sometimes skipped. Both follow from the subject being
// two things at once — see users.User.SSOLinkRevokedAt and HasLocalCredential.
//
// One function rather than three lines repeated in
// deactivate/reset-password/clear-MFA, so a fourth credential type is added only
// here. The DAV cache has no per-user index (its keys are salted hashes of
// username+password), so invalidation clears the whole map; that costs other
// users at most one extra scrypt verification on their next sync.
func (s *Server) revokeAllUserCredentials(u users.User) error {
	return s.revokeAllUserCredentialsExcept(u, "")
}

// revokeAllUserCredentialsExcept is revokeAllUserCredentials with one session
// spared. The self-service password change needs this: it must cut off devices
// and CardDAV exactly like the admin paths do, but logging the user out of the
// tab they just changed their password in would be a surprising way to answer
// "I secured my account".
func (s *Server) revokeAllUserCredentialsExcept(u users.User, keepSessionToken string) error {
	s.revokeUserSessions(u.ID, keepSessionToken)
	// Native registration holds this lock from its final subscriber-generation
	// check through device commit. Keep deletion and subscriber rotation in the
	// same critical section so the two credential paths cannot interleave.
	s.pairingMu.Lock()
	defer s.pairingMu.Unlock()
	var errs []error
	if err := s.revokeUserDevices(u.ID); err != nil {
		errs = append(errs, err)
	}
	// Delete the credential, not just the cache entry. invalidateUser clears an
	// in-memory verification cache, but the scrypt hash lives in carddav-auth.json,
	// so readDAVPassword loaded it again on the next request and minted a fresh
	// AuthContext. A stolen app password therefore survived admin reset-password,
	// admin clear-MFA and the self-service password change.
	if err := os.Remove(s.userCardDAVAuthPath(u.ID)); err != nil && !os.IsNotExist(err) {
		s.logger.Error("failed to revoke carddav credential", "user_id", u.ID, "error", err.Error())
		errs = append(errs, fmt.Errorf("remove CardDAV credential: %w", err))
	}
	// Cut off the linked SSO identity — by flag, and only for an account that
	// has a credential of its own to fall back on.
	//
	// RevokeSSOLink re-reads users.json inside the store's file lock, so it
	// cannot clobber a write that landed after the caller's copy of u was taken
	// — the password change is exactly that case. That copy is still the right
	// thing to read HasLocalCredential from: SetPassword runs before this, so a
	// stale read can only say "no credential" for an account that has just been
	// given one, and skipping is the safe direction of that error.
	//
	// An unlinked or already-revoked account is a no-op; ErrNotFound means the
	// record is gone, which is nothing left to revoke.
	if u.HasLocalCredential() {
		if err := s.users.RevokeSSOLink(u.ID); err != nil && !errors.Is(err, users.ErrNotFound) {
			s.logger.Error("failed to revoke sso link", "user_id", u.ID, "error", err.Error())
			errs = append(errs, fmt.Errorf("revoke SSO link: %w", err))
		}
	} else if u.SSOSub != "" {
		s.logger.Info("kept sso link: account has no other credential",
			"user_id", u.ID)
	}
	// Rotate the subscriber ID last, once the devices are gone.
	//
	// Everything above revokes something that EXISTS: a session, a device row, a
	// stored credential. An outstanding native pairing token is none of those —
	// it is a stateless HMAC over {sub, exp, nonce, purpose}, signed with the
	// server-wide pairing secret and bound to nothing this function touches. So
	// a token minted before an admin password reset still redeemed after one and
	// minted a fresh device credential, with MFAApprover set, on an account the
	// admin believed was secured. The single-use nonce guard does not help: the
	// token is redeemed exactly once, just later than intended.
	//
	// Rotating the subscriber ID kills every outstanding token at once, because
	// their Sub stops resolving to any account. The stale index entry has to go
	// with it — subIndex is a lazily-rebuilt cache, so leaving the old ID mapped
	// would keep answering for exactly the tokens this is meant to invalidate.
	if store, err := s.userStore(u.ID); err != nil {
		errs = append(errs, fmt.Errorf("open state store to rotate subscriber id: %w", err))
	} else if previous, err := store.RotateSubscriberID(); err != nil {
		s.logger.Error("failed to rotate subscriber id", "user_id", u.ID, "error", err.Error())
		errs = append(errs, fmt.Errorf("rotate subscriber id: %w", err))
	} else if previous != "" {
		s.userMu.Lock()
		delete(s.subIndex, previous)
		s.userMu.Unlock()
	}

	s.davCredentials.invalidateUser(u.Username)
	return errors.Join(errs...)
}

// revokeUserDevices removes every paired native device for userID from both
// the per-user store and the global deviceIndex, so an admin-driven
// deactivate / password-reset / MFA-clear cuts off device access with the same
// action that cuts off web sessions (see revokeUserSessions). Best-effort:
// errors are logged, not fatal, so revocation of the primary credential still
// succeeds.
func (s *Server) revokeUserDevices(userID string) error {
	store, err := s.userStore(userID)
	if err != nil {
		return fmt.Errorf("open device store: %w", err)
	}
	devices, err := store.ListNativeDevicesStrict()
	if err != nil {
		return err
	}
	for _, dev := range devices {
		if _, err := store.RemoveNativeDevice(dev.DeviceID); err != nil {
			return fmt.Errorf("remove native device %q: %w", dev.DeviceID, err)
		}
		s.userMu.Lock()
		delete(s.deviceIndex, dev.DeviceID)
		s.userMu.Unlock()
	}
	return nil
}

// rescanDeviceIndex rebuilds deviceID -> userID across every per-user store.
// Mirrors rescanSubscriberIndex, including going through state.Store rather
// than parsing storage directly.
func (s *Server) rescanDeviceIndex() {
	next := map[string]string{}
	for _, userID := range s.knownUserIDs() {
		// Not userStore: this pass touches every account and is driven by an
		// unauthenticated caller's unknown device id, so counting it as user
		// activity made the idle-store sweep unreachable.
		store, err := s.userStoreForMaintenance(userID)
		if err != nil {
			continue
		}
		devices, err := store.ListNativeDevicesStrict()
		if err != nil {
			continue
		}
		for _, d := range devices {
			if id := strings.TrimSpace(d.DeviceID); id != "" {
				next[id] = userID
			}
		}
	}
	s.userMu.Lock()
	// Merge into the live index rather than replacing it. A reservation made by
	// reserveDeviceID for an in-flight registration has not reached disk yet, so
	// replacing the map would drop it — and two concurrent registrations racing the
	// same client-chosen deviceId would then both see a free slot, which is the
	// device-ID hijack reserveDeviceID exists to prevent.
	//
	// Merging can leave an entry for a device the other process since unpaired. That
	// is safe: the index only resolves deviceId -> owner so the owner's store can be
	// opened; authorization is decided by state.Store.GetNativeDevice and the
	// secret-hash check in deviceAuthFromRequest, which read through to disk and
	// fail closed.
	for id, owner := range next {
		s.deviceIndex[id] = owner
	}
	s.userMu.Unlock()
}
