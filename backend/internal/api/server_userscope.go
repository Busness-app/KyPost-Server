package api

import (
	"encoding/json"
	"errors"
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
)

// getOrCreateUserStore returns the cached per-user store, constructing and
// caching it on first access. Shared by the userStore/userContactsStore/
// userGroupsStore/userRulesStore/userMailCacheStore getters below, which
// otherwise differ only in which map and constructor they use.
func getOrCreateUserStore[T any](mu *sync.Mutex, cache map[string]T, userID string, construct func() (T, error)) (T, error) {
	mu.Lock()
	defer mu.Unlock()
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
	return getOrCreateUserStore(&s.userMu, s.userStores, userID, func() (*state.Store, error) {
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
	return getOrCreateUserStore(&s.userMu, s.userContacts, userID, func() (*contacts.Store, error) {
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
	return getOrCreateUserStore(&s.userMu, s.userSendAs, userID, func() (*sendas.Store, error) {
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
	return getOrCreateUserStore(&s.userMu, s.userGroups, userID, func() (*groups.Store, error) {
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
	return getOrCreateUserStore(&s.userMu, s.userRules, userID, func() (*rules.Store, error) {
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
	return getOrCreateUserStore(&s.userMu, s.userMailCache, userID, func() (*mailcache.Store, error) {
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
	if entry, ok := s.userMail[userID]; ok && entry.updatedAt == payload.UpdatedAt {
		return entry.client, nil
	}
	client := imapadapter.NewAPIClientFromStoredConfig(s.userIMAPConfigPath(userID), s.imapConfigKeyPath)
	s.userMail[userID] = &serverMailEntry{client: client, updatedAt: payload.UpdatedAt}
	return client, nil
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

// rescanSubscriberIndex rebuilds subscriberID -> userID by reading every
// per-user state.json. Cheap at this scale (a handful of small files).
func (s *Server) rescanSubscriberIndex() {
	usersDir := filepath.Join(s.stateDir, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return
	}
	next := map[string]string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(usersDir, e.Name(), "state.json"))
		if err != nil {
			continue
		}
		var doc struct {
			SubscriberID string `json:"subscriberId"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			continue
		}
		if id := strings.TrimSpace(doc.SubscriberID); id != "" {
			next[id] = e.Name()
		}
	}
	s.userMu.Lock()
	s.subIndex = next
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

	s.rescanDeviceIndex()

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
	// below.
	s.lookupUserByDevice(deviceID)

	s.userMu.Lock()
	defer s.userMu.Unlock()
	if existing, ok := s.deviceIndex[deviceID]; ok && existing != ownerID {
		return false
	}
	s.deviceIndex[deviceID] = ownerID
	return true
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

// rescanDeviceIndex rebuilds deviceID -> userID by reading every per-user
// state.json's nativeDevices array. Mirrors rescanSubscriberIndex.
func (s *Server) rescanDeviceIndex() {
	usersDir := filepath.Join(s.stateDir, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return
	}
	next := map[string]string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(usersDir, e.Name(), "state.json"))
		if err != nil {
			continue
		}
		var doc struct {
			NativeDevices []struct {
				DeviceID string `json:"deviceId"`
			} `json:"nativeDevices"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			continue
		}
		for _, d := range doc.NativeDevices {
			if id := strings.TrimSpace(d.DeviceID); id != "" {
				next[id] = e.Name()
			}
		}
	}
	s.userMu.Lock()
	s.deviceIndex = next
	s.userMu.Unlock()
}
