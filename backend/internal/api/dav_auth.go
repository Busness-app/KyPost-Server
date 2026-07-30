package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/users"
)

// davCredentialTTL bounds how long a verified Basic Auth credential is
// trusted before re-checking scrypt. Native CardDAV clients (macOS/iOS
// Contacts, Nextcloud) commonly re-authenticate on every PROPFIND/REPORT
// within a sync session; without this cache each of those would pay
// scrypt's cost (N=16384) again.
const davCredentialTTL = 90 * time.Second

type davCredentialCacheEntry struct {
	authContext AuthContext
	expiresAt   time.Time
}

// davCredentialCache is a short-lived, in-memory cache of verified CardDAV
// Basic Auth credentials, keyed by a hash of username+password.
type davCredentialCache struct {
	mu      sync.Mutex
	entries map[string]davCredentialCacheEntry
}

func newDAVCredentialCache() davCredentialCache {
	return davCredentialCache{entries: map[string]davCredentialCacheEntry{}}
}

// davCredentialCacheKey folds the username the same way GetByUsername resolves
// it, so the two spellings of one account share one cache entry rather than
// silently paying scrypt again per spelling — and so nothing here re-learns the
// lesson handleLogin's lockout key did (see users.NormalizeUsername).
func davCredentialCacheKey(username, password string) string {
	sum := sha256.Sum256([]byte(users.NormalizeUsername(username) + "\x00" + password))
	return hex.EncodeToString(sum[:])
}

func (c *davCredentialCache) get(username, password string) (AuthContext, bool) {
	key := davCredentialCacheKey(username, password)
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return AuthContext{}, false
	}
	return entry.authContext, true
}

func (c *davCredentialCache) put(username, password string, ac AuthContext) {
	key := davCredentialCacheKey(username, password)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = davCredentialCacheEntry{authContext: ac, expiresAt: time.Now().Add(davCredentialTTL)}
}

// invalidateUser drops every cached credential. There's no way to know which
// cache keys belonged to a given username without recomputing every
// possible password hash, so password regeneration/revocation just clears
// the whole cache — cheap at the expected scale (a handful of self-hosted
// users).
func (c *davCredentialCache) invalidateUser(_ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]davCredentialCacheEntry{}
}

// withDAVBasicAuth authenticates a CardDAV request via HTTP Basic Auth
// against the caller's app-specific CardDAV password (not their login
// password — see handleContactsDAVPassword), and injects an AuthContext into
// the request context so downstream code can use authFromContext uniformly
// with session-authenticated handlers.
func (s *Server) withDAVBasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || strings.TrimSpace(username) == "" || password == "" {
			// A missing-credentials 401 is the normal Basic Auth challenge
			// round every client starts with, so it never counts as a strike.
			s.requireDAVAuth(w)
			return
		}

		// Per-IP lockout: unlike login, every failed DAV attempt below pays a
		// full scrypt verification, so an uncapped attacker is a CPU-exhaustion
		// vector even though guessing the server-generated password is
		// hopeless. Checked before the credential cache so a locked-out IP is
		// refused outright.
		lockKey := lockoutKeyForIP(clientIP(r))
		if allowed, retryAfter := s.davLockout.tryAttempt(lockKey); !allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			http.Error(w, "too many failed attempts, try again later", http.StatusTooManyRequests)
			return
		}

		if ac, cached := s.davCredentials.get(username, password); cached {
			// A cache hit is a successful authentication and must settle the
			// strike tryAttempt just reserved. Without this, a CardDAV client
			// polling with correct credentials would spend a strike per
			// request and lock itself out within seconds.
			s.davLockout.recordSuccess(lockKey)
			// Re-check the account live even on a hit. revokeAllUserCredentials
			// clears this cache on deactivate/reset, but a request that read
			// Active==true just before the deactivation can still `put` just
			// after that clear — so the cache alone left a deactivated account
			// with full CardDAV read/write for up to davCredentialTTL. This is a
			// map lookup and a scrypt-free field read; the scrypt verification
			// the cache exists to skip is still skipped.
			u, err := s.users.Get(ac.UserID)
			if err != nil || !u.Active {
				s.davCredentials.invalidateUser(ac.Username)
				s.requireDAVAuth(w)
				return
			}
			// Role is re-read for the same reason currentUser does not snapshot
			// it into the session: an admin demoted mid-sync must not keep the
			// old role for the rest of the cache TTL.
			ac.Role = u.Role
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
			return
		}

		u, err := s.users.GetByUsername(username)
		if err != nil || !u.Active {
			// Pay the same scrypt cost a real password check would, so
			// response timing doesn't reveal whether the username exists —
			// mirrors equalizeLoginTiming's use on the login endpoint. Under
			// the shared KDF slot: this is unauthenticated, and 128 MiB per
			// concurrent attempt is otherwise an OOM primitive.
			if err := s.withKDFSlot(r.Context(), func() { equalizeLoginTiming(password) }); err != nil {
				s.davLockout.cancelAttempt(lockKey)
				writeKDFBusy(w)
				return
			}
			s.requireDAVAuth(w)
			return
		}
		passFile, exists, err := s.readDAVPassword(u.ID)
		if err != nil || !exists {
			// No CardDAV app-password configured for this account: still pay
			// the scrypt cost so this path isn't distinguishable by timing
			// from a wrong-password attempt against a configured account.
			if err := s.withKDFSlot(r.Context(), func() { equalizeLoginTiming(password) }); err != nil {
				s.davLockout.cancelAttempt(lockKey)
				writeKDFBusy(w)
				return
			}
			s.requireDAVAuth(w)
			return
		}
		verified := false
		// Shedding answers 503 rather than the 401 requireDAVAuth would send. A
		// CardDAV client that receives 401 for a correct password commonly
		// discards its stored credential and prompts the user, so reporting
		// overload as a rejection would log every synced device out during a
		// load spike.
		if err := s.withKDFSlot(r.Context(), func() { verified = users.VerifySecretHash(passFile.Hash, password) }); err != nil {
			s.davLockout.cancelAttempt(lockKey)
			writeKDFBusy(w)
			return
		}
		if !verified {
			s.requireDAVAuth(w)
			return
		}

		s.davLockout.recordSuccess(lockKey)
		ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}
		s.davCredentials.put(username, password, ac)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	})
}

func (s *Server) requireDAVAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="kypost"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
