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

	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// davCredentialTTL bounds how long a verified Basic Auth credential is
// trusted before re-checking against the password KDF. Native CardDAV clients
// (macOS/iOS Contacts, Nextcloud) commonly re-authenticate on every
// PROPFIND/REPORT within a sync session; without this cache each of those
// would pay the password KDF's cost again.
const davCredentialTTL = 90 * time.Second

type davCredentialCacheEntry struct {
	authContext AuthContext
	expiresAt   time.Time
}

// davCredentialCache is a short-lived, in-memory cache of verified CardDAV
// Basic Auth credentials, keyed by a hash of username+password.
//
// `generation` is what makes revocation immediate rather than eventually
// immediate. Clearing the map is not enough on its own: a request that read the
// credential file just before revokeAllUserCredentials deleted it is still in
// flight, and its `put` lands after the clear — re-admitting a credential that
// no longer exists for a full davCredentialTTL. Callers therefore snapshot the
// generation BEFORE they read the credential they are about to verify, and
// `put` drops the entry if invalidation bumped it in between.
type davCredentialCache struct {
	mu         sync.Mutex
	entries    map[string]davCredentialCacheEntry
	generation uint64
}

func newDAVCredentialCache() davCredentialCache {
	return davCredentialCache{entries: map[string]davCredentialCacheEntry{}}
}

// davCredentialCacheKey folds the username the same way GetByUsername resolves
// it, so the two spellings of one account share one cache entry rather than
// silently paying the password KDF again per spelling — and so nothing here
// re-learns the lesson handleLogin's lockout key did (see users.NormalizeUsername).
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

// currentGeneration snapshots the invalidation counter. Take it BEFORE reading
// the credential that is about to be verified, and hand it back to put.
func (c *davCredentialCache) currentGeneration() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generation
}

// put caches a verified credential, unless the cache was invalidated since gen
// was taken — in which case the credential this verification was based on may
// already have been deleted, and caching it would resurrect it.
func (c *davCredentialCache) put(gen uint64, username, password string, ac AuthContext) {
	key := davCredentialCacheKey(username, password)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != gen {
		return
	}
	c.entries[key] = davCredentialCacheEntry{authContext: ac, expiresAt: time.Now().Add(davCredentialTTL)}
}

// invalidateUser drops every cached credential. There's no way to know which
// cache keys belonged to a given username without recomputing every
// possible password hash, so password regeneration/revocation just clears
// the whole cache — cheap at the expected scale (a handful of self-hosted
// users).
//
// The generation bump is the half that closes the window: clearing the map
// evicts what is already cached, bumping the generation rejects what verifiers
// still in flight are about to cache.
func (c *davCredentialCache) invalidateUser(_ string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]davCredentialCacheEntry{}
	c.generation++
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
		// full password KDF verification, so an uncapped attacker is a
		// CPU-exhaustion vector even though guessing the server-generated
		// password is hopeless. Checked before the credential cache so a
		// locked-out IP is refused outright.
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
			// map lookup and a KDF-free field read; the password KDF verification
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
			if !s.meterAccountWrite(w, r, ac.UserID) {
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
			return
		}

		// Snapshot the invalidation counter before anything below reads the
		// account or the credential file, so a revocation that races this
		// verification is guaranteed to be seen by the put at the end (see
		// davCredentialCache).
		gen := s.davCredentials.currentGeneration()

		u, err := s.users.GetByUsername(username)
		if err != nil || !u.Active {
			// Pay the same Argon2id cost a real password check would, so
			// response timing doesn't reveal whether the username exists —
			// mirrors equalizeLoginTiming's use on the login endpoint. Under
			// the shared KDF slot: this is unauthenticated, and 64 MiB per
			// concurrent attempt is otherwise an OOM primitive. An account
			// still holding a scrypt hash costs more to check for real until
			// its next successful login or app-password use rehashes it; the
			// dummy here is always Argon2id at the current parameters, so that
			// skew never leaks into this comparison.
			if err := equalizeLoginTiming(r.Context(), password); err != nil {
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
			// the password KDF cost so this path isn't distinguishable by timing
			// from a wrong-password attempt against a configured account.
			if err := equalizeLoginTiming(r.Context(), password); err != nil {
				s.davLockout.cancelAttempt(lockKey)
				writeKDFBusy(w)
				return
			}
			s.requireDAVAuth(w)
			return
		}
		// Shedding answers 503 rather than the 401 requireDAVAuth would send. A
		// CardDAV client that receives 401 for a correct password commonly
		// discards its stored credential and prompts the user, so reporting
		// overload as a rejection would log every synced device out during a
		// load spike.
		verified, err := users.VerifySecretHash(r.Context(), passFile.Hash, password)
		if err != nil {
			s.davLockout.cancelAttempt(lockKey)
			writeKDFBusy(w)
			return
		}
		if !verified {
			s.requireDAVAuth(w)
			return
		}

		// The credential just verified, so a stale hash format (legacy scrypt,
		// or an Argon2id hash below the current cost) is upgraded now — the
		// only moment the plaintext is legitimately in hand. See
		// rehashDAVAppPassword for why this is guarded rather than an
		// unconditional write.
		if users.NeedsRehash(passFile.Hash) {
			s.rehashDAVAppPassword(r.Context(), u.ID, passFile.Hash, password, gen)
		}

		s.davLockout.recordSuccess(lockKey)
		ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}
		s.davCredentials.put(gen, username, password, ac)
		if !s.meterAccountWrite(w, r, ac.UserID) {
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, ac)))
	})
}

// rehashDAVAppPassword re-derives an app password's hash at the current cost
// and persists it, but only if nothing has revoked or replaced the credential
// since gen was snapshotted (before the file was read) and verifiedHash was
// read from it. Best-effort and silent on every abort: the caller's request
// already has its answer, and the next successful auth against whatever
// credential is current retries the upgrade.
//
// The guard exists because this runs after TWO derivations queue for up to
// KDFMaxQueueWait each (VerifySecretHash in the caller, then HashPassword
// here) — long enough for the credential this is about to persist to have
// been revoked or replaced underneath it. Three writers race this: DELETE and
// POST-regenerate in contacts_handlers.go, and revokeAllUserCredentialsExcept
// in server_userscope.go (password reset, MFA clear). Skipping the generation
// or hash check would let a rehash that started before one of them finished
// resurrect a deleted credential, or clobber a freshly regenerated one with a
// re-derivation of the OLD password. All three call
// davCredentials.invalidateUser, which bumps the generation this compares
// against, and the re-read closes the remaining window between that bump and
// this write — see users.Store.RehashPassword for the same shape applied to
// the login password, verifying inside a lock this file has none of.
func (s *Server) rehashDAVAppPassword(ctx context.Context, userID, verifiedHash, password string, gen uint64) {
	hash, err := users.HashPassword(ctx, password)
	if err != nil {
		s.logger.Error("carddav app-password hash upgrade failed", "user_id", userID, "error", err.Error())
		return
	}
	if s.davCredentials.currentGeneration() != gen {
		return
	}
	current, exists, err := s.readDAVPassword(userID)
	if err != nil || !exists || current.Hash != verifiedHash {
		return
	}
	if err := s.writeDAVPassword(userID, davPasswordFile{Hash: hash, CreatedAt: current.CreatedAt}); err != nil {
		s.logger.Error("carddav app-password hash upgrade failed to persist", "user_id", userID, "error", err.Error())
	}
}

func (s *Server) requireDAVAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="kypost"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
