package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/users"
)

// SyncUserPayload represents a user object in a KySignOn replication event.
type SyncUserPayload struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
	Email    string `json:"email"`
}

// SyncWebhookEvent represents the directory replication event envelope.
//
// JTI and IAT are named after RFC 8417 Security Event Tokens, which is the
// same envelope OIDC back-channel logout uses and for the same reason: an HMAC
// proves who wrote an event, never when. Without them a captured
// `user.updated{role:"admin"}` stays valid forever, so re-delivering it
// re-promotes a user the directory demoted months ago.
//
// Id and Ts are accepted as aliases so a sender that already spells them that
// way keeps working. Neither pair is required unless the operator sets
// RequireFreshEvents; see handleSyncWebhook.
type SyncWebhookEvent struct {
	JTI string `json:"jti"`
	IAT int64  `json:"iat"`
	ID  string `json:"id"`
	Ts  int64  `json:"ts"`

	Event string          `json:"event"`
	User  SyncUserPayload `json:"user"`
}

func (e SyncWebhookEvent) eventID() string {
	if e.JTI != "" {
		return e.JTI
	}
	return e.ID
}

func (e SyncWebhookEvent) issuedAt() int64 {
	if e.IAT != 0 {
		return e.IAT
	}
	return e.Ts
}

const (
	// syncEventMaxAge is how long after issue an event may still be applied.
	syncEventMaxAge = 5 * time.Minute
	// syncEventMaxSkew tolerates a sender whose clock runs slightly fast.
	syncEventMaxSkew = 60 * time.Second
	// syncReplayCapacity bounds the replay cache. The pruning below already
	// caps it at one window's worth of traffic; this is the backstop for a
	// sender that holds the pairing secret and floods unique ids.
	syncReplayCapacity = 10000
)

// replayCache remembers event ids for as long as one could still be accepted.
type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// seenRecently reports whether id was already applied inside the window.
func (c *replayCache) seenRecently(id string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	_, dup := c.seen[id]
	return dup
}

// record marks id applied. It is called only after the event took effect, so a
// delivery that failed halfway is retried rather than answered "duplicate".
func (c *replayCache) record(id string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[string]time.Time)
	}
	c.pruneLocked(now)
	c.seen[id] = now
}

// full reports whether the cache can no longer take a new id without
// forgetting one it still needs. Callers fail closed rather than accept an
// event they could not later recognise as a replay.
func (c *replayCache) full(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked(now)
	return len(c.seen) >= syncReplayCapacity
}

func (c *replayCache) pruneLocked(now time.Time) {
	window := syncEventMaxAge + syncEventMaxSkew
	for k, t := range c.seen {
		if now.Sub(t) > window {
			delete(c.seen, k)
		}
	}
}

// handleSyncWebhook handles signed replication events from KySignOn.
//
// Every persistence error reaches the sender. The predecessor discarded them
// all and answered 200 {"ok":true}: a deactivation that never hit disk, or a
// credential revocation that failed, was reported as delivered, the directory
// stopped retrying, and the supposedly removed user stayed authenticated.
func (s *Server) handleSyncWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<18))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	settings := s.ssoStore.Load()
	if !s.syncRequestAuthorized(r, body, settings.ClientSecret) {
		http.Error(w, "unauthorized sync request", http.StatusUnauthorized)
		return
	}

	var ev SyncWebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	now := time.Now()
	evID, evIAT := ev.eventID(), ev.issuedAt()
	replayProtected := evID != "" && evIAT != 0

	if !replayProtected {
		if settings.RequireFreshEvents {
			http.Error(w, "event must carry jti and iat", http.StatusBadRequest)
			return
		}
		s.syncFreshnessWarn.Do(func() {
			s.logger.Error("sync webhook events carry no jti/iat, so replays cannot be detected",
				"action", "update KySignOn to send jti and iat, then enable requireFreshEvents")
		})
	} else {
		age := now.Sub(time.Unix(evIAT, 0))
		if age > syncEventMaxAge || age < -syncEventMaxSkew {
			http.Error(w, "event timestamp is outside the accepted window", http.StatusBadRequest)
			return
		}
		if s.syncReplay.seenRecently(evID, now) {
			// A legitimate at-least-once sender re-delivering something we
			// already applied deserves an ack, not an error.
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "duplicate": true})
			return
		}
		if s.syncReplay.full(now) {
			http.Error(w, "replay cache saturated, retry shortly", http.StatusServiceUnavailable)
			return
		}
	}

	if status, err := s.applySyncEvent(ev); err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	if replayProtected {
		s.syncReplay.record(evID, now)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// syncRequestAuthorized accepts either the pairing secret or the SSO client
// secret, as a bearer token or as an HMAC over the exact bytes received.
func (s *Server) syncRequestAuthorized(r *http.Request, body []byte, clientSecret string) bool {
	authHeader := r.Header.Get("Authorization")
	sigHeader := r.Header.Get("X-Sync-Signature")

	for _, secret := range []string{s.pairingSecret, clientSecret} {
		if secret == "" {
			continue
		}
		if hmac.Equal([]byte(authHeader), []byte("Bearer "+secret)) {
			return true
		}
		if sigHeader == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(sigHeader), []byte(expected)) {
			return true
		}
	}
	return false
}

// applySyncEvent performs the requested state transition, returning the status
// the sender should see. A 5xx means "retry"; a 4xx means "this will never
// work, an operator needs to look at it".
func (s *Server) applySyncEvent(ev SyncWebhookEvent) (int, error) {
	role := users.RoleUser
	if strings.EqualFold(ev.User.Role, "admin") {
		role = users.RoleAdmin
	}

	// Every event below keys off the directory's user id. Without one,
	// "create" would provision an account with no SSO subject attached and
	// "delete" would look up the empty string.
	if strings.TrimSpace(ev.User.ID) == "" {
		return http.StatusBadRequest, errors.New("event carries no user id")
	}

	switch ev.Event {
	case "user.created":
		_, err := s.users.GetBySSOSub(ev.User.ID)
		if err == nil {
			return 0, nil // already provisioned; creating is idempotent
		}
		if !errors.Is(err, users.ErrNotFound) {
			return http.StatusInternalServerError, errors.New("failed to look up user")
		}
		if _, err := s.users.CreateSSOUser(ev.User.Username, role, ev.User.ID, ev.User.Username, ev.User.Email); err != nil {
			return syncErrStatus(err, "failed to create user")
		}
		return 0, nil

	case "user.updated":
		u, err := s.users.GetBySSOSub(ev.User.ID)
		if errors.Is(err, users.ErrNotFound) {
			return 0, nil // nothing here is linked to that identity
		}
		if err != nil {
			return http.StatusInternalServerError, errors.New("failed to look up user")
		}
		if u.Role != role {
			if _, err := s.users.SetRole(u.ID, role); err != nil {
				return syncErrStatus(err, "failed to set role")
			}
		}
		if ev.User.Active {
			if !u.Active {
				if _, err := s.users.Reactivate(u.ID); err != nil {
					return syncErrStatus(err, "failed to reactivate user")
				}
			}
			return 0, nil
		}
		return s.deactivateAndRevoke(u.ID)

	case "user.deleted":
		u, err := s.users.GetBySSOSub(ev.User.ID)
		if errors.Is(err, users.ErrNotFound) {
			return 0, nil // already gone
		}
		if err != nil {
			return http.StatusInternalServerError, errors.New("failed to look up user")
		}
		return s.deactivateAndRevoke(u.ID)

	default:
		return http.StatusBadRequest, errors.New("unknown sync event type")
	}
}

// deactivateAndRevoke runs the removal unconditionally rather than only when
// the local user still looks active.
//
// That is what makes a retry converge. If a previous delivery deactivated the
// user and then failed to revoke their credentials, the user is already
// inactive — a "deactivate only if active" guard would skip straight past the
// revocation that never happened and report success. Both steps are idempotent,
// so repeating them costs nothing and closes that gap.
func (s *Server) deactivateAndRevoke(userID string) (int, error) {
	deactivated, err := s.users.Deactivate(userID)
	if err != nil {
		return syncErrStatus(err, "failed to deactivate user")
	}
	if err := s.revokeAllUserCredentials(deactivated); err != nil {
		return http.StatusInternalServerError, errors.New("failed to revoke user credentials")
	}
	return 0, nil
}

// syncErrStatus separates "try again" from "this cannot be applied here".
func syncErrStatus(err error, what string) (int, error) {
	switch {
	case errors.Is(err, users.ErrLastActiveAdmin):
		// Retrying forever will not conjure a second administrator. Say so
		// once, loudly, so the sender stops and an operator intervenes.
		return http.StatusConflict, errors.New(what + ": refusing to remove the last active admin")
	case errors.Is(err, users.ErrUsernameTaken):
		return http.StatusConflict, errors.New(what + ": username already in use by a local account")
	case errors.Is(err, users.ErrUsernameInvalid):
		return http.StatusBadRequest, errors.New(what + ": username is not representable here")
	default:
		return http.StatusInternalServerError, errors.New(what)
	}
}
