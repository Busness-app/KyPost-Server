package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"kypost-server/backend/internal/users"
)

// withAdmin layers an admin-role requirement on top of withAuth. Handlers
// wrapped by it can rely on authFromContext returning an admin.
func (s *Server) withAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		ac, ok := authFromContext(r)
		if !ok || ac.Role != users.RoleAdmin {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "admin access required"})
			return
		}
		next(w, r)
	})
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	all, err := s.users.List()
	if err != nil {
		http.Error(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	out := make([]users.Public, 0, len(all))
	for _, u := range all {
		out = append(out, u.Public())
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleUsersCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		http.Error(w, "username required", http.StatusBadRequest)
		return
	}
	// Checked here as well as inside Create so a bad username is reported
	// alongside a bad password rather than only after the password passes.
	if err := users.ValidateUsername(req.Username); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := users.ValidatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	role, err := parseRole(req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.users.Create(req.Username, req.Password, role)
	if err != nil {
		if errors.Is(err, users.ErrUsernameTaken) {
			http.Error(w, "username already in use", http.StatusConflict)
			return
		}
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("user created", "user_id", u.ID, "username", u.Username, "role", string(u.Role))
	writeJSON(w, http.StatusCreated, u.Public())
}

func (s *Server) handleUsersUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	role, err := parseRole(req.Role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if role != users.RoleAdmin {
		if blocked, err := s.isLastActiveAdmin(id); err != nil {
			http.Error(w, "failed to update user", http.StatusInternalServerError)
			return
		} else if blocked {
			http.Error(w, "cannot demote the last active admin", http.StatusBadRequest)
			return
		}
	}
	u, err := s.users.SetRole(id, role)
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("user role updated", "user_id", u.ID, "role", string(u.Role))
	writeJSON(w, http.StatusOK, u.Public())
}

func (s *Server) handleUsersResetPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := users.ValidatePassword(req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.users.SetPassword(id, req.Password, true)
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	// The admin's own session isn't among this account's sessions, so there's
	// no "current session" to keep — every one of the target's live sessions
	// (e.g. a stolen cookie the reset is meant to shut out) is revoked, along
	// with paired devices (own secret, independent of the password) and cached
	// CardDAV credentials. See revokeAllUserCredentials.
	if err := s.revokeAllUserCredentials(u); err != nil {
		http.Error(w, "password reset completed but credential revocation failed; retry immediately", http.StatusInternalServerError)
		return
	}
	s.logger.Info("user password reset by admin", "user_id", u.ID)
	writeJSON(w, http.StatusOK, u.Public())
}

func (s *Server) handleUsersDeactivate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if blocked, err := s.isLastActiveAdmin(id); err != nil {
		http.Error(w, "failed to deactivate user", http.StatusInternalServerError)
		return
	} else if blocked {
		http.Error(w, "cannot deactivate the last active admin", http.StatusBadRequest)
		return
	}
	u, err := s.users.Deactivate(id)
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	// Cut off every credential type the account holds — web sessions, paired
	// devices, and cached CardDAV Basic Auth (see revokeAllUserCredentials).
	// The device-auth path also rejects inactive accounts live (see
	// deviceAuthFromRequest), but purging here makes revocation explicit and
	// durable across any future reactivation.
	if err := s.revokeAllUserCredentials(u); err != nil {
		http.Error(w, "user deactivated but credential revocation failed; retry immediately", http.StatusInternalServerError)
		return
	}
	s.logger.Info("user deactivated", "user_id", u.ID)
	writeJSON(w, http.StatusOK, u.Public())
}

func (s *Server) handleUsersReactivate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.users.Reactivate(id)
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("user reactivated", "user_id", u.ID)
	writeJSON(w, http.StatusOK, u.Public())
}

// handleUsersClearMFA lets an admin reset another user's two-factor auth
// (TOTP, recovery codes, and push approval) when they've lost access to their
// authenticator, e.g. a new device with no recovery codes saved.
func (s *Server) handleUsersClearMFA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := s.users.DisableTOTP(id)
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	// Clearing MFA is an account-recovery action; revoke paired devices and
	// cached CardDAV credentials too, so nothing issued under the old trust
	// state retains access.
	if err := s.revokeAllUserCredentials(u); err != nil {
		http.Error(w, "MFA cleared but credential revocation failed; retry immediately", http.StatusInternalServerError)
		return
	}
	// Also purge any in-flight push-MFA challenge: DisableTOTP clears the
	// PushMFAEnabled bit, but a challenge already approved before this call
	// is otherwise still redeemable via handlePushFinish until it naturally
	// expires (up to a few minutes) — see mfa.Store.DeleteByUser.
	s.mfaChallenges.DeleteByUser(u.ID)
	s.logger.Info("user MFA cleared by admin", "user_id", u.ID)
	writeJSON(w, http.StatusOK, u.Public())
}

// isLastActiveAdmin reports whether the given user is the only active admin
// left, in which case deactivating or demoting them would lock everyone out
// of user management permanently.
func (s *Server) isLastActiveAdmin(id string) (bool, error) {
	all, err := s.users.List()
	if err != nil {
		return false, err
	}
	target := false
	otherActiveAdmins := 0
	for _, u := range all {
		if u.Role != users.RoleAdmin || !u.Active {
			continue
		}
		if u.ID == id {
			target = true
		} else {
			otherActiveAdmins++
		}
	}
	return target && otherActiveAdmins == 0, nil
}

func parseRole(raw string) (users.Role, error) {
	switch users.Role(strings.TrimSpace(raw)) {
	case users.RoleAdmin:
		return users.RoleAdmin, nil
	case users.RoleUser, "":
		return users.RoleUser, nil
	default:
		return "", errors.New("invalid role; expected admin or user")
	}
}

func writeUserStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, users.ErrNotFound) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	// A rejected password or username is caller error, not a store failure —
	// both messages are safe to echo verbatim since they only state the rule.
	if errors.Is(err, users.ErrPasswordWeak) || errors.Is(err, users.ErrUsernameInvalid) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// The store now enforces the last-admin invariant inside its own write
	// lock (the handler's pre-check remains as a fast path with a friendlier
	// message, but this is the authoritative refusal).
	if errors.Is(err, users.ErrLastActiveAdmin) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if errors.Is(err, users.ErrNotClientProtected) || errors.Is(err, users.ErrWouldDowngradeCustody) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Error(w, "user store error", http.StatusInternalServerError)
}
