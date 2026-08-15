package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
type SyncWebhookEvent struct {
	Event string          `json:"event"`
	User  SyncUserPayload `json:"user"`
}

// handleSyncWebhook handles signed replication events from KySignOn.
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

	authHeader := r.Header.Get("Authorization")
	sigHeader := r.Header.Get("X-Sync-Signature")

	authorized := false
	if s.pairingSecret != "" {
		if authHeader == "Bearer "+s.pairingSecret {
			authorized = true
		} else if sigHeader != "" {
			mac := hmac.New(sha256.New, []byte(s.pairingSecret))
			mac.Write(body)
			expectedSig := hex.EncodeToString(mac.Sum(nil))
			if hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
				authorized = true
			}
		}
	}

	if !authorized {
		ssoSettings := s.ssoStore.Load()
		if ssoSettings.ClientSecret != "" {
			if authHeader == "Bearer "+ssoSettings.ClientSecret {
				authorized = true
			} else if sigHeader != "" {
				mac := hmac.New(sha256.New, []byte(ssoSettings.ClientSecret))
				mac.Write(body)
				expectedSig := hex.EncodeToString(mac.Sum(nil))
				if hmac.Equal([]byte(sigHeader), []byte(expectedSig)) {
					authorized = true
				}
			}
		}
	}

	if !authorized {
		http.Error(w, "unauthorized sync request", http.StatusUnauthorized)
		return
	}

	var ev SyncWebhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid json payload", http.StatusBadRequest)
		return
	}

	switch ev.Event {
	case "user.created":
		if _, err := s.users.GetBySSOSub(ev.User.ID); err != nil {
			role := users.RoleUser
			if strings.EqualFold(ev.User.Role, "admin") {
				role = users.RoleAdmin
			}
			_, _ = s.users.CreateSSOUser(ev.User.Username, role, ev.User.ID, ev.User.Username, ev.User.Email)
		}
	case "user.updated":
		if u, err := s.users.GetBySSOSub(ev.User.ID); err == nil {
			role := users.RoleUser
			if strings.EqualFold(ev.User.Role, "admin") {
				role = users.RoleAdmin
			}
			if u.Role != role {
				_, _ = s.users.SetRole(u.ID, role)
			}
			if ev.User.Active && !u.Active {
				_, _ = s.users.Reactivate(u.ID)
			} else if !ev.User.Active && u.Active {
				if deactivated, errD := s.users.Deactivate(u.ID); errD == nil {
					_ = s.revokeAllUserCredentials(deactivated)
				}
			}
		}
	case "user.deleted":
		if u, err := s.users.GetBySSOSub(ev.User.ID); err == nil {
			if deactivated, errD := s.users.Deactivate(u.ID); errD == nil {
				_ = s.revokeAllUserCredentials(deactivated)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
