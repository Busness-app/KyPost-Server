// Instance and per-user settings: config, notification preferences, label
// preferences and allowlist, the classifier tuning prompt, and the decision
// audit feed.
package api

import (
	"time"

	"encoding/json"
	"errors"
	"io"
	"kypost-server/backend/internal/adapters/classifier"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/redaction"
	"kypost-server/backend/internal/users"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.cfgMu.RLock()
		cfg := s.cfg
		s.cfgMu.RUnlock()
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
		s.cfgMu.RLock()
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
		s.cfgMu.RUnlock()
		// Remote LLM settings are admin-only. Reject (rather than silently
		// drop) a non-admin change so a broken save is never masked.
		if ac, ok := authFromContext(r); classifierChanged && (!ok || ac.Role != users.RoleAdmin) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "remote llm settings require admin access"})
			return
		}
		// Validate here, not only at process start. Values that fail a boot
		// check were accepted, persisted and echoed back as live, and then took
		// effect as a crash loop or a silently disabled control at the next
		// restart — with the only interface for fixing config.yaml being this
		// same API.
		if _, err := time.LoadLocation(next.Timezone); next.Timezone != "" && err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid timezone: " + err.Error()})
			return
		}
		if _, err := redaction.New(next.Redaction.Patterns); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid redaction pattern: " + err.Error()})
			return
		}
		// Allowlist labels become IMAP keywords verbatim. Mailbox names may
		// contain spaces and keywords may not, and the UI populates this list
		// from discovered mailbox names — so an unvalidated entry here is a
		// per-message stall in the shared poller later.
		for _, label := range next.Labels.Allowlist {
			if err := imapadapter.ValidateKeyword(label); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "label cannot be used as an IMAP keyword: " + err.Error()})
				return
			}
		}
		if next.RateLimits.PerMinute <= 0 || next.RateLimits.PerHour <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "rate limits must be greater than zero"})
			return
		}
		if err := config.Save(s.configPath, next); err != nil {
			http.Error(w, "failed to save config", http.StatusInternalServerError)
			return
		}
		s.cfgMu.Lock()
		s.cfg = next
		s.cfgMu.Unlock()
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
	s.cfgMu.RLock()
	configured := append([]string{}, s.cfg.Labels.Allowlist...)
	s.cfgMu.RUnlock()

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
		// No MkdirAll here: AtomicWriteFile already creates the parent, and it
		// creates it 0700. This used to do it first at 0755, which made a
		// per-user directory world-readable — exactly the drift fsutil's own
		// comment says it exists to prevent.
		//
		// AtomicWriteFile, like every other persisted file here: os.WriteFile
		// truncates in place, so a full disk or a mid-write exit (which
		// scheduleContainerRestart does) leaves a half-written prompt.
		if err := fsutil.AtomicWriteFile(tuningPath, []byte(req.Content), 0o600); err != nil {
			http.Error(w, "failed to save tuning file", http.StatusInternalServerError)
			return
		}
		// Tuning is now passed to the model per classify call, so no classifier
		// process restart is needed for edits to take effect.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": tuningPath, "restartOk": true, "restartError": ""})
	default:
		// Unreachable today, and that is the point: a third method added to
		// the mux would otherwise fall out of this switch as a silent 200.
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
