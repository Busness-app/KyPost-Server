// Admin-only operations: log tail/list, first-run setup state, manual restart
// and poll triggers, and the classifier connectivity test.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"kypost-server/backend/internal/adapters/classifier"
	"kypost-server/backend/internal/config"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
