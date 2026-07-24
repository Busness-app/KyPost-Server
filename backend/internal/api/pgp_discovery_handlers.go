package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"kypost-server/backend/internal/pgpdiscovery"
)

// handlePGPDiscoverySettings serves the per-user PGP key-discovery
// preferences: GET reads them (defaults when unset), PUT persists them.
func (s *Server) handlePGPDiscoverySettings(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	dir := s.userStateDir(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		settings, err := pgpdiscovery.Load(dir)
		if err != nil {
			http.Error(w, "failed to read discovery settings", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, settings)
	case http.MethodPut:
		var settings pgpdiscovery.Settings
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&settings); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := pgpdiscovery.Save(dir, settings); err != nil {
			http.Error(w, "failed to save discovery settings", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, settings)
	}
}

// handlePGPDiscoverySuppressions lists the caller's discovery opt-outs.
func (s *Server) handlePGPDiscoverySuppressions(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	list, err := pgpdiscovery.LoadSuppressions(s.userStateDir(ac.UserID))
	if err != nil {
		http.Error(w, "failed to read discovery suppressions", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []pgpdiscovery.Suppression{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"suppressions": list})
}

// handlePGPDiscoverySuppressionByEmail removes one opt-out ("allow discovery
// again"). {email} is percent-decoded by the router; 404 when the address was
// not suppressed.
func (s *Server) handlePGPDiscoverySuppressionByEmail(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	email := strings.TrimSpace(r.PathValue("email"))
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	removed, err := pgpdiscovery.RemoveSuppression(s.userStateDir(ac.UserID), email)
	if err != nil {
		http.Error(w, "failed to update discovery suppressions", http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "suppression not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePGPDiscoverySuppressContact is the explicit "remove key & stop
// rediscovering" action: it clears the contact's PGP key fields (keeping the
// contact) and records an explicit discovery opt-out for each of its
// addresses.
func (s *Server) handlePGPDiscoverySuppressContact(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		ContactUID string `json:"contactUID"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(req.ContactUID)
	if uid == "" {
		http.Error(w, "contactUID is required", http.StatusBadRequest)
		return
	}
	store, err := s.userContactsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	c, found := store.Get(uid)
	if !found || c.Deleted {
		http.Error(w, "contact not found", http.StatusNotFound)
		return
	}
	dir := s.userStateDir(ac.UserID)
	for _, e := range c.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			if err := pgpdiscovery.AddSuppression(dir, v, pgpdiscovery.ReasonExplicit); err != nil {
				http.Error(w, "failed to record discovery suppression", http.StatusInternalServerError)
				return
			}
		}
	}
	c.PGPKey = ""
	c.PGPKeySource = ""
	c.PGPKeyFingerprint = ""
	c.PGPKeyVerified = false
	updated, err := store.Upsert(c)
	if err != nil {
		http.Error(w, "failed to update contact", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
