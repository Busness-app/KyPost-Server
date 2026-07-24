package api

import (
	"encoding/json"
	"io"
	"net/http"

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
