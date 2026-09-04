package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
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
		// StoreDiscoveredKeys/AdvertiseAutocrypt/PublishWKD are decoded as
		// *bool, mirroring pgpdiscovery.Load's own fix for this exact
		// hazard: all three default on, so a plain bool field would
		// silently persist false whenever a client (e.g. a stale tab
		// loaded before a field was added) PUTs a body that omits them.
		// nil means "field not provided" and keeps whatever is currently
		// stored instead of clobbering it with the zero value.
		var req struct {
			AutoEncryptWhenKeyKnown bool  `json:"autoEncryptWhenKeyKnown"`
			StoreDiscoveredKeys     *bool `json:"storeDiscoveredKeys"`
			AdvertiseAutocrypt      *bool `json:"advertiseAutocrypt"`
			PublishWKD              *bool `json:"publishWKD"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		// Update, not Load-then-Save: the merge below reads the stored value
		// for every omitted field, so two concurrent PUTs (two open tabs)
		// would otherwise both start from the same snapshot and the second
		// write would silently discard the first one's change.
		settings, err := pgpdiscovery.Update(dir, func(current pgpdiscovery.Settings) pgpdiscovery.Settings {
			next := current
			next.AutoEncryptWhenKeyKnown = req.AutoEncryptWhenKeyKnown
			if req.StoreDiscoveredKeys != nil {
				next.StoreDiscoveredKeys = *req.StoreDiscoveredKeys
			}
			if req.AdvertiseAutocrypt != nil {
				next.AdvertiseAutocrypt = *req.AdvertiseAutocrypt
			}
			if req.PublishWKD != nil {
				next.PublishWKD = *req.PublishWKD
			}
			return next
		})
		if err != nil {
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
	c, found, err := store.Get(uid)
	if err != nil {
		http.Error(w, "failed to read contacts", http.StatusInternalServerError)
		return
	}
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
