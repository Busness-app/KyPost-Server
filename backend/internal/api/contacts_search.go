package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
)

// contactsSearchDefaultLimit and contactsSearchMaxLimit bound the number of
// results returned by GET /api/contacts/search — this is a compose-time
// autocomplete surface, so results stay small even if the caller asks for
// more (unlike /api/mail/search's much larger defaults/cap).
const (
	contactsSearchDefaultLimit = 5
	contactsSearchMaxLimit     = 25
)

// handleContactsSearch serves compose-autocomplete lookups against the
// caller's own address book.
func (s *Server) handleContactsSearch(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	if strings.TrimSpace(q) == "" {
		http.Error(w, "q parameter is required", http.StatusBadRequest)
		return
	}

	limit := contactsSearchDefaultLimit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > contactsSearchMaxLimit {
		limit = contactsSearchMaxLimit
	}

	results, err := store.Search(q, limit)
	if err != nil {
		http.Error(w, "failed to read contacts", http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []contacts.Contact{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"contacts": results})
}
