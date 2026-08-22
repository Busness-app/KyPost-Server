package api

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"kypost-server/backend/internal/groups"
)

type groupPayload struct {
	Name string `json:"name"`
}

func groupFromPayload(id, name string) groups.Group {
	return groups.Group{ID: id, Name: name}
}

// handleGroups serves the caller's own group list and creates new groups.
func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	store, err := s.groupsFor(r)
	if err != nil {
		http.Error(w, "failed to open groups store", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := store.List()
		if err != nil {
			http.Error(w, "failed to read groups", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": list})
	case http.MethodPost:
		var payload groupPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(payload.Name)
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		created, err := store.Upsert(groupFromPayload("", name))
		if err != nil {
			http.Error(w, "failed to create group", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGroupByID renames or deletes a single group. Deleting also strips
// the group's ID from every contact's GroupIDs, since groups.Store itself
// doesn't know about contacts.Store.
func (s *Server) handleGroupByID(w http.ResponseWriter, r *http.Request) {
	store, err := s.groupsFor(r)
	if err != nil {
		http.Error(w, "failed to open groups store", http.StatusInternalServerError)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		_, ok, err := store.Get(id)
		if err != nil {
			http.Error(w, "failed to read groups", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "group not found", http.StatusNotFound)
			return
		}
		var payload groupPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		name := strings.TrimSpace(payload.Name)
		if name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		updated, err := store.Upsert(groupFromPayload(id, name))
		if err != nil {
			http.Error(w, "failed to rename group", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		removed, err := store.Delete(id)
		if err != nil {
			http.Error(w, "failed to delete group", http.StatusInternalServerError)
			return
		}
		if removed {
			if err := s.removeGroupFromContacts(r, id); err != nil {
				http.Error(w, "group deleted but failed to update contacts", http.StatusInternalServerError)
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// removeGroupFromContacts strips a deleted group's ID from every contact
// that referenced it, so Contact.GroupIDs never points at a dead group.
func (s *Server) removeGroupFromContacts(r *http.Request, groupID string) error {
	contactsStore, err := s.contactsFor(r)
	if err != nil {
		return err
	}
	all, err := contactsStore.List()
	if err != nil {
		return err
	}
	for _, c := range all {
		if !slices.Contains(c.GroupIDs, groupID) {
			continue
		}
		c.GroupIDs = slices.DeleteFunc(slices.Clone(c.GroupIDs), func(id string) bool { return id == groupID })
		if _, err := contactsStore.Upsert(c); err != nil {
			return err
		}
	}
	return nil
}
