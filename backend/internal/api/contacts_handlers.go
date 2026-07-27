package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/fsutil"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/users"
)

// contactPayload is the client-supplied subset of contacts.Contact — it omits
// the server-assigned/bookkeeping fields (uid, rev, deleted, timestamps).
type contactPayload struct {
	FormattedName string                    `json:"fn"`
	GivenName     string                    `json:"givenName,omitempty"`
	FamilyName    string                    `json:"familyName,omitempty"`
	MiddleName    string                    `json:"middleName,omitempty"`
	Prefix        string                    `json:"prefix,omitempty"`
	Suffix        string                    `json:"suffix,omitempty"`
	Nickname      string                    `json:"nickname,omitempty"`
	Org           string                    `json:"org,omitempty"`
	Title         string                    `json:"title,omitempty"`
	Emails        []contacts.ContactValue   `json:"emails,omitempty"`
	Phones        []contacts.ContactValue   `json:"phones,omitempty"`
	Addresses     []contacts.ContactAddress `json:"addresses,omitempty"`
	Notes         string                    `json:"notes,omitempty"`
	Birthday      string                    `json:"birthday,omitempty"`

	// PhotoRef is server-owned: it is set only by POST /api/contacts/{id}/photo
	// and cleared by DELETE. It is serialized so a GET response carries it, but
	// toContact deliberately ignores whatever a client sends back — see the
	// comment there. It used to be copied through, which made the one thing
	// standing between a client string and an os.Stat + http.ServeFile a lone
	// filepath.Base; that blocks traversal but not "..", which resolves to the
	// caller's own state directory.
	PhotoRef           string                        `json:"photoRef,omitempty"`
	GroupIDs           []string                      `json:"groupIDs,omitempty"`
	PGPKey             string                        `json:"pgpKey,omitempty"`
	IMs                []contacts.ContactIM          `json:"ims,omitempty"`
	Websites           []contacts.ContactURL         `json:"websites,omitempty"`
	Relations          []contacts.ContactRelation    `json:"relations,omitempty"`
	Events             []contacts.ContactEvent       `json:"events,omitempty"`
	PhoneticGivenName  string                        `json:"phoneticGivenName,omitempty"`
	PhoneticFamilyName string                        `json:"phoneticFamilyName,omitempty"`
	Department         string                        `json:"department,omitempty"`
	CustomFields       []contacts.ContactCustomField `json:"customFields,omitempty"`
	Pronouns           string                        `json:"pronouns,omitempty"`
}

func (p contactPayload) toContact(uid string) contacts.Contact {
	return contacts.Contact{
		UID:           uid,
		FormattedName: strings.TrimSpace(p.FormattedName),
		GivenName:     p.GivenName,
		FamilyName:    p.FamilyName,
		MiddleName:    p.MiddleName,
		Prefix:        p.Prefix,
		Suffix:        p.Suffix,
		Nickname:      p.Nickname,
		Org:           p.Org,
		Title:         p.Title,
		Emails:        p.Emails,
		Phones:        p.Phones,
		Addresses:     p.Addresses,
		Notes:         p.Notes,
		Birthday:      p.Birthday,
		// PhotoRef is intentionally NOT copied from the payload. It names a
		// file the server writes and later serves; callers do not get to
		// choose it. Callers that need to preserve an existing photo across an
		// update get it carried forward by the store, not echoed by the client.
		GroupIDs:           p.GroupIDs,
		PGPKey:             p.PGPKey,
		IMs:                p.IMs,
		Websites:           p.Websites,
		Relations:          p.Relations,
		Events:             p.Events,
		PhoneticGivenName:  p.PhoneticGivenName,
		PhoneticFamilyName: p.PhoneticFamilyName,
		Department:         p.Department,
		CustomFields:       p.CustomFields,
		Pronouns:           p.Pronouns,
	}
}

// backfillPGPKeyFingerprint gives a TOFU pin to manually/legacy-entered
// contact keys that don't have one yet, so the resolver's key_changed guard
// (gated on pinnedFP != "") protects them too — otherwise an unpinned manual
// key can be silently overwritten by a later WKD lookup once it expires. It
// only fills in the fingerprint; PGPKeySource/PGPKeyVerified are left alone
// so a discovery-set key's provenance isn't relabeled by an unrelated edit.
// An unparseable key is left with an empty fingerprint rather than failing
// the write — the armored text itself is still stored as-is.
func backfillPGPKeyFingerprint(c contacts.Contact) contacts.Contact {
	if c.PGPKey == "" || c.PGPKeyFingerprint != "" {
		return c
	}
	key, err := crypto.NewKeyFromArmored(c.PGPKey)
	if err != nil {
		return c
	}
	c.PGPKeyFingerprint = key.GetFingerprint()
	return c
}

// discoveryCreatedEmails returns the email addresses of the contact at uid if
// it exists and was created by the key-discovery ladder — the set to suppress
// when it is deleted. A non-discovery contact (or a missing one) yields nil,
// so deleting it records no suppression.
func discoveryCreatedEmails(store *contacts.Store, uid string) []string {
	c, ok := store.Get(uid)
	if !ok || !c.DiscoveryCreated {
		return nil
	}
	emails := make([]string, 0, len(c.Emails))
	for _, e := range c.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			emails = append(emails, v)
		}
	}
	return emails
}

// suppressDiscoveryOnDelete records a discovery opt-out (reason "deleted") for
// each address of a removed discovery-created contact, so the ladder does not
// silently re-create it on the next encrypted send. Best-effort: a failed
// write is swallowed because the delete itself already succeeded.
func (s *Server) suppressDiscoveryOnDelete(userID string, emails []string) {
	dir := s.userStateDir(userID)
	for _, e := range emails {
		_ = pgpdiscovery.AddSuppression(dir, e, pgpdiscovery.ReasonDeleted)
	}
}

// handleContacts serves the caller's own address book list and creates new
// contacts.
func (s *Server) handleContacts(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := store.List()
		if list == nil {
			list = []contacts.Contact{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"contacts": list})
	case http.MethodPost:
		var payload contactPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(payload.FormattedName) == "" {
			http.Error(w, "fn is required", http.StatusBadRequest)
			return
		}
		if ac, ok := authFromContext(r); ok {
			payload.GroupIDs = s.sanitizeGroupIDsForUser(ac.UserID, payload.GroupIDs)
		}
		created, err := store.Upsert(backfillPGPKeyFingerprint(payload.toContact("")))
		if err != nil {
			http.Error(w, "failed to create contact", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleContactsDedupe finds and merges duplicate contacts in the caller's own
// address book, returning a report of what merged. Duplicates arrive because
// web CRUD, mobile sync, and the CardDAV client pull each assign their own UIDs.
func (s *Server) handleContactsDedupe(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	report, err := store.Dedupe()
	if err != nil {
		http.Error(w, "failed to dedupe contacts", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleContactByID serves single-contact read/update/delete for the caller's
// own address book.
func (s *Server) handleContactByID(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	uid := strings.TrimSpace(r.PathValue("id"))
	if uid == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		c, ok := store.Get(uid)
		if !ok || c.Deleted {
			http.Error(w, "contact not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, c)
	case http.MethodPut:
		existing, ok := store.Get(uid)
		if !ok || existing.Deleted {
			http.Error(w, "contact not found", http.StatusNotFound)
			return
		}
		var payload contactPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(payload.FormattedName) == "" {
			http.Error(w, "fn is required", http.StatusBadRequest)
			return
		}
		if ac, ok := authFromContext(r); ok {
			payload.GroupIDs = s.sanitizeGroupIDsForUser(ac.UserID, payload.GroupIDs)
		}
		updated, err := store.Upsert(backfillPGPKeyFingerprint(payload.toContact(uid)))
		if err != nil {
			http.Error(w, "failed to update contact", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	case http.MethodDelete:
		emails := discoveryCreatedEmails(store, uid)
		removed, err := store.Delete(uid)
		if err != nil {
			http.Error(w, "failed to delete contact", http.StatusInternalServerError)
			return
		}
		if removed && len(emails) > 0 {
			if ac, ok := authFromContext(r); ok {
				s.suppressDiscoveryOnDelete(ac.UserID, emails)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleContactsBulkDelete deletes multiple contacts in the caller's own
// address book, returning a report of successes and failures.
func (s *Server) handleContactsBulkDelete(w http.ResponseWriter, r *http.Request) {
	store, err := s.contactsFor(r)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	uniqueIDs := make([]string, 0, len(req.IDs))
	seen := map[string]bool{}
	for _, uid := range req.IDs {
		clean := strings.TrimSpace(uid)
		if clean == "" {
			continue
		}
		if seen[clean] {
			continue
		}
		seen[clean] = true
		uniqueIDs = append(uniqueIDs, clean)
	}
	if len(uniqueIDs) == 0 {
		http.Error(w, "at least one id is required", http.StatusBadRequest)
		return
	}

	type bulkDeleteFailure struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	ac, _ := authFromContext(r)
	failures := make([]bulkDeleteFailure, 0)
	processed := 0
	for _, uid := range uniqueIDs {
		emails := discoveryCreatedEmails(store, uid)
		if _, err := store.Delete(uid); err != nil {
			failures = append(failures, bulkDeleteFailure{ID: uid, Error: err.Error()})
			continue
		}
		processed++
		if len(emails) > 0 {
			s.suppressDiscoveryOnDelete(ac.UserID, emails)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        len(failures) == 0,
		"processed": processed,
		"failed":    failures,
	})
}

// davPasswordFile is the on-disk shape of the caller's app-specific CardDAV
// password (a scrypt hash, never the raw secret — the raw value is shown
// exactly once at generation time).
type davPasswordFile struct {
	Hash      string `json:"hash"`
	CreatedAt string `json:"createdAt"`
}

func (s *Server) readDAVPassword(userID string) (davPasswordFile, bool, error) {
	b, err := os.ReadFile(s.userCardDAVAuthPath(userID))
	if err != nil {
		if os.IsNotExist(err) {
			return davPasswordFile{}, false, nil
		}
		return davPasswordFile{}, false, err
	}
	var f davPasswordFile
	if err := json.Unmarshal(b, &f); err != nil {
		return davPasswordFile{}, false, err
	}
	return f, true, nil
}

func (s *Server) writeDAVPassword(userID string, f davPasswordFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(s.userCardDAVAuthPath(userID), b, 0o600)
}

// handleContactsDAVPassword manages the caller's app-specific CardDAV
// password: GET reports whether one is configured, POST (re)generates one
// (returning the raw secret exactly once), DELETE revokes it.
func (s *Server) handleContactsDAVPassword(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		f, exists, err := s.readDAVPassword(ac.UserID)
		if err != nil {
			http.Error(w, "failed to read carddav password state", http.StatusInternalServerError)
			return
		}
		resp := map[string]any{"configured": exists}
		if exists {
			resp["createdAt"] = f.CreatedAt
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		raw, err := randomToken(24)
		if err != nil {
			http.Error(w, "failed to generate password", http.StatusInternalServerError)
			return
		}
		hash, err := users.HashPassword(raw)
		if err != nil {
			http.Error(w, "failed to store password", http.StatusInternalServerError)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		if err := s.writeDAVPassword(ac.UserID, davPasswordFile{Hash: hash, CreatedAt: now}); err != nil {
			http.Error(w, "failed to persist carddav password", http.StatusInternalServerError)
			return
		}
		s.davCredentials.invalidateUser(ac.Username)
		writeJSON(w, http.StatusOK, map[string]any{"password": raw, "createdAt": now})
	case http.MethodDelete:
		if err := os.Remove(s.userCardDAVAuthPath(ac.UserID)); err != nil && !os.IsNotExist(err) {
			http.Error(w, "failed to revoke carddav password", http.StatusInternalServerError)
			return
		}
		s.davCredentials.invalidateUser(ac.Username)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// contactSyncChange is one mobile-side create/update/delete pushed via
// POST /api/contacts/sync. Rev carries the client's last-known revision but
// is not currently used for conflict rejection — v1 policy is last-write-wins
// (see backend/AGENTS.md and Mobile_Contact_Sync.md).
type contactSyncChange struct {
	UID     string `json:"uid"`
	Rev     int64  `json:"rev"`
	Deleted bool   `json:"deleted,omitempty"`
	contactPayload
}

type contactsSyncPushRequest struct {
	BaseCursor int64               `json:"baseCursor"`
	Changes    []contactSyncChange `json:"changes"`
}

// handleContactsSync is the mobile two-way sync endpoint. It is unauthenticated
// by web session — like handleNotificationNativePull, the caller proves
// ownership of a specific paired device with the deviceId + deviceSecret
// minted during registration (POST /api/notifications/native/register), sent
// via the X-Kypost-Device-Id/X-Kypost-Device-Secret headers (see
// device_auth.go).
func (s *Server) handleContactsSync(w http.ResponseWriter, r *http.Request) {
	userID, _, ok, retryAfter := s.deviceAuthFromRequest(r)
	if !ok {
		writeDeviceAuthFailure(w, retryAfter)
		return
	}
	store, err := s.userContactsStore(userID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.writeContactsSyncResponse(w, store, parseNonNegativeInt64Query(r, "since"))
	case http.MethodPost:
		var req contactsSyncPushRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		for _, change := range req.Changes {
			uid := strings.TrimSpace(change.UID)
			if change.Deleted {
				if uid == "" {
					continue
				}
				if _, err := store.Delete(uid); err != nil {
					http.Error(w, "failed to apply change", http.StatusInternalServerError)
					return
				}
				continue
			}
			if strings.TrimSpace(change.FormattedName) == "" {
				continue
			}
			change.GroupIDs = s.sanitizeGroupIDsForUser(userID, change.GroupIDs)
			if _, err := store.Upsert(change.toContact(uid)); err != nil {
				http.Error(w, "failed to apply change", http.StatusInternalServerError)
				return
			}
		}
		s.writeContactsSyncResponse(w, store, req.BaseCursor)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) writeContactsSyncResponse(w http.ResponseWriter, store *contacts.Store, since int64) {
	changed, deleted, cursor, tooOld := store.ChangedSince(since)
	resp := map[string]any{"cursor": cursor, "tooOld": tooOld}
	if !tooOld {
		resp["changed"] = changed
		resp["deleted"] = deleted
	}
	writeJSON(w, http.StatusOK, resp)
}

func parseNonNegativeInt64Query(r *http.Request, key string) int64 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return 0
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
