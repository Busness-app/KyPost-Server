package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
)

type pgpIdentityResponse struct {
	Fingerprint string `json:"fingerprint"`
	KeyID       string `json:"keyId"`
	PublicKey   string `json:"publicKey"`
	Source      string `json:"source"`
	CreatedAt   string `json:"createdAt"`
	Revoked     bool   `json:"revoked"`
	Expired     bool   `json:"expired"`
}

func (s *Server) handlePGPIdentityGenerate(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// Generating over an EXISTING identity replaces it, which is the same
	// irreversible act as deleting it — the old key is gone and everything
	// encrypted to it with it. Gated on the same terms (pgp_stepup.go); a first
	// generation, which is what this endpoint is normally for, is not.
	var req struct {
		Password   string `json:"password,omitempty"`
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)
	}
	if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}

	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "failed to load user", http.StatusInternalServerError)
		return
	}

	// The OpenPGP User ID's email must be the address this account actually
	// sends/receives mail as (the configured IMAP username, same address
	// used as the SMTP From in handleMailSend) — not the KyPost login name,
	// which for accounts like "admin" isn't an email address at all and
	// leaves the generated key with no way to tie back to the user's real
	// mailbox.
	imapPayload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read mail configuration", http.StatusInternalServerError)
		return
	}
	if !exists || imapPayload.Username == "" {
		http.Error(w, "configure your mail account before generating a pgp identity", http.StatusBadRequest)
		return
	}

	// Every address this account has already proven it owns — the IMAP
	// account address plus each verified send-as alias — goes onto the key
	// as a User ID, because both WKD serving (validateDiscoveredKey) and
	// Autocrypt advertising (buildAutocryptHeader) refuse a key that does
	// not carry the address in question. Aliases verified *after* this key
	// is generated get their User ID added to the existing key at
	// verification time instead (see the poller's send-as check), so the two
	// orderings converge on the same key.
	//
	// A failure to read the alias store is surfaced rather than swallowed:
	// silently minting a key missing its alias User IDs is invisible to the
	// user and only fixable by regenerating the key.
	sendAsStore, err := s.userSendAsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open send-as store", http.StatusInternalServerError)
		return
	}
	var aliasEmails []string
	for _, alias := range sendAsStore.ListVerified() {
		aliasEmails = append(aliasEmails, alias.Email)
	}

	id, err := pgpmail.GenerateIdentity(u.Username, imapPayload.Username, aliasEmails...)
	if err != nil {
		http.Error(w, "failed to generate pgp identity", http.StatusInternalServerError)
		return
	}
	s.storePGPIdentity(w, ac.UserID, id, "generated")
}

func (s *Server) handlePGPIdentityImport(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		ArmoredPrivateKey string `json:"armoredPrivateKey"`
		Passphrase        string `json:"passphrase"`
		// Step-up credential, required only when this replaces an existing
		// identity — see pgp_stepup.go.
		Password   string `json:"password,omitempty"`
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ArmoredPrivateKey) == "" {
		http.Error(w, "armoredPrivateKey is required", http.StatusBadRequest)
		return
	}
	if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}

	id, err := pgpmail.ImportIdentity(req.ArmoredPrivateKey, req.Passphrase)
	if err != nil {
		http.Error(w, "failed to import pgp identity: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.storePGPIdentity(w, ac.UserID, id, "imported")
}

// storePGPIdentity seals id's private key and persists it to the given
// user, replacing any existing PGP identity, then responds with the public
// view. Shared by generate and import.
func (s *Server) storePGPIdentity(w http.ResponseWriter, userID string, id *pgpmail.Identity, source string) {
	sealed, err := id.SealPrivateKey(s.pgpPrivateKeyPath)
	if err != nil {
		http.Error(w, "failed to seal pgp private key", http.StatusInternalServerError)
		return
	}
	createdAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, source, createdAt); err != nil {
		http.Error(w, "failed to store pgp identity", http.StatusInternalServerError)
		return
	}
	status := id.Status()
	writeJSON(w, http.StatusOK, pgpIdentityResponse{
		Fingerprint: id.Fingerprint,
		KeyID:       id.KeyID,
		PublicKey:   id.ArmoredPublicKey,
		Source:      source,
		CreatedAt:   createdAt,
		Revoked:     status.Revoked,
		Expired:     status.Expired,
	})
}

func (s *Server) handlePGPIdentity(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := s.users.Get(ac.UserID)
		if err != nil {
			http.Error(w, "failed to load user", http.StatusInternalServerError)
			return
		}
		if u.PGPFingerprint == "" {
			http.Error(w, "no pgp identity configured", http.StatusNotFound)
			return
		}
		status, _ := pgpmail.CheckKeyStatus(u.PGPPublicKey)
		writeJSON(w, http.StatusOK, pgpIdentityResponse{
			Fingerprint: u.PGPFingerprint,
			KeyID:       u.PGPKeyID,
			PublicKey:   u.PGPPublicKey,
			Source:      u.PGPKeySource,
			CreatedAt:   u.PGPKeyCreatedAt,
			Revoked:     status.Revoked,
			Expired:     status.Expired,
		})
	case http.MethodDelete:
		// The most destructive operation in this file, and the only one that
		// cannot be undone by any later action: mail already encrypted to this
		// key stays unreadable once the key is gone. A session alone is not
		// enough — see pgp_stepup.go.
		var req struct {
			Password   string `json:"password,omitempty"`
			AuthSecret string `json:"authSecret,omitempty"`
		}
		// An empty body is fine and stays a 401 rather than a 400: an account
		// with no identity has nothing to delete and nothing to confirm, and one
		// that does gets the credential prompt from requirePGPStepUp.
		if r.Body != nil {
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req)
		}
		if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
			return
		}
		if _, err := s.users.ClearPGPIdentity(ac.UserID); err != nil {
			http.Error(w, "failed to delete pgp identity", http.StatusInternalServerError)
			return
		}
		s.logger.Info("pgp identity deleted", "user_id", ac.UserID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
