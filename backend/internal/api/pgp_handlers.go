package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
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

// serverCustodyRetiredMessage answers the two endpoints that used to mint a
// private key this server could open. Both now refuse: the browser generates
// or imports the key, wraps it, and POSTs the opaque envelope to
// /api/pgp/identity/client, so no new account can enter server custody.
//
// They stay routed rather than being deleted so an older client gets this
// sentence instead of a bare 404 it would report as "server unreachable".
const serverCustodyRetiredMessage = "the server no longer creates PGP keys it can read — your browser " +
	"generates the key and wraps it, then stores it with POST /api/pgp/identity/client. " +
	"Update your client."

// serverCustodyMigrationMessage answers an EXISTING server-custody account that
// asks the server to use its key. The key is intact and recoverable; only the
// server's willingness to use it is gone. Every refusal names the way out,
// because the alternative is a user who reads "not supported" as "my mail is
// lost". POST /api/pgp/identity/export-legacy still returns the key, and the
// master key that opens it is deliberately still configured.
const serverCustodyMigrationMessage = "this account's PGP key is held by the server, which is no longer " +
	"supported. Migrate it: POST /api/pgp/identity/export-legacy to get the key back, let your browser " +
	"wrap it under your password, then POST /api/pgp/identity/client. Your key and your existing mail " +
	"are not lost."

func (s *Server) handlePGPIdentityGenerate(w http.ResponseWriter, r *http.Request) {
	http.Error(w, serverCustodyRetiredMessage, http.StatusBadRequest)
}

func (s *Server) handlePGPIdentityImport(w http.ResponseWriter, r *http.Request) {
	http.Error(w, serverCustodyRetiredMessage, http.StatusBadRequest)
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
		// that does gets the credential prompt from requirePGPStepUp. A body
		// that is present but malformed is NOT the same thing — decoding it
		// leaves whichever fields happened to parse, and the least surprising
		// answer for the one irreversible operation in this file is to refuse
		// rather than to act on a half-read confirmation.
		if r.Body != nil {
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				http.Error(w, "invalid request payload", http.StatusBadRequest)
				return
			}
		}
		if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
			return
		}
		if _, err := s.users.ClearPGPIdentity(ac.UserID); err != nil {
			http.Error(w, "failed to delete pgp identity", http.StatusInternalServerError)
			return
		}
		s.clearDeviceEnrollmentsFor(ac.UserID, "identity deleted")
		s.logger.Info("pgp identity deleted", "user_id", ac.UserID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
