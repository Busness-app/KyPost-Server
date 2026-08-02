package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/users"
)

// maxWrappedKeyBytes bounds the opaque client-wrapped envelope. A wrapped
// Curve25519 private key is a couple of KB; an imported RSA-4096 key with
// many User IDs is still well under this. The server never parses the blob,
// so a cap is the only validation available to it.
const maxWrappedKeyBytes = 128 << 10

// handlePGPWrappedKey returns the caller's own wrapped private key envelope
// so their browser can unwrap it locally.
//
// Serving this to the authenticated owner is not a disclosure: the envelope
// is sealed under a key derived from their password, which the server does
// not have and cannot derive (it stores only a scrypt hash). An attacker
// with a stolen session gets a blob they still have to crack the password to
// open — which is the security property the whole mode exists to provide.
func (s *Server) handlePGPWrappedKey(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	if u.PGPFingerprint == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no pgp identity configured"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protection":  u.PGPProtection(),
		"wrapped":     u.PGPPrivateKeyWrapped,
		"fingerprint": u.PGPFingerprint,
		"keyId":       u.PGPKeyID,
		"publicKey":   u.PGPPublicKey,
	})
}

type clientIdentityRequest struct {
	PublicKey string `json:"publicKey"`
	Wrapped   string `json:"wrapped"`
	Source    string `json:"source"`

	// Step-up credential, required only when this REPLACES an existing identity
	// (pgp_stepup.go). Both forms are accepted because a client-protected
	// account never sends its password to this server — see login_params.go.
	Password   string `json:"password,omitempty"`
	AuthSecret string `json:"authSecret,omitempty"`
}

// handlePGPIdentityClient stores an identity whose private half the browser
// generated (or imported) and wrapped itself. The server receives the public
// key and an opaque envelope, and gains no ability to read the user's mail.
//
// The fingerprint and key ID are derived from the uploaded public key here,
// never taken from the request: a client that could assert an arbitrary
// fingerprint could get its own key published under someone else's identity
// through WKD or Autocrypt.
func (s *Server) handlePGPIdentityClient(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req clientIdentityRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxWrappedKeyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Replacing an EXISTING identity needs the account credential, not just the
	// session: the new public key outlives the session, gets published through
	// WKD and Autocrypt, and redirects every future correspondent to it. First
	// -time setup is not gated — see pgp_stepup.go.
	if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}
	wrapped := strings.TrimSpace(req.Wrapped)
	if wrapped == "" {
		http.Error(w, "wrapped private key is required", http.StatusBadRequest)
		return
	}
	info, err := pgpmail.InspectPublicKey(req.PublicKey)
	if err != nil {
		http.Error(w, "invalid public key: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Refuse a key that is already unusable, so a user cannot end up with an
	// identity that silently fails on first send.
	if status, serr := pgpmail.CheckKeyStatus(info.ArmoredPublicKey); serr == nil && !status.Usable() {
		http.Error(w, "this key is revoked or expired", http.StatusBadRequest)
		return
	}

	source := strings.TrimSpace(req.Source)
	if source != "imported" {
		source = "generated"
	}
	u, err := s.users.SetPGPIdentityClientProtected(
		ac.UserID, info.Fingerprint, info.KeyID, info.ArmoredPublicKey,
		wrapped, source, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("pgp identity stored with client-side protection",
		"user_id", u.ID, "fingerprint", u.PGPFingerprint, "source", source)
	writeJSON(w, http.StatusOK, u.Public())
}

// handlePGPRewrapKey replaces the wrapped envelope without touching the
// identity, for when the user changes their password: the wrapping key is
// derived from that password, so the browser unwraps with the old one and
// rewraps with the new one and posts the result here.
//
// If this call is lost (a crash between the password write and this one),
// the stored envelope is still the one wrapped under the OLD password. That
// is recoverable — the user re-enters their previous password once to
// unlock — and is strictly better than the alternative of letting the server
// hold the key so it can rewrap unattended.
func (s *Server) handlePGPRewrapKey(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Wrapped string `json:"wrapped"`
		// Step-up credential. Always required here: rewrapping presupposes an
		// identity to rewrap, so this endpoint is never first-time setup.
		Password   string `json:"password,omitempty"`
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxWrappedKeyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Wrapped) == "" {
		http.Error(w, "wrapped private key is required", http.StatusBadRequest)
		return
	}
	// A stolen session could otherwise overwrite the envelope with a blob whose
	// contents nobody can check — the server cannot open it by design — leaving
	// the owner locked out of every message ever encrypted to them.
	if !s.requirePGPStepUp(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}
	if _, err := s.users.RewrapPGPPrivateKey(ac.UserID, strings.TrimSpace(req.Wrapped)); err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("pgp private key rewrapped", "user_id", ac.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePGPExportLegacyKey hands a legacy server-sealed private key back to
// its owner exactly once per call, so their browser can rewrap it under a
// key the server does not hold and then POST it to
// /api/pgp/identity/client — after which the server-readable copy is gone.
//
// This is the only endpoint in the codebase that returns a private key, and
// it is gated on a fresh password re-entry rather than the session alone. A
// session cookie is a bearer token that could have been stolen; the password
// is the same secret that protects the key everywhere else, so requiring it
// here means this endpoint cannot be used to obtain something the caller
// could not already obtain. It refuses outright once the account is already
// client-protected, so it can never be used to downgrade.
func (s *Server) handlePGPExportLegacyKey(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Password string `json:"password"`
		// AuthSecret is the client-derived credential, for an account whose
		// password never reaches this server. See login_params.go.
		AuthSecret string `json:"authSecret,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	// Shared with the PGP step-up gates (pgp_stepup.go): same throttle, same
	// two credential forms, same answers. This endpoint set the standard the
	// others now meet, and one implementation of it is one place for it to be
	// got right.
	if !s.confirmAccountCredential(w, r, ac.UserID, req.Password, req.AuthSecret) {
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}

	if u.PGPProtection() == users.PGPProtectionClient {
		http.Error(w, "this key is already client-protected", http.StatusConflict)
		return
	}
	if !u.HasServerReadableKey() {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no legacy pgp key to migrate"})
		return
	}
	identity, err := pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, s.pgpPrivateKeyPath)
	if err != nil {
		http.Error(w, "failed to load pgp identity", http.StatusInternalServerError)
		return
	}
	armored, err := identity.ExportArmoredPrivateKey()
	if err != nil {
		http.Error(w, "failed to export pgp identity", http.StatusInternalServerError)
		return
	}
	s.logger.Info("legacy pgp key exported for client-side rewrap", "user_id", ac.UserID)
	writeJSON(w, http.StatusOK, map[string]any{
		"privateKey": armored,
		"publicKey":  identity.ArmoredPublicKey,
	})
}
