package api

import (
	"net/http"
	"strings"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/users"
)

// handlePGPBootstrap returns everything a client needs to bring its PGP
// state up from nothing, in one round trip.
//
// GET /api/pgp/bootstrap
//
// A client cannot keep the unwrapped private key across restarts — the web
// vault holds it in page memory only, and the mobile apps are told not to
// put it in the Keystore/Keychain, because anything that survives a restart
// without the password is recoverable without the password. So every cold
// start is a full reload: the app comes up knowing nothing and has to
// rediscover whether this account even has a key, which protection mode it
// is under, whether it must prompt for an unlock, and what public keys it
// needs to verify signatures with.
//
// Doing that as four separate calls (identity, wrapped key, contacts,
// protection mode) means four chances to get a partial answer and render a
// half-initialized UI — the state where an app shows "no PGP identity" to
// someone who has one, or silently treats encrypted mail as unreadable
// because the wrapped-key call was the one that failed. One endpoint gives
// the client a single consistent snapshot to act on.
//
// It is withMailAuth so a paired device can call it with per-device
// credentials; it returns nothing a session-authenticated caller could not
// already obtain.
func (s *Server) handlePGPBootstrap(w http.ResponseWriter, r *http.Request) {
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

	protection := u.PGPProtection()
	resp := map[string]any{
		// hasIdentity is deliberately separate from protection: an account
		// with no key at all and an account whose mode the client does not
		// recognize are different situations, and conflating them is how a
		// client ends up offering "unlock" for a key that does not exist.
		"hasIdentity": u.PGPFingerprint != "",
		"protection":  protection,
		"fingerprint": u.PGPFingerprint,
		"keyId":       u.PGPKeyID,
		"publicKey":   u.PGPPublicKey,
		"keySource":   u.PGPKeySource,
		"createdAt":   u.PGPKeyCreatedAt,
	}

	switch protection {
	case users.PGPProtectionClient:
		// The wrapped envelope is self-describing (kdf, iterations, salt,
		// iv), so the client derives the unwrapping key from what is in the
		// blob rather than from hardcoded parameters. That is what lets the
		// KDF change later without stranding existing clients.
		resp["wrappedPrivateKey"] = u.PGPPrivateKeyWrapped
		resp["unlockRequired"] = true
		resp["canDecryptServerSide"] = false
		resp["migrationAvailable"] = false
	case users.PGPProtectionServer:
		// Legacy: the server still decrypts, so the client has nothing to
		// unlock — but it should offer the one-time migration.
		resp["wrappedPrivateKey"] = ""
		resp["unlockRequired"] = false
		resp["canDecryptServerSide"] = true
		resp["migrationAvailable"] = true
	default:
		resp["wrappedPrivateKey"] = ""
		resp["unlockRequired"] = false
		resp["canDecryptServerSide"] = false
		resp["migrationAvailable"] = false
	}

	// Contact public keys, so a freshly-started client can verify inbound
	// signatures immediately instead of waiting on a contacts sync. Public
	// key material only.
	signerKeys := []string{}
	if contactsStore, cerr := s.userContactsStore(ac.UserID); cerr == nil {
		if keys := allKnownPGPKeys(contactsStore); len(keys) > 0 {
			signerKeys = keys
		}
	}
	resp["signerPublicKeys"] = signerKeys

	// The addresses a newly generated key must carry as User IDs: the IMAP
	// account address plus every verified send-as alias. Both WKD serving
	// and Autocrypt advertising refuse a key that does not carry the address
	// in question, so a client generating a key needs this and must not
	// guess — the login name is frequently not an email address at all.
	// Mirrors handlePGPIdentityGenerate's own derivation.
	resp["suggestedUserIDs"] = s.suggestedKeyUserIDs(ac.UserID)
	resp["displayName"] = u.Username

	// Tell the client where to go for ciphertext rather than making it infer
	// the route, so an older server and a newer app disagree loudly (absent
	// field) instead of silently 404ing every decrypt.
	resp["payloadEndpoint"] = "/api/mail/pgp-payload"

	writeJSON(w, http.StatusOK, resp)
}

// suggestedKeyUserIDs returns the addresses a key generated for userID should
// carry, primary address first. Empty when no mail account is configured —
// the caller surfaces that rather than minting a key with no usable User ID.
func (s *Server) suggestedKeyUserIDs(userID string) []string {
	out := []string{}
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(userID), s.imapConfigKeyPath)
	if err != nil || !exists || strings.TrimSpace(payload.Username) == "" {
		return out
	}
	out = append(out, strings.TrimSpace(payload.Username))

	seen := map[string]bool{strings.ToLower(out[0]): true}
	store, err := s.userSendAsStore(userID)
	if err != nil {
		// A key missing its alias User IDs is only fixable by regenerating,
		// so this is worth a log line rather than a silent partial answer.
		s.logger.Error("failed to open send-as store for key user ids", "user_id", userID, "error", err.Error())
		return out
	}
	for _, alias := range store.ListVerified() {
		addr := strings.TrimSpace(alias.Email)
		if addr == "" || seen[strings.ToLower(addr)] {
			continue
		}
		seen[strings.ToLower(addr)] = true
		out = append(out, addr)
	}
	return out
}
