package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/users"
)

// handlePGPPayload returns the raw OpenPGP payload for one message, so a
// client holding the private key can decrypt it locally.
//
// GET /api/mail/pgp-payload?mailbox=&messageId=<uid>
//
// This endpoint exists because the inbox DTO cannot carry the ciphertext.
// decryptPGPMessageContent deliberately leaves PGPEncryptedPayload populated
// for client-protected accounts, but inboxEmail has no field for it and
// mailcache.Entry does not persist it, so it was dropped at serialization
// and never reached any client — web included. Adding it to every inbox row
// would be the obvious fix and the wrong one: an armored message can be
// megabytes, and the inbox delta path would carry all of them on every poll.
// Fetching one message's ciphertext on demand, the same way attachments are
// already fetched (see serveAttachmentDownload), keeps the list cheap.
//
// It is withMailAuth, not withAuth: a paired mobile device authenticates with
// per-device credentials and no session cookie, and it needs this exactly as
// much as the browser does.
func (s *Server) handlePGPPayload(w http.ResponseWriter, r *http.Request) {
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
	// Only client-protected accounts have any business fetching ciphertext:
	// for a server-protected account the server already decrypted the body
	// into the inbox response, so handing the raw payload back as well would
	// widen exposure for no functional gain.
	if u.PGPProtection() != users.PGPProtectionClient {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this account's PGP key is not client-protected; the server already decrypts these messages",
		})
		return
	}

	mailbox, uid, err := attachmentRequestParams(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	contents, err := mailClient.GetMessageBodies(r.Context(), mailbox, []int{uid})
	if err != nil {
		s.logger.Error("pgp payload fetch failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
		http.Error(w, "failed to fetch message", http.StatusBadGateway)
		return
	}
	content, found := contents[uid]
	if !found {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}
	if content.TooLarge {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": "message exceeds the maximum size this server will hold in memory",
		})
		return
	}

	encrypted := strings.TrimSpace(content.PGPEncryptedPayload)
	signature := strings.TrimSpace(content.PGPSignaturePayload)
	if encrypted == "" && signature == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "message carries no OpenPGP payload"})
		return
	}

	// signerKeys lets the client verify an embedded signature without a
	// second round trip for the whole address book. Public keys only —
	// nothing here is secret.
	var signerKeys []string
	if contactsStore, cerr := s.userContactsStore(ac.UserID); cerr == nil {
		signerKeys = allKnownPGPKeys(contactsStore)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messageId":        uid,
		"mailbox":          mailbox,
		"encryptedPayload": encrypted,
		"signaturePayload": signature,
		"body":             signedOnlyBody(content, encrypted),
		"signerPublicKeys": signerKeys,
	})
}

// signedOnlyBody returns the readable body for a signed-but-not-encrypted
// message, which the client needs alongside the detached signature in order
// to verify it. Encrypted messages have no readable body to return.
func signedOnlyBody(content imapadapter.MessageContent, encryptedPayload string) string {
	if encryptedPayload != "" {
		return ""
	}
	return content.Body
}
