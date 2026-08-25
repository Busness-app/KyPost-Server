package api

import (
	"errors"
	"net/http"
	"strconv"
)

// handleMailBody returns one message's body, so the inbox list does not have to
// carry every body it will never render.
//
// GET /api/mail/body?mailbox=&messageId=<uid>
//
// The list rows show sender, subject, date and badges; only the opened message
// shows text. Shipping all 500 bodies to render one of them measured 13.3 MiB
// per load against 184 KiB for the same window with bodies=0 — and the SPA
// re-requests that window every 15 seconds. This is the same on-demand shape
// handlePGPPayload and serveAttachmentDownload already use, for the same
// reason.
//
// No PGP handling here on purpose. The server decrypts nothing now (see
// decryptPGPPayload: client custody hands the ciphertext back, server custody
// returns a migration error), so an encrypted message has no plaintext body on
// this side under either mode. The browser fetches ciphertext or signed bytes
// from /api/mail/pgp-payload and renders what it verified itself; this endpoint
// returns exactly the body the list used to carry, and nothing more.
//
// withMailAuth, not withAuth: a paired device authenticates with per-device
// credentials and no session cookie, and needs this as much as the browser.
func (s *Server) handleMailBody(w http.ResponseWriter, r *http.Request) {
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

	// ponytail: straight to IMAP, no cache read. The mail cache already holds
	// this body whenever the window is warm, but exposing a by-UID getter is
	// only worth it if opening a message measures slow — add mailcache.Store.Body
	// and try it here first if it does.
	contents, err := mailClient.GetMessageBodies(r.Context(), mailbox, []int{uid})
	if err != nil {
		s.logger.Error("message body fetch failed", "mailbox", mailbox, "uid", strconv.Itoa(uid), "error", err.Error())
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

	writeJSON(w, http.StatusOK, map[string]any{
		"body":     content.Body,
		"bodyMode": content.BodyMode,
	})
}
