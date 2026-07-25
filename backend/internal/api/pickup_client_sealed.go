package api

import (
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/users"
)

// maxSealedPickupBytes bounds one browser-sealed pickup blob. Matches the
// inbound message cap with headroom for base64 expansion.
const maxSealedPickupBytes = 34 << 20

// handlePickupCreate stores a browser-encrypted pickup record and returns the
// link to email.
//
// POST /api/pgp/pickup  {"recipient": "...", "sealed": "<opaque>"}
//
// The returned URL carries the record id and its fetch token but NOT the
// decryption key: the caller appends that as a URL fragment. Fragments are
// never transmitted by browsers, so the key reaches the recipient through the
// link without ever reaching this server on the fetch.
//
// The server does see the key once — it relays the notification email that
// contains the link. That is unavoidable while it holds the SMTP credentials,
// and it is a meaningful improvement on the server-sealed path regardless:
// the key is never written to disk, so an attacker who obtains the volume,
// a backup, or the box later gets ciphertext. Only a server compromised at
// the moment of sending sees the key. See docs/E2E_PGP.md.
func (s *Server) handlePickupCreate(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if !s.pairingSecretConfigured() {
		http.Error(w, "pickup links are not configured (PAIRING_SECRET is unset)", http.StatusServiceUnavailable)
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	// Server-protected accounts keep the existing server-sealed path: the
	// server can already read their mailbox, so client-sealing the pickup
	// blob adds machinery without changing what the server can see.
	if u.PGPProtection() != users.PGPProtectionClient {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "client-sealed pickup requires a client-protected PGP key",
		})
		return
	}

	var req struct {
		Recipient string `json:"recipient"`
		Sealed    string `json:"sealed"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxSealedPickupBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	recipient := strings.TrimSpace(req.Recipient)
	sealed := strings.TrimSpace(req.Sealed)
	if recipient == "" || sealed == "" {
		http.Error(w, "recipient and sealed payload are required", http.StatusBadRequest)
		return
	}
	// Refuse anything that looks like it still has readable structure. This
	// is a guard against a client bug shipping plaintext, not a security
	// boundary — the server cannot verify ciphertext it has no key for.
	if !looksLikeSealedBlob(sealed) {
		http.Error(w, "sealed payload does not look encrypted", http.StatusBadRequest)
		return
	}

	id, err := s.pickupStore.CreateClientSealed(ac.UserID, recipient, sealed, pickupLinkTTL)
	if err != nil {
		s.logger.Error("failed to create client-sealed pickup record", "error", err.Error())
		http.Error(w, "failed to create pickup record", http.StatusInternalServerError)
		return
	}
	token, expiresAt, err := s.createPairingToken(id, pairingPurposePickupLink, pickupLinkTTL)
	if err != nil {
		http.Error(w, "failed to create pickup token", http.StatusInternalServerError)
		return
	}

	s.logger.Info("client-sealed pickup record created", "user_id", ac.UserID, "pickup_id", id)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id,
		// The caller appends "#<key>" to this. Nothing here contains the key.
		"url":       s.pickupBaseURL() + "/pickup/" + id + "?t=" + token,
		"expiresAt": expiresAt.Format(time.RFC3339),
	})
}

// looksLikeSealedBlob is a shape check on the JSON envelope the browser
// produces (see frontend/src/lib/pickupCrypto.ts): version, iv, ciphertext.
func looksLikeSealedBlob(sealed string) bool {
	var env struct {
		V          int    `json:"v"`
		IV         string `json:"iv"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal([]byte(sealed), &env); err != nil {
		return false
	}
	return env.V == 1 && strings.TrimSpace(env.IV) != "" && strings.TrimSpace(env.Ciphertext) != ""
}

// handlePickupBlob hands the sealed blob to the recipient's browser, once.
//
// GET /pickup/{id}/blob?t=<token>
//
// Unauthenticated and token-gated, exactly like the pickup page itself — the
// recipient has no account here. Consuming happens on this call rather than
// on the page load, so a link-preview bot that fetches the HTML does not burn
// the message before a human reads it.
func (s *Server) handlePickupBlob(w http.ResponseWriter, r *http.Request) {
	if !s.pairingSecretConfigured() {
		http.Error(w, "pickup links are not configured", http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	token := strings.TrimSpace(r.URL.Query().Get("t"))
	if id == "" || token == "" {
		http.Error(w, "invalid pickup link", http.StatusBadRequest)
		return
	}
	if err := s.validatePairingToken(id, token, pairingPurposePickupLink, time.Now()); err != nil {
		http.Error(w, "this link is invalid or has expired", http.StatusForbidden)
		return
	}

	sealed, err := s.pickupStore.ViewClientSealed(id)
	if errors.Is(err, pgpmail.ErrPickupNotClientSealed) {
		// A server-sealed record reached the client-sealed route. The page
		// handler picks the right renderer, so this only happens if a client
		// constructs the URL itself.
		http.Error(w, "this message is not client-encrypted", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "this message has already been viewed or has expired", http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(sealed))
}

// clientSealedPickupPage is the shell served for a client-sealed record. The
// decryption happens in pickup-decrypt.js, which reads the key from
// location.hash — so the key never reaches this server, and this HTML
// contains no message content at all.
//
// The script is a separate file rather than inline because the app-wide CSP
// sets script-src 'self' with no 'unsafe-inline'; an inline script would be
// blocked, and loosening the CSP for this page would weaken the policy that
// protects the far riskier email-rendering surface.
const clientSealedPickupPage = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Encrypted message</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;line-height:1.5}
pre{white-space:pre-wrap;font-family:inherit;background:#f6f6f6;padding:12px;border-radius:8px}
.err{color:#a00}.muted{color:#666}
</style>
</head><body>
<h1 id="subject">Encrypted message</h1>
<div id="status" class="muted">Decrypting in your browser…</div>
<pre id="body" hidden></pre>
<p id="notice" class="muted" hidden>This message has now been marked as viewed and cannot be retrieved again.</p>
<script src="/pickup-decrypt.js" data-pickup-id="%s" data-pickup-token="%s"></script>
</body></html>`

func (s *Server) servePickupDecryptPage(w http.ResponseWriter, id, token string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// id/token are echoed into attributes; both are already validated as a
	// UUID and an HMAC token, but escape anyway rather than relying on that
	// remaining true.
	_, _ = w.Write([]byte(sprintfPickupPage(html.EscapeString(id), html.EscapeString(token))))
}

func sprintfPickupPage(id, token string) string {
	out := strings.Replace(clientSealedPickupPage, "%s", id, 1)
	return strings.Replace(out, "%s", token, 1)
}
