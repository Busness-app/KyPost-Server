package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strings"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/sendas"
)

// maxSendAsAliasesPerUser bounds how many alias records (pending + verified)
// one account may accumulate, to cap the blast radius of the abuse this
// endpoint could otherwise enable (each Create sends an unsolicited email to
// a third party the caller doesn't necessarily control).
const maxSendAsAliasesPerUser = 20

// handleSendAs serves the caller's own send-as alias list and creates new
// pending aliases (dispatching a probe email to the candidate address).
func (s *Server) handleSendAs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		store, err := s.sendAsFor(r)
		if err != nil {
			http.Error(w, "failed to open send-as store", http.StatusInternalServerError)
			return
		}
		list := store.List()
		if list == nil {
			list = []sendas.Alias{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"aliases": list})
	case http.MethodPost:
		s.handleSendAsCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSendAsCreate implements the POST branch of handleSendAs. The
// validation/side-effect ordering below is deliberate — cheap, no-network
// checks reject bad requests before anything touches the rate limiter or the
// network — and must not be reordered.
func (s *Server) handleSendAsCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// 1. Validate and normalize the email.
	parsed, err := mail.ParseAddress(req.Email)
	if err != nil {
		http.Error(w, "invalid email address", http.StatusBadRequest)
		return
	}
	normalizedEmail := strings.ToLower(parsed.Address)

	// 2. Resolve the caller.
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	// 3. Load the caller's own IMAP config.
	imapCfg, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read mail credentials", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "imap configuration is required before sending", http.StatusBadRequest)
		return
	}

	// 4. The caller's own account address is allowed here, deliberately.
	//
	// It used to be rejected as redundant — sending as your own address needs
	// no alias. But WKD publication now requires every address to have passed
	// this same challenge (see publishableAddressesAt), because the IMAP
	// username it previously trusted is self-declared and provably nothing.
	// Rejecting the account address would leave users with no way to prove the
	// one address they most need published. One verification mechanism, every
	// address, including your own.

	// 5. Enforce the per-user cap.
	store, err := s.sendAsFor(r)
	if err != nil {
		http.Error(w, "failed to open send-as store", http.StatusInternalServerError)
		return
	}
	if len(store.List()) >= maxSendAsAliasesPerUser {
		http.Error(w, "too many send-as aliases for this account", http.StatusBadRequest)
		return
	}

	// 6. Rate limit. One atomic check-and-record: adjacent allowed()/record()
	// calls still left a window in which two concurrent POSTs for the same
	// (user, email) pair both observed "allowed" and both mailed the candidate
	// address, which belongs to a third party who did not ask to hear from this
	// server.
	key := ac.UserID + "|" + normalizedEmail
	if allowed, retryAfter := s.sendAsCooldown.tryConsume(key); !allowed {
		retrySeconds := int(retryAfter.Seconds()) + 1
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error":             "too many verification attempts for this address, try again later",
			"retryAfterSeconds": retrySeconds,
		})
		return
	}
	// 7. Create the pending record before attempting to send the probe
	// email. Do not roll this back if sending fails (step 9) — a send
	// failure just means the record sits pending until the (later,
	// not-yet-implemented) verification poller's expiry logic naturally
	// marks it failed.
	alias, err := store.Create(ac.UserID, normalizedEmail, strings.TrimSpace(req.DisplayName))
	if err != nil {
		http.Error(w, "failed to create alias", http.StatusInternalServerError)
		return
	}

	// 8. Resolve the SMTP target.
	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(imapCfg)
	if err != nil {
		http.Error(w, "smtp host is not configured", http.StatusBadRequest)
		return
	}

	// 9. Send the probe email. The pending record created in step 7 remains
	// in place regardless of the outcome.
	msg := mailmsg.Message{
		From:    mailmsg.SanitizeHeaderValue(imapCfg.Username),
		To:      []string{normalizedEmail},
		Subject: "Verify send-as: " + alias.VerificationCode,
		Body:    "This is an automated verification message from KyPost. No action is needed — this check completes automatically. If you don't recognize this, you can ignore it.",
		Mode:    "plain",
	}.Build()

	if err := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, imapCfg.Username, imapCfg.Password, mailmsg.SanitizeHeaderValue(imapCfg.Username), []string{normalizedEmail}, msg); err != nil {
		http.Error(w, fmt.Sprintf("failed to send verification email: %s", err), http.StatusBadGateway)
		return
	}

	// 10. Success response.
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        true,
		"id":        alias.ID,
		"status":    alias.Status,
		"expiresAt": alias.ExpiresAt,
	})
}

// handleSendAsByID deletes one of the caller's own send-as alias records.
func (s *Server) handleSendAsByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		store, err := s.sendAsFor(r)
		if err != nil {
			http.Error(w, "failed to open send-as store", http.StatusInternalServerError)
			return
		}
		record, ok := store.Get(id)
		if !ok {
			http.Error(w, "alias not found", http.StatusNotFound)
			return
		}
		ac, ok := authFromContext(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if record.UserID != ac.UserID {
			// Not 403 — don't reveal to a caller that a given ID exists
			// under a different account.
			http.Error(w, "alias not found", http.StatusNotFound)
			return
		}
		if err := store.Delete(id); err != nil {
			http.Error(w, "failed to delete alias", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
