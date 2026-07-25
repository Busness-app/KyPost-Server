package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/sendas"
)

// maxClientCiphertextBytes bounds one browser-supplied PGP/MIME ciphertext.
// It matches the inbound message cap so an encrypted send is bounded the
// same way a received message is, with headroom for armor overhead.
const maxClientCiphertextBytes = 34 << 20

// clientEncryptedSendRequest is a send whose PGP work already happened in
// the browser. Each delivery is a complete RFC 3156 PGP/MIME message and the
// SMTP recipients it goes to; the server relays them and does not (cannot)
// look inside.
type clientEncryptedSendRequest struct {
	From    string `json:"from"`
	Subject string `json:"subject"`
	// Deliveries are pre-encrypted. Multiple entries exist so BCC recipients
	// each get their own ciphertext and never appear in each other's
	// encryption headers — the same split buildPGPDeliveries makes
	// server-side.
	Deliveries []clientEncryptedDelivery `json:"deliveries"`
	// To/CC/BCC are the plaintext address lists, used only for the Sent-folder
	// copy and for logging. They are not trusted as the SMTP envelope: that
	// comes from each delivery's own Recipients.
	To  []string `json:"to"`
	CC  []string `json:"cc"`
	BCC []string `json:"bcc"`
	// SentCopy is the plaintext body stored in the Sent folder, matching the
	// server-side path's behavior of saving Sent unencrypted so the user can
	// still read their own outbox.
	SentCopy string `json:"sentCopy"`
	Mode     string `json:"mode"`
}

type clientEncryptedDelivery struct {
	Recipients []string `json:"recipients"`
	Ciphertext string   `json:"ciphertext"`
}

// handleMailSendPGP delivers messages the browser encrypted and signed
// itself, for accounts whose PGP key is end-to-end protected.
//
// The server's role here is deliberately reduced to an SMTP relay for its
// own user: it holds the mailbox credentials the browser must not, and it
// has none of the key material it would need to produce or inspect these
// ciphertexts. That asymmetry is the whole design — see
// users.User's PGP block.
func (s *Server) handleMailSendPGP(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}

	var req clientEncryptedSendRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxClientCiphertextBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(req.Deliveries) == 0 {
		http.Error(w, "no deliveries supplied", http.StatusBadRequest)
		return
	}

	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read mail configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "mail account is not configured", http.StatusBadRequest)
		return
	}
	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accountAddr := strings.TrimSpace(payload.Username)
	_, envelopeFrom, status, msg := resolveMailFrom(accountAddr, req.From, func() (*sendas.Store, error) {
		return s.sendAsFor(r)
	})
	if status != 0 {
		http.Error(w, msg, status)
		return
	}

	// Deliver each ciphertext to its own recipient set. The first is the
	// hard-error send (so the caller learns the account/SMTP is broken); the
	// rest are per-BCC and best-effort, mirroring the server-side path.
	failed := 0
	for i, delivery := range req.Deliveries {
		recipients := sanitizeRecipients(delivery.Recipients)
		ciphertext := strings.TrimSpace(delivery.Ciphertext)
		if len(recipients) == 0 || ciphertext == "" {
			continue
		}
		if !strings.HasPrefix(ciphertext, "Content-Type:") && !strings.Contains(ciphertext, "-----BEGIN PGP MESSAGE-----") {
			http.Error(w, "delivery does not look like a PGP/MIME message", http.StatusBadRequest)
			return
		}
		sendErr := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, payload.Username, payload.Password,
			envelopeFrom, recipients, []byte(ciphertext))
		if sendErr == nil {
			continue
		}
		if i == 0 {
			s.logger.Error("client-encrypted mail send failed", "error", sendErr.Error())
			http.Error(w, "failed to send email: "+sendErr.Error(), http.StatusBadGateway)
			return
		}
		failed++
		s.logger.Error("client-encrypted bcc send failed", "recipient", recipients[0], "error", sendErr.Error())
	}

	// Best-effort Sent copy, saved in plaintext exactly as the server-side
	// encrypted path does, so the user can still read their own outbox.
	sentSaved := true
	warning := ""
	if mailClient, mailErr := s.userMailClient(ac.UserID); mailErr == nil {
		if err := mailClient.SaveSent(r.Context(), imapadapter.DraftMessage{
			To:      req.To,
			CC:      req.CC,
			BCC:     req.BCC,
			Subject: req.Subject,
			Body:    req.SentCopy,
			Mode:    req.Mode,
		}); err != nil {
			sentSaved = false
			warning = "email sent but could not be saved to Sent folder"
			s.logger.Error("client-encrypted send: save-sent failed", "error", err.Error())
		}
	}
	if failed > 0 && warning == "" {
		warning = strconv.Itoa(failed) + " bcc delivery(s) failed"
	}
	s.logger.Info("client-encrypted mail send completed",
		"user_id", ac.UserID, "deliveries", strconv.Itoa(len(req.Deliveries)), "failed", strconv.Itoa(failed))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sentSaved": sentSaved, "warning": warning})
}

func sanitizeRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, r := range in {
		addr := strings.TrimSpace(r)
		if addr == "" || seen[strings.ToLower(addr)] {
			continue
		}
		seen[strings.ToLower(addr)] = true
		out = append(out, addr)
	}
	return out
}
