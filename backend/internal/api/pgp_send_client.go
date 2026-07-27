package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/textproto"
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

	// Shape first, sender second. Every delivery is checked for well-formedness
	// before any of them is sent — a malformed delivery at index 3 discovered
	// only after 0, 1 and 2 went out is a partial send the caller cannot undo —
	// and this pass needs no IMAP config, so a malformed request still costs no
	// config read and no SMTP connection.
	for i, delivery := range req.Deliveries {
		recipients, rerr := parseDeliveryRecipients(delivery.Recipients)
		if rerr != nil {
			http.Error(w, fmt.Sprintf("delivery %d: %s", i, rerr), http.StatusBadRequest)
			return
		}
		if len(recipients) == 0 || strings.TrimSpace(delivery.Ciphertext) == "" {
			continue
		}
		if err := validatePGPMimeDeliveryShape(strings.TrimSpace(delivery.Ciphertext)); err != nil {
			http.Error(w, fmt.Sprintf("delivery %d: %s", i, err), http.StatusBadRequest)
			return
		}
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
	headerFrom, envelopeFrom, status, msg := resolveMailFrom(accountAddr, req.From, func() (*sendas.Store, error) {
		return s.sendAsFor(r)
	})
	if status != 0 {
		http.Error(w, msg, status)
		return
	}

	// Now that the authorized From is known, bind every delivery's own From to
	// it. This is the check whose absence let the endpoint relay a fully
	// caller-chosen From — DKIM-aligned on a shared smarthost — straight past
	// the send-as authorization resolveMailFrom exists to enforce.
	for i, delivery := range req.Deliveries {
		ciphertext := strings.TrimSpace(delivery.Ciphertext)
		if ciphertext == "" {
			continue
		}
		if err := validateDeliveryFrom(ciphertext, headerFrom); err != nil {
			http.Error(w, fmt.Sprintf("delivery %d: %s", i, err), http.StatusForbidden)
			return
		}
	}

	// Deliver each ciphertext to its own recipient set. The first is the
	// hard-error send (so the caller learns the account/SMTP is broken); the
	// rest are per-BCC and best-effort, mirroring the server-side path.
	failed := 0
	for i, delivery := range req.Deliveries {
		recipients, _ := parseDeliveryRecipients(delivery.Recipients)
		ciphertext := strings.TrimSpace(delivery.Ciphertext)
		if len(recipients) == 0 || ciphertext == "" {
			continue
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

// parseDeliveryRecipients trims, de-duplicates and *validates* each envelope
// recipient.
//
// The non-PGP send path runs its recipients through parseRecipientList; this
// one only trimmed and de-duplicated, so unparseable strings reached
// client.Rcpt. Two send paths disagreeing about what an address is is the kind
// of gap that grows teeth later, so they now agree.
func parseDeliveryRecipients(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, r := range in {
		raw := strings.TrimSpace(r)
		if raw == "" {
			continue
		}
		parsed, err := mail.ParseAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient address %q", raw)
		}
		key := strings.ToLower(parsed.Address)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, parsed.Address)
	}
	return out, nil
}

// requiredDeliveryHeaders are the RFC 5322 headers a delivery must carry.
//
// SMTPDeliver relays these bytes verbatim — it does not synthesize headers —
// so whatever the client sends is the entire message as far as the receiving
// MTA is concerned. Date is included because a message without one is
// non-conformant and gets stamped by a relay (or not at all) rather than
// reflecting when the sender actually sent it.
var requiredDeliveryHeaders = []string{"From:", "To:", "Subject:", "Date:"}

// forbiddenDeliveryHeaders are trace/authentication headers only a receiving
// MTA may legitimately add. A client that supplies them is asserting a
// delivery history that did not happen — and an Authentication-Results line
// forged here is exactly what the anti-phishing scan and the send-as
// verification both read elsewhere.
var forbiddenDeliveryHeaders = []string{"Received", "Authentication-Results", "Return-Path", "Bcc"}

// validatePGPMimeDelivery rejects a client-supplied delivery that is not a
// complete RFC 5322 message.
//
// The previous check was `HasPrefix("Content-Type:") || contains armor`,
// which accepted a body carrying only Content-Type and MIME-Version — no
// From, To, Subject, or Date. The browser's own wrapAsPGPMime emitted
// exactly that, so this endpoint would have relayed header-less messages
// that receiving MTAs reject or render blank, and the validation that was
// supposed to catch it instead certified it as fine.
//
// Only the header block is inspected. Everything past the blank line is
// ciphertext the server cannot read and has no business parsing.
// authorizedFrom is the header-From resolveMailFrom approved for this caller —
// their own account address, or a verified send-as alias. The delivery's own
// From must equal it.
//
// That binding is the point. This endpoint relays the caller's bytes verbatim,
// and the previous version of this function checked only that a few header
// *names* appeared as substrings and that the armor marker appeared anywhere
// in the delivery — so the From the recipient saw was entirely caller-chosen,
// the body did not have to be encrypted (an HTML comment satisfied the armor
// check), and the whole send-as authorization subsystem was bypassable by
// anyone with a session or a paired device secret. On a shared organizational
// smarthost, mail spoofed this way is DKIM-aligned.
func validatePGPMimeDelivery(delivery, authorizedFrom string) error {
	if err := validatePGPMimeDeliveryShape(delivery); err != nil {
		return err
	}
	return validateDeliveryFrom(delivery, authorizedFrom)
}

// validatePGPMimeDeliveryShape checks everything about a delivery that does not
// depend on who the caller is, so it can run before any per-account state is
// loaded. Split out from the From binding for exactly that reason: a malformed
// request should cost no IMAP config read and no SMTP connection.
func validatePGPMimeDeliveryShape(delivery string) error {
	headerBlock, _, found := strings.Cut(delivery, "\r\n\r\n")
	if !found {
		// Tolerate bare-LF folding from a client that did not use CRLF; the
		// SMTP layer normalizes on the way out.
		headerBlock, _, found = strings.Cut(delivery, "\n\n")
	}
	if !found {
		return errors.New("delivery has no header block: expected RFC 5322 headers followed by a blank line")
	}

	hdr, err := parseDeliveryHeaders(headerBlock)
	if err != nil {
		return fmt.Errorf("delivery headers are not parseable: %w", err)
	}

	var missing []string
	for _, header := range requiredDeliveryHeaders {
		name := textproto.CanonicalMIMEHeaderKey(strings.TrimSuffix(header, ":"))
		if len(hdr[name]) == 0 {
			missing = append(missing, strings.TrimSuffix(header, ":"))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("delivery is missing required header(s): %s", strings.Join(missing, ", "))
	}
	for _, name := range forbiddenDeliveryHeaders {
		if len(hdr[textproto.CanonicalMIMEHeaderKey(name)]) > 0 {
			return fmt.Errorf("delivery must not carry a %s header", name)
		}
	}

	// Exactly one From. Duplicates are refused rather than resolved: which one
	// a receiving MTA honors is not ours to guess, and a second From above a
	// signed one is a standard way to make what a verifier checks and what a
	// reader sees differ.
	if len(hdr["From"]) != 1 {
		return errors.New("delivery must carry exactly one From header")
	}
	if _, err := mail.ParseAddress(hdr["From"][0]); err != nil {
		return errors.New("delivery From header is not a valid address")
	}

	// RFC 3156 shape, rather than "the armor marker appears somewhere". This
	// endpoint exists to relay ciphertext the server cannot read; a cleartext
	// body with the marker buried in it is not that.
	ctype := ""
	if len(hdr["Content-Type"]) > 0 {
		ctype = hdr["Content-Type"][0]
	}
	mediaType, params, err := mime.ParseMediaType(ctype)
	if err != nil {
		return errors.New("delivery is missing a valid Content-Type header")
	}
	if !strings.EqualFold(mediaType, "multipart/encrypted") ||
		!strings.EqualFold(strings.TrimSpace(params["protocol"]), "application/pgp-encrypted") {
		return errors.New(`delivery must be multipart/encrypted with protocol="application/pgp-encrypted"`)
	}
	if !strings.Contains(delivery, "-----BEGIN PGP MESSAGE-----") {
		return errors.New("delivery carries no OpenPGP message")
	}
	return nil
}

// parseDeliveryHeaders reads just the header block, normalizing bare-LF line
// endings first so a client that folded with \n is still parseable.
func parseDeliveryHeaders(headerBlock string) (textproto.MIMEHeader, error) {
	normalized := strings.ReplaceAll(strings.ReplaceAll(headerBlock, "\r\n", "\n"), "\n", "\r\n")
	reader := textproto.NewReader(bufio.NewReader(strings.NewReader(normalized + "\r\n\r\n")))
	return reader.ReadMIMEHeader()
}

// validateDeliveryFrom binds a delivery's own From header to the address
// resolveMailFrom authorized for this caller — their account address, or a
// verified send-as alias.
//
// This is the check whose absence made the endpoint a sender-spoofing relay:
// handleMailSendPGP called resolveMailFrom and discarded its headerFrom
// return, so the From the recipient saw was whatever the caller wrote, relayed
// verbatim over the account's authenticated SMTP session. On a shared
// organizational smarthost that mail is DKIM-aligned and indistinguishable
// from genuine internal mail — and a paired device, which the route table
// deliberately denies send-as management, could produce it.
//
// Shape is assumed already checked by validatePGPMimeDeliveryShape.
func validateDeliveryFrom(delivery, authorizedFrom string) error {
	headerBlock, _, found := strings.Cut(delivery, "\r\n\r\n")
	if !found {
		headerBlock, _, found = strings.Cut(delivery, "\n\n")
	}
	if !found {
		return errors.New("delivery has no header block")
	}
	hdr, err := parseDeliveryHeaders(headerBlock)
	if err != nil {
		return fmt.Errorf("delivery headers are not parseable: %w", err)
	}
	if len(hdr["From"]) != 1 {
		return errors.New("delivery must carry exactly one From header")
	}
	parsedFrom, err := mail.ParseAddress(hdr["From"][0])
	if err != nil {
		return errors.New("delivery From header is not a valid address")
	}
	parsedAuthorized, err := mail.ParseAddress(authorizedFrom)
	if err != nil {
		return errors.New("no authorized From address for this account")
	}
	if !strings.EqualFold(strings.TrimSpace(parsedFrom.Address), strings.TrimSpace(parsedAuthorized.Address)) {
		return errors.New("delivery From is not an address this account may send as")
	}
	return nil
}
