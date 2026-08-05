// Composing and sending mail: recipient parsing, the PGP recipient plan and
// per-recipient delivery split, From resolution, and the send/draft handlers.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/users"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
)

// maxRecipientsPerSend bounds one outbound message's recipient count, well
// above any real send and far below what the 25 MiB body could carry.
const maxRecipientsPerSend = 500

// countRecipients counts comma-separated entries without allocating a parsed
// list, so an oversized request is refused before any per-address work.
func countRecipients(fields ...string) int {
	n := 0
	for _, f := range fields {
		for _, part := range strings.Split(f, ",") {
			if strings.TrimSpace(part) != "" {
				n++
			}
		}
	}
	return n
}

func parseRecipientList(raw string) ([]string, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(raw, ";", ","))
	if normalized == "" {
		return []string{}, nil
	}
	addresses, err := mail.ParseAddressList(normalized)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if addr == nil {
			continue
		}
		clean := strings.TrimSpace(addr.Address)
		if clean == "" {
			continue
		}
		out = append(out, clean)
	}
	return out, nil
}

// decodeMailRequest decodes and validates the shared to/cc/bcc/subject/body/
// mode/attachments JSON body used by both the send and draft-save endpoints.
// On error it returns the client-facing error message alongside the error.
func decodeMailRequest(r *http.Request) (mailRequest, string, error) {
	var raw struct {
		To          string `json:"to"`
		CC          string `json:"cc"`
		BCC         string `json:"bcc"`
		Subject     string `json:"subject"`
		Body        string `json:"body"`
		Mode        string `json:"mode"`
		From        string `json:"from"`
		Attachments []struct {
			Name       string `json:"name"`
			MimeType   string `json:"mimeType"`
			DataBase64 string `json:"dataBase64"`
		} `json:"attachments"`
		Encrypt             bool `json:"encrypt"`
		Sign                bool `json:"sign"`
		AllowPickupFallback bool `json:"allowPickupFallback"`
	}
	// Check the declared size before reading, so an oversized send says so.
	// Without this the LimitReader below just truncates the JSON mid-value and
	// the decoder reports a syntax error, which reaches the user as "invalid
	// request" — indistinguishable from malformed JSON, for what is the single
	// most likely reason a send fails.
	if r.ContentLength > maxMailRequestBytes {
		return mailRequest{}, mailTooLargeMessage, errors.New("request body limit exceeded")
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxMailRequestBytes)).Decode(&raw); err != nil {
		// A chunked request declares no length, so the limit above cannot see
		// it and the reader truncates instead. Truncation surfaces as an
		// unexpected EOF, which is far more often an over-cap body than a
		// client that stopped writing valid JSON halfway.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return mailRequest{}, mailTooLargeMessage, err
		}
		return mailRequest{}, "invalid request", err
	}

	attachments := make([]mailmsg.Attachment, 0, len(raw.Attachments))
	attachmentTotal := 0
	for _, a := range raw.Attachments {
		content, err := base64.StdEncoding.DecodeString(a.DataBase64)
		if err != nil {
			return mailRequest{}, "invalid attachment encoding", err
		}
		attachmentTotal += len(content)
		if attachmentTotal > maxMailAttachmentBytes {
			return mailRequest{}, attachmentsTooLargeMessage,
				errors.New("attachment size limit exceeded")
		}
		attachments = append(attachments, mailmsg.Attachment{
			Name:     a.Name,
			MimeType: a.MimeType,
			Content:  content,
		})
	}

	// Bounded. Key resolution re-reads and re-unmarshals the entire contacts
	// file per address, so an unbounded list made one 25 MiB request into hours
	// of uninterruptible O(addresses x contacts) work that a client disconnect
	// could not stop.
	if n := countRecipients(raw.To, raw.CC, raw.BCC); n > maxRecipientsPerSend {
		return mailRequest{}, "too many recipients", fmt.Errorf("too many recipients: %d (limit %d)", n, maxRecipientsPerSend)
	}

	toList, err := parseRecipientList(raw.To)
	if err != nil || len(toList) == 0 {
		if err == nil {
			err = errors.New("missing to recipient")
		}
		return mailRequest{}, "valid TO recipient is required", err
	}
	ccList, err := parseRecipientList(raw.CC)
	if err != nil {
		return mailRequest{}, "invalid CC recipients", err
	}
	bccList, err := parseRecipientList(raw.BCC)
	if err != nil {
		return mailRequest{}, "invalid BCC recipients", err
	}

	return mailRequest{
		Subject:             raw.Subject,
		Body:                raw.Body,
		EncodedBody:         base64.StdEncoding.EncodeToString([]byte(raw.Body)),
		Mode:                raw.Mode,
		To:                  toList,
		CC:                  ccList,
		BCC:                 bccList,
		Attachments:         attachments,
		Encrypt:             raw.Encrypt,
		Sign:                raw.Sign,
		AllowPickupFallback: raw.AllowPickupFallback,
		From:                raw.From,
	}, "", nil
}

func sanitizeHeaderValue(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
}

// findContactPGPKey looks up email among the store's contacts (case-
// insensitive) and returns its armored PGP public key, if the matching
// contact has one on file.
func findContactPGPKey(store *contacts.Store, email string) (string, bool) {
	target := strings.ToLower(strings.TrimSpace(email))
	if target == "" {
		return "", false
	}
	for _, c := range store.List() {
		if c.PGPKey == "" {
			continue
		}
		for _, e := range c.Emails {
			if strings.ToLower(strings.TrimSpace(e.Value)) == target {
				return c.PGPKey, true
			}
		}
	}
	return "", false
}

// buildPGPRecipientPlan resolves each recipient's contact PGP key and
// builds a pgpRecipientPlan. Recipients are deduplicated case-insensitively
// across To+CC+BCC combined, keeping only the first occurrence — an address
// listed in both To and BCC is treated as a To recipient.
func buildPGPRecipientPlan(ctx context.Context, toList, ccList, bccList []string, resolver *keyResolver) pgpRecipientPlan {
	var plan pgpRecipientPlan
	seen := map[string]bool{}

	// The TIER is load-bearing and must not be collapsed away here: tierKeyChanged
	// carries Usable:false, so returning only (Armored, Usable) made a broken pin
	// indistinguishable from a recipient who never had a key.
	resolve := func(recipient string) (armoredKey string, usable bool, changed bool) {
		rk := resolver.resolve(ctx, recipient)
		return rk.Armored, rk.Usable, rk.Tier == tierKeyChanged
	}

	toCC := append(append([]string{}, toList...), ccList...)
	for _, recipient := range toCC {
		lower := strings.ToLower(strings.TrimSpace(recipient))
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		key, ok, changed := resolve(recipient)
		switch {
		case ok:
			plan.toCCEmails = append(plan.toCCEmails, recipient)
			plan.toCCKeys = append(plan.toCCKeys, key)
		case changed:
			plan.keyChangedEmails = append(plan.keyChangedEmails, recipient)
		default:
			plan.withoutKeyEmails = append(plan.withoutKeyEmails, recipient)
		}
	}
	for _, recipient := range bccList {
		lower := strings.ToLower(strings.TrimSpace(recipient))
		if lower == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		key, ok, changed := resolve(recipient)
		switch {
		case ok:
			plan.bccEmails = append(plan.bccEmails, recipient)
			plan.bccKeys = append(plan.bccKeys, key)
		case changed:
			plan.keyChangedEmails = append(plan.keyChangedEmails, recipient)
		default:
			plan.withoutKeyEmails = append(plan.withoutKeyEmails, recipient)
		}
	}
	return plan
}

// buildPGPDeliveries encrypts msg once for plan's shared To/CC recipients
// (if any) and once individually for each of plan's BCC recipients, so no
// BCC recipient's key ID ever appears in a ciphertext another recipient can
// inspect. signer is passed straight through to EncryptMIME for every
// delivery (nil if the caller didn't request signing).
func buildPGPDeliveries(msg []byte, plan pgpRecipientPlan, signer *pgpmail.Identity) ([]pgpDelivery, error) {
	var deliveries []pgpDelivery
	if len(plan.toCCEmails) > 0 {
		ciphertext, err := pgpmail.EncryptMIME(msg, plan.toCCKeys, signer)
		if err != nil {
			return nil, fmt.Errorf("encrypt to/cc recipients: %w", err)
		}
		deliveries = append(deliveries, pgpDelivery{Recipients: plan.toCCEmails, Ciphertext: ciphertext})
	}
	for i, recipient := range plan.bccEmails {
		ciphertext, err := pgpmail.EncryptMIME(msg, []string{plan.bccKeys[i]}, signer)
		if err != nil {
			return nil, fmt.Errorf("encrypt bcc recipient %s: %w", recipient, err)
		}
		deliveries = append(deliveries, pgpDelivery{Recipients: []string{recipient}, Ciphertext: ciphertext})
	}
	return deliveries, nil
}

// encryptedSentCopy wraps an outbound message as a PGP/MIME copy encrypted to
// the sender's own key, for the Sent folder. Returns nil (and no error) when
// there is no key to encrypt to.
//
// Encrypting to recipients does not require a key of your own — handleMailSend
// only insists on one for signing — so selfArmoredPubKey is genuinely optional
// and its absence is not a failure. The caller keeps today's plaintext copy in
// that case; there is nothing better available.
//
// Passing the same signer used for the deliveries keeps the copy's signature
// state matching what went out, so the reader does not report a signed message
// as unsigned in Sent.
func encryptedSentCopy(msg []byte, selfArmoredPubKey string, signer *pgpmail.Identity) ([]byte, error) {
	if strings.TrimSpace(selfArmoredPubKey) == "" {
		return nil, nil
	}
	// EncryptMIME moves the real Subject inside the ciphertext as a protected
	// header and leaves OuterPlaceholderSubject outside, exactly as it does for
	// the deliveries — so the stored copy hides the same things the wire
	// message does.
	return pgpmail.EncryptMIME(msg, []string{selfArmoredPubKey}, signer)
}

// sentCopyForSend returns the PGP/MIME Sent copy for this send, or nil.
//
// Only an encrypted send gets a wrapped copy. Wrapping an unencrypted one would
// lock the sender out of an outbox they never asked to protect, and would put a
// "PGP: encrypted" badge on a message that went out in the clear — the same
// misreporting this fixes, pointing the other way. An unencrypted send
// therefore returns nil with no warning, and the caller rebuilds the readable
// copy as always.
//
// For an ENCRYPTED send, nil means no Sent copy is saved at all. It does not
// mean "fall back to the readable one" — see sentCopyDraftForSend.
//
// That fallback used to exist, justified by the observation that a
// server-custody account's key is one this server holds anyway, so a readable
// copy revealed nothing to this server that it could not already read. True,
// and beside the point: the Sent copy is APPENDed to the account's IMAP host,
// which is somebody else's machine and holds no key at all. The body and the
// real Subject of every encrypted message landed there in the clear — the exact
// disclosure the sender ticked a box to prevent. The client-custody path
// (sentCopyDraft, pgp_send_client.go) has always refused to save anything
// rather than save cleartext; this is the same refusal, arrived at late.
//
// Losing the copy is a real cost and is never silent. The second return is a
// warning for the send response, because the user asked for encryption, the
// message DID go out, and a log line they will never read is not their answer.
// finishMailSend also reports sentSaved:false, which the composer already
// renders.
//
// The two failure kinds warn differently because the remedy differs: an encrypt
// failure is something to report, while "you have no key of your own" is fixed
// by generating one.
func (s *Server) sentCopyForSend(userID string, msg []byte, req mailRequest, signer *pgpmail.Identity) ([]byte, string) {
	if !req.Encrypt {
		return nil, ""
	}
	const warning = "This message was sent encrypted, but the copy for your Sent folder could not be encrypted, so it was not saved. Your recipients received the message."
	const noKeyWarning = "This message was sent encrypted. You have no PGP key of your own to encrypt a Sent copy to, so no copy was saved. Generate a key to keep copies of the encrypted mail you send."
	u, err := s.users.Get(userID)
	if err != nil {
		s.logger.Error("sent copy not saved: cannot read account", "error", err.Error())
		return nil, warning
	}
	copyBytes, err := encryptedSentCopy(msg, u.PGPPublicKey, signer)
	if err != nil {
		s.logger.Error("sent copy not saved: encrypt failed", "error", err.Error())
		return nil, warning
	}
	if copyBytes == nil {
		// No key of this account's own. Encrypting to recipients never required
		// one, so nothing FAILED — but there is still no copy, and that is not
		// something to leave the sender to discover.
		s.logger.Info("sent copy not saved: account has no pgp key of its own", "user_id", userID)
		return nil, noKeyWarning
	}
	return copyBytes, ""
}

// joinWarnings combines the send warnings into the single response.warning
// field, dropping empties. A send can produce more than one (undelivered BCC
// ciphertexts plus an unencrypted Sent copy) and the user needs both.
func joinWarnings(warnings ...string) string {
	kept := make([]string, 0, len(warnings))
	for _, w := range warnings {
		if strings.TrimSpace(w) != "" {
			kept = append(kept, w)
		}
	}
	return strings.Join(kept, " ")
}

// sentCopyDraftForSend decides what finishMailSend APPENDs to Sent: the
// already-wrapped ciphertext verbatim when there is one, the message rebuilt
// from the request when the send was not encrypted, and NOTHING (save=false)
// for an encrypted send with no ciphertext to append.
//
// The third case is the one worth stating. It is reached when encryption of the
// copy failed, or when the sender has no key of their own, and the only two
// answers available are "save the cleartext" and "save nothing". Saving the
// cleartext puts the body and real Subject of a message the user encrypted onto
// their IMAP provider's disk, which is the disclosure they encrypted to
// prevent, and it is invisible from the composer — the send reports success and
// the copy looks ordinary. Saving nothing loses the record, which is worse for
// bookkeeping and better for the promise the product makes; sentCopyForSend
// warns and finishMailSend reports sentSaved:false, so unlike the disclosure it
// is at least something the sender is told about. sentCopyDraft on the
// client-custody path (pgp_send_client.go) made the same choice.
//
// Verbatim matters for the first case. Rebuilding from Subject/Body would wrap
// a complete PGP/MIME message in a fresh envelope — no reader would decrypt it
// — and would need the real Subject, the value the encryption exists to hide.
//
// Recipient lists stay in the clear either way: the Sent folder listing is
// unusable without them, and SMTP already carried them.
func sentCopyDraftForSend(req mailRequest, toList, ccList, bccList []string, encryptedCopy []byte) (imapadapter.DraftMessage, bool) {
	draft := imapadapter.DraftMessage{To: toList, CC: ccList, BCC: bccList}
	if len(encryptedCopy) > 0 {
		draft.Subject = pgpmail.OuterPlaceholderSubject
		draft.Raw = encryptedCopy
		return draft, true
	}
	if req.Encrypt {
		return imapadapter.DraftMessage{}, false
	}
	draft.Subject = req.Subject
	draft.Body = req.Body
	draft.Mode = req.Mode
	draft.Attachments = req.Attachments
	return draft, true
}

// resolveMailFrom decides the From header value handleMailSend should use,
// given the account's own IMAP username (accountAddr — already sanitized
// and confirmed non-empty by the caller) and the client-requested From
// address (requestedFrom, exactly as decoded from the JSON body — not yet
// trimmed or validated).
//
// If requestedFrom is empty, or names the account's own address
// (case-insensitively), it resolves to accountAddr and aliasStoreFn is
// never called — this preserves today's zero-lookup behavior exactly for
// every existing caller (which never sends `from` at all) and for a caller
// that explicitly re-submits their own address.
//
// Otherwise requestedFrom is parsed as an RFC 5322 address, and
// aliasStoreFn (typically s.sendAsFor(r), passed lazily so it's only
// invoked when actually needed) is consulted for a verified alias matching
// it. A verified alias's stored DisplayName is used to format the
// resolved From via mail.Address.String(), so a display name with special
// characters gets properly quoted/encoded.
//
// On success it returns the resolved header-From and envelope-From values
// and status 0. On failure it returns empty values, along with the exact
// HTTP status code and client-facing message handleMailSend should respond
// with — malformed address (400), alias store unavailable (500), or
// address not a verified alias (403).
//
// headerFrom and envelopeFrom MUST be kept separate by every caller:
// headerFrom may carry a display name (RFC 5322 formatted, for the MIME
// From: header) while envelopeFrom is always a bare addr-spec. net/smtp's
// Mail()/SendMail() never parses the from string it's given — it only
// wraps it verbatim as MAIL FROM:<%s> — so passing a display-name-formatted
// or already-angle-bracketed value as the envelope sender produces a
// malformed SMTP command that real servers reject.
func resolveMailFrom(accountAddr, requestedFrom string, aliasStoreFn func() (*sendas.Store, error)) (headerFrom, envelopeFrom string, status int, msg string) {
	requested := strings.TrimSpace(requestedFrom)
	if requested == "" {
		return accountAddr, accountAddr, 0, ""
	}
	parsed, perr := mail.ParseAddress(requested)
	if perr != nil {
		return "", "", http.StatusBadRequest, "invalid from address"
	}
	candidate := strings.ToLower(parsed.Address)
	if strings.EqualFold(candidate, accountAddr) {
		return accountAddr, accountAddr, 0, ""
	}
	aliasStore, aerr := aliasStoreFn()
	if aerr != nil {
		return "", "", http.StatusInternalServerError, "failed to check send-as aliases"
	}
	alias, ok, ferr := aliasStore.FindVerifiedByEmail(candidate)
	if ferr != nil {
		// Unreadable alias file: a storage fault, not a verdict. Answering 403
		// here would be a guess, and answering from the last good in-memory copy
		// would authorize an alias the account may have deleted.
		return "", "", http.StatusInternalServerError, "failed to check send-as aliases"
	}
	if !ok {
		return "", "", http.StatusForbidden, "the from address is not a verified send-as alias for this account"
	}
	headerFrom = sanitizeHeaderValue((&mail.Address{Name: alias.DisplayName, Address: alias.Email}).String())
	envelopeFrom = sanitizeHeaderValue(alias.Email)
	return headerFrom, envelopeFrom, 0, ""
}

func (s *Server) handleMailSend(w http.ResponseWriter, r *http.Request) {
	req, errMsg, err := decodeMailRequest(r)
	if err != nil {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	toList, ccList, bccList := req.To, req.CC, req.BCC

	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	payload, exists, err := mailmsg.ReadIMAPConfigPayload(s.userIMAPConfigPath(ac.UserID), s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read mail credentials", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "imap configuration is required before sending", http.StatusBadRequest)
		return
	}

	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		http.Error(w, "smtp host is not configured", http.StatusBadRequest)
		return
	}

	accountAddr := sanitizeHeaderValue(payload.Username)
	if accountAddr == "" {
		http.Error(w, "imap username is required for sender", http.StatusBadRequest)
		return
	}
	headerFrom, envelopeFrom, fromStatus, fromMsg := resolveMailFrom(accountAddr, req.From, func() (*sendas.Store, error) {
		return s.sendAsFor(r)
	})
	if fromStatus != 0 {
		http.Error(w, fromMsg, fromStatus)
		return
	}

	autocryptHeader := s.outboundAutocryptHeader(ac.UserID, envelopeFrom)

	msg := mailmsg.Message{
		From:        headerFrom,
		To:          toList,
		CC:          ccList,
		Subject:     req.Subject,
		EncodedBody: req.EncodedBody,
		Mode:        req.Mode,
		Attachments: req.Attachments,
		Autocrypt:   autocryptHeader,
	}.Build()

	// The Sent copy is built from its own source because msg deliberately omits
	// BCC — a delivered message must not name its blind recipients — while a
	// stored copy is the only record the sender has of who they sent to.
	// mailmsg.Message.Build writes Bcc as a header for exactly this case, and
	// the plaintext Sent copy has always carried it. Encrypting msg instead
	// would have dropped it: pgpmail preserves Bcc on the outer envelope
	// (envelopeHeaderOrder) but cannot invent a header the input never had, and
	// SaveSent ignores DraftMessage.BCC whenever Raw is set, so the recipient
	// list travels in these bytes or not at all.
	//
	// Bcc stays on the outer envelope rather than moving inside the ciphertext,
	// matching To and Cc: the Sent listing is unreadable without recipients,
	// and pgpmail's protected headers are deliberately Subject-only.
	sentCopySource := mailmsg.Message{
		From:        headerFrom,
		To:          toList,
		CC:          ccList,
		BCC:         bccList,
		Subject:     req.Subject,
		EncodedBody: req.EncodedBody,
		Mode:        req.Mode,
		Attachments: req.Attachments,
		Autocrypt:   autocryptHeader,
	}.Build()

	var signer *pgpmail.Identity
	if req.Sign || req.Encrypt {
		u, uerr := s.users.Get(ac.UserID)
		// An end-to-end key cannot be used here: the server has no way to
		// open it, by design. Refuse loudly and point at the browser path
		// rather than falling through to sending the message unsigned and
		// unencrypted, which is the one outcome a user who ticked those
		// boxes must never silently get.
		if uerr == nil && u.PGPProtection() == users.PGPProtectionClient {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":            "this account's PGP key is end-to-end protected, so the server cannot sign or encrypt on your behalf",
				"clientSideNeeded": true,
			})
			return
		}
		if uerr == nil && u.HasServerReadableKey() {
			signer, err = pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, s.pgpPrivateKeyPath)
			if err != nil {
				http.Error(w, "failed to load pgp identity", http.StatusInternalServerError)
				return
			}
		} else if req.Sign {
			http.Error(w, "signing requires a pgp identity — generate or import one first", http.StatusBadRequest)
			return
		}
	}
	if req.Sign && signer != nil {
		if status := signer.Status(); !status.Usable() {
			http.Error(w, "cannot sign — your pgp identity is revoked or expired, generate or import a new one", http.StatusBadRequest)
			return
		}
	}

	if !req.Encrypt {
		if req.Sign {
			signed, serr := pgpmail.SignMIME(msg, signer)
			if serr != nil {
				http.Error(w, "failed to sign message", http.StatusInternalServerError)
				return
			}
			msg = signed
		}
		recipients := append(append(append([]string{}, toList...), ccList...), bccList...)
		// Nothing was encrypted, so the Sent copy stays readable.
		s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, recipients, msg, req, nil, "", nil)
		return
	}

	contactsStore, cerr := s.userContactsStore(ac.UserID)
	if cerr != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	discoverySettings, derr := pgpdiscovery.Load(s.userStateDir(ac.UserID))
	if derr != nil {
		http.Error(w, "failed to load pgp discovery settings", http.StatusInternalServerError)
		return
	}
	suppressed, serr := pgpdiscovery.SuppressedSet(s.userStateDir(ac.UserID))
	if serr != nil {
		http.Error(w, "failed to load pgp discovery suppressions", http.StatusInternalServerError)
		return
	}
	resolver := &keyResolver{store: contactsStore, settings: discoverySettings, discover: req.Encrypt, suppressed: suppressed}
	plan := buildPGPRecipientPlan(r.Context(), toList, ccList, bccList, resolver)

	// Refuse before any delivery when a recipient has no usable key and the
	// caller did not opt in. The pickup fallback stores this message's
	// plaintext server-side for seven days and mails the link in the clear,
	// so it is a downgrade the sender chooses, not one they discover later.
	//
	// Ordering matters: nothing has been sent at this point, so a client may
	// re-send with allowPickupFallback set once the user confirms, with no
	// risk of a duplicate or half-delivered message.
	// A broken pin is refused outright, and AllowPickupFallback cannot override
	// it. The pickup fallback exists for recipients who have no key; a recipient
	// whose PINNED key stopped matching is the TOFU control reporting that the
	// key served for this address changed, which is the one case where mailing
	// the plaintext in the clear is worst. Telling the sender "no usable PGP key"
	// and offering the fallback — as this endpoint did — actively invites them to
	// downgrade in exactly that situation.
	//
	// The sender's remedy is to verify the new fingerprint out of band and update
	// the contact, not to send anyway.
	if len(plan.keyChangedEmails) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "the PGP key on file for some recipients no longer matches the key now " +
				"published for their address; verify the new fingerprint with them before sending",
			"keyChangedRecipients":    plan.keyChangedEmails,
			"pickupFallbackAvailable": false,
		})
		return
	}
	if len(plan.withoutKeyEmails) > 0 && !req.AllowPickupFallback {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":                   "some recipients have no usable PGP key; sending them a one-time link stores this message's plaintext on the server for 7 days",
			"keylessRecipients":       plan.withoutKeyEmails,
			"pickupFallbackAvailable": true,
		})
		return
	}

	if len(plan.toCCEmails) == 0 && len(plan.bccEmails) == 0 {
		if !req.AllowPickupFallback {
			http.Error(w, "none of the recipients have a known pgp key — disable encryption or add keys to your contacts first", http.StatusBadRequest)
			return
		}
		// Opted in with nothing to encrypt to: the pickup notifications ARE the
		// entire delivery, so unlike the mixed keyed/keyless path below, their
		// outcome has to be checked before answering, not logged best-effort
		// after. If PAIRING_SECRET is unset, sendPickupNotification fails every
		// recipient immediately (pickup_handlers.go) and nothing goes out at
		// all — answering 200 in that case would silently convert a hard
		// failure into a lie, which is exactly the failure mode a hard 400 used
		// to prevent before this opt-in existed.
		failed := s.sendPickupNotifications(ac.UserID, envelopeFrom, plan.withoutKeyEmails, req.Subject, req.Body, req.Mode, smtpHost, smtpPort, addr, payload.Username, payload.Password)
		total := len(plan.withoutKeyEmails)
		if total > 0 && failed == total {
			http.Error(w, "failed to deliver a pickup link to any recipient; nothing was sent", http.StatusBadGateway)
			return
		}
		extraWarning := ""
		if failed > 0 {
			extraWarning = fmt.Sprintf("failed to deliver a pickup link to %d of %d recipient(s)", failed, total)
		}
		// Passing no recipients is safe — finishMailSend skips SMTP on an empty
		// list and still saves the Sent copy.
		//
		// That copy is encrypted like any other on this path even though the
		// delivery was pickup links rather than PGP: the sender ticked encrypt,
		// and the client-custody path wraps its copy the same way regardless of
		// how many recipients turned out to be keyless. Leaving this one case
		// readable would make the Sent folder's meaning depend on the
		// recipients' key coverage, which the sender cannot see from there.
		sentCopy, copyWarning := s.sentCopyForSend(ac.UserID, sentCopySource, req, encryptSigner(signer, req.Sign))
		if !s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, nil, nil, req, sentCopy, joinWarnings(extraWarning, copyWarning), nil) {
			return
		}
		return
	}

	deliveries, eerr := buildPGPDeliveries(msg, plan, encryptSigner(signer, req.Sign))
	if eerr != nil {
		http.Error(w, "failed to encrypt message", http.StatusInternalServerError)
		return
	}

	// deliveries[0] is always the correct hard-error-gated send: buildPGPDeliveries
	// guarantees the shared To/CC ciphertext (if any) comes first, otherwise the
	// first BCC recipient's ciphertext is deliveries[0]. deliveries is guaranteed
	// non-empty here because the branch above already returned early whenever
	// both plan.toCCEmails and plan.bccEmails were empty, so at least one of
	// them is non-empty by the time buildPGPDeliveries runs. Treating index 0
	// uniformly (rather than special-casing on len(plan.toCCEmails) > 0) avoids
	// a BCC-only send picking an empty "main" delivery, which previously let
	// finishMailSend report ok:true via its empty-recipient-list guard before
	// any of the actual best-effort BCC sends had even been attempted.
	mainRecipients, mainCiphertext := deliveries[0].Recipients, deliveries[0].Ciphertext
	bccDeliveries := deliveries[1:]

	// The remaining deliveries run inside finishMailSend, after the primary
	// send has succeeded and before the response is written. They are still
	// best-effort in the sense that none of them can turn the whole send into a
	// hard error — the keyed recipients above already have the message, so
	// there is nothing to retry wholesale — but "best effort" no longer means
	// "silent". What failed is counted and travels back as response.warning.
	// msg is still the cleartext build here — buildPGPDeliveries encrypted per
	// recipient without touching it — so this wraps the same content the
	// recipients got, to the sender's own key.
	sentCopy, copyWarning := s.sentCopyForSend(ac.UserID, sentCopySource, req, encryptSigner(signer, req.Sign))

	// copyWarning rides in as extraWarning; finishMailSend appends whatever the
	// follow-on deliveries report, so the sender gets both.
	s.finishMailSend(w, r, ac.UserID, smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, toList, ccList, bccList, mainRecipients, mainCiphertext, req, sentCopy, copyWarning, func() string {
		bccFailed := 0
		for _, delivery := range bccDeliveries {
			if err := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, payload.Username, payload.Password, envelopeFrom, delivery.Recipients, delivery.Ciphertext); err != nil {
				s.logger.Error("bcc pgp send failed", "recipient_count", strconv.Itoa(len(delivery.Recipients)), "error", err.Error())
				bccFailed++
			}
		}
		pickupFailed := s.sendPickupNotifications(ac.UserID, envelopeFrom, plan.withoutKeyEmails, req.Subject, req.Body, req.Mode, smtpHost, smtpPort, addr, payload.Username, payload.Password)
		return partialDeliveryWarning(bccFailed, len(bccDeliveries), pickupFailed, len(plan.withoutKeyEmails))
	})
}

// partialDeliveryWarning describes what an encrypted send did not manage to
// deliver, for the response's warning field.
//
// The two kinds are counted separately rather than summed because the sender's
// next move differs. A blind copy that bounced is an address or receiving-server
// problem and the message may still arrive on a retry; a pickup link that never
// went out means that recipient has nothing at all and no idea a message exists.
// Returns "" when everything was delivered, which is the overwhelmingly common
// case and must not decorate a clean send with an empty warning.
func partialDeliveryWarning(bccFailed, bccTotal, pickupFailed, pickupTotal int) string {
	parts := []string{}
	if bccFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d blind copies were not delivered", bccFailed, bccTotal))
	}
	if pickupFailed > 0 {
		parts = append(parts, fmt.Sprintf("%d of %d secure links could not be sent", pickupFailed, pickupTotal))
	}
	return strings.Join(parts, "; ")
}

// sendPickupNotifications mails a pickup link to every keyless recipient,
// logging each individual failure and returning how many failed. Shared by
// the all-keyless opt-in path and the mixed keyed/keyless path so the two
// call sites can't drift apart on the notification loop's behavior — the two
// differ only in what they do with the failure count: the all-keyless path
// has nothing else to fall back on and must check it, the mixed path already
// delivered to the keyed recipients and treats this as best-effort logging.
func (s *Server) sendPickupNotifications(userID, envelopeFrom string, recipients []string, subject, body, mode, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword string) int {
	failed := 0
	for i, recipient := range recipients {
		if err := s.sendPickupNotification(userID, envelopeFrom, recipient, subject, body, mode, smtpHost, smtpPort, addr, smtpUsername, smtpPassword); err != nil {
			// Index, not address: this file is the instance-wide log, which
			// GET /api/logs serves to any admin, and an admin has no mailbox
			// access to other users. See log_privacy_test.go.
			s.logger.Error("pickup notification send failed", "recipient_index", strconv.Itoa(i), "error", err.Error())
			failed++
		}
	}
	return failed
}

// encryptSigner decides which signer identity (if any) should be embedded
// into an encrypted message. Encrypt and Sign are independent per-email
// toggles: an identity being loaded (because Encrypt requires checking
// whether one exists, or because Sign itself was requested) must not imply
// the message gets signed. Only pass a signer through to EncryptMIME when
// the caller explicitly asked to sign — otherwise Encrypt=true, Sign=false
// would silently produce a signed-and-encrypted message whenever the sender
// happens to have a PGP identity configured, costing them deniability they
// never asked to give up.
func encryptSigner(signer *pgpmail.Identity, sign bool) *pgpmail.Identity {
	if !sign {
		return nil
	}
	return signer
}

// finishMailSend sends msg over SMTP to recipients and best-effort saves it
// to the Sent folder, writing the JSON response. Returns false if the send
// itself failed (response already written), so callers with follow-up work
// (e.g. pickup notifications) know not to proceed.
//
// sentCopy is the PGP/MIME copy to append instead of rebuilding the message
// from req. It is nil for an unencrypted send (rebuild as always), and nil for
// an encrypted send whose copy could not be encrypted — in which case nothing
// is appended at all and sentSaved comes back false. An encrypted send used to
// append the rebuilt plaintext unconditionally, which left the cleartext and
// real subject of every encrypted message on the IMAP store and gave the reader
// nothing to derive its "PGP: encrypted" badge from — so the Sent folder showed
// an encrypted send exactly like a cleartext one. See sentCopyDraftForSend.
//
// extraWarning is folded into the response's warning field alongside any
// save-to-Sent warning generated here — the all-keyless opt-in path uses it
// to report partial pickup-notification failures the caller would otherwise
// never see; every other caller passes "".
func (s *Server) finishMailSend(w http.ResponseWriter, r *http.Request, userID, smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, toList, ccList, bccList, recipients []string, msg []byte, req mailRequest, sentCopy []byte, extraWarning string, afterPrimary func() string) bool {
	s.logger.Info("mail send requested", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "recipientCount", strconv.Itoa(len(recipients)))

	if len(recipients) > 0 {
		if sendErr := mailmsg.SMTPDeliver(smtpHost, smtpPort, addr, smtpUsername, smtpPassword, from, recipients, msg); sendErr != nil {
			s.logger.Error("mail send failed", "smtpHost", smtpHost, "smtpPort", strconv.Itoa(smtpPort), "error", sendErr.Error())
			http.Error(w, fmt.Sprintf("failed to send email: %s", sendErr.Error()), http.StatusBadGateway)
			return false
		}
	}

	warning := extraWarning
	// Follow-on deliveries — per-BCC ciphertexts and pickup links — run here,
	// between the primary send and the answer, and never when the primary send
	// failed above.
	//
	// Both halves of that matter. They used to run after finishMailSend had
	// already written {"ok":true}, so a send whose blind copies all bounced
	// reported success and the sender learned nothing; putting them before the
	// response is what lets their outcome reach the person who pressed Send.
	// Keeping them after the primary send is what stops a 502 — which the
	// composer treats as "nothing went out, try again" — from having quietly
	// delivered half the message first, so the retry duplicates it.
	if afterPrimary != nil {
		if followOn := afterPrimary(); followOn != "" {
			if warning != "" {
				warning += "; "
			}
			warning += followOn
		}
	}
	sentSaved := true
	if draft, saveCopy := sentCopyDraftForSend(req, toList, ccList, bccList, sentCopy); !saveCopy {
		// An encrypted send with no ciphertext copy. Nothing is appended — see
		// sentCopyDraftForSend — and the reason already travelled here as
		// extraWarning from sentCopyForSend, so this adds no second warning of
		// its own. It must still report sentSaved:false: the composer renders
		// that, and reporting true for a copy that was deliberately not written
		// would be the same lie the plaintext fallback used to tell.
		sentSaved = false
	} else if mailClient, mailErr := s.userMailClient(userID); mailErr != nil {
		// No IMAP client means no APPEND happened either. This used to leave
		// sentSaved true, which reported a copy that was never written.
		sentSaved = false
		if warning != "" {
			warning += "; "
		}
		warning += "email sent but could not be saved to Sent folder"
		s.logger.Error("mail sent but save-sent unavailable", "error", mailErr.Error())
	} else if err := mailClient.SaveSent(r.Context(), draft); err != nil {
		sentSaved = false
		if warning != "" {
			warning += "; "
		}
		warning += "email sent but could not be saved to Sent folder"
		s.logger.Error("mail sent but save-sent failed", "error", err.Error())
	}
	s.logger.Info("mail send completed", "sentSaved", strconv.FormatBool(sentSaved))

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sentSaved": sentSaved, "warning": warning})
	return true
}

func (s *Server) handleMailDraft(w http.ResponseWriter, r *http.Request) {
	mailClient, err := s.mailFor(r)
	if err != nil {
		if errors.Is(err, errIMAPNotConfigured) {
			http.Error(w, "imap configuration is required before saving drafts", http.StatusBadRequest)
			return
		}
		http.Error(w, "imap client is not configured", http.StatusServiceUnavailable)
		return
	}

	req, errMsg, err := decodeMailRequest(r)
	if err != nil {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}

	if err := mailClient.SaveDraft(r.Context(), imapadapter.DraftMessage{
		To:          req.To,
		CC:          req.CC,
		BCC:         req.BCC,
		Subject:     req.Subject,
		Body:        req.Body,
		Mode:        req.Mode,
		Attachments: req.Attachments,
	}); err != nil {
		http.Error(w, "failed to save draft", http.StatusBadGateway)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
