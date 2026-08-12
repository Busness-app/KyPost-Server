package processor

import (
	"bytes"
	"context"
	"net/mail"
	"strconv"
	"strings"
	"time"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/sendas"
)

// verifyDKIMForDomain indirects imapadapter.VerifyDKIMForDomain so tests in
// this package can reach the verified branch below at all: the real verifier
// resolves the signing domain's public key from live DNS, which no unit test
// here can satisfy. Production never reassigns it; the DKIM crypto itself is
// covered in internal/adapters/imap/dkim_verify_test.go.
var verifyDKIMForDomain = imapadapter.VerifyDKIMForDomain

// verifyDKIMCoversHeader indirects imapadapter.VerifyDKIMCoversHeader for the
// same reason, and is the check that actually gates alias verification: a
// signature must cover the header the code was found in, not merely come from
// the right domain.
var verifyDKIMCoversHeader = imapadapter.VerifyDKIMCoversHeader

// userSendAsStore returns the cached send-as alias store for a user,
// mirroring userMailCacheStore/userRulesStore — the api process
// independently constructs its own sendas.Store over the same on-disk
// send_as_aliases.json (the HTTP handlers from Task 5), so refreshFromDiskLocked
// is what keeps the two processes' in-memory views coherent, exactly as with
// state.Store.
func (p *Poller) userSendAsStore(userID string) (*sendas.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.sendAsStores[userID]; ok {
		return st, nil
	}
	st, err := sendas.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.sendAsStores[userID] = st
	return st, nil
}

// checkPendingSendAsAliases advances every one of userID's pending send-as
// alias verifications by one poll tick.
//
// A pending record whose ExpiresAt has already passed is marked failed and
// is never checked again — no indefinite retry, matching the feature's
// fixed 5-minute verification window.
//
// Every other pending record is checked by searching the user's own INBOX
// for a message whose subject contains the record's VerificationCode. A
// bare subject match is not sufficient on its own — it proves only that
// *some* message with that text exists in an inbox the account owner fully
// controls, which they could trivially fake themselves (e.g. via IMAP
// APPEND, which involves no MTA and lets the owner write any header they
// like). Verification additionally requires that message to carry a
// cryptographically valid DKIM signature (VerifyDKIMForDomain) whose d=
// domain matches the candidate address's own domain — a signature the
// account owner cannot forge without that domain's private key, unlike a
// merely-claimed Authentication-Results header. See dkim_verify.go for the
// full rationale.
//
// Errors from the mail client (search/fetch failures) are logged and
// leave the affected record pending for the next tick — they are not
// escalated to the caller, matching this file's general policy of never
// letting one user's IMAP trouble abort a poll tick.
func (p *Poller) checkPendingSendAsAliases(ctx context.Context, userID string, mail imapadapter.Client) {
	store, err := p.userSendAsStore(userID)
	if err != nil {
		p.log.Error("failed to open send-as store", "user_id", userID, "error", err.Error())
		return
	}

	for _, alias := range store.List() {
		if alias.Status != "pending" {
			continue
		}

		expiresAt, perr := time.Parse(time.RFC3339, alias.ExpiresAt)
		if perr != nil || !expiresAt.After(time.Now()) {
			if err := store.MarkFailed(alias.ID); err != nil {
				p.log.Error("failed to mark expired send-as alias failed",
					"user_id", userID, "alias_id", alias.ID, "error", err.Error())
			}
			continue
		}

		matches, err := mail.SearchMessages(ctx, "INBOX", "subject", alias.VerificationCode, 10)
		if err != nil {
			p.log.Error("send-as verification search failed",
				"user_id", userID, "alias_id", alias.ID, "error", err.Error())
			continue
		}
		if len(matches) == 0 {
			continue
		}

		// Zero on a parse failure, which makes the Date check below inert rather
		// than rejecting everything — the Subject check is the load-bearing one.
		createdAt, _ := time.Parse(time.RFC3339, alias.CreatedAt)

		domain := domainOf(alias.Email)
		verified := false
		for _, m := range matches {
			raw, err := mail.FetchRawMessage(ctx, "INBOX", m.UID)
			if err != nil {
				p.log.Error("send-as verification raw fetch failed",
					"user_id", userID, "alias_id", alias.ID, "uid", strconv.Itoa(m.UID), "error", err.Error())
				continue
			}
			// The verification code lives in the Subject, so the signature must
			// actually cover the Subject — a d= match alone proved nothing
			// about it. RFC 6376 hashes only the headers named in h=, takes the
			// last occurrence of each, and tolerates extras, so an account
			// holder could take any genuinely signed message from the target
			// domain, staple "Subject: <code>" on top, IMAP-APPEND it to their
			// own INBOX, and have the alias verified without ever controlling
			// the address. Run-3 replaced a forgeable Authentication-Results
			// header with real crypto here; this binds that crypto to the thing
			// actually being trusted.
			if !verifyDKIMCoversHeader(raw, domain, "Subject") {
				continue
			}
			// And the signature must cover the From header, checked the same
			// way as Subject. Without this the comparison below is worthless:
			// rawFromAddress reads the FIRST From, while the DKIM header picker
			// scans backwards and signs the LAST, so an unsigned
			// "From: <alias>" stapled above the signed one would satisfy it.
			if !verifyDKIMCoversHeader(raw, domain, "From") {
				continue
			}
			// The signed From must be the alias ITSELF, not merely something at
			// the same domain. Comparing domains meant any account holder with
			// one mailbox at a domain could verify every other address there —
			// including a colleague's — and the instance would then publish
			// their key over WKD under it. autocrypt_harvest.go binds the exact
			// address for the same reason.
			if !strings.EqualFold(strings.TrimSpace(rawFromAddress(raw)), strings.TrimSpace(alias.Email)) {
				continue
			}
			// And the signed Subject must actually CARRY this challenge's code.
			//
			// Everything above proves the message came from the alias's domain
			// with a signed From equal to the alias. None of it proves the
			// message is a response to THIS challenge. Until this check the code
			// was used only as the IMAP SEARCH term — and that search is
			// answered by a server the account holder chose, since
			// POST /api/imap/config stores any host with no connection attempt
			// and no ownership check. So one genuine, unmodified, correctly
			// signed message the target once sent the attacker (any
			// mailing-list post) satisfied the alias.
			//
			// The Subject is already proven DKIM-covered and proven to occur
			// exactly once by the check above, so reading it back here is
			// reading signed data.
			if !strings.Contains(rawSubject(raw), alias.VerificationCode) {
				continue
			}
			// A message that predates the challenge cannot be a response to it.
			// Without this, an attacker's server may serve an old message that
			// happens to quote a code — and codes are not secret from the
			// account holder, who is the one being challenged.
			if sentAt, ok := rawSentAt(raw); ok && sentAt.Before(createdAt) {
				continue
			}
			// An unattended responder is not a person proving control.
			if rawIsAutoReply(raw) {
				continue
			}
			verified = true
			break
		}
		if verified {
			if err := store.MarkVerified(alias.ID); err != nil {
				p.log.Error("failed to mark send-as alias verified",
					"user_id", userID, "alias_id", alias.ID, "error", err.Error())
			}
		}
	}

	if err := store.SweepTerminal(24 * time.Hour); err != nil {
		p.log.Error("send-as terminal sweep failed", "user_id", userID, "error", err.Error())
	}
}

// domainOf returns the portion of email after '@', lowercased, or "" if
// email has no '@' — used to scope the Authentication-Results check to the
// candidate address's own domain, never the account's own.
func domainOf(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 && i+1 < len(email) {
		return strings.ToLower(email[i+1:])
	}
	return ""
}

// rawFromAddress pulls the lowercased addr-spec out of a complete message's
// From header, or "" when it has none.
func rawFromAddress(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return parseFromAddress(msg.Header.Get("From"))
}

// rawSubject returns the message's Subject header, or "" if the message does
// not parse.
//
// Package-level rather than inline in checkPendingSendAsAliases because that
// function's `mail imapadapter.Client` parameter shadows the net/mail import.
func rawSubject(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	return msg.Header.Get("Subject")
}

// rawSentAt returns the message's Date, and whether it parsed. Same shadowing
// reason as rawSubject.
func rawSentAt(raw []byte) (time.Time, bool) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return time.Time{}, false
	}
	t, err := mail.ParseDate(msg.Header.Get("Date"))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// rawIsAutoReply reports whether the message announces itself as machine
// generated.
//
// The probe is sent FROM the requesting account's own address, so an
// out-of-office or helpdesk auto-acknowledgement at the target address returns
// a domain-signed reply that quotes the code in its Subject and carries the
// target's From — satisfying every other check without anyone at that address
// ever reading it. RFC 3834 exists precisely so a responder can be recognised;
// honouring it is what stops an unattended bounce from constituting proof of
// control.
func rawIsAutoReply(raw []byte) bool {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	if v := strings.ToLower(strings.TrimSpace(msg.Header.Get("Auto-Submitted"))); v != "" && v != "no" {
		return true
	}
	for _, h := range []string{"X-Autoreply", "X-Autorespond", "X-Auto-Response-Suppress"} {
		if strings.TrimSpace(msg.Header.Get(h)) != "" {
			return true
		}
	}
	// A mailing list is an unattended REDISTRIBUTOR, which fails this function's
	// premise the same way an auto-responder does: a machine at the alias domain
	// emitting a signed message is not a person proving control of the mailbox.
	//
	// It is the sharper case, because no forgery is involved. A list applying
	// DMARC From-munging (Mailman's dmarc_moderation_action = Munge From, and
	// Google Groups' equivalent) rewrites From to the list address precisely so
	// alignment holds against its own domain — which means it DKIM-signs that
	// rewritten From and the echoed Subject with d=<list domain>. Post a message
	// carrying the challenge code, and the redistributed copy satisfies every
	// other gate here genuinely: real signature, real domain, real From. The
	// code is readable from GET /api/mail/send-as, so the attacker does not even
	// need the server's own probe to reach the list.
	for _, h := range []string{"List-Id", "List-Post", "List-Unsubscribe", "List-Help"} {
		if strings.TrimSpace(msg.Header.Get(h)) != "" {
			return true
		}
	}
	switch strings.ToLower(strings.TrimSpace(msg.Header.Get("Precedence"))) {
	case "auto_reply", "list", "bulk":
		return true
	}
	return false
}
