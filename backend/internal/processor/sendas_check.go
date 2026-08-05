package processor

import (
	"bytes"
	"context"
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"time"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/users"
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
			raw, err := mail.FetchRawMessage(ctx, m.UID)
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

// reconcilePGPUserIDs self-signs a User ID onto the user's existing PGP key
// for every verified send-as address the key does not already carry. It runs
// once per user per tick (right after checkPendingSendAsAliases, see
// runUserTick), which makes it serve two purposes with one code path:
//
//   - an alias verified during this very tick gets its User ID immediately;
//   - an alias verified at any point in the past — including before keys
//     carried alias User IDs at all — is repaired without the user having to
//     regenerate their key or re-verify the address.
//
// It matters because a key that does not carry an address as a User ID is
// unusable for it: WKD import (validateDiscoveredKey), Autocrypt
// (buildAutocryptHeader) and GnuPG's own WKD User ID filtering all discard
// such a key, so serving it under that address would ship bytes nobody
// accepts. The opposite ordering — key generated after the aliases exist —
// is handled in handlePGPIdentityGenerate.
//
// Only *verified* aliases are considered: a User ID is what makes the key
// usable for an address, so an unproven address must never get one.
//
// Like every other late-tick step, it is skipped for a user whose inbox
// fetch failed this tick (tickUser returns early), so an account with broken
// IMAP is repaired on the first tick its mail works again — which is also
// the first tick at which anything else about that account is current.
//
// The steady-state cost is deliberately low: the check reads only the stored
// public key's User IDs, and nothing unseals, re-signs or persists the
// private key unless an address is actually missing. Every failure is logged
// and swallowed — alias verification is never rolled back over a key-update
// problem, and the next tick simply retries. A user with no PGP identity is
// a no-op, not an error.
func (p *Poller) reconcilePGPUserIDs(userID string) {
	store, err := p.userSendAsStore(userID)
	if err != nil {
		p.log.Error("failed to open send-as store for pgp user id reconcile",
			"user_id", userID, "error", err.Error())
		return
	}
	verifiedAliases := store.ListVerified()
	if len(verifiedAliases) == 0 {
		return
	}

	u, err := p.users.Get(userID)
	if err != nil {
		p.log.Error("failed to load user for pgp user id reconcile",
			"user_id", userID, "error", err.Error())
		return
	}
	if u.PGPPublicKey == "" {
		return
	}
	// An end-to-end key cannot be edited here: adding a User ID re-signs the
	// key, which needs the private half, and under client protection this
	// process has no way to obtain it. The browser does this instead, when
	// the user's vault is unlocked. Skipping quietly is correct — this is a
	// background convenience, not something to fail a verification over.
	if !u.HasServerReadableKey() {
		p.log.Info("skipping pgp user id reconcile for client-protected key; the browser will add verified aliases",
			"user_id", userID)
		return
	}

	present, err := pgpmail.UserIDEmails(u.PGPPublicKey)
	if err != nil {
		p.log.Error("failed to read pgp key user ids",
			"user_id", userID, "error", err.Error())
		return
	}
	covered := make(map[string]bool, len(present))
	for _, addr := range present {
		covered[addr] = true
	}
	var missing []string
	for _, alias := range verifiedAliases {
		addr := strings.ToLower(strings.TrimSpace(alias.Email))
		if addr == "" || covered[addr] {
			continue
		}
		covered[addr] = true
		missing = append(missing, addr)
	}
	if len(missing) == 0 {
		return
	}

	identity, err := pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, p.pgpKeyPath)
	if err != nil {
		p.log.Error("failed to open pgp private key for user id reconcile",
			"user_id", userID, "error", err.Error())
		return
	}
	changed := false
	for _, addr := range missing {
		added, err := identity.AddUserID(u.Username, addr)
		if err != nil {
			// One bad address must not cost the others their User ID.
			p.log.Error("failed to add send-as address as pgp user id",
				"user_id", userID, "error", err.Error())
			continue
		}
		changed = changed || added
	}
	if !changed {
		return
	}

	sealed, err := identity.SealPrivateKey(p.pgpKeyPath)
	if err != nil {
		p.log.Error("failed to re-seal pgp private key after user id reconcile",
			"user_id", userID, "error", err.Error())
		return
	}
	// Fingerprint, key ID, source and creation time are all unchanged — the
	// primary key is the same key, only its User ID set grew — so this writes
	// key material only, under the fingerprint it read at the top of the
	// function.
	//
	// That expectation is the point. Everything between the read and here
	// (opening the private key, re-signing each missing User ID, re-sealing)
	// takes hundreds of microseconds, and the user may replace or migrate their
	// key in that window. This used to call SetPGPIdentity, which rewrote the
	// whole identity unconditionally: a key generated during the window was
	// reverted to the stale copy, and a migration to client custody had its
	// browser envelope destroyed and a server-readable key put back.
	//
	// A refusal here is not a failure worth retrying differently — the next
	// tick re-reads whatever key is current and reconciles that one instead.
	if _, err := p.users.UpdatePGPKeyMaterial(userID, identity.Fingerprint,
		identity.ArmoredPublicKey, sealed); err != nil {
		if errors.Is(err, users.ErrPGPFingerprintChanged) || errors.Is(err, users.ErrWouldDowngradeCustody) {
			p.log.Info("pgp key changed while reconciling user ids; leaving the newer key alone",
				"user_id", userID, "reason", err.Error())
			return
		}
		p.log.Error("failed to store pgp identity after user id reconcile",
			"user_id", userID, "error", err.Error())
		return
	}
	p.log.Info("added verified send-as addresses to pgp key",
		"user_id", userID, "count", strconv.Itoa(len(missing)))
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
	return strings.EqualFold(strings.TrimSpace(msg.Header.Get("Precedence")), "auto_reply")
}
