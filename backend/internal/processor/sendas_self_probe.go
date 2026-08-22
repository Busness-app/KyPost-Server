package processor

import (
	"net/mail"
	"strings"
	"time"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/sendas"
)

// selfProbeRetryInterval is how long to wait before re-probing the account's
// own address after a probe failed to verify. A domain that does not DKIM-sign
// its users' submitted mail can never satisfy the verifier, so that failure is
// usually permanent — but not always (an admin may turn signing on), and the
// probe costs one message. Weekly retries repair the fixable case without
// putting an unexplained message in anyone's inbox on a loop.
const selfProbeRetryInterval = 7 * 24 * time.Hour

// sendSendAsProbe matches mailmsg.SMTPDeliver's signature, indirected as a
// package-level var so tests can intercept the probe without standing up an
// SMTP server — the same seam idiom sendRejectionNotice uses.
var sendSendAsProbe = mailmsg.SMTPDeliver

// ensureOwnAddressProven keeps the account's own address covered by the same
// send-as proof every other publishable address needs.
//
// WKD publication serves a user's key only under addresses proven by the
// send-as challenge (api.publishableAddressesAt). That includes the account's
// own address, because the IMAP username it used to trust is self-declared:
// POST /api/imap/config accepts any username with no connection attempt and no
// ownership challenge, so on an instance with a DNS-verified domain any user
// could name a colleague's address and have their own key served as that
// colleague's. Proving an IMAP login would not fix it either — the user
// chooses the IMAP host too, so a login proves only that they control some
// mailbox somewhere.
//
// The send-as challenge is the one proof this codebase has that actually binds
// an address to its domain, so it is the single gate. This function is what
// stops that gate being a wall: the account's own address is the one case that
// can be proven with no user action at all, because the probe is a self-send.
// It leaves through the account's own submission server, is DKIM-signed by the
// address's own domain, and lands back in the same INBOX
// checkPendingSendAsAliases already searches — so the candidate address, the
// From domain and the DKIM d= all coincide, and the next tick verifies it.
//
// It is no weaker than the alias flow it reuses. Someone claiming a
// colleague's address while pointing IMAP and SMTP at hosts they control can
// put whatever they like in their own INBOX, but they cannot produce that
// domain's DKIM signature over the Subject carrying the code.
//
// Everything here is best-effort and silent on failure: this is a background
// convenience, and no poll tick is worth failing over an SMTP problem. What is
// deliberately *not* silent is the outcome — a probe that never verifies
// leaves a failed record in the user's send-as list (SweepTerminal keeps it),
// so "your key is not being published because we could not prove this address"
// is visible in the UI rather than being an invisible fail-closed.
//
// Like reconcilePGPUserIDs, it runs at the end of a user's tick and so is
// skipped for an account whose inbox fetch failed — which is fine, since an
// account with broken IMAP could not receive the probe anyway.
func (p *Poller) ensureOwnAddressProven(userID string) {
	// Only users who actually publish get an unsolicited message. No key means
	// nothing to serve; PublishWKD off means nothing would be served either.
	u, err := p.users.Get(userID)
	if err != nil || u.PGPPublicKey == "" {
		return
	}
	settings, err := pgpdiscovery.Load(p.userStateDir(userID))
	if err != nil || !settings.PublishWKD {
		return
	}

	payload, exists, err := mailmsg.ReadIMAPConfigPayload(p.userIMAPConfigPath(userID), p.imapKeyPath)
	if err != nil || !exists {
		return
	}
	ownAddress := strings.ToLower(strings.TrimSpace(payload.Username))
	// Plenty of IMAP servers take a bare login name rather than an address.
	// There is nothing to probe and no domain that could ever sign the reply.
	if parsed, perr := mail.ParseAddress(ownAddress); perr != nil || domainOf(parsed.Address) == "" {
		return
	}

	store, err := p.userSendAsStore(userID)
	if err != nil {
		p.log.Error("failed to open send-as store for own-address probe",
			"user_id", userID, "error", err.Error())
		return
	}
	aliases, err := store.List()
	if err != nil {
		p.log.Error("failed to read send-as aliases for own-address probe",
			"user_id", userID, "error", err.Error())
		return
	}
	// An unreadable list must not read as "no probe on record": that is the
	// branch that sends a fresh probe email, so a storage fault would mail one
	// on every tick.
	stale, ok := ownAddressProbeDue(aliases, ownAddress)
	if !ok {
		return
	}

	// A previous probe failed long enough ago to be worth retrying. Clear it
	// first: the store keeps only the current state per address, and leaving
	// the old failure behind would make the list read as two conflicting
	// answers for one address.
	if stale != "" {
		if err := store.Delete(stale); err != nil {
			p.log.Error("failed to clear stale own-address probe",
				"user_id", userID, "error", err.Error())
			return
		}
	}

	smtpHost, smtpPort, addr, err := mailmsg.ResolveSMTPTarget(payload)
	if err != nil {
		return
	}

	alias, err := store.CreateAuto(userID, ownAddress)
	if err != nil {
		p.log.Error("failed to record own-address probe",
			"user_id", userID, "error", err.Error())
		return
	}

	from := mailmsg.SanitizeHeaderValue(payload.Username)
	msg := mailmsg.Message{
		From:    from,
		To:      []string{ownAddress},
		Subject: "Verify send-as: " + alias.VerificationCode,
		Body: "This is an automated verification message from KyPost, confirming that mail addressed to this account really arrives here. " +
			"It is what lets your public key be published for this address. No action is needed — this check completes automatically.",
		Mode: "plain",
	}.Build()

	if err := sendSendAsProbe(smtpHost, smtpPort, addr, payload.Username, payload.Password, from, []string{ownAddress}, msg); err != nil {
		// Nothing left, so nothing to wait for. Drop the record rather than
		// leaving a pending one claiming a probe is in flight — that would
		// block the next tick from retrying for the full 5-minute window over
		// a message that never left the building.
		if derr := store.Delete(alias.ID); derr != nil {
			p.log.Error("failed to roll back own-address probe record",
				"user_id", userID, "error", derr.Error())
		}
		p.log.Error("failed to send own-address verification probe",
			"user_id", userID, "error", err.Error())
		return
	}
	p.log.Info("sent own-address verification probe so this key can be published",
		"user_id", userID)
}

// ownAddressProbeDue decides whether to probe ownAddress, given every alias
// record on file. It returns (id-of-a-stale-failed-record, true) when a probe
// should be sent — the id is "" unless an expired failure needs clearing
// first — and ("", false) when it should not.
//
// Not due when the address is already verified (the proof is in hand), when an
// unexpired pending record exists (a probe is in flight; duplicating it would
// mail the user twice for one answer), or when the last attempt failed within
// selfProbeRetryInterval.
//
// Records for other addresses are ignored entirely: a user's aliases are their
// own business, and only the account address is auto-probed.
func ownAddressProbeDue(aliases []sendas.Alias, ownAddress string) (staleID string, due bool) {
	now := time.Now()
	for _, a := range aliases {
		if !strings.EqualFold(strings.TrimSpace(a.Email), ownAddress) {
			continue
		}
		switch a.Status {
		case "verified":
			return "", false
		case "pending":
			expiresAt, err := time.Parse(time.RFC3339, a.ExpiresAt)
			if err == nil && expiresAt.After(now) {
				return "", false
			}
			// An expired pending record is one checkPendingSendAsAliases has
			// not reached yet; it will mark it failed on this same tick. Leave
			// it alone and reconsider next tick, rather than racing it.
			return "", false
		case "failed":
			failedAt, err := time.Parse(time.RFC3339, a.FailedAt)
			if err == nil && failedAt.After(now.Add(-selfProbeRetryInterval)) {
				return "", false
			}
			staleID = a.ID
		}
	}
	return staleID, true
}
