package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/pgpmail"
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
	// The protection gate is applied further down, once this UID's shape is
	// known: it refuses ciphertext, and whether that is what was asked for
	// cannot be decided before the message has been looked at.

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
	hasSignature := strings.TrimSpace(content.PGPSignaturePayload) != ""
	if encrypted == "" && !hasSignature {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "message carries no OpenPGP payload"})
		return
	}

	// Only client-protected accounts have any business fetching CIPHERTEXT:
	// for a server-protected account the server already decrypted the body
	// into the inbox response, so handing the raw payload back as well would
	// widen exposure for no functional gain.
	//
	// That reasoning does not reach a signed-only message, which is why the
	// gate is narrowed to the encrypted case. There is no ciphertext to widen
	// exposure of, the body is already in the inbox response this same account
	// just fetched, and the signed bytes are the only way to check a signature
	// now that the server does not — under either protection mode.
	if encrypted != "" && u.PGPProtection() != users.PGPProtectionClient {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "this account's PGP key is not client-protected; the server already decrypts these messages",
		})
		return
	}

	// The sender the client will display, and the addr-spec the binding uses.
	// Both are shipped: the client renders one and binds on the other, and it
	// must never re-derive the second from the first. See boundSignerKeysForSender.
	//
	// The two are attacker-separable, not just differently-derived: a From
	// with display name "bob@example.com" and mailbox eve@evil.example
	// renders as `sender = "bob@example.com <eve@evil.example>"` while
	// `resolvedSender` — and therefore signerKeys — correctly binds to
	// eve@evil.example. Showing "sender" as the identity next to a verified
	// badge would credit the display-name text an attacker chose freely, not
	// the mailbox that actually signed. Any UI that renders a verification
	// verdict must key it off resolvedSender, never off sender.
	sender := strings.TrimSpace(content.Sender)
	resolvedSender := senderAddrSpec(sender)

	// signerKeys lets the client verify an embedded signature without a
	// second round trip for the whole address book. Public keys only —
	// nothing here is secret.
	//
	// Each key carries the addresses the address book binds it to, so the
	// client accepts a signature only from a key bound to the sender it is
	// displaying. It used to receive every key it held with no binding at all
	// and re-derive one from the keys' User IDs, which is both forgeable (one
	// key, two self-asserted User IDs) and parser-dependent. Narrowed further
	// here to just this message's sender: the client no longer parses the
	// From header itself at all, so this narrowing IS the binding. See
	// boundSignerKeysForSender.
	signerKeys := []boundSignerKey{}
	if contactsStore, cerr := s.userContactsStore(ac.UserID); cerr == nil {
		signerKeys = boundSignerKeysForSender(contactsStore, resolvedSender)
	}

	var signedPartBase64, signaturePayload string
	if encrypted == "" && hasSignature {
		signedPart, armoredSignature := s.signedOnlyParts(r.Context(), mailClient, mailbox, uid)
		if len(signedPart) > 0 && armoredSignature != "" {
			signedPartBase64 = base64.StdEncoding.EncodeToString(signedPart)
			signaturePayload = armoredSignature
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messageId":        uid,
		"mailbox":          mailbox,
		"encryptedPayload": encrypted,
		// The signature and the bytes it covers both come out of the SAME raw
		// fetch. Reading the signature from go-imap's decoded attachment while
		// reading the data from raw bytes would pair two different parses of
		// one message, and a mismatch between them reads to the user as a
		// forged signature.
		"signaturePayload": signaturePayload,
		"signedPartBase64": signedPartBase64,
		// The server's own decoded render. Native clients read this and do not
		// verify. The web client ignores it for a signed message and renders
		// the part it verified instead — a body shown under a verdict must be
		// the body that verdict describes.
		"body":           content.Body,
		"signerKeys":     signerKeys,
		"sender":         sender,
		"resolvedSender": resolvedSender,
	})
}

// signedOnlyParts returns the verbatim signed MIME part and the armored
// detached signature for a signed-but-not-encrypted message, by re-fetching
// the message raw.
//
// The raw fetch is the point. Everything else in the read path holds go-imap's
// MIME-parsed, transfer-decoded copy, and a detached signature covers the
// part's transmitted bytes — so a verdict computed from the parsed copy is
// meaningless, which is precisely the bug this replaced. A second IMAP round
// trip buys a signature check that can actually succeed, and it only happens
// when a reader opens a message already known to carry a signature.
//
// Both values empty with no error means "nothing here to verify": the caller
// ships an empty signedPartBase64 and the client shows its could-not-check
// state rather than a failure.
func (s *Server) signedOnlyParts(ctx context.Context, mailClient imapadapter.Client, mailbox string, uid int) (signedPart []byte, armoredSignature string) {
	raw, err := mailClient.FetchRawMessage(ctx, mailbox, uid)
	if err != nil || len(raw) == 0 {
		s.logger.Info("signed-only raw fetch failed", "mailbox", mailbox, "uid", strconv.Itoa(uid))
		return nil, ""
	}
	part, sig, err := pgpmail.ExtractSignedParts(raw)
	if err != nil {
		return nil, ""
	}
	return part, sig
}
