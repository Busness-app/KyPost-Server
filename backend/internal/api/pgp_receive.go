package api

import (
	"net/mail"
	"strings"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/users"
)

// pgpDecryptResult is the subset of fields both imapadapter.MessageContent
// and imapadapter.UnreadMessage carry for an encrypted message. The two
// shapes are structurally identical here, so the decrypt logic lives once
// and each caller copies fields in and out.
type pgpDecryptResult struct {
	Body string
	// BodyMode is the decrypted display part's render mode ("html"/"plain"),
	// from pgpmail.ParseContent. The outer message's mode says nothing about it:
	// a multipart/encrypted envelope carries no readable text part, so without
	// this the plaintext inside would inherit "plain" and an HTML message would
	// render as escaped source.
	BodyMode string
	// Attachments are the files inside the ciphertext. The inbox paths only
	// need HasAttachments, but the attachment endpoints serve these directly —
	// the outer message has just the armored payload as its single part, so
	// this is the only place the real files exist.
	Attachments       []mailmsg.Attachment
	HasAttachments    bool
	Signed            bool
	Verified          bool
	SignerFingerprint string
	ProtectedSubject  string
	DecryptError      string
	// KeepPayload tells the caller to leave PGPEncryptedPayload in place for
	// the client to decrypt itself, rather than clearing it. True exactly
	// when the account's key is client-protected.
	KeepPayload bool
}

// decryptPGPPayload decrypts payload with userID's private key, when the
// server still holds one it can open.
//
// Under client-side key protection it does NOT decrypt, because there is
// nothing here to decrypt with — that is the entire point of the mode. It
// returns KeepPayload so the ciphertext travels to the browser untouched,
// and the browser unwraps its own key and decrypts there. A server that
// could still read this would not be end-to-end encrypted, whatever the
// README said.
func (s *Server) decryptPGPPayload(userID, payload, senderAddress string) pgpDecryptResult {
	u, err := s.users.Get(userID)
	if err != nil || u.PGPFingerprint == "" {
		return pgpDecryptResult{DecryptError: "no pgp identity configured for this account"}
	}

	if u.PGPProtection() == users.PGPProtectionClient {
		// Hand the ciphertext through. No error: this is the healthy path.
		return pgpDecryptResult{KeepPayload: true}
	}

	if !u.HasServerReadableKey() {
		return pgpDecryptResult{DecryptError: "no pgp private key available for this account"}
	}

	identity, err := pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, s.pgpPrivateKeyPath)
	if err != nil {
		return pgpDecryptResult{DecryptError: "failed to load pgp identity"}
	}

	var signerKeys []string
	if contactsStore, cerr := s.userContactsStore(userID); cerr == nil {
		signerKeys = signerKeysForSender(contactsStore, senderAddress)
	}

	result, err := pgpmail.DecryptMIME(payload, identity, signerKeys)
	if err != nil {
		return pgpDecryptResult{DecryptError: "failed to decrypt message"}
	}
	body, mode, attachments, err := pgpmail.ParseContent(result.Content)
	if err != nil {
		return pgpDecryptResult{DecryptError: "failed to parse decrypted message"}
	}

	out := pgpDecryptResult{
		Body:              body,
		BodyMode:          mode,
		Attachments:       attachments,
		HasAttachments:    len(attachments) > 0,
		Signed:            result.Signed,
		Verified:          result.Verified,
		SignerFingerprint: result.SignerFingerprint,
	}
	if subject, ok := pgpmail.ExtractProtectedSubject(result.Content); ok {
		out.ProtectedSubject = subject
	}
	return out
}

// decryptPGPMessageContent decrypts c's PGPEncryptedPayload where the server
// is able to, and otherwise leaves the ciphertext for the client. On any
// failure it returns c with a PGPDecryptError set rather than erroring the
// whole inbox fetch — one bad message must not break the list.
//
// Keep decryptPGPMessageContent and decryptPGPUnreadMessage in sync — they
// are the same logic over two structurally-identical IMAP types that cannot be
// unified without reflection. A drift is a silent PGP badge bug, so both
// must call applyPGPDecryptResult.
func (s *Server) decryptPGPMessageContent(userID, senderAddress string, c imapadapter.MessageContent) imapadapter.MessageContent {
	c.PGPEncrypted = true
	r := s.decryptPGPPayload(userID, c.PGPEncryptedPayload, senderAddress)
	if r.KeepPayload {
		// ponytail: KeepPayload means Body == "" intentionally — not a missing body.
		// The cache warm at server_inbox.go:513 must treat this as healthy.
		return c
	}
	c.PGPEncryptedPayload = ""
	if r.DecryptError != "" {
		c.PGPDecryptError = r.DecryptError
		return c
	}
	applyPGPDecryptResult(&c.Body, &c.BodyMode, &c.HasAttachments, &c.PGPSigned, &c.PGPVerified, &c.PGPSignerFingerprint, &c.PGPProtectedSubject, r)
	return c
}

// decryptPGPUnreadMessage mirrors decryptPGPMessageContent for the
// imapadapter.UnreadMessage shape used by ListUnreadMessages's classic
// (non-delta) inbox path.
func (s *Server) decryptPGPUnreadMessage(userID string, msg imapadapter.UnreadMessage) imapadapter.UnreadMessage {
	msg.PGPEncrypted = true
	r := s.decryptPGPPayload(userID, msg.PGPEncryptedPayload, msg.Sender)
	if r.KeepPayload {
		return msg
	}
	msg.PGPEncryptedPayload = ""
	if r.DecryptError != "" {
		msg.PGPDecryptError = r.DecryptError
		return msg
	}
	applyPGPDecryptResult(&msg.Body, &msg.BodyMode, &msg.HasAttachments, &msg.PGPSigned, &msg.PGPVerified, &msg.PGPSignerFingerprint, &msg.PGPProtectedSubject, r)
	return msg
}

func applyPGPDecryptResult(body *string, mode *string, hasAttachments *bool, signed *bool, verified *bool, fingerprint *string, protectedSubject *string, r pgpDecryptResult) {
	*body = r.Body
	*mode = r.BodyMode
	*hasAttachments = r.HasAttachments
	*signed = r.Signed
	*verified = r.Verified
	*fingerprint = r.SignerFingerprint
	if r.ProtectedSubject != "" {
		*protectedSubject = r.ProtectedSubject
	}
}

// verifySignedOnlyMessageContent verifies c's PGPSignaturePayload — a
// detached signature from an RFC 3156 multipart/signed (signed but not
// encrypted) message — against the contact keys bound to the claimed sender,
// the same signer lookup decryptPGPPayload uses. This needs only public keys, so it
// works identically under both protection modes. Verification is
// best-effort per pgpmail.VerifyDetached's doc comment: third-party MIME
// canonicalization can differ from what was actually signed, so a
// verification failure just leaves PGPVerified false rather than erroring
// the whole inbox fetch.
//
// Keep verifySignedOnlyMessageContent and verifySignedOnlyUnreadMessage in sync.
func (s *Server) verifySignedOnlyMessageContent(userID, senderAddress string, c imapadapter.MessageContent) imapadapter.MessageContent {
	c.PGPSigned = true
	sig := c.PGPSignaturePayload
	c.PGPSignaturePayload = ""
	verified, fingerprint := s.verifyDetachedForUser(userID, c.Body, sig, senderAddress)
	c.PGPVerified = verified
	c.PGPSignerFingerprint = fingerprint
	return c
}

// verifySignedOnlyUnreadMessage mirrors verifySignedOnlyMessageContent for
// the imapadapter.UnreadMessage shape used by ListUnreadMessages's classic
// (non-delta) inbox path.
func (s *Server) verifySignedOnlyUnreadMessage(userID string, msg imapadapter.UnreadMessage) imapadapter.UnreadMessage {
	msg.PGPSigned = true
	sig := msg.PGPSignaturePayload
	msg.PGPSignaturePayload = ""
	verified, fingerprint := s.verifyDetachedForUser(userID, msg.Body, sig, msg.Sender)
	msg.PGPVerified = verified
	msg.PGPSignerFingerprint = fingerprint
	return msg
}

func (s *Server) verifyDetachedForUser(userID, body, sig, senderAddress string) (verified bool, fingerprint string) {
	contactsStore, err := s.userContactsStore(userID)
	if err != nil {
		return false, ""
	}
	signerKeys := signerKeysForSender(contactsStore, senderAddress)
	if len(signerKeys) == 0 {
		return false, ""
	}
	result, err := pgpmail.VerifyDetached([]byte(body), sig, signerKeys)
	if err != nil {
		return false, ""
	}
	return result.Verified, result.SignerFingerprint
}

// boundSignerKey is one address-bound contact key as the client sees it.
//
// Verified and Source exist because a flat "signature verified" would
// claim identity on evidence that often shows only continuity: most keys
// arrive by Autocrypt harvest, and TOFU guarantees "same key as last
// time", not "this is who they say they are". The client renders the two
// differently.
//
// Conflict reports a contact whose stored key no longer matches its TOFU
// pin. Such a contact used to be skipped, so a CHANGED key reached the
// client as "no key bound to this sender" — indistinguishable from an
// ordinary new correspondent, which is the one case TOFU must shout
// about. PublicKey is deliberately empty on a conflicted entry: it can
// never be trusted to verify anything, and shipping it invites a client
// to try.
//
// Nothing secret crosses the wire. This is the user's own address book
// describing itself, and the public key was already here.
type boundSignerKey struct {
	Addresses []string `json:"addresses"`
	PublicKey string   `json:"publicKey"`
	Verified  bool     `json:"verified,omitempty"`
	Source    string   `json:"source,omitempty"`
	Conflict  bool     `json:"conflict,omitempty"`
}

// senderAddrSpec extracts the bare addr-spec from a From header value.
//
// The inbox path carries the RAW header — imap.Overview.Sender is
// e.From.String(), which go-imap renders as `Name <addr>` whenever a display
// name is present. Comparing that against an address matched nothing, so the
// binding below silently returned no keys and the signature indicator vanished
// for every legitimately signed message from a correspondent who has a display
// name. Meanwhile a bare `From: bob@example.com` — the form an attacker
// controls and therefore always chooses — went on matching. A binding that
// only ever fires for the attacker is worse than no binding.
//
// mail.ParseAddressList is the primary parser. It rejects some headers that
// arrive in real mail (unquoted specials in the display name), so the
// angle-addr fallback covers those rather than failing the whole verification.
// A multi-address From is rejected — RFC 5322 allows it, but this binding must
// be deterministic: the first address wins for an attacker who lists two.
func senderAddrSpec(sender string) string {
	raw := strings.TrimSpace(sender)
	if raw == "" {
		return ""
	}
	if list, err := mail.ParseAddressList(raw); err == nil {
		if len(list) == 1 {
			return strings.ToLower(strings.TrimSpace(list[0].Address))
		}
		if len(list) > 1 {
			// ponytail: multiple addresses — attacker-controlled ordering;
			// returning none forces verification to fail closed rather than
			// crediting the first attacker-chosen address.
			return ""
		}
	}
	if open := strings.LastIndex(raw, "<"); open >= 0 {
		if close := strings.Index(raw[open+1:], ">"); close >= 0 {
			candidate := strings.ToLower(strings.TrimSpace(raw[open+1 : open+1+close]))
			if candidate != "" {
				return candidate
			}
		}
	}
	// ponytail: fall back to raw lowercased — caller will handle "" as no keys
	// rather than silently crediting a display name. See testdata/from-corpus.json
	return strings.ToLower(raw)
}

// contactBindsAddress reports whether the address book itself says this
// contact is senderAddress — i.e. the address appears among the contact's own
// email addresses.
func contactBindsAddress(c contacts.Contact, senderAddress string) bool {
	for _, e := range c.Emails {
		if strings.ToLower(strings.TrimSpace(e.Value)) == senderAddress {
			return true
		}
	}
	return false
}

// keyMatchesPin reports whether a contact's stored key is the one its TOFU pin
// names.
//
// An empty pin is accepted. Every write path has pinned since the fingerprint
// backfill (contacts.applyUpsertLocked), but contacts stored before it exist
// and refusing them would silently drop verification for the whole legacy
// address book. An empty pin means "never pinned", not "pinned to nothing".
func keyMatchesPin(c contacts.Contact) bool {
	if c.PGPKeyFingerprint == "" {
		return true
	}
	info, err := pgpmail.InspectPublicKey(c.PGPKey)
	if err != nil {
		return false
	}
	return strings.EqualFold(info.Fingerprint, c.PGPKeyFingerprint)
}

// signerKeysForSender returns the candidate signer keys for a message claiming
// to come from senderAddress: the keys of those CONTACTS whose own address list
// contains that address.
//
// This is what binds "signature verified" to the sender. Getting the anchor
// right has taken three attempts, so it is worth stating what each one assumed.
//
// Offering the whole address book (allKnownPGPKeys) made Verified mean "some
// contact of yours signed this": DecryptMIME reports success against whichever
// offered key produced the signature and has no address to compare it to.
//
// Narrowing to keys that carry the address as the parsed email of one of their
// User IDs was the second attempt, and it is still forgeable, because a User ID
// is self-asserted and a key may carry arbitrarily many. Mallory generates ONE
// key with the User IDs `Mallory <mallory@evil.example>` and
// `Bob <bob@example.com>` — the repo's own GenerateIdentity does it in one
// variadic call, no packet crafting. The Autocrypt harvest validates the key
// against her From, matches on the FIRST User ID, and pins it under her own
// contact. She then signs a message with `From: bob@example.com`, the second
// User ID satisfies the binding, and the badge goes green — even when the
// reader holds and has manually verified Bob's real key. No code path anywhere
// in the backend inspects a key's full User ID set, so every any-UID check
// inherits this.
//
// The address book is the anchor because it is the only assertion here the USER
// made. `c.Emails` says who a contact is; a User ID says only what its owner
// typed. The fingerprint pin is checked alongside it so a key swapped under an
// existing contact without updating its pin cannot inherit that contact's
// binding.
//
// Narrowing the candidate set rather than post-checking the fingerprint means
// there is no window where a wrong-key signature is ever considered valid.
//
// An empty result means nothing can verify, so Verified stays false — which is
// the correct answer for a sender whose key we do not hold.
func signerKeysForSender(store *contacts.Store, senderAddress string) []string {
	address := senderAddrSpec(senderAddress)
	if address == "" {
		return nil
	}
	var keys []string
	for _, c := range store.List() {
		if c.PGPKey == "" || !contactBindsAddress(c, address) || !keyMatchesPin(c) {
			continue
		}
		keys = append(keys, c.PGPKey)
	}
	return keys
}

// boundSignerKeys returns every contact key the client may verify with, each
// labelled with the addresses the address book binds it to.
//
// It replaces handing the browser a bare list of every key it might need
// (allKnownPGPKeys), which forced the browser to redo the sender binding from
// the keys' User IDs using openpgp.js — a different parser from the go-crypto
// one that decided which contact each key was pinned to. The two disagree on
// adversarial User IDs in both directions, so the browser could vouch for a key
// the server's own binding rejects. Shipping the binding instead of the inputs
// removes the second parser from the trust decision entirely; the browser
// compares address strings the server derived.
//
// A key with no bound address is omitted rather than sent unlabelled: it could
// only ever verify nothing, and an empty Addresses list is exactly the kind of
// thing a client might read as "matches everything".
func boundSignerKeys(store *contacts.Store) []boundSignerKey {
	out := []boundSignerKey{}
	for _, c := range store.List() {
		if c.PGPKey == "" {
			continue
		}
		addresses := make([]string, 0, len(c.Emails))
		seen := map[string]bool{}
		for _, e := range c.Emails {
			addr := strings.ToLower(strings.TrimSpace(e.Value))
			if addr == "" || seen[addr] {
				continue
			}
			seen[addr] = true
			addresses = append(addresses, addr)
		}
		if len(addresses) == 0 {
			continue
		}
		// A pin mismatch is reported, not dropped — but without key
		// material, so no client can verify against it.
		if !keyMatchesPin(c) {
			out = append(out, boundSignerKey{Addresses: addresses, Conflict: true})
			continue
		}
		out = append(out, boundSignerKey{
			Addresses: addresses,
			PublicKey: c.PGPKey,
			Verified:  c.PGPKeyVerified,
			Source:    c.PGPKeySource,
		})
	}
	return out
}

// boundSignerKeysForSender is boundSignerKeys narrowed to one sender.
//
// This is now THE signature binding for the Android client, which no longer
// parses the From header at all. Its hand-rolled parser diverged from
// net/mail.ParseAddressList on 27 of 111 adversarial headers — most seriously
// on RFC 5322 comments, where `Bob (Eve <eve@evil>) <bob@x>` is a valid header
// that Go binds to bob@x and the client bound to eve@evil, letting any contact
// forge a verified badge for anyone. Three client-side fix rounds each closed
// one construct and opened another. Shipping the decision instead of the inputs
// removes the second parser, exactly as boundSignerKeys' own comment says of
// the browser.
//
// address must already be a bare addr-spec from senderAddrSpec. An empty
// address matches nothing, which is the safe direction: no keys, so no verdict
// beyond "signed, but not by a key you hold for this sender".
func boundSignerKeysForSender(store *contacts.Store, address string) []boundSignerKey {
	out := []boundSignerKey{}
	if address == "" {
		return out
	}
	for _, k := range boundSignerKeys(store) {
		for _, a := range k.Addresses {
			if a == address {
				out = append(out, k)
				break
			}
		}
	}
	return out
}
