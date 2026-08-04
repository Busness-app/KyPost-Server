package api

import (
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
func (s *Server) decryptPGPMessageContent(userID, senderAddress string, c imapadapter.MessageContent) imapadapter.MessageContent {
	c.PGPEncrypted = true
	r := s.decryptPGPPayload(userID, c.PGPEncryptedPayload, senderAddress)
	if r.KeepPayload {
		return c
	}
	c.PGPEncryptedPayload = ""
	if r.DecryptError != "" {
		c.PGPDecryptError = r.DecryptError
		return c
	}
	c.Body = r.Body
	c.BodyMode = r.BodyMode
	c.HasAttachments = r.HasAttachments
	c.PGPSigned = r.Signed
	c.PGPVerified = r.Verified
	c.PGPSignerFingerprint = r.SignerFingerprint
	if r.ProtectedSubject != "" {
		c.PGPProtectedSubject = r.ProtectedSubject
	}
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
	msg.Body = r.Body
	msg.BodyMode = r.BodyMode
	msg.HasAttachments = r.HasAttachments
	msg.PGPSigned = r.Signed
	msg.PGPVerified = r.Verified
	msg.PGPSignerFingerprint = r.SignerFingerprint
	if r.ProtectedSubject != "" {
		msg.PGPProtectedSubject = r.ProtectedSubject
	}
	return msg
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

// signerKeysForSender returns the candidate signer keys for a message claiming
// to come from senderAddress: only those contact keys that carry that address as
// the PARSED email of one of their User IDs.
//
// This is what binds "signature verified" to the sender on the server-custody
// path. Offering the whole address book (allKnownPGPKeys) made Verified mean
// "some contact of yours signed this", because DecryptMIME reports success
// against whichever offered key produced the signature and has no address to
// compare it to — its signature takes none. So any key in the book verified any
// From, and the badge the client renders from PGPVerified said "signature
// verified" under an address the signing key had nothing to do with. Run-4
// reported this; the fix that followed was applied only to the browser, and this
// path kept the old behaviour.
//
// Narrowing the candidate set rather than post-checking the fingerprint means
// there is no window where a wrong-key signature is ever considered valid.
//
// An empty result means nothing can verify, so Verified stays false — which is
// the correct answer for a sender whose key we do not hold.
func signerKeysForSender(store *contacts.Store, senderAddress string) []string {
	address := strings.ToLower(strings.TrimSpace(senderAddress))
	if address == "" {
		return nil
	}
	var keys []string
	for _, c := range store.List() {
		if c.PGPKey != "" && pgpmail.ArmoredKeyCertifiesAddress(c.PGPKey, address) {
			keys = append(keys, c.PGPKey)
		}
	}
	return keys
}

// allKnownPGPKeys returns every contact's armored public key.
//
// NOT for verification — see signerKeysForSender. Verification must offer only
// keys bound to the claimed sender.
func allKnownPGPKeys(store *contacts.Store) []string {
	var keys []string
	for _, c := range store.List() {
		if c.PGPKey != "" {
			keys = append(keys, c.PGPKey)
		}
	}
	return keys
}
