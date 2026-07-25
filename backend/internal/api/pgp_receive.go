package api

import (
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/users"
)

// pgpDecryptResult is the subset of fields both imapadapter.MessageContent
// and imapadapter.UnreadMessage carry for an encrypted message. The two
// shapes are structurally identical here, so the decrypt logic lives once
// and each caller copies fields in and out.
type pgpDecryptResult struct {
	Body              string
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
func (s *Server) decryptPGPPayload(userID, payload string) pgpDecryptResult {
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
		signerKeys = allKnownPGPKeys(contactsStore)
	}

	result, err := pgpmail.DecryptMIME(payload, identity, signerKeys)
	if err != nil {
		return pgpDecryptResult{DecryptError: "failed to decrypt message"}
	}
	body, attachments, err := pgpmail.ParseContent(result.Content)
	if err != nil {
		return pgpDecryptResult{DecryptError: "failed to parse decrypted message"}
	}

	out := pgpDecryptResult{
		Body:              body,
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
func (s *Server) decryptPGPMessageContent(userID string, c imapadapter.MessageContent) imapadapter.MessageContent {
	c.PGPEncrypted = true
	r := s.decryptPGPPayload(userID, c.PGPEncryptedPayload)
	if r.KeepPayload {
		return c
	}
	c.PGPEncryptedPayload = ""
	if r.DecryptError != "" {
		c.PGPDecryptError = r.DecryptError
		return c
	}
	c.Body = r.Body
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
	r := s.decryptPGPPayload(userID, msg.PGPEncryptedPayload)
	if r.KeepPayload {
		return msg
	}
	msg.PGPEncryptedPayload = ""
	if r.DecryptError != "" {
		msg.PGPDecryptError = r.DecryptError
		return msg
	}
	msg.Body = r.Body
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
// encrypted) message — against every known contact's public key, the same
// signer lookup decryptPGPPayload uses. This needs only public keys, so it
// works identically under both protection modes. Verification is
// best-effort per pgpmail.VerifyDetached's doc comment: third-party MIME
// canonicalization can differ from what was actually signed, so a
// verification failure just leaves PGPVerified false rather than erroring
// the whole inbox fetch.
func (s *Server) verifySignedOnlyMessageContent(userID string, c imapadapter.MessageContent) imapadapter.MessageContent {
	c.PGPSigned = true
	sig := c.PGPSignaturePayload
	c.PGPSignaturePayload = ""
	verified, fingerprint := s.verifyDetachedForUser(userID, c.Body, sig)
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
	verified, fingerprint := s.verifyDetachedForUser(userID, msg.Body, sig)
	msg.PGPVerified = verified
	msg.PGPSignerFingerprint = fingerprint
	return msg
}

func (s *Server) verifyDetachedForUser(userID, body, sig string) (verified bool, fingerprint string) {
	contactsStore, err := s.userContactsStore(userID)
	if err != nil {
		return false, ""
	}
	signerKeys := allKnownPGPKeys(contactsStore)
	if len(signerKeys) == 0 {
		return false, ""
	}
	result, err := pgpmail.VerifyDetached([]byte(body), sig, signerKeys)
	if err != nil {
		return false, ""
	}
	return result.Verified, result.SignerFingerprint
}

// allKnownPGPKeys returns every contact's armored public key, offered as the
// candidate signer set when verifying an inbound signed-and-encrypted
// message: the sender isn't known in advance, so all are tried — DecryptMIME
// only reports success against whichever key actually produced the
// signature.
func allKnownPGPKeys(store *contacts.Store) []string {
	var keys []string
	for _, c := range store.List() {
		if c.PGPKey != "" {
			keys = append(keys, c.PGPKey)
		}
	}
	return keys
}
