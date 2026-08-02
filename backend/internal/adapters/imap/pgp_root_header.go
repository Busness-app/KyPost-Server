package imap

import (
	"mime"
	"strings"

	goimap "github.com/BrianLeishman/go-imap"
)

// Confirming a PGP/MIME envelope against the message's REAL root Content-Type.
//
// RFC 3156 puts the fact in exactly one place: the root header,
// `multipart/encrypted; protocol="application/pgp-encrypted"`. goimap's Email
// struct does not carry root headers at all, so pgpEnvelopePayload had to
// reconstruct the judgement from the MIME parts that survive parsing — every
// part a plausible envelope part, at least one of them armored ciphertext.
//
// That test has a false positive its own doc comment admits to: a bodyless
// message carrying a single armored .pgp attachment is indistinguishable from a
// real envelope by parts alone. A sender can build one deliberately, and the
// payoff is small but real — the poller skips classification for an encrypted
// message, so the forgery buys a message the default label and a padlock in the
// reader.
//
// The root header is not something goimap discards forever, only something it
// does not parse: one extra header-only UID FETCH gets it. So the attachment
// test stays as the CHEAP CANDIDATE FILTER — it runs on every message with no
// round trip and rejects almost everything — and only the handful that pass it
// cost a header fetch, which then decides.

// pgpMIMEProtocol is the protocol parameter RFC 3156 requires on the root
// multipart/encrypted Content-Type.
const pgpMIMEProtocol = "application/pgp-encrypted"

// isPGPMIMERootContentType reports whether a raw Content-Type header value is
// an RFC 3156 PGP/MIME envelope root.
//
// Both halves are required. multipart/encrypted alone says the message is
// encrypted by SOMETHING (S/MIME's application/pkcs7-mime is the other common
// answer), and treating that as OpenPGP would hand the reader a payload it
// cannot decrypt while telling the user it can.
func isPGPMIMERootContentType(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" {
		return false
	}
	// Tolerate the full header line ("Content-Type: multipart/encrypted; ...")
	// as well as a bare value, because FetchHeaderFields returns lines with
	// their field name still attached.
	if idx := strings.Index(value, ":"); idx >= 0 && strings.EqualFold(strings.TrimSpace(value[:idx]), "content-type") {
		value = strings.TrimSpace(value[idx+1:])
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		// Strictly, `protocol=application/pgp-encrypted` unquoted is malformed:
		// "/" is not a token character, so ParseMediaType rejects the whole
		// header. Mainstream senders quote it, but rejecting the unquoted form
		// would mean showing a genuinely encrypted message as unencrypted on a
		// technicality — a worse error here than being lenient, since this test
		// only ever NARROWS a set of candidates that already look like
		// envelopes. Fall back to reading the parts by hand.
		return looksLikePGPMIMERoot(value)
	}
	if !strings.EqualFold(mediaType, "multipart/encrypted") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(params["protocol"]), pgpMIMEProtocol)
}

// looksLikePGPMIMERoot is the lenient re-read of a Content-Type that
// mime.ParseMediaType refused. It asks the same two questions — is the media
// type multipart/encrypted, and is the protocol parameter OpenPGP's — without
// requiring the header to be well-formed in every other respect.
func looksLikePGPMIMERoot(value string) bool {
	parts := strings.Split(value, ";")
	if len(parts) == 0 || !strings.EqualFold(strings.TrimSpace(parts[0]), "multipart/encrypted") {
		return false
	}
	for _, part := range parts[1:] {
		name, val, found := strings.Cut(part, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "protocol") {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		if strings.EqualFold(val, pgpMIMEProtocol) {
			return true
		}
	}
	return false
}

// confirmPGPEnvelopeUIDs asks the server for the root Content-Type of each
// candidate UID and returns the subset that really are PGP/MIME envelopes.
//
// candidates are UIDs that already passed pgpEnvelopePayload, so this is one
// small header-only FETCH for the rare message that looks like an envelope,
// never a per-message cost on the whole mailbox.
//
// On a FETCH error it returns ok=false and the caller keeps the attachment-only
// verdict. Falling back rather than failing closed is deliberate: an IMAP blip
// would otherwise strip the encrypted marking off every genuinely encrypted
// message in the batch, which is a worse and much more likely outcome than the
// forgery this narrows — and it is not a path an attacker can provoke, since
// nothing in a message decides whether the connection holds.
func confirmPGPEnvelopeUIDs(d *goimap.Dialer, candidates []int) (map[int]bool, bool) {
	if len(candidates) == 0 {
		return map[int]bool{}, true
	}
	headers, err := fetchHeaderFieldsLocked(d, candidates, "Content-Type")
	if err != nil {
		return nil, false
	}
	confirmed := make(map[int]bool, len(candidates))
	for _, uid := range candidates {
		for _, line := range headers[uid] {
			if isPGPMIMERootContentType(line) {
				confirmed[uid] = true
				break
			}
		}
	}
	return confirmed, true
}

// pgpEnvelopeVerdict is the per-UID answer collectPGPEnvelopes produces.
type pgpEnvelopeVerdict struct {
	// Payload is the armored ciphertext, empty when this UID is not an envelope.
	Payload string
}

// collectPGPEnvelopes decides, for a batch of already-fetched messages, which
// are whole-message PGP/MIME envelopes.
//
// bodies maps UID to the message's rendered body: only a BODYLESS message can
// be an envelope, because a readable body means the armored block is an
// attachment on ordinary mail rather than the message itself.
func collectPGPEnvelopes(d *goimap.Dialer, emails map[int]*goimap.Email, bodies map[int]string) map[int]pgpEnvelopeVerdict {
	candidates, payloads := pgpEnvelopeCandidates(emails, bodies)
	if len(candidates) == 0 {
		return map[int]pgpEnvelopeVerdict{}
	}
	confirmed, ok := confirmPGPEnvelopeUIDs(d, candidates)
	return applyEnvelopeConfirmation(candidates, payloads, confirmed, ok)
}

// pgpEnvelopeCandidates picks the UIDs worth spending a header fetch on: a
// bodyless message whose every part is a plausible envelope part.
//
// Split out as a pure function because this package has no fake
// *goimap.Dialer, so the candidate rule and the confirmation rule can only be
// tested where they do not touch one.
func pgpEnvelopeCandidates(emails map[int]*goimap.Email, bodies map[int]string) ([]int, map[int]string) {
	candidates := make([]int, 0, len(emails))
	payloads := make(map[int]string, len(emails))
	for uid, e := range emails {
		if e == nil || bodies[uid] != "" {
			continue
		}
		if payload := pgpEnvelopePayload(e.Attachments); payload != "" {
			candidates = append(candidates, uid)
			payloads[uid] = payload
		}
	}
	return candidates, payloads
}

// applyEnvelopeConfirmation turns the confirmed set into per-UID verdicts.
//
// headersRead=false means the header fetch itself failed, and every candidate
// keeps its attachment-only verdict — see confirmPGPEnvelopeUIDs for why that
// is the safer direction to fail in.
func applyEnvelopeConfirmation(candidates []int, payloads map[int]string, confirmed map[int]bool, headersRead bool) map[int]pgpEnvelopeVerdict {
	out := make(map[int]pgpEnvelopeVerdict, len(candidates))
	for _, uid := range candidates {
		if !headersRead || confirmed[uid] {
			out[uid] = pgpEnvelopeVerdict{Payload: payloads[uid]}
		}
	}
	return out
}
