package pgpmail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"
)

// ErrNotSignedMessage reports that a message is not an RFC 3156
// multipart/signed structure this package can pull signed bytes out of.
//
// Callers treat it as "there is nothing to verify here", never as a failed
// verification: the two are different things to a reader, and conflating them
// would put a warning badge on ordinary mail.
var ErrNotSignedMessage = errors.New("pgpmail: not an RFC 3156 multipart/signed message")

const (
	armorSignatureBegin = "-----BEGIN PGP SIGNATURE-----"
	armorSignatureEnd   = "-----END PGP SIGNATURE-----"
)

// ExtractSignedParts pulls the two things needed to verify an RFC 3156
// multipart/signed message out of its raw RFC 5322 bytes: the first part
// VERBATIM, and the armored detached signature from the second.
//
// "Verbatim" is the whole point. The signature covers the signed part's
// transmitted bytes — its Content-Type and Content-Transfer-Encoding headers,
// the CRLF that ends them, and content still base64- or quoted-printable-
// encoded. This is why the function scans bytes instead of using
// mime/multipart.Reader: rebuilding "headers + CRLF + body" out of a parsed
// Part.Header loses the original header order, folding and casing, and the
// signature was computed over the original.
//
// It is also why the caller must pass a RAW fetch (imap.FetchRawMessage /
// BODY.PEEK[]) rather than anything that has been through go-imap's MIME
// parser. Passing a decoded body is the bug this function was written to
// retire: it verified nothing and reported every signed message as unverified.
//
// Per RFC 2046 5.1.1 the CRLF preceding a boundary delimiter belongs to the
// delimiter, not to the part — so it is excluded here, which is what lets a
// multipart/mixed signed part keep the trailing CRLF that is genuinely its own.
func ExtractSignedParts(raw []byte) (signedPart []byte, armoredSignature string, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("pgpmail: parse raw message: %w", err)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return nil, "", ErrNotSignedMessage
	}
	if !strings.EqualFold(mediaType, "multipart/signed") {
		return nil, "", ErrNotSignedMessage
	}
	// An absent protocol parameter is tolerated (some senders omit it) but a
	// protocol naming a DIFFERENT signature format is not: an S/MIME message is
	// not something this package can verify, and treating it as one would put a
	// "could not be checked" warning on mail that is correctly signed by other
	// means.
	if protocol := params["protocol"]; protocol != "" &&
		!strings.EqualFold(protocol, "application/pgp-signature") {
		return nil, "", ErrNotSignedMessage
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, "", ErrNotSignedMessage
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, "", fmt.Errorf("pgpmail: read raw body: %w", err)
	}

	// A boundary delimiter is only significant at the start of a line. The first
	// one sits at the very start of the body with no CRLF in front of it, so
	// prepending one lets a single "\r\n--boundary" search find every delimiter
	// including the first. Every index below is into `search`, not `body`.
	search := append([]byte("\r\n"), body...)
	delim := []byte("\r\n--" + boundary)

	openIdx := bytes.Index(search, delim)
	if openIdx < 0 {
		return nil, "", ErrNotSignedMessage
	}
	// Skip the rest of the delimiter line (it may carry trailing whitespace)
	// to land on the first byte of the part itself.
	lineEnd := bytes.Index(search[openIdx+len(delim):], []byte("\r\n"))
	if lineEnd < 0 {
		return nil, "", ErrNotSignedMessage
	}
	partStart := openIdx + len(delim) + lineEnd + len("\r\n")

	nextIdx := bytes.Index(search[partStart:], delim)
	if nextIdx < 0 {
		return nil, "", ErrNotSignedMessage
	}
	signedPart = search[partStart : partStart+nextIdx]

	// The signature lives in whatever follows. Read it out of the armor markers
	// rather than by parsing the second part: RFC 3156 requires the signature
	// part to be 7bit armor, so if the markers are not there in plain sight
	// there is nothing this can verify, and guessing at a transfer encoding
	// would be inventing a verdict.
	rest := search[partStart+nextIdx:]
	begin := bytes.Index(rest, []byte(armorSignatureBegin))
	if begin < 0 {
		return nil, "", ErrNotSignedMessage
	}
	end := bytes.Index(rest[begin:], []byte(armorSignatureEnd))
	if end < 0 {
		return nil, "", ErrNotSignedMessage
	}
	armoredSignature = string(rest[begin : begin+end+len(armorSignatureEnd)])

	return signedPart, armoredSignature, nil
}
