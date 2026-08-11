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

	// RFC 1847 2.1: multipart/signed contains EXACTLY two body parts. Anything
	// else is refused outright rather than parsed leniently.
	//
	// This is CVE-2021-4126's shape. A third part is not covered by the
	// signature, and the parsers disagree about it: enmime's DepthMatchFirst
	// picks it as the display body while this function returns part 1. A reader
	// that shows enmime's body under this function's verdict then displays
	// content nobody signed beneath a "signature verified" badge.
	//
	// The check counts delimiters rather than looking for content after the
	// signature part, because the armor is located by scanning everything after
	// the opening delimiter (below) — so ordering the parts as
	// [signed][attacker][signature] would walk straight past a positional test.
	// A conforming message has exactly three delimiter lines: open, separator,
	// and close.
	opens := delimiterOffsets(search, delim)
	if len(opens) != 3 {
		return nil, "", ErrNotSignedMessage
	}

	openIdx := opens[0]
	// RFC 2046 5.1.1 allows only transport padding between the boundary and the
	// line ending. Skipping to the next CRLF regardless would accept
	// "--boundaryJUNK" as a delimiter for "boundary", which no conforming
	// parser does — and since boundary= lives in the UNSIGNED outer header, an
	// attacker picks it freely.
	lineEnd := delimiterLineEnd(search[openIdx+len(delim):])
	if lineEnd < 0 {
		return nil, "", ErrNotSignedMessage
	}
	partStart := openIdx + len(delim) + lineEnd

	nextIdx := opens[1]
	if nextIdx <= partStart {
		return nil, "", ErrNotSignedMessage
	}
	signedPart = search[partStart:nextIdx]
	// Re-anchor the armor scan to just past the separator delimiter, so the
	// offsets below read the same as before this check existed.
	nextIdx -= partStart

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

// delimiterOffsets returns the offset of every CONFORMING boundary delimiter
// line in search — one whose boundary token is followed only by transport
// padding and a line ending, or by "--" for the close delimiter.
//
// A prefix match alone is not enough: "--boundaryJUNK" starts with
// "--boundary", and treating it as a delimiter is what let a rewritten
// (unsigned) boundary parameter re-cut the message into different parts.
func delimiterOffsets(search, delim []byte) []int {
	var out []int
	for off := 0; ; {
		i := bytes.Index(search[off:], delim)
		if i < 0 {
			return out
		}
		abs := off + i
		tail := search[abs+len(delim):]
		if delimiterLineEnd(tail) >= 0 || isCloseDelimiter(tail) {
			out = append(out, abs)
		}
		off = abs + len(delim)
	}
}

// delimiterLineEnd returns the offset just past the CRLF of a conforming
// delimiter line starting at b (i.e. immediately after the boundary token), or
// -1 if what follows is not transport padding plus a line ending.
func delimiterLineEnd(b []byte) int {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	if !bytes.HasPrefix(b[i:], []byte("\r\n")) {
		return -1
	}
	return i + len("\r\n")
}

// isCloseDelimiter reports whether b, the bytes just after a boundary token,
// begins the "--" that terminates a multipart body.
func isCloseDelimiter(b []byte) bool {
	return bytes.HasPrefix(b, []byte("--"))
}
