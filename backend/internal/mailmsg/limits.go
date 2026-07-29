package mailmsg

import (
	"errors"
	"io"
)

// ErrMessageTooLarge is the shared sentinel every inbound-mail read site
// returns when the data it would otherwise have to hold in memory exceeds
// MaxInboundMessageBytes: a raw fetched message (imap.FetchRawMessage), a
// fetched attachment (imap.APIClient's fetchAttachments, GetAttachment), or a
// decrypted/parsed PGP/MIME payload (pgpmail.DecryptMIME, pgpmail.ParseContent).
// GetMessageBodies is the one exception: a batch call across many UIDs must
// not let one oversized message fail every other UID in the same call, so it
// marks that UID's MessageContent.TooLarge instead of returning this sentinel
// for the whole batch. Defined once here — rather
// than in package imap or package pgpmail — because both of those already
// import mailmsg (for Attachment/Message) with no import back the other way,
// so this is the natural shared home without adding a new import edge, and
// package processor (the poller, which needs to catch this sentinel) already
// depends on mailmsg for the Task 16 SMTP-send helpers.
var ErrMessageTooLarge = errors.New("mailmsg: message exceeds maximum allowed size")

// MaxInboundMessageBytes bounds how much of a single inbound message (raw
// bytes, attachment content, decrypted PGP payload) this server will hold in
// memory at once. A large attachment or a PGP decompression bomb must not be
// able to OOM the process.
//
// This is deliberately NOT the same number as the outbound
// maxMailAttachmentBytes cap in internal/api/server.go, and it used to claim it
// was. The two answer different questions: this one is "how much can we hold in
// memory for a message someone else composed", while the outbound cap is
// derived from the 25 MiB request-body limit and so lands lower once base64
// expansion is accounted for. A server should be able to receive a message
// slightly larger than the largest one it will let you send.
//
// This is a package-level var, not a const, so tests can substitute a much
// smaller limit and exercise the overflow/boundary behavior cheaply instead
// of actually allocating 25 MiB of test data.
var MaxInboundMessageBytes int64 = 25 << 20

// BoundedRead reads at most limit+1 bytes from r. If the (limit+1)th byte is
// reached — i.e. r had more than limit bytes available — it returns
// ErrMessageTooLarge instead of the truncated data, so a caller can never
// mistake a silently-truncated read for the real, complete message. Mirrors
// the io.LimitReader idiom already used for bounded reads elsewhere in this
// codebase (e.g. processor/native_sender.go's response-body caps), extended
// with the "read one byte past the limit" trick to distinguish "exactly at
// the limit" from "over the limit" rather than silently truncating.
func BoundedRead(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrMessageTooLarge
	}
	return data, nil
}
