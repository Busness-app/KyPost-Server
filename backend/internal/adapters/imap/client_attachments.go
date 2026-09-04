// Attachment enumeration and fetch, plus the size accounting the fetch
// partitioning depends on.
package imap

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Busness-app/kypost-server/backend/internal/mailmsg"

	goimap "github.com/BrianLeishman/go-imap"
)

func emailContentSize(e *goimap.Email) int64 {
	total := int64(len(e.HTML)) + int64(len(e.Text))
	for _, a := range e.Attachments {
		total += int64(len(a.Content))
	}
	return total
}

// fetchAttachments pulls one message and returns its parsed attachments
// (go-imap's GetEmails decodes MIME parts into Email.Attachments).
//
// The "UID <uid> LARGER <cap>" SEARCH runs BEFORE the fetch, the same
// protocol-level bound ListUnreadInbox and FetchRawMessage use. This used to
// be a post-fetch check only, on the argument that both callers serve one
// explicit, user-clicked UID and so "the one-message blast radius is the same
// whether the size check runs before or after the fetch". That last part was
// simply false: before the fetch the blast radius is zero bytes, and after it
// the entire message has already been requested, buffered, MIME-parsed and
// base64-decoded into memory by go-imap — emailContentSize can then only
// describe the allocation, not prevent it. Which UID is fetched is the user's
// choice; how big the message at that UID is belongs to whoever sent it, and
// the recipient merely opening a message with attachments is enough to spend
// it (ReadPage loads the attachment list automatically).
//
// LARGER is evaluated against the server's own RFC822.SIZE, so an oversized
// message's literal is never sent to us at all. The post-fetch
// emailContentSize check is kept as defense-in-depth for what SEARCH cannot
// bound: RFC822.SIZE is the stored size, while Email.Attachments holds decoded
// content, and a server that reports the size wrongly is still a server.
func (c *APIClient) fetchAttachments(ctx context.Context, mailbox string, uid int) ([]goimap.Attachment, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if uid <= 0 {
		return nil, fmt.Errorf("invalid message id %d", uid)
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}
	mailbox = strings.TrimSpace(mailbox)
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	sb := goimap.Search().UID(strconv.Itoa(uid)).Larger(int(mailmsg.MaxInboundMessageBytes))
	oversizedUIDs, err := d.SearchUIDs(sb)
	if err != nil {
		return nil, fmt.Errorf("imap search oversized: %w", err)
	}
	if len(oversizedUIDs) > 0 {
		return nil, mailmsg.ErrMessageTooLarge
	}

	emails, err := d.GetEmails(uid)
	if err != nil {
		return nil, fmt.Errorf("imap fetch emails: %w", err)
	}
	e := emails[uid]
	if e == nil {
		return nil, fmt.Errorf("message %d not found in %q", uid, mailbox)
	}
	if emailContentSize(e) > mailmsg.MaxInboundMessageBytes {
		return nil, mailmsg.ErrMessageTooLarge
	}
	return e.Attachments, nil
}

func (c *APIClient) ListAttachments(ctx context.Context, mailbox string, uid int) ([]AttachmentInfo, error) {
	attachments, err := c.fetchAttachments(ctx, mailbox, uid)
	if err != nil {
		return nil, err
	}
	infos := make([]AttachmentInfo, 0, len(attachments))
	for i, a := range attachments {
		infos = append(infos, AttachmentInfo{
			Index:    i,
			Name:     a.Name,
			MimeType: a.MimeType,
			Size:     len(a.Content),
		})
	}
	return infos, nil
}

// GetAttachment returns one attachment's content by index. The
// mailmsg.MaxInboundMessageBytes cap is enforced by fetchAttachments (on the
// whole message's total content, before any attachment is picked out here),
// so a request for a single attachment from an oversized message fails with
// mailmsg.ErrMessageTooLarge just as ListAttachments does.
func (c *APIClient) GetAttachment(ctx context.Context, mailbox string, uid int, index int) (AttachmentInfo, []byte, error) {
	attachments, err := c.fetchAttachments(ctx, mailbox, uid)
	if err != nil {
		return AttachmentInfo{}, nil, err
	}
	if index < 0 || index >= len(attachments) {
		return AttachmentInfo{}, nil, ErrAttachmentNotFound
	}
	a := attachments[index]
	info := AttachmentInfo{
		Index:    index,
		Name:     a.Name,
		MimeType: a.MimeType,
		Size:     len(a.Content),
	}
	return info, a.Content, nil
}
