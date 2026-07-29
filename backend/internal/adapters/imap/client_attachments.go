// Attachment enumeration and fetch, plus the size accounting the fetch
// partitioning depends on.
package imap

import (
	"context"
	"fmt"
	"kypost-server/backend/internal/mailmsg"
	"strings"

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
// Deliberately kept as a post-fetch-only check (no pre-fetch LARGER SEARCH
// like ListUnreadInbox/GetMessageBodies): both of this method's callers
// (ListAttachments, GetAttachment) are reached only from an HTTP handler
// serving one explicit, user-clicked UID (see server.go's
// serveAttachmentList/serveAttachmentDownload) — never from an unattended
// batch pass over a mailbox an attacker could aim at a victim's routine
// sync. The one-message blast radius here is the same whether the size
// check runs before or after the fetch, so the extra SEARCH round trip
// buys no additional protection worth the complexity.
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
