// APPENDing messages the user composed: drafts and Sent copies.
package imap

import (
	"context"
	"errors"
	"fmt"
	"kypost-server/backend/internal/mailmsg"
	"time"

	goimap "github.com/BrianLeishman/go-imap"
)

// ensureFolderThenRun runs try against folder, creating the folder and retrying
// once if the first attempt fails (the folder commonly doesn't exist yet).
func ensureFolderThenRun(d *goimap.Dialer, folder string, try func(folder string) error) error {
	if err := try(folder); err == nil {
		return nil
	}
	if err := d.CreateFolder(folder); err != nil {
		return err
	}
	return try(folder)
}

func (c *APIClient) saveMessage(ctx context.Context, draft DraftMessage, use string, flags []string, failureVerb string) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	if len(draft.To) == 0 {
		return errors.New("at least one TO recipient is required")
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return err
	}

	raw := draft.Raw
	if len(raw) == 0 {
		raw = mailmsg.Message{
			From:        c.username,
			To:          draft.To,
			CC:          draft.CC,
			BCC:         draft.BCC,
			Subject:     draft.Subject,
			Body:        draft.Body,
			Mode:        draft.Mode,
			Attachments: draft.Attachments,
		}.Build()
	}

	// The account's own Drafts/Sent folder, as the server names it. The list of
	// spellings this replaced could not reach past its first entry: the helper
	// behind it created the missing folder and reported success, so a server
	// with INBOX.Sent got a second, top-level Sent that only this application
	// ever wrote to.
	folder, err := c.specialFolderLocked(d, use)
	if err != nil {
		return fmt.Errorf("failed to %s: %w", failureVerb, err)
	}
	if err := d.Append(folder, flags, time.Now(), raw); err != nil {
		return fmt.Errorf("failed to %s: %w", failureVerb, err)
	}
	return nil
}

func (c *APIClient) SaveDraft(ctx context.Context, draft DraftMessage) error {
	return c.saveMessage(ctx, draft, useDrafts, []string{"\\Draft"}, "save draft")
}

func (c *APIClient) SaveSent(ctx context.Context, draft DraftMessage) error {
	return c.saveMessage(ctx, draft, useSent, []string{"\\Seen"}, "save sent mail")
}
