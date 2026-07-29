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

func (c *APIClient) saveMessage(ctx context.Context, draft DraftMessage, targets []string, flags []string, failureVerb string) error {
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

	var lastErr error
	for _, folder := range targets {
		err := ensureFolderThenRun(d, folder, func(folder string) error {
			return d.Append(folder, flags, time.Now(), raw)
		})
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return fmt.Errorf("failed to %s: %w", failureVerb, lastErr)
	}
	return fmt.Errorf("failed to %s", failureVerb)
}

func (c *APIClient) SaveDraft(ctx context.Context, draft DraftMessage) error {
	return c.saveMessage(ctx, draft, []string{"Drafts", "INBOX/Drafts", "INBOX.Drafts"}, []string{"\\Draft"}, "save draft")
}

func (c *APIClient) SaveSent(ctx context.Context, draft DraftMessage) error {
	targets := []string{"Sent", "INBOX/Sent", "INBOX.Sent", "Sent Items", "INBOX/Sent Items", "INBOX.Sent Items"}
	return c.saveMessage(ctx, draft, targets, []string{"\\Seen"}, "save sent mail")
}
