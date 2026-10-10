package mailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	imapadapter "github.com/Busnes-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busnes-app/kypost-server/backend/internal/mailmsg"
	"github.com/jhillyerd/enmime/v2"
)

// Client implements the existing mail interface over a permanent store.
// Construction requires a verified account's From address. Runtime source
// selection remains disabled until PGP recovery and source fences are complete.
type Client struct {
	store *Store
	from  string
	admit func(context.Context) error
}

var _ imapadapter.Client = (*Client)(nil)

// MessageReferenceGeneration is wire identity, never the internal UID namespace.
func (c *Client) MessageReferenceGeneration() string { return c.store.MessageReferenceGeneration() }

const batchBytes = int64(192 << 20)
const batchCount = 1000

// NewClient borrows the store; the caller owns its lifetime and closure.
func NewClient(store *Store, from string) (*Client, error) {
	a, err := mail.ParseAddress(from)
	if store == nil || err != nil || a.Address != from {
		return nil, errors.New("native mailbox requires a store and verified account address")
	}
	return &Client{store: store, from: from}, nil
}

// OpenClient owns an existing runtime database. Cached clients retain storage
// identity only: every operation calls admit again, including PGP replacement.
// Eviction drops the client; cleanup waits until its operations are unreachable.
func OpenClient(dir string, owner Owner, limits Limits, from, source string, admit func(context.Context) error) (*Client, error) {
	if admit == nil {
		return nil, ErrOwner
	}
	store, err := OpenExisting(dir, owner, limits, source)
	if err != nil {
		return nil, err
	}
	c, err := NewClient(store, from)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	c.admit = admit
	runtime.AddCleanup(c, func(s *Store) { _ = s.Close() }, store)
	return c, nil
}

func (c *Client) checkAccess(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.admit != nil {
		return c.admit(ctx)
	}
	return nil
}

func normalizeFolder(folder string) (string, error) {
	folder = strings.TrimSpace(folder)
	if folder == "" {
		folder = "INBOX"
	}
	parts := strings.SplitN(folder, "/", 2)
	if strings.EqualFold(parts[0], "INBOX") {
		folder = "INBOX"
		if len(parts) == 2 {
			folder += "/" + parts[1]
		}
	}
	if err := imapadapter.ValidateMailboxName(folder); err != nil {
		return "", err
	}
	if !validFolder(folder) {
		return "", imapadapter.ErrUnsafeMailbox
	}
	return folder, nil
}
func nativeOverview(m Message) imapadapter.Overview {
	o := imapadapter.OverviewFromHeaders(int(m.ID), mail.Header{"From": {m.Sender}, "Subject": {m.Subject}, "To": {m.To}, "Cc": {m.CC}, "Bcc": {m.BCC}})
	o.AtUTC = m.AtUTC
	o.Keywords = append([]string{}, m.Labels...)
	if m.Seen {
		o.Status = "read"
	}
	return o
}
func (c *Client) ListOverviews(ctx context.Context, folder string, limit int) ([]imapadapter.Overview, error) {
	if limit <= 0 {
		limit = 500
	}
	return c.listOverviews(ctx, folder, 0, limit)
}

// ListOverviewsBefore pages older mail below the internal ID before.
func (c *Client) ListOverviewsBefore(ctx context.Context, folder string, before, limit int) ([]imapadapter.Overview, bool, error) {
	if limit <= 0 {
		limit = 500
	}
	if before <= 1 {
		return []imapadapter.Overview{}, false, nil
	}
	out, err := c.listOverviews(ctx, folder, int64(before), limit+1)
	if err != nil || len(out) <= limit {
		return out, false, err
	}
	return out[:limit], true, nil
}

func (c *Client) listOverviews(ctx context.Context, folder string, before int64, limit int) ([]imapadapter.Overview, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return nil, err
	}
	messages, err := c.store.List(ctx, folder, before, limit)
	if err != nil {
		return nil, err
	}
	out := make([]imapadapter.Overview, 0, len(messages))
	for _, m := range messages {
		out = append(out, nativeOverview(m))
	}
	return out, nil
}
func (c *Client) FetchRawMessage(ctx context.Context, folder string, uid int) ([]byte, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return nil, err
	}
	if uid <= 0 {
		return nil, ErrNotFound
	}
	raw, err := c.store.rawWithin(ctx, folder, int64(uid), mailmsg.MaxInboundMessageBytes)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > mailmsg.MaxInboundMessageBytes {
		return nil, mailmsg.ErrMessageTooLarge
	}
	return raw, nil
}
func (c *Client) parsed(ctx context.Context, folder string, uid int) (imapadapter.ParsedContent, int64, error) {
	raw, err := c.FetchRawMessage(ctx, folder, uid)
	if err != nil {
		return imapadapter.ParsedContent{}, 0, err
	}
	parsed, err := imapadapter.ParseRawContent(raw)
	cost := int64(len(raw) + len(parsed.Text) + len(parsed.HTML))
	for _, a := range parsed.Attachments {
		cost += int64(len(a.Content))
	}
	return parsed, cost, err
}
func (c *Client) GetMessageBodies(ctx context.Context, folder string, uids []int) (map[int]imapadapter.MessageContent, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	if len(uids) > batchCount {
		return nil, errors.New("mailbox body batch exceeds message limit")
	}
	out := map[int]imapadapter.MessageContent{}
	var used int64
	for _, uid := range uids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, seen := out[uid]; seen {
			continue
		}
		p, size, err := c.parsed(ctx, folder, uid)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil && !errors.Is(err, imapadapter.ErrMalformedMIME) && !errors.Is(err, mailmsg.ErrMessageTooLarge) {
			return nil, err
		}
		// Charge wire/decoded work even when MIME is malformed and yields no body.
		if used+size > batchBytes {
			break
		}
		used += size
		if errors.Is(err, imapadapter.ErrMalformedMIME) {
			out[uid] = imapadapter.MessageContent{ParseError: true}
			continue
		}
		if errors.Is(err, mailmsg.ErrMessageTooLarge) {
			out[uid] = imapadapter.MessageContent{TooLarge: true}
			continue
		}
		out[uid] = p.Content
	}
	return out, nil
}
func (c *Client) ListUnreadMessages(ctx context.Context, folder string, limit int) ([]imapadapter.UnreadMessage, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	// Despite its historical name, IMAP lists read and unread messages here.
	overviews, err := c.ListOverviews(ctx, folder, limit)
	if err != nil {
		return nil, err
	}
	ids := make([]int, len(overviews))
	for i, o := range overviews {
		ids[i] = o.UID
	}
	bodies, err := c.GetMessageBodies(ctx, folder, ids)
	if err != nil {
		return nil, err
	}
	out := []imapadapter.UnreadMessage{}
	for _, o := range overviews {
		b, ok := bodies[o.UID]
		if !ok || b.TooLarge {
			continue
		}
		out = append(out, imapadapter.UnreadMessage{MessageID: o.MessageID, Subject: o.Subject, Sender: o.Sender, SenderBindingAddress: o.SenderBindingAddress, SentTo: o.SentTo, CC: o.CC, BCC: o.BCC, Keywords: o.Keywords, AtUTC: o.AtUTC, Status: o.Status, Body: b.Body, BodyMode: b.BodyMode, HasAttachments: b.HasAttachments, PGPEncryptedPayload: b.PGPEncryptedPayload, PGPEncrypted: b.PGPEncrypted, PGPSignaturePayload: b.PGPSignaturePayload})
	}
	return out, nil
}
func (c *Client) ListUnreadInbox(ctx context.Context, checkpoint string) ([]imapadapter.Message, string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, checkpoint, err
	}
	after := int64(0)
	if checkpoint != "" {
		var err error
		after, err = strconv.ParseInt(checkpoint, 10, 64)
		if err != nil || after < 0 {
			return nil, checkpoint, errors.New("invalid native mailbox checkpoint")
		}
	}
	messages, err := c.store.unreadAfter(ctx, after, 200)
	if err != nil {
		return nil, checkpoint, err
	}
	out := []imapadapter.Message{}
	var used int64
	next := after
	for _, m := range messages {
		o := nativeOverview(m)
		p, size, err := c.parsed(ctx, "INBOX", int(m.ID))
		if errors.Is(err, ErrNotFound) {
			continue
		}
		tooLarge := errors.Is(err, mailmsg.ErrMessageTooLarge)
		malformed := errors.Is(err, imapadapter.ErrMalformedMIME)
		if err != nil && !tooLarge && !malformed {
			return nil, checkpoint, err
		}
		if !tooLarge && used+size > batchBytes {
			break
		}
		used += size
		out = append(out, imapadapter.Message{ID: o.MessageID, Subject: o.Subject, Sender: o.Sender, SentTo: o.SentTo, CC: o.CC, BCC: o.BCC, Keywords: o.Keywords, AtUTC: o.AtUTC, Body: p.Text, BodyHTML: p.HTML, HasAttachments: p.Content.HasAttachments, PGPEncrypted: p.Content.PGPEncrypted, TooLarge: tooLarge, ParseError: malformed})
		next = m.ID
	}
	return out, strconv.FormatInt(next, 10), nil
}
func (c *Client) ListAttachments(ctx context.Context, folder string, uid int) ([]imapadapter.AttachmentInfo, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	p, _, err := c.parsed(ctx, folder, uid)
	if err != nil {
		return nil, err
	}
	out := make([]imapadapter.AttachmentInfo, len(p.Attachments))
	for i, a := range p.Attachments {
		out[i] = imapadapter.NewAttachmentInfo(i, a)
	}
	return out, nil
}
func (c *Client) GetAttachment(ctx context.Context, folder string, uid, index int) (imapadapter.AttachmentInfo, []byte, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return imapadapter.AttachmentInfo{}, nil, err
	}
	p, _, err := c.parsed(ctx, folder, uid)
	if err != nil {
		return imapadapter.AttachmentInfo{}, nil, err
	}
	if index < 0 || index >= len(p.Attachments) {
		return imapadapter.AttachmentInfo{}, nil, imapadapter.ErrAttachmentNotFound
	}
	return imapadapter.NewAttachmentInfo(index, p.Attachments[index]), p.Attachments[index].Content, nil
}
func (c *Client) FetchHeaderFields(ctx context.Context, folder string, uids []int, fields ...string) (map[int][]string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	if len(uids) > batchCount || len(fields) > 100 {
		return nil, errors.New("mailbox header batch exceeds limit")
	}
	for _, field := range fields {
		if err := imapadapter.ValidateHeaderFieldName(field); err != nil {
			return nil, err
		}
	}
	out := map[int][]string{}
	var used int64
	for _, uid := range uids {
		if _, exists := out[uid]; exists {
			continue
		}
		raw, err := c.FetchRawMessage(ctx, folder, uid)
		if errors.Is(err, ErrNotFound) || errors.Is(err, mailmsg.ErrMessageTooLarge) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if used+int64(len(raw)) > batchBytes {
			break
		}
		used += int64(len(raw))
		m, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		lines := []string{}
		seen := map[string]bool{}
		for _, field := range fields {
			key := strings.ToLower(field)
			if seen[key] {
				continue
			}
			seen[key] = true
			for name, values := range m.Header {
				if strings.EqualFold(name, field) {
					for _, v := range values {
						lines = append(lines, name+": "+v)
					}
				}
			}
		}
		out[uid] = lines
	}
	return out, nil
}
func (c *Client) SearchMessages(ctx context.Context, folder, field, query string, limit int) ([]imapadapter.Overview, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "from" {
		field = "sender"
	}
	if field == "" {
		field = "all"
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return []imapadapter.Overview{}, nil
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > batchCount || len(query) > 4096 {
		return nil, errors.New("invalid mailbox search")
	}
	if field != "sender" && field != "subject" && field != "body" && field != "all" {
		return nil, errors.New("invalid search field")
	}
	query = strings.ToLower(query)
	out := []imapadapter.Overview{}
	var before, used int64
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// ponytail: bounded full scan, no plaintext search index. Add an index only
	// after representative storage tests; encrypted bodies are never decrypted.
	for {
		messages, err := c.store.List(ctx, folder, before, 200)
		if err != nil {
			return nil, err
		}
		if len(messages) == 0 {
			break
		}
		for _, m := range messages {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			before = m.ID
			o := nativeOverview(m)
			found := (field == "sender" || field == "all") && strings.Contains(strings.ToLower(o.Sender), query) || (field == "subject" || field == "all") && strings.Contains(strings.ToLower(o.Subject), query)
			if !found && (field == "body" || field == "all") {
				raw, err := c.FetchRawMessage(ctx, folder, int(m.ID))
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return nil, err
				}
				used += int64(len(raw))
				if used > batchBytes {
					return nil, errors.New("mailbox search byte budget exceeded; narrow the search")
				}
				if field == "all" {
					headers, err := mail.ReadMessage(bytes.NewReader(raw))
					if err != nil {
						return nil, imapadapter.ErrMalformedMIME
					}
					for _, values := range headers.Header {
						for _, value := range values {
							if strings.Contains(strings.ToLower(enmime.DecodeRFC2047(value)), query) {
								found = true
								break
							}
						}
						if found {
							break
						}
					}
				}
				if !found {
					p, err := imapadapter.ParseRawContent(raw)
					if errors.Is(err, imapadapter.ErrMalformedMIME) {
						continue
					}
					if err != nil {
						return nil, err
					}
					used += int64(len(p.Text) + len(p.HTML))
					if used > batchBytes {
						return nil, errors.New("mailbox search byte budget exceeded; narrow the search")
					}
					found = !p.Content.PGPEncrypted && strings.Contains(strings.ToLower(p.Text+"\n"+p.HTML), query)
				}
			}
			if found {
				out = append(out, o)
				if len(out) == limit {
					return out, nil
				}
			}
		}
	}
	return out, nil
}
func (c *Client) save(ctx context.Context, draft imapadapter.DraftMessage, folder string) error {
	if len(draft.To) == 0 {
		return errors.New("at least one TO recipient is required")
	}
	raw := draft.Raw
	if len(raw) == 0 {
		raw = mailmsg.Message{From: c.from, To: draft.To, CC: draft.CC, BCC: draft.BCC, Subject: draft.Subject, Body: draft.Body, Mode: draft.Mode, Attachments: draft.Attachments}.Build()
	}
	_, err := c.store.Append(ctx, folder, bytes.NewReader(raw), folder == "Drafts")
	return err
}
func (c *Client) SaveDraft(ctx context.Context, draft imapadapter.DraftMessage) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	return c.save(ctx, draft, "Drafts")
}
func (c *Client) SaveSent(ctx context.Context, draft imapadapter.DraftMessage) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	return c.save(ctx, draft, "Sent")
}
func (c *Client) EnsureLabel(ctx context.Context, label string) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	if err := imapadapter.ValidateKeyword(label); err != nil {
		return err
	}
	return c.store.ensureLabel(ctx, strings.TrimSpace(label))
}
func (c *Client) ListLabels(ctx context.Context) ([]string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	return c.store.labels(ctx)
}
func (c *Client) ApplyLabel(ctx context.Context, id, label string) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	if err := imapadapter.ValidateKeyword(label); err != nil {
		return err
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil || uid <= 0 {
		return ErrNotFound
	}
	return c.store.editFlags(ctx, "", uid, nil, strings.TrimSpace(label), true)
}
func (c *Client) RemoveLabel(ctx context.Context, id, label string) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	if err := imapadapter.ValidateKeyword(label); err != nil {
		return err
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil || uid <= 0 {
		return ErrNotFound
	}
	return c.store.editFlags(ctx, "", uid, nil, strings.TrimSpace(label), false)
}
func (c *Client) ApplyInboxAction(ctx context.Context, id, action, folder, target string) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return err
	}
	uid, err := strconv.ParseInt(id, 10, 64)
	if err != nil || uid <= 0 {
		return ErrNotFound
	}
	switch action {
	case "read", "unread":
		seen := action == "read"
		return c.store.editFlags(ctx, folder, uid, &seen, "", false)
	case "archive":
		m, err := c.store.metadata(ctx, folder, uid)
		if err != nil {
			return err
		}
		at, err := time.Parse(time.RFC3339, m.AtUTC)
		if err != nil {
			return err
		}
		target = fmt.Sprintf("Archive/%d", at.Year())
		if _, err = c.CreateFolder(ctx, "Archive", strconv.Itoa(at.Year())); err != nil {
			return err
		}
	case "spam":
		target = "Junk"
	case "delete":
		if folder == "Trash" {
			return c.store.Delete(ctx, folder, uid)
		}
		target = "Trash"
	case "move":
		if strings.TrimSpace(target) == "" {
			return errors.New("target mailbox is required")
		}
		target, err = normalizeFolder(target)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported inbox action")
	}
	return c.store.Move(ctx, folder, uid, target)
}
func (c *Client) ListSubfolders(ctx context.Context, parent string) ([]string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return nil, err
	}
	if parent != "" {
		var err error
		parent, err = normalizeFolder(parent)
		if err != nil {
			return nil, err
		}
	}
	folders, err := c.store.Folders(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{}
	seen := map[string]bool{}
	for _, folder := range folders {
		candidate := ""
		if parent == "" {
			if folder == "INBOX" || folder == "Archive" || strings.HasPrefix(folder, "Archive/") {
				continue
			}
			if strings.HasPrefix(folder, "INBOX/") {
				rest := strings.TrimPrefix(folder, "INBOX/")
				candidate = "INBOX/" + strings.Split(rest, "/")[0]
			} else {
				candidate = strings.Split(folder, "/")[0]
			}
		} else if strings.HasPrefix(folder, parent+"/") {
			candidate = parent + "/" + strings.Split(strings.TrimPrefix(folder, parent+"/"), "/")[0]
		}
		if candidate != "" && !seen[candidate] {
			out = append(out, candidate)
			seen[candidate] = true
		}
	}
	sort.Strings(out)
	return out, nil
}
func leaf(name string) error {
	if strings.ContainsAny(name, "/.") {
		return imapadapter.ErrUnsafeMailbox
	}
	if err := imapadapter.ValidateMailboxName(name); err != nil {
		return err
	}
	if !validFolder(name) {
		return imapadapter.ErrUnsafeMailbox
	}
	return nil
}
func (c *Client) CreateFolder(ctx context.Context, parent, name string) (string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return "", err
	}
	parent = strings.TrimSpace(parent)
	name = strings.TrimSpace(name)
	if err := leaf(name); err != nil {
		return "", err
	}
	target := name
	if parent != "" {
		var err error
		parent, err = normalizeFolder(parent)
		if err != nil {
			return "", err
		}
		target = parent + "/" + name
	}
	if err := c.store.createFolder(ctx, parent, target); err != nil {
		return "", err
	}
	return target, nil
}
func (c *Client) RenameFolder(ctx context.Context, folder, name string) (string, error) {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return "", err
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if err = leaf(name); err != nil {
		return "", err
	}
	i := strings.LastIndex(folder, "/")
	if i < 0 {
		return "", errors.New("folder must have a parent mailbox")
	}
	target := folder[:i+1] + name
	if target == folder {
		return folder, nil
	}
	return target, c.store.RenameFolder(ctx, folder, target)
}
func (c *Client) DeleteFolder(ctx context.Context, folder string) error {
	defer runtime.KeepAlive(c)
	if err := c.checkAccess(ctx); err != nil {
		return err
	}
	folder, err := normalizeFolder(folder)
	if err != nil {
		return err
	}
	return c.store.deleteFolderToParent(ctx, folder)
}
