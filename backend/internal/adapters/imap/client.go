package imap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kypost-server/backend/internal/cryptutil"
	"kypost-server/backend/internal/mailmsg"

	goimap "github.com/BrianLeishman/go-imap"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"

	"kypost-server/backend/internal/config"
)

type Message struct {
	ID       string
	Subject  string
	Sender   string
	SentTo   string
	CC       string
	BCC      string
	Keywords []string
	AtUTC    string
	Body     string
	// BodyHTML is the message's text/html part, when it has one, and is empty
	// otherwise. It exists because Body above is NOT the body the clients
	// render: ListUnreadInbox (which fills this struct) prefers the text/plain
	// part, while every client-facing path — ListUnreadMessages,
	// GetMessageBodies — prefers text/html. A multipart/alternative message can
	// therefore show the poller an innocuous plain-text part while the clients
	// display a hostile HTML one.
	//
	// The anti-phishing scan (processor.scanForAppImpersonation) needs both for
	// exactly that reason: a kypost:// pairing link planted only in the HTML
	// part would otherwise be invisible to the server while being one click
	// away in the UI. Filled from the same GetEmails parse as Body, so it costs
	// no extra IMAP round trip.
	BodyHTML string
	// HasAttachments is set from the same GetEmails parse that fills Body, so
	// the poller's cache-warm path can carry it into mailcache.Entry without
	// any extra IMAP round trip.
	HasAttachments bool
	// TooLarge is set instead of Body/HasAttachments being populated when
	// this message is too large to safely pull into memory — see
	// ListUnreadInbox, which decides this via a server-side
	// "UNSEEN LARGER <cap>" SEARCH before ever fetching the body, so an
	// oversized message's HTML/text/attachments are never read off the wire
	// in the first place. Sender/Subject/SentTo/CC/BCC are still populated,
	// sourced from a cheap GetOverviews FETCH (flags/envelope only, no
	// body), so the poller can build a rejection notice without ever
	// holding the oversized body in memory. The poller's handleMessage
	// checks this instead of an error return, since ListUnreadInbox fetches
	// every unread message in one batch — one oversized message must not
	// fail the whole batch (nor block checkpoint progress for every other
	// message in it).
	TooLarge bool
}

type UnreadMessage struct {
	MessageID string
	Subject   string
	Sender    string
	SentTo    string
	CC        string
	BCC       string
	Keywords  []string
	AtUTC     string
	Body      string
	// BodyMode is BodyModeHTML or BodyModePlain — which MIME part Body was
	// taken from. See clientBody for why the client must not re-derive this.
	BodyMode string
	Status   string
	// HasAttachments comes from the same GetEmails parse as Body.
	HasAttachments bool
	// PGPEncryptedPayload holds the armored OpenPGP message when the
	// fetched email's Content-Type was multipart/encrypted (RFC 3156) —
	// detected by sniffing e.Attachments for an armored PGP message, since
	// neither e.Text nor e.HTML is populated for content types goimap can't
	// render as plain text. Empty when the message isn't PGP-encrypted.
	// Decryption itself happens in internal/api, which holds the reading
	// user's key — this package only detects and exposes the raw payload.
	PGPEncryptedPayload string
	// PGPSignaturePayload holds the armored OpenPGP detached signature when
	// the fetched email is RFC 3156 multipart/signed (signed but not
	// encrypted) — detected by sniffing e.Attachments for an armored PGP
	// signature block. Unlike PGPEncryptedPayload, this is set alongside a
	// normal, readable Body (signed-only mail isn't opaque to goimap).
	// Empty when the message carries no detached signature. Verification
	// happens in internal/api, which holds the sender's known public keys.
	PGPSignaturePayload string
	// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint/
	// PGPDecryptError are populated by internal/api after decryption or
	// signature verification; they start zero-valued here.
	PGPEncrypted         bool
	PGPSigned            bool
	PGPVerified          bool
	PGPSignerFingerprint string
	PGPDecryptError      string
	// PGPProtectedSubject holds the real subject recovered from the encrypted
	// payload's protected headers, when present. Populated by internal/api
	// after decryption; zero-valued here. Kept separate from the envelope
	// subject so the mail cache's overview-subject diffing isn't disturbed.
	PGPProtectedSubject string
}

// MessageContent is the per-UID result of GetMessageBodies: the rendered body
// plus whether the message carries attachments, both from one GetEmails parse.
type MessageContent struct {
	Body string
	// BodyMode is BodyModeHTML or BodyModePlain — see clientBody.
	BodyMode       string
	HasAttachments bool
	// TooLarge is set instead of Body/HasAttachments being populated when
	// this UID was identified as oversized by GetMessageBodies's server-side
	// "UID <set> LARGER <cap>" SEARCH (or, as a defense-in-depth fallback,
	// by the post-fetch emailContentSize check) — mirrors Message.TooLarge
	// on ListUnreadInbox's result type. The message's content is never
	// buffered into memory in the search-caught case. Set per-UID rather
	// than failing the whole GetMessageBodies call, since one oversized
	// message must not make every other UID in the same batch unreadable.
	TooLarge bool
	// PGPEncryptedPayload holds the armored OpenPGP message when the
	// fetched email's Content-Type was multipart/encrypted (RFC 3156) —
	// detected by sniffing e.Attachments for an armored PGP message, since
	// neither e.Text nor e.HTML is populated for content types goimap can't
	// render as plain text. Empty when the message isn't PGP-encrypted.
	// Decryption itself happens in internal/api, which holds the reading
	// user's key — this package only detects and exposes the raw payload.
	PGPEncryptedPayload string
	// PGPSignaturePayload holds the armored OpenPGP detached signature when
	// the fetched email is RFC 3156 multipart/signed (signed but not
	// encrypted) — detected by sniffing e.Attachments for an armored PGP
	// signature block. Unlike PGPEncryptedPayload, this is set alongside a
	// normal, readable Body. Empty when the message carries no detached
	// signature. Verification happens in internal/api, which holds the
	// sender's known public keys.
	PGPSignaturePayload string
	// PGPEncrypted/PGPSigned/PGPVerified/PGPSignerFingerprint/
	// PGPDecryptError are populated by internal/api after decryption or
	// signature verification; they start zero-valued here.
	PGPEncrypted         bool
	PGPSigned            bool
	PGPVerified          bool
	PGPSignerFingerprint string
	PGPDecryptError      string
	// PGPProtectedSubject holds the real subject recovered from the encrypted
	// payload's protected headers, when present. Populated by internal/api
	// after decryption; zero-valued here. Kept separate from the envelope
	// subject so the mail cache's overview-subject diffing isn't disturbed.
	PGPProtectedSubject string
}

// pgpDetectPayload scans attachments for an armored OpenPGP message — the
// RFC 3156 multipart/encrypted data part, which goimap's underlying enmime
// parser (see message.go) always classifies as an attachment (its
// application/octet-stream content type unconditionally matches enmime's
// attachment rule, regardless of Content-Disposition). Detection is
// content-based (pgpcrypto.IsPGPMessage sniffs the armor header) rather than
// MIME-type-based, so it also picks up encrypted mail from any other
// PGP/MIME sender.
func pgpDetectPayload(attachments []goimap.Attachment) string {
	for _, a := range attachments {
		if pgpcrypto.IsPGPMessage(string(a.Content)) {
			return string(a.Content)
		}
	}
	return ""
}

// pgpDetectSignature scans attachments for an armored OpenPGP detached
// signature — the application/pgp-signature part of an RFC 3156
// multipart/signed message (the "signature.asc" attachment written by this
// codebase's own signed-MIME builder, and the equivalent from any other
// PGP/MIME sender). Unlike encrypted mail, a signed-only message keeps a
// normal readable body, so callers check for this alongside the body rather
// than only when the body is empty.
func pgpDetectSignature(attachments []goimap.Attachment) string {
	for _, a := range attachments {
		if strings.HasPrefix(strings.TrimSpace(string(a.Content)), "-----BEGIN PGP SIGNATURE-----") {
			return string(a.Content)
		}
	}
	return ""
}

// Overview is UID + envelope + flags for one message, without body content
// — backed by GetOverviews (UID FETCH ... ALL), which per RFC 3501 never
// includes body text. Used by the mail-cache sync path (ListOverviews) so
// the expensive body fetch (GetMessageBodies) happens only for UIDs the
// cache doesn't already have.
type Overview struct {
	MessageID string
	Subject   string
	Sender    string
	SentTo    string
	CC        string
	BCC       string
	Keywords  []string
	AtUTC     string
	Status    string
	UID       int
}

type DraftMessage struct {
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Body        string
	Mode        string
	Attachments []mailmsg.Attachment
	// Raw is a complete RFC 5322 message to append verbatim. When set, every
	// other field except To (which saveMessage requires) is ignored and no
	// message is built.
	//
	// This exists for the client-custody Sent copy, which arrives already
	// wrapped as PGP/MIME by the browser. Running it back through
	// mailmsg.Message.Build would nest a complete multipart/encrypted message
	// inside a freshly generated envelope, so no reader would decrypt it — and
	// it would need the real Subject to rebuild a header, which is exactly the
	// value the encryption exists to hide.
	Raw []byte
}

// AttachmentInfo is one attachment's metadata, without its content. JSON
// tags match the /api/mail/attachments wire shape.
type AttachmentInfo struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	MimeType string `json:"mimeType"`
	Size     int    `json:"size"`
}

// ErrAttachmentNotFound reports an attachment index that doesn't exist on
// the message; the API maps it to 404.
var ErrAttachmentNotFound = errors.New("attachment not found")

type Client interface {
	ListUnreadInbox(ctx context.Context, sinceCheckpoint string) ([]Message, string, error)
	ListUnreadMessages(ctx context.Context, mailbox string, limit int) ([]UnreadMessage, error)
	// ListOverviews returns UID + envelope + flags for the last N messages
	// in mailbox, without a body fetch — the selective, cheap counterpart
	// to ListUnreadMessages used by the mail cache's live-diff path.
	ListOverviews(ctx context.Context, mailbox string, limit int) ([]Overview, error)
	// SearchMessages searches messages in mailbox by field (sender/subject/body/all)
	// and returns the newest N matching messages as Overview objects.
	SearchMessages(ctx context.Context, mailbox, field, query string, limit int) ([]Overview, error)
	// GetMessageBodies fetches body content and attachment presence for
	// exactly the given UIDs — called only for UIDs the mail cache reports as
	// genuinely new. UIDs the server reports as oversized (see
	// MessageContent.TooLarge) are excluded from the buffering fetch and come
	// back with TooLarge set instead of a Body.
	GetMessageBodies(ctx context.Context, mailbox string, uids []int) (map[int]MessageContent, error)
	ListLabels(ctx context.Context) ([]string, error)
	ListSubfolders(ctx context.Context, parent string) ([]string, error)
	CreateFolder(ctx context.Context, parent, name string) (string, error)
	RenameFolder(ctx context.Context, folder, name string) (string, error)
	DeleteFolder(ctx context.Context, folder string) error
	EnsureLabel(ctx context.Context, label string) error
	ApplyLabel(ctx context.Context, messageID, label string) error
	// RemoveLabel clears an IMAP keyword flag from one message — the mirror
	// of ApplyLabel, using Keywords[label]=false to emit -FLAGS.
	RemoveLabel(ctx context.Context, messageID, label string) error
	ApplyInboxAction(ctx context.Context, messageID, action, mailbox, targetMailbox string) error
	// ListAttachments returns attachment metadata for one message (UID).
	ListAttachments(ctx context.Context, mailbox string, uid int) ([]AttachmentInfo, error)
	// GetAttachment returns one attachment's metadata and content by index.
	GetAttachment(ctx context.Context, mailbox string, uid int, index int) (AttachmentInfo, []byte, error)
	SaveDraft(ctx context.Context, draft DraftMessage) error
	SaveSent(ctx context.Context, draft DraftMessage) error
	// FetchHeaderFields issues a raw UID FETCH for BODY.PEEK[HEADER.FIELDS (...)]
	// — see auth_results.go for the full contract.
	FetchHeaderFields(ctx context.Context, uids []int, fields ...string) (map[int][]string, error)
	// FetchRawMessage fetches the complete raw RFC 5322 message (headers +
	// body, exactly as stored) for one UID — see raw_message.go for the full
	// contract.
	FetchRawMessage(ctx context.Context, uid int) ([]byte, error)
}

type APIClient struct {
	mu       sync.Mutex
	opMu     sync.Mutex
	dialer   *goimap.Dialer
	host     string
	port     int
	username string
	password string
	mailbox  string

	// configPath/configKeyPath override the process-wide default stored
	// config location so one client can be built per user's credential file.
	configPath    string
	configKeyPath string
}

type storedIMAPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Mailbox  string `json:"mailbox"`
}

// NewAPIClientFromStoredConfig builds a client that loads its credentials
// from a specific encrypted config file (per-user), never from env vars.
func NewAPIClientFromStoredConfig(configPath, configKeyPath string) *APIClient {
	return &APIClient{
		port:          993,
		mailbox:       "INBOX",
		configPath:    configPath,
		configKeyPath: configKeyPath,
	}
}

func defaultConfigPath() string {
	return config.SecretFile("IMAP_CONFIG_FILE", "imap-config.json")
}

func defaultConfigKeyPath() string {
	return config.SecretFile("IMAP_CONFIG_KEY_FILE", "imap-config.key")
}

func (c *APIClient) ensureCredentialsFromStoredConfigLocked() error {
	if strings.TrimSpace(c.host) != "" && strings.TrimSpace(c.username) != "" && strings.TrimSpace(c.password) != "" {
		return nil
	}

	configPath := c.configPath
	if strings.TrimSpace(configPath) == "" {
		configPath = defaultConfigPath()
	}
	keyPath := c.configKeyPath
	if strings.TrimSpace(keyPath) == "" {
		keyPath = defaultConfigKeyPath()
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read imap config: %w", err)
	}

	plain, err := decryptStoredPayload(raw, keyPath)
	if err != nil {
		return fmt.Errorf("decrypt imap config: %w", err)
	}

	var payload storedIMAPConfig
	if err := json.Unmarshal(plain, &payload); err != nil {
		return fmt.Errorf("parse imap config: %w", err)
	}

	payload.Host = strings.TrimSpace(payload.Host)
	payload.Username = strings.TrimSpace(payload.Username)
	payload.Password = strings.TrimSpace(payload.Password)
	payload.Mailbox = strings.TrimSpace(payload.Mailbox)
	if payload.Port <= 0 {
		payload.Port = 993
	}
	if payload.Mailbox == "" {
		payload.Mailbox = "INBOX"
	}

	if payload.Host == "" || payload.Username == "" || payload.Password == "" {
		return nil
	}

	c.host = payload.Host
	c.port = payload.Port
	c.username = payload.Username
	c.password = payload.Password
	if strings.TrimSpace(c.mailbox) == "" || c.mailbox == "INBOX" {
		c.mailbox = payload.Mailbox
	}

	return nil
}

func decryptStoredPayload(raw []byte, keyPath string) ([]byte, error) {
	env, ok := cryptutil.ParseEnvelope(raw)
	if !ok {
		// Backward-compatibility with plaintext credentials.
		return raw, nil
	}

	// imap never creates the master key — only the api process does; a
	// missing key here is an error, not a reason to generate a new one.
	key, err := cryptutil.LoadKey(keyPath)
	if err != nil {
		return nil, err
	}
	return cryptutil.Open(env, key)
}

// overviewFromEmail builds an Overview from a go-imap *Email, parsing IMAP
// flags into Keywords/Status (a \Seen flag maps to Status "read", leading
// backslash flags are otherwise ignored, everything else is a label
// keyword). Works regardless of whether e came from GetOverviews directly
// or from GetEmails (which internally calls GetOverviews first and never
// overwrites Flags/Sent/Received when it later merges in body content).
func overviewFromEmail(uid int, e *goimap.Email) Overview {
	if e == nil {
		return Overview{MessageID: strconv.Itoa(uid), UID: uid, Status: "unread"}
	}

	keywords := []string{}
	status := "unread"
	seen := map[string]bool{}
	for _, flag := range e.Flags {
		clean := strings.TrimSpace(flag)
		if clean == "" {
			continue
		}
		if strings.EqualFold(clean, "\\Seen") {
			status = "read"
			continue
		}
		if strings.HasPrefix(clean, "\\") {
			continue
		}
		key := strings.ToLower(clean)
		if seen[key] {
			continue
		}
		seen[key] = true
		keywords = append(keywords, clean)
	}

	ts := e.Sent
	if ts.IsZero() {
		ts = e.Received
	}
	atUTC := ""
	if !ts.IsZero() {
		atUTC = ts.UTC().Format(time.RFC3339)
	}

	return Overview{
		MessageID: strconv.Itoa(uid),
		Subject:   strings.TrimSpace(e.Subject),
		Sender:    strings.TrimSpace(e.From.String()),
		SentTo:    strings.TrimSpace(e.To.String()),
		CC:        strings.TrimSpace(e.CC.String()),
		BCC:       strings.TrimSpace(e.BCC.String()),
		Keywords:  keywords,
		AtUTC:     atUTC,
		Status:    status,
		UID:       uid,
	}
}

// uidSetCriteria renders uids as an IMAP sequence-set (RFC 3501 §9:
// comma-separated numbers) for use as the argument to a SearchBuilder.UID
// search key, so a pre-fetch oversized-message SEARCH can be scoped to
// exactly the UIDs a caller is asking about instead of the whole mailbox.
func uidSetCriteria(uids []int) string {
	parts := make([]string, len(uids))
	for i, uid := range uids {
		parts[i] = strconv.Itoa(uid)
	}
	return strings.Join(parts, ",")
}

// partitionUIDsBySize splits filtered (the batch of UIDs a caller is about to
// process — ListUnreadInbox's unseen, past-checkpoint UIDs, or
// GetMessageBodies's requested UIDs) into toFetch — safe to hand to
// go-imap's GetEmails, which fully buffers each message's body and
// attachments into memory — and tooLarge — UIDs a server-side
// "... LARGER <cap>" SEARCH (UNSEEN-scoped for ListUnreadInbox, UID-set-scoped
// for GetMessageBodies) already identified as oversized, which must never be
// passed to GetEmails at all. oversized is exactly what that SEARCH returned;
// membership is intersected against filtered so a UID the search reports but
// that isn't in this batch (e.g. it fell out of UNSEEN between the two round
// trips) is silently ignored rather than fabricating a message for it. Pulled
// out as a pure function, with no IMAP connection involved, specifically so a
// test can assert on it directly — this package has no live/fake
// *goimap.Dialer to drive ListUnreadInbox/GetMessageBodies themselves
// end-to-end (see client_test.go), so this is the seam that proves oversized
// UIDs are structurally excluded from the fetch list, not just
// checked-and-discarded after GetEmails already ran.
func partitionUIDsBySize(filtered []int, oversized []int) (toFetch []int, tooLarge []int) {
	large := make(map[int]bool, len(oversized))
	for _, uid := range oversized {
		large[uid] = true
	}
	toFetch = make([]int, 0, len(filtered))
	tooLarge = make([]int, 0)
	for _, uid := range filtered {
		if large[uid] {
			tooLarge = append(tooLarge, uid)
		} else {
			toFetch = append(toFetch, uid)
		}
	}
	return toFetch, tooLarge
}

func (c *APIClient) ListUnreadInbox(ctx context.Context, sinceCheckpoint string) ([]Message, string, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, "", err
	}

	uids, err := d.GetUIDs("UNSEEN")
	if err != nil {
		return nil, "", fmt.Errorf("imap search unseen: %w", err)
	}
	if len(uids) == 0 {
		return []Message{}, sinceCheckpoint, nil
	}

	minUID := parseCheckpointUID(sinceCheckpoint)
	filtered := make([]int, 0, len(uids))
	for _, uid := range uids {
		if uid > minUID {
			filtered = append(filtered, uid)
		}
	}
	if len(filtered) == 0 {
		return []Message{}, sinceCheckpoint, nil
	}
	sort.Ints(filtered)

	// Ask the server which of these are oversized *before* fetching any
	// bodies: LARGER is evaluated against the server's own RFC822.SIZE, so
	// an oversized message's literal is never sent to us at all — a genuine
	// protocol-level pre-fetch bound, not just a post-fetch check (contrast
	// fetchAttachments below, which has no equivalent search step ahead of
	// it and so keeps the post-fetch emailContentSize check as its only
	// guard; GetMessageBodies uses this same UNSEEN/UID-scoped LARGER
	// technique for its own batch). UNSEEN is included in the same SEARCH
	// so this stays scoped to exactly the messages we're about to consider
	// (IMAP ANDs search criteria together).
	sb := goimap.Search().Unseen().Larger(int(mailmsg.MaxInboundMessageBytes))
	oversizedUIDs, err := d.SearchUIDs(sb)
	if err != nil {
		return nil, "", fmt.Errorf("imap search oversized: %w", err)
	}
	toFetch, tooLarge := partitionUIDsBySize(filtered, oversizedUIDs)

	out := make([]Message, 0, len(filtered))
	maxUID := minUID

	// Oversized UIDs: only a cheap GetOverviews FETCH (flags + envelope, no
	// body/attachments) — their Text/HTML/Attachments are never fetched.
	if len(tooLarge) > 0 {
		overviews, err := d.GetOverviews(tooLarge...)
		if err != nil {
			return nil, "", fmt.Errorf("imap fetch overviews: %w", err)
		}
		for _, uid := range tooLarge {
			if err := ctx.Err(); err != nil {
				return nil, "", err
			}
			ov := overviewFromEmail(uid, overviews[uid])
			out = append(out, Message{
				ID:       ov.MessageID,
				Subject:  ov.Subject,
				Sender:   ov.Sender,
				SentTo:   ov.SentTo,
				CC:       ov.CC,
				BCC:      ov.BCC,
				Keywords: ov.Keywords,
				AtUTC:    ov.AtUTC,
				TooLarge: true,
			})
			// maxUID advances past this UID the same as any other
			// successfully-handled message, so the poller (which rejects
			// and notifies instead of processing it — see handleMessage)
			// doesn't refetch it every tick.
			if uid > maxUID {
				maxUID = uid
			}
		}
	}

	// Everything else: the normal full-body fetch.
	var emails map[int]*goimap.Email
	if len(toFetch) > 0 {
		emails, err = d.GetEmails(toFetch...)
		if err != nil {
			return nil, "", fmt.Errorf("imap fetch emails: %w", err)
		}
	}
	for _, uid := range toFetch {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		e := emails[uid]
		if e == nil {
			continue
		}
		ov := overviewFromEmail(uid, e)
		// Defense-in-depth: the message could have grown between the
		// SEARCH above and this fetch (new mail arriving mid-poll, a
		// concurrent APPEND, etc). Re-check the actual decoded size rather
		// than trusting the search result was still accurate by the time
		// GetEmails ran.
		if emailContentSize(e) > mailmsg.MaxInboundMessageBytes {
			out = append(out, Message{
				ID:       ov.MessageID,
				Subject:  ov.Subject,
				Sender:   ov.Sender,
				SentTo:   ov.SentTo,
				CC:       ov.CC,
				BCC:      ov.BCC,
				Keywords: ov.Keywords,
				AtUTC:    ov.AtUTC,
				TooLarge: true,
			})
			if uid > maxUID {
				maxUID = uid
			}
			continue
		}
		body, bodyHTML := inboxBodies(e)
		out = append(out, Message{
			ID:             ov.MessageID,
			Subject:        ov.Subject,
			Sender:         ov.Sender,
			SentTo:         ov.SentTo,
			CC:             ov.CC,
			BCC:            ov.BCC,
			Keywords:       ov.Keywords,
			AtUTC:          ov.AtUTC,
			Body:           body,
			BodyHTML:       bodyHTML,
			HasAttachments: len(e.Attachments) > 0,
		})
		if uid > maxUID {
			maxUID = uid
		}
	}

	next := sinceCheckpoint
	if maxUID > minUID {
		next = strconv.Itoa(maxUID)
	}
	return out, next, nil
}

func (c *APIClient) ListUnreadMessages(ctx context.Context, mailbox string, limit int) ([]UnreadMessage, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	mailbox = strings.TrimSpace(mailbox)

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	uids, err := d.GetLastNUIDs(limit)
	if err != nil {
		return nil, fmt.Errorf("imap list recent messages: %w", err)
	}
	if len(uids) == 0 {
		return []UnreadMessage{}, nil
	}

	sort.Ints(uids)

	// A single GetEmails call is enough: it internally calls GetOverviews
	// first and never overwrites Flags/Sent/Received when it later merges
	// in body content, so overviewFromEmail(uid, e) below already has
	// everything a second, separate GetOverviews call used to provide.
	emails, err := d.GetEmails(uids...)
	if err != nil {
		return nil, fmt.Errorf("imap fetch emails: %w", err)
	}

	out := make([]UnreadMessage, 0, len(uids))
	for i := len(uids) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uid := uids[i]
		e := emails[uid]
		if e == nil {
			continue
		}

		ov := overviewFromEmail(uid, e)

		// Prefer HTML for inbox preview so the UI can render rich email content.
		// Fall back to plain text for text-only messages.
		body, bodyMode := clientBody(e)

		msg := UnreadMessage{
			BodyMode:       bodyMode,
			MessageID:      ov.MessageID,
			Subject:        ov.Subject,
			Sender:         ov.Sender,
			SentTo:         ov.SentTo,
			CC:             ov.CC,
			BCC:            ov.BCC,
			Keywords:       ov.Keywords,
			AtUTC:          ov.AtUTC,
			Body:           body,
			Status:         ov.Status,
			HasAttachments: len(e.Attachments) > 0,
		}
		if body == "" {
			if payload := pgpDetectPayload(e.Attachments); payload != "" {
				msg.PGPEncryptedPayload = payload
				msg.HasAttachments = false
			}
		} else if sig := pgpDetectSignature(e.Attachments); sig != "" {
			msg.PGPSignaturePayload = sig
		}
		out = append(out, msg)
	}

	return out, nil
}

// ListOverviews returns UID + envelope + flags for the last N messages in
// mailbox, without a body fetch (GetLastNUIDs + GetOverviews only — no
// GetEmails/body FETCH). Used by the mail-cache Sync path so the expensive
// body fetch happens only for UIDs the cache doesn't already have.
func (c *APIClient) ListOverviews(ctx context.Context, mailbox string, limit int) ([]Overview, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	mailbox = strings.TrimSpace(mailbox)

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	uids, err := d.GetLastNUIDs(limit)
	if err != nil {
		return nil, fmt.Errorf("imap list recent messages: %w", err)
	}
	if len(uids) == 0 {
		return []Overview{}, nil
	}

	sort.Ints(uids)

	overviews, err := d.GetOverviews(uids...)
	if err != nil {
		return nil, fmt.Errorf("imap fetch overviews: %w", err)
	}

	out := make([]Overview, 0, len(uids))
	for i := len(uids) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uid := uids[i]
		e := overviews[uid]
		if e == nil {
			continue
		}
		out = append(out, overviewFromEmail(uid, e))
	}
	return out, nil
}

// SearchMessages searches for messages in mailbox by field (sender/subject/body/all)
// and returns the newest N matching messages as Overview objects.
func (c *APIClient) SearchMessages(ctx context.Context, mailbox, field, query string, limit int) ([]Overview, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	mailbox = strings.TrimSpace(mailbox)
	field = strings.ToLower(strings.TrimSpace(field))
	query = strings.TrimSpace(query)

	if query == "" {
		return []Overview{}, nil
	}

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	sb := goimap.Search()
	switch field {
	case "subject":
		sb.Subject(query)
	case "sender", "from":
		sb.From(query)
	case "body":
		sb.Body(query)
	default:
		sb.Text(query)
	}

	uids, err := d.SearchUIDs(sb)
	if err != nil {
		return nil, fmt.Errorf("imap search: %w", err)
	}
	if len(uids) == 0 {
		return []Overview{}, nil
	}

	sort.Ints(uids)

	// Keep only the last (newest) `limit` results
	if len(uids) > limit {
		uids = uids[len(uids)-limit:]
	}

	overviews, err := d.GetOverviews(uids...)
	if err != nil {
		return nil, fmt.Errorf("imap fetch overviews: %w", err)
	}

	out := make([]Overview, 0, len(uids))
	for i := len(uids) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		uid := uids[i]
		e := overviews[uid]
		if e == nil {
			continue
		}
		out = append(out, overviewFromEmail(uid, e))
	}
	return out, nil
}

// GetMessageBodies fetches full body content (HTML preferred, falling back
// to plain text) and attachment presence for exactly the given UIDs — the
// selective counterpart to ListOverviews, called only for UIDs the mail cache
// reports as new.
func (c *APIClient) GetMessageBodies(ctx context.Context, mailbox string, uids []int) (map[int]MessageContent, error) {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(uids) == 0 {
		return map[int]MessageContent{}, nil
	}
	mailbox = strings.TrimSpace(mailbox)

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return nil, err
	}
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return nil, err
	}

	// Ask the server which of the requested UIDs are oversized *before*
	// fetching any bodies — the same technique ListUnreadInbox uses for the
	// poller's UNSEEN batch, scoped here to exactly the UID set this caller
	// asked about via a UID search key (ANDed with LARGER, since IMAP search
	// criteria are implicitly conjunctive). This closes the gap the
	// LARGER-search-less mail-cache-sync/rules-run paths otherwise had: an
	// attacker-delivered oversized message could previously be fully
	// buffered by GetEmails below before any size check ran, on every
	// inbox-cache-sync or rules-run pass over the victim's mailbox.
	sb := goimap.Search().UID(uidSetCriteria(uids)).Larger(int(mailmsg.MaxInboundMessageBytes))
	oversizedUIDs, err := d.SearchUIDs(sb)
	if err != nil {
		return nil, fmt.Errorf("imap search oversized: %w", err)
	}
	toFetch, tooLarge := partitionUIDsBySize(uids, oversizedUIDs)

	out := make(map[int]MessageContent, len(uids))
	for _, uid := range tooLarge {
		out[uid] = MessageContent{TooLarge: true}
	}

	var emails map[int]*goimap.Email
	if len(toFetch) > 0 {
		emails, err = d.GetEmails(toFetch...)
		if err != nil {
			return nil, fmt.Errorf("imap fetch emails: %w", err)
		}
	}
	for _, uid := range toFetch {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := emails[uid]
		if e == nil {
			continue
		}
		// Defense-in-depth: the message could have grown between the
		// SEARCH above and this fetch (new mail arriving concurrently,
		// etc). Re-check the actual decoded size rather than trusting the
		// search result was still accurate by the time GetEmails ran. Marks
		// this one UID TooLarge and moves on instead of failing the whole
		// batch — one oversized message must not make every other UID in
		// this call unreadable.
		if emailContentSize(e) > mailmsg.MaxInboundMessageBytes {
			out[uid] = MessageContent{TooLarge: true}
			continue
		}
		body, bodyMode := clientBody(e)
		content := MessageContent{Body: body, BodyMode: bodyMode, HasAttachments: len(e.Attachments) > 0}
		if body == "" {
			if payload := pgpDetectPayload(e.Attachments); payload != "" {
				content.PGPEncryptedPayload = payload
				content.HasAttachments = false
			}
		} else if sig := pgpDetectSignature(e.Attachments); sig != "" {
			content.PGPSignaturePayload = sig
		}
		out[uid] = content
	}
	return out, nil
}

func (c *APIClient) ApplyInboxAction(ctx context.Context, messageID, action, mailbox, targetMailbox string) error {
	c.opMu.Lock()
	defer c.opMu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	uid, err := strconv.Atoi(strings.TrimSpace(messageID))
	if err != nil || uid <= 0 {
		return fmt.Errorf("invalid message id %q", messageID)
	}
	action = strings.ToLower(strings.TrimSpace(action))
	targetMailbox = strings.TrimSpace(targetMailbox)

	d, err := c.ensureConnectedLocked()
	if err != nil {
		return err
	}
	mailbox = strings.TrimSpace(mailbox)
	if err := c.selectMailboxLocked(d, mailbox); err != nil {
		return err
	}
	// targetMailbox reaches UID MOVE via moveToFolder/ensureFolderThenRun
	// (which also CREATEs it), so it is a protocol sink in its own right and
	// is not covered by the select above.
	if err := validateOptionalMailboxName(targetMailbox); err != nil {
		return err
	}

	moveToFolder := func(folder string) error {
		return ensureFolderThenRun(d, folder, func(folder string) error {
			return d.MoveEmail(uid, folder)
		})
	}

	isTrashMailbox := func(name string) bool {
		clean := strings.TrimSpace(strings.ToLower(name))
		return clean == "trash" || clean == "inbox/trash" || clean == "inbox.trash"
	}

	switch action {
	case "read":
		if err := d.MarkSeen(uid); err != nil {
			return fmt.Errorf("imap mark seen uid %d: %w", uid, err)
		}
		return nil
	case "archive":
		year := time.Now().Year()
		emails, err := d.GetEmails(uid)
		if err == nil {
			if email := emails[uid]; email != nil {
				ts := email.Sent
				if ts.IsZero() {
					ts = email.Received
				}
				if !ts.IsZero() {
					year = ts.UTC().Year()
				}
			}
		}
		archiveTargets := []string{fmt.Sprintf("Archive/%d", year), fmt.Sprintf("Archive.%d", year)}
		var lastErr error
		for _, folder := range archiveTargets {
			if err := moveToFolder(folder); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return fmt.Errorf("imap move uid %d to yearly archive: %w", uid, lastErr)
		}
		return nil
	case "spam":
		if err := moveToFolder("Spam"); err != nil {
			return fmt.Errorf("imap move uid %d to Spam: %w", uid, err)
		}
		return nil
	case "delete":
		if isTrashMailbox(mailbox) {
			if err := d.DeleteEmail(uid); err != nil {
				return fmt.Errorf("imap delete uid %d from Trash: %w", uid, err)
			}
			return nil
		}
		trashTargets := []string{"Trash", "INBOX/Trash", "INBOX.Trash"}
		var lastErr error
		for _, folder := range trashTargets {
			if err := moveToFolder(folder); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
		if lastErr != nil {
			return fmt.Errorf("imap move uid %d to Trash: %w", uid, lastErr)
		}
		return nil
	case "move":
		if targetMailbox == "" {
			return errors.New("target mailbox is required")
		}
		if strings.EqualFold(strings.TrimSpace(mailbox), targetMailbox) {
			return nil
		}
		if err := moveToFolder(targetMailbox); err != nil {
			return fmt.Errorf("imap move uid %d to %q: %w", uid, targetMailbox, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported inbox action %q", action)
	}
}

// emailContentSize sums the bytes an already-fetched *goimap.Email holds in
// memory: its HTML/text bodies plus every attachment's content. Used to
// enforce mailmsg.MaxInboundMessageBytes uniformly across GetMessageBodies
// and fetchAttachments (and, transitively, ListAttachments/GetAttachment,
// which both call fetchAttachments) — a single message with many small
// attachments that add up past the cap is exactly as much of an OOM risk as
// one huge attachment, so the check is on the total, not any single part.
// inboxBodies splits one parsed email into the two body views ListUnreadInbox
// reports: Body, which keeps this path's long-standing text/plain preference
// (it is what gets classified, redacted, and warmed into the mail cache), and
// BodyHTML, which is the text/html part verbatim or empty. See Message.BodyHTML
// for why both are needed.
//
// Extracted as a pure function rather than left inline so it can be tested
// without a live *goimap.Dialer, matching partitionUIDsBySize and
// parseHeaderFieldsRecords in this package.
func inboxBodies(e *goimap.Email) (body, bodyHTML string) {
	bodyHTML = strings.TrimSpace(e.HTML)
	body = strings.TrimSpace(e.Text)
	if body == "" {
		body = bodyHTML
	}
	return body, bodyHTML
}

// Body render modes. These say which MIME part Body was taken from, so the
// client never has to guess from the bytes.
const (
	BodyModeHTML  = "html"
	BodyModePlain = "plain"
)

// clientBody picks the body every client-facing path reports, and says which
// part it came from.
//
// The mode is the point. Sniffing "does this look like HTML?" at the render
// site cannot distinguish markup from a plain-text message that merely
// contains angle brackets, and "<user@example.com>" — RFC 5322's own address
// form — is the common case it gets wrong: routed through the HTML pipeline it
// parses as an unknown tag and is dropped, silently deleting an address out of
// the message. The parse already knows the answer here; carry it.
// An empty body reports an EMPTY mode, not BodyModePlain. "" is the wire
// contract's "the server does not know" — and a message with no readable text
// part (a PGP envelope, an attachment-only mail) is precisely a case where it
// does not. Returning "plain" there stamped a confident answer on a body that
// was never parsed, mailcache.Store.Sync then preserved it forever, and the
// client trusted it over the fallback it would otherwise have used.
func clientBody(e *goimap.Email) (body, mode string) {
	if body = strings.TrimSpace(e.HTML); body != "" {
		return body, BodyModeHTML
	}
	if body = strings.TrimSpace(e.Text); body != "" {
		return body, BodyModePlain
	}
	return "", ""
}

// goimapDefaults sets the vendored library's package-level tunables exactly
// once.
//
// DialTimeout/CommandTimeout/RetryCount are globals inside go-imap, and this
// assignment used to run inline on every first-connect. Each APIClient has its
// own mutex but there is one of them per user, and the poller runs several
// user ticks concurrently, so -race flagged concurrent writes here. Every
// writer wrote the same constants, which is why it never misbehaved — but the
// project runs -race in CI, and it stops being benign the moment any of these
// becomes configurable.
var goimapDefaults sync.Once

func configureGoIMAPDefaults() {
	goimapDefaults.Do(func() {
		goimap.DialTimeout = 10 * time.Second
		goimap.CommandTimeout = 45 * time.Second
		goimap.RetryCount = 3
	})
}

// Close tears down this client's IMAP connection, if it has opened one.
//
// An APIClient holds a live, authenticated *goimap.Dialer for its whole life
// and Go's GC does not close sockets, so a client that is dropped without this
// leaves its session open on the far end until the server times it out —
// minutes to half an hour, and IMAP providers cap concurrent sessions per
// account (Gmail: 15). Both cache owners rebuild their client when the stored
// credentials change (api's userMailClient/invalidateUserMail, the poller's
// userMailClient), so without a close every IMAP settings save burned one
// session per process and a handful of saves could lock a user out of their
// own mailbox.
//
// Deliberately NOT added to the Client interface: the interface is implemented
// by six test fakes that have nothing to close, and the two eviction sites
// type-assert io.Closer instead. Safe to call more than once, and safe on a
// client that never connected.
func (c *APIClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.dialer == nil {
		return nil
	}
	err := c.dialer.Close()
	c.dialer = nil
	return err
}

func (c *APIClient) ensureConnectedLocked() (*goimap.Dialer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.ensureCredentialsFromStoredConfigLocked(); err != nil {
		return nil, err
	}

	if strings.TrimSpace(c.host) == "" || strings.TrimSpace(c.username) == "" || strings.TrimSpace(c.password) == "" {
		return nil, errors.New("missing IMAP credentials; configure IMAP_HOST, IMAP_USERNAME, and IMAP_PASSWORD or save credentials in IMAP settings")
	}

	if c.dialer == nil {
		configureGoIMAPDefaults()

		d, err := goimap.New(c.username, c.password, c.host, c.port)
		if err != nil {
			return nil, fmt.Errorf("imap connect: %w", err)
		}
		c.dialer = d
	}

	if err := c.dialer.SelectFolder(c.mailbox); err != nil {
		if recErr := c.dialer.Reconnect(); recErr != nil {
			return nil, fmt.Errorf("imap select folder %q: %w", c.mailbox, err)
		}
		if err := c.dialer.SelectFolder(c.mailbox); err != nil {
			return nil, fmt.Errorf("imap select folder %q after reconnect: %w", c.mailbox, err)
		}
	}

	return c.dialer, nil
}

func parseCheckpointUID(checkpoint string) int {
	v := strings.TrimSpace(checkpoint)
	if v == "" {
		return 0
	}
	uid, err := strconv.Atoi(v)
	if err != nil || uid < 0 {
		return 0
	}
	return uid
}
