package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/mailmsg"
)

// fakeMailClient is a configurable imapadapter.Client for exercising
// serveInbox's cache-first classic path and since-based delta path without
// a real IMAP connection. Every method call is counted so tests can assert
// IMAP was (or wasn't) touched.
type fakeMailClient struct {
	unread      []imapadapter.UnreadMessage
	unreadErr   error
	unreadCalls int

	overviews     []imapadapter.Overview
	overviewsErr  error
	overviewCalls int

	searchResults []imapadapter.Overview
	searchErr     error
	searchCalls   int

	bodies             map[int]string
	bodyHasAttachments map[int]bool
	bodyPGPEncrypted   map[int]bool
	bodiesErr          error
	bodiesCalls        int
	lastBodyUIDs       []int

	attachments    map[int][]mailmsg.Attachment
	attachmentsErr error

	// appliedLabels/removedLabels record every ApplyLabel/RemoveLabel call
	// (messageID, label pairs) so tests can assert exactly what keyword
	// actions reached the mail client.
	appliedLabels []labelCall
	removedLabels []labelCall
}

type labelCall struct {
	messageID string
	label     string
}

func (f *fakeMailClient) ListUnreadInbox(_ context.Context, _ string) ([]imapadapter.Message, string, error) {
	return nil, "", nil
}

func (f *fakeMailClient) ListUnreadMessages(_ context.Context, _ string, _ int) ([]imapadapter.UnreadMessage, error) {
	f.unreadCalls++
	return f.unread, f.unreadErr
}

func (f *fakeMailClient) ListOverviews(_ context.Context, _ string, _ int) ([]imapadapter.Overview, error) {
	f.overviewCalls++
	return f.overviews, f.overviewsErr
}

func (f *fakeMailClient) SearchMessages(_ context.Context, _ string, _ string, _ string, _ int) ([]imapadapter.Overview, error) {
	f.searchCalls++
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	if f.searchResults != nil {
		return f.searchResults, nil
	}
	return []imapadapter.Overview{}, nil
}

func (f *fakeMailClient) GetMessageBodies(_ context.Context, _ string, uids []int) (map[int]imapadapter.MessageContent, error) {
	f.bodiesCalls++
	f.lastBodyUIDs = append([]int{}, uids...)
	if f.bodiesErr != nil {
		return nil, f.bodiesErr
	}
	out := map[int]imapadapter.MessageContent{}
	for _, uid := range uids {
		if b, ok := f.bodies[uid]; ok {
			out[uid] = imapadapter.MessageContent{Body: b, HasAttachments: f.bodyHasAttachments[uid], PGPEncrypted: f.bodyPGPEncrypted[uid]}
		}
	}
	return out, nil
}

func (f *fakeMailClient) ListLabels(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeMailClient) ListSubfolders(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (f *fakeMailClient) CreateFolder(_ context.Context, _ string, _ string) (string, error) {
	return "", nil
}
func (f *fakeMailClient) RenameFolder(_ context.Context, _ string, _ string) (string, error) {
	return "", nil
}
func (f *fakeMailClient) DeleteFolder(_ context.Context, _ string) error { return nil }
func (f *fakeMailClient) EnsureLabel(_ context.Context, _ string) error  { return nil }
func (f *fakeMailClient) ApplyLabel(_ context.Context, messageID string, label string) error {
	f.appliedLabels = append(f.appliedLabels, labelCall{messageID: messageID, label: label})
	return nil
}
func (f *fakeMailClient) RemoveLabel(_ context.Context, messageID string, label string) error {
	f.removedLabels = append(f.removedLabels, labelCall{messageID: messageID, label: label})
	return nil
}
func (f *fakeMailClient) ApplyInboxAction(_ context.Context, _ string, _ string, _ string, _ string) error {
	return nil
}
func (f *fakeMailClient) SaveDraft(_ context.Context, _ imapadapter.DraftMessage) error { return nil }
func (f *fakeMailClient) SaveSent(_ context.Context, _ imapadapter.DraftMessage) error  { return nil }
func (f *fakeMailClient) FetchHeaderFields(context.Context, []int, ...string) (map[int][]string, error) {
	return nil, nil
}
func (f *fakeMailClient) FetchRawMessage(context.Context, int) ([]byte, error) { return nil, nil }

// Attachment fixtures for the /api/mail/attachment(s) handler tests.
func (f *fakeMailClient) ListAttachments(_ context.Context, _ string, uid int) ([]imapadapter.AttachmentInfo, error) {
	if f.attachmentsErr != nil {
		return nil, f.attachmentsErr
	}
	infos := make([]imapadapter.AttachmentInfo, 0, len(f.attachments[uid]))
	for i, a := range f.attachments[uid] {
		infos = append(infos, imapadapter.AttachmentInfo{
			Index: i, Name: a.Name, MimeType: a.MimeType, Size: len(a.Content),
		})
	}
	return infos, nil
}

func (f *fakeMailClient) GetAttachment(_ context.Context, _ string, uid int, index int) (imapadapter.AttachmentInfo, []byte, error) {
	if f.attachmentsErr != nil {
		return imapadapter.AttachmentInfo{}, nil, f.attachmentsErr
	}
	attachments := f.attachments[uid]
	if index < 0 || index >= len(attachments) {
		return imapadapter.AttachmentInfo{}, nil, imapadapter.ErrAttachmentNotFound
	}
	a := attachments[index]
	info := imapadapter.AttachmentInfo{
		Index: index, Name: a.Name, MimeType: a.MimeType, Size: len(a.Content),
	}
	return info, a.Content, nil
}

func testInboxCache(t *testing.T) *mailcache.Store {
	t.Helper()
	cache, err := mailcache.New(t.TempDir())
	if err != nil {
		t.Fatalf("mailcache.New: %v", err)
	}
	return cache
}

type inboxResponse struct {
	Tabs    []string                `json:"tabs"`
	ByTab   map[string][]inboxEmail `json:"byTab"`
	Delta   bool                    `json:"delta"`
	Cursor  int64                   `json:"cursor"`
	Removed []string                `json:"removed"`
}

func decodeInboxResponse(t *testing.T, rec *httptest.ResponseRecorder) inboxResponse {
	t.Helper()
	var resp inboxResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	return resp
}

func allEmails(resp inboxResponse) []inboxEmail {
	var out []inboxEmail
	for _, entries := range resp.ByTab {
		out = append(out, entries...)
	}
	return out
}

func TestServeInbox_ClassicServedFromWarmCache(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	if err := cache.Upsert("INBOX", []mailcache.Entry{
		{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "body-1"},
		{UID: 2, MessageID: "2", Subject: "b", Sender: "b@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "body-2"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	fake := &fakeMailClient{}
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 2, 0, false)

	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if fake.unreadCalls != 0 || fake.overviewCalls != 0 || fake.bodiesCalls != 0 {
		t.Fatalf("expected zero IMAP calls when cache is fully warmed, got unread=%d overviews=%d bodies=%d", fake.unreadCalls, fake.overviewCalls, fake.bodiesCalls)
	}

	resp := decodeInboxResponse(t, rec)
	if resp.Delta {
		t.Fatalf("classic response must not set delta=true")
	}
	emails := allEmails(resp)
	if len(emails) != 2 {
		t.Fatalf("expected 2 emails from cache, got %d", len(emails))
	}
	for _, e := range emails {
		if e.Body == "" {
			t.Fatalf("expected cached body to be served, got empty body for %+v", e)
		}
		if e.ChangeType != "" {
			t.Fatalf("classic response entries must not set changeType, got %+v", e)
		}
	}
}

func TestServeInbox_ClassicFallsBackAndSelfWarms(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
		{MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "body-1"},
	}}

	rec1 := httptest.NewRecorder()
	srv.serveInbox(rec1, context.Background(), userID, fake, cache, cfg, "", 1, 0, false)
	if rec1.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec1.Code, rec1.Body.String())
	}
	if fake.unreadCalls != 1 {
		t.Fatalf("expected exactly one live fetch on a cold cache, got %d", fake.unreadCalls)
	}

	// Second call for the same mailbox+limit should now be servable from
	// the self-warmed cache, with no further live fetch.
	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", 1, 0, false)
	if fake.unreadCalls != 1 {
		t.Fatalf("expected no additional live fetch after self-warming, got %d total calls", fake.unreadCalls)
	}
	resp := decodeInboxResponse(t, rec2)
	emails := allEmails(resp)
	if len(emails) != 1 || emails[0].Body != "body-1" {
		t.Fatalf("expected the self-warmed body to be served, got %+v", emails)
	}
}

// TestServeInbox_ClassicLiveFallbackReportsDecryptError guards against a
// regression where a failed PGP decrypt (no identity configured, in this
// case) never reached the response JSON: the message would render with
// PGPEncrypted=true, an empty body, and no error indication at all,
// indistinguishable from "still loading". The live-fallback path must copy
// decryptPGPUnreadMessage's PGPDecryptError onto the bucketed inboxEmail.
func TestServeInbox_ClassicLiveFallbackReportsDecryptError(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	// The test user has no PGP identity configured, so
	// decryptPGPUnreadMessage takes the "no pgp identity configured"
	// failure branch and sets PGPDecryptError.
	fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
		{
			MessageID:           "1",
			Subject:             "a",
			Sender:              "a@example.com",
			Status:              "unread",
			AtUTC:               "2026-01-01T00:00:00Z",
			PGPEncryptedPayload: "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
		},
	}}

	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, false)
	if rec.Code != 200 {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}

	resp := decodeInboxResponse(t, rec)
	emails := allEmails(resp)
	if len(emails) != 1 {
		t.Fatalf("expected one entry, got %+v", emails)
	}
	if emails[0].PGPDecryptError == "" {
		t.Fatalf("expected PGPDecryptError to be populated for a failed decrypt, got %+v", emails[0])
	}
	if emails[0].Body != "" {
		t.Fatalf("expected empty body for a failed decrypt, got %q", emails[0].Body)
	}
}

func TestServeInbox_DeltaFirstCallAllNew(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		},
		bodies: map[int]string{1: "body-1"},
	}

	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)

	if fake.overviewCalls != 1 {
		t.Fatalf("expected exactly one overview fetch, got %d", fake.overviewCalls)
	}
	if fake.bodiesCalls != 1 {
		t.Fatalf("expected exactly one body fetch for the new message, got %d", fake.bodiesCalls)
	}

	resp := decodeInboxResponse(t, rec)
	if !resp.Delta {
		t.Fatalf("expected delta=true")
	}
	if resp.Cursor == 0 {
		t.Fatalf("expected a non-zero cursor")
	}
	if len(resp.Removed) != 0 {
		t.Fatalf("expected no removed entries on first sync, got %+v", resp.Removed)
	}
	emails := allEmails(resp)
	if len(emails) != 1 || emails[0].ChangeType != "new" || emails[0].Body != "body-1" {
		t.Fatalf("expected one new entry with body populated, got %+v", emails)
	}
}

func TestServeInbox_DeltaFlagChangeIsUpdatedWithoutRefetchingBody(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		},
		bodies: map[int]string{1: "body-1"},
	}
	rec1 := httptest.NewRecorder()
	srv.serveInbox(rec1, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)
	first := decodeInboxResponse(t, rec1)

	// Second poll: the message's status flipped to read. The client's
	// cursor is the one returned by the first call.
	fake.overviews = []imapadapter.Overview{
		{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "read", AtUTC: "2026-01-01T00:00:00Z"},
	}
	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", 10, first.Cursor, true)

	if fake.bodiesCalls != 1 {
		t.Fatalf("expected no additional body fetch for an already-known message, got %d total body fetch calls", fake.bodiesCalls)
	}
	resp := decodeInboxResponse(t, rec2)
	emails := allEmails(resp)
	if len(emails) != 1 || emails[0].ChangeType != "updated" || emails[0].Status != "read" {
		t.Fatalf("expected one updated entry with status=read, got %+v", emails)
	}
	if emails[0].Body != "" {
		t.Fatalf("expected no body on an updated entry (client already has it), got %q", emails[0].Body)
	}
}

// TestServeInbox_DeltaUpdatedCarriesPGPFields guards against a regression
// where a flag-only delta update (read/unread, label change) reset a
// message's PGP badge state to zero-values on the client: PGPEncrypted is
// warm-path metadata like HasAttachments, not body content, so it must
// survive an "updated" bucket entry the same way HasAttachments does.
func TestServeInbox_DeltaUpdatedCarriesPGPFields(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		},
		bodies:           map[int]string{1: "body-1"},
		bodyPGPEncrypted: map[int]bool{1: true},
	}
	rec1 := httptest.NewRecorder()
	srv.serveInbox(rec1, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)
	first := decodeInboxResponse(t, rec1)
	firstEmails := allEmails(first)
	if len(firstEmails) != 1 || !firstEmails[0].PGPEncrypted {
		t.Fatalf("expected first sync's new entry to carry PGPEncrypted=true, got %+v", firstEmails)
	}

	// Second poll: the message's status flipped to read, nothing PGP-related
	// changed. The delta response should still report PGPEncrypted=true for
	// the "updated" entry, not reset it to false.
	fake.overviews = []imapadapter.Overview{
		{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "read", AtUTC: "2026-01-01T00:00:00Z"},
	}
	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", 10, first.Cursor, true)

	resp := decodeInboxResponse(t, rec2)
	emails := allEmails(resp)
	if len(emails) != 1 || emails[0].ChangeType != "updated" {
		t.Fatalf("expected one updated entry, got %+v", emails)
	}
	if !emails[0].PGPEncrypted {
		t.Fatalf("expected PGPEncrypted=true to survive a flag-only delta update, got %+v", emails[0])
	}
}

func TestServeInbox_DeltaSkipsBodyFetchWhenAlreadyWarmed(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	// Simulate the daemon having already warmed uid 1's body before any
	// client ever polls.
	if err := cache.Upsert("INBOX", []mailcache.Entry{
		{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "warmed-body"},
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		},
	}
	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)

	if fake.bodiesCalls != 0 {
		t.Fatalf("expected no body fetch when the daemon already warmed the body, got %d calls, uids=%v", fake.bodiesCalls, fake.lastBodyUIDs)
	}
	resp := decodeInboxResponse(t, rec)
	emails := allEmails(resp)
	if len(emails) != 1 || emails[0].ChangeType != "new" || emails[0].Body != "warmed-body" {
		t.Fatalf("expected the warmed body to be served for the new entry, got %+v", emails)
	}
}

func TestServeInbox_DeltaWindowFalloutReportedAsRemoved(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	fake := &fakeMailClient{
		overviews: []imapadapter.Overview{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
			{UID: 2, MessageID: "2", Subject: "b", Sender: "b@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		},
		bodies: map[int]string{1: "body-1", 2: "body-2"},
	}
	rec1 := httptest.NewRecorder()
	srv.serveInbox(rec1, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)
	first := decodeInboxResponse(t, rec1)

	// uid 1 ages out of the window.
	fake.overviews = []imapadapter.Overview{
		{UID: 2, MessageID: "2", Subject: "b", Sender: "b@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
	}
	rec2 := httptest.NewRecorder()
	srv.serveInbox(rec2, context.Background(), userID, fake, cache, cfg, "", 10, first.Cursor, true)

	resp := decodeInboxResponse(t, rec2)
	if len(resp.Removed) != 1 || resp.Removed[0] != "1" {
		t.Fatalf("expected uid 1 reported as removed, got %+v", resp.Removed)
	}
}

func TestServeInbox_TabBucketingByKeyword(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cache := testInboxCache(t)
	cfg := config.Default()

	// The tabs come from THIS ACCOUNT's label set, not the house list — that
	// is what per-user labels changed. Set it directly rather than relying on
	// the seed, so the test says which list it means.
	if err := config.UpdateUserSettings(srv.userSettingsPath(userID), func(us *config.UserSettings) error {
		us.Labels.Seeded = true
		us.Labels.Allowlist = []string{"Work"}
		return nil
	}); err != nil {
		t.Fatalf("seed user labels: %v", err)
	}

	fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
		{MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "b1", Keywords: []string{"Work"}},
		{MessageID: "2", Subject: "b", Sender: "b@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "b2"},
	}}

	rec := httptest.NewRecorder()
	srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, false)
	resp := decodeInboxResponse(t, rec)

	if len(resp.ByTab["Work"]) != 1 || resp.ByTab["Work"][0].MessageID != "1" {
		t.Fatalf("expected message 1 bucketed into Work tab, got %+v", resp.ByTab["Work"])
	}
	if len(resp.ByTab[inboxUncategorizedTab]) != 1 || resp.ByTab[inboxUncategorizedTab][0].MessageID != "2" {
		t.Fatalf("expected message 2 bucketed into Uncategorized, got %+v", resp.ByTab[inboxUncategorizedTab])
	}
}

// findByMessageID locates one entry across every tab in resp, so callers
// don't need to know which tab bucketing put it in.
func findByMessageID(resp inboxResponse, messageID string) (inboxEmail, bool) {
	for _, entries := range resp.ByTab {
		for _, e := range entries {
			if e.MessageID == messageID {
				return e, true
			}
		}
	}
	return inboxEmail{}, false
}

// TestServeInbox_KeywordsPopulatedOnAllPaths proves entry.Keywords is
// stamped inside bucket() regardless of which of serveInbox's 4 code paths
// built the inboxEmail: cache-warm (classic warmed), live-fallback
// (classic cold cache), delta-new, and delta-updated. A common bug shape
// here is patching only one call site.
func TestServeInbox_KeywordsPopulatedOnAllPaths(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	cfg := config.Default()

	t.Run("cache-warm", func(t *testing.T) {
		cache := testInboxCache(t)
		if err := cache.Upsert("INBOX", []mailcache.Entry{
			{UID: 1, MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "b1", Keywords: []string{"Work"}},
		}); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		fake := &fakeMailClient{}
		rec := httptest.NewRecorder()
		// Snapshot only reports warmed=true for a full window of exactly
		// `limit` cached entries, so limit must match the 1 entry seeded
		// above for this to exercise the cache-warm path rather than
		// falling through to live-fallback.
		srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 1, 0, false)
		resp := decodeInboxResponse(t, rec)
		e, ok := findByMessageID(resp, "1")
		if !ok || len(e.Keywords) != 1 || e.Keywords[0] != "Work" {
			t.Fatalf("expected Keywords=[Work] on cache-warm path, got %+v (found=%v)", e, ok)
		}
		if fake.unreadCalls != 0 {
			t.Fatalf("expected zero live IMAP calls on a fully warmed cache, got %d", fake.unreadCalls)
		}
	})

	t.Run("live-fallback", func(t *testing.T) {
		cache := testInboxCache(t)
		fake := &fakeMailClient{unread: []imapadapter.UnreadMessage{
			{MessageID: "2", Subject: "b", Sender: "b@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Body: "b2", Keywords: []string{"Work"}},
		}}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, false)
		resp := decodeInboxResponse(t, rec)
		e, ok := findByMessageID(resp, "2")
		if !ok || len(e.Keywords) != 1 || e.Keywords[0] != "Work" {
			t.Fatalf("expected Keywords=[Work] on live-fallback path, got %+v (found=%v)", e, ok)
		}
	})

	t.Run("delta-new", func(t *testing.T) {
		cache := testInboxCache(t)
		fake := &fakeMailClient{overviews: []imapadapter.Overview{
			{UID: 3, MessageID: "3", Subject: "c", Sender: "c@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Keywords: []string{"Work"}},
		}, bodies: map[int]string{3: "b3"}}
		rec := httptest.NewRecorder()
		srv.serveInbox(rec, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)
		resp := decodeInboxResponse(t, rec)
		e, ok := findByMessageID(resp, "3")
		if !ok || len(e.Keywords) != 1 || e.Keywords[0] != "Work" {
			t.Fatalf("expected Keywords=[Work] on delta-new path, got %+v (found=%v)", e, ok)
		}
		if e.ChangeType != "new" {
			t.Fatalf("expected changeType=new, got %+v", e)
		}
	})

	t.Run("delta-updated", func(t *testing.T) {
		cache := testInboxCache(t)
		fake := &fakeMailClient{overviews: []imapadapter.Overview{
			{UID: 4, MessageID: "4", Subject: "d", Sender: "d@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z"},
		}, bodies: map[int]string{4: "b4"}}
		first := httptest.NewRecorder()
		srv.serveInbox(first, context.Background(), userID, fake, cache, cfg, "", 10, 0, true)
		firstResp := decodeInboxResponse(t, first)

		// Second delta call with the same UID now carrying a keyword flags
		// it as "updated" (metadata changed, no new body fetch).
		fake.overviews = []imapadapter.Overview{
			{UID: 4, MessageID: "4", Subject: "d", Sender: "d@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Keywords: []string{"Work"}},
		}
		second := httptest.NewRecorder()
		srv.serveInbox(second, context.Background(), userID, fake, cache, cfg, "", 10, firstResp.Cursor, true)
		resp := decodeInboxResponse(t, second)
		e, ok := findByMessageID(resp, "4")
		if !ok || len(e.Keywords) != 1 || e.Keywords[0] != "Work" {
			t.Fatalf("expected Keywords=[Work] on delta-updated path, got %+v (found=%v)", e, ok)
		}
		if e.ChangeType != "updated" {
			t.Fatalf("expected changeType=updated, got %+v", e)
		}
	})
}

// TestHandleMailSearch_PopulatesKeywords guards against a regression where
// GET /api/mail/search built its inboxEmail response literal independently
// of serveInbox's bucket() closure and computed a Label from
// overview.Keywords without ever also copying Keywords onto the response —
// so a message found via search never showed its keyword chips even though
// the same message browsed normally would.
func TestHandleMailSearch_PopulatesKeywords(t *testing.T) {
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID

	srv.cfgMu.Lock()
	srv.cfg.Labels.Allowlist = []string{"Work"}
	srv.cfgMu.Unlock()

	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	fake := &fakeMailClient{searchResults: []imapadapter.Overview{
		{MessageID: "1", Subject: "a", Sender: "a@example.com", Status: "unread", AtUTC: "2026-01-01T00:00:00Z", Keywords: []string{"Work"}},
	}}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/mail/search?q=hello", nil)
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if fake.searchCalls != 1 {
		t.Fatalf("expected exactly one SearchMessages call, got %d", fake.searchCalls)
	}

	var resp struct {
		Results []inboxEmail `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 search result, got %+v", resp.Results)
	}
	got := resp.Results[0]
	if len(got.Keywords) != 1 || got.Keywords[0] != "Work" {
		t.Fatalf("expected Keywords=[Work] on search result, got %+v", got)
	}
	if got.Label != "Work" {
		t.Fatalf("expected Label=Work on search result, got %+v", got)
	}
}

func TestFakeMailClient_RemoveLabelRecordsCall(t *testing.T) {
	var client imapadapter.Client = &fakeMailClient{}
	fake := client.(*fakeMailClient)
	if err := client.RemoveLabel(context.Background(), "42", "VIP"); err != nil {
		t.Fatalf("RemoveLabel: %v", err)
	}
	if len(fake.removedLabels) != 1 || fake.removedLabels[0].messageID != "42" || fake.removedLabels[0].label != "VIP" {
		t.Fatalf("expected RemoveLabel(42, VIP) recorded, got %+v", fake.removedLabels)
	}
}
