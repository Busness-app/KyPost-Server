package processor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"kypost-server/backend/internal/cryptutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/config"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/rules"
	"kypost-server/backend/internal/state"
)

// TestMailCacheEntriesFromMessages covers the pure conversion tickUser uses
// to opportunistically warm the mail cache with what ListUnreadInbox just
// fetched for classification (poller.go). Full tickUser integration
// (constructing a Poller against a fake IMAP dialer) isn't covered here —
// this codebase has no fake-goimap-Dialer test infrastructure, matching the
// same gap noted for adapters/imap's ListOverviews/GetMessageBodies.
func TestMailCacheEntriesFromMessages(t *testing.T) {
	messages := []imapadapter.Message{
		{
			ID: "42", Subject: "Invoice", Sender: "alice@example.com", SentTo: "me@example.com",
			CC: "cc@example.com", BCC: "bcc@example.com", Keywords: []string{"Work"},
			AtUTC: "2026-01-01T00:00:00Z", Body: "the body",
		},
		// Malformed IDs (shouldn't happen in practice, since imap.Message.ID
		// is always strconv.Itoa(uid)) must be skipped, not panic or produce
		// a garbage UID.
		{ID: "not-a-number", Subject: "bad"},
	}

	entries := mailCacheEntriesFromMessages(messages)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (malformed ID skipped), got %d: %+v", len(entries), entries)
	}

	e := entries[0]
	if e.UID != 42 || e.MessageID != "42" {
		t.Fatalf("expected uid/messageId 42, got %+v", e)
	}
	if e.Subject != "Invoice" || e.Sender != "alice@example.com" || e.SentTo != "me@example.com" {
		t.Fatalf("expected envelope fields carried over, got %+v", e)
	}
	if e.CC != "cc@example.com" || e.BCC != "bcc@example.com" {
		t.Fatalf("expected CC/BCC carried over, got %+v", e)
	}
	if len(e.Keywords) != 1 || e.Keywords[0] != "Work" {
		t.Fatalf("expected keywords carried over, got %+v", e.Keywords)
	}
	if e.Body != "the body" {
		t.Fatalf("expected body carried over so the classic cache-first path can serve it, got %q", e.Body)
	}
	// ListUnreadInbox only ever returns messages matching an IMAP UNSEEN
	// search, so Status is always "unread" regardless of flags.
	if e.Status != "unread" {
		t.Fatalf("expected status always unread, got %q", e.Status)
	}
}

func TestMailCacheEntriesFromMessages_EmptyInput(t *testing.T) {
	entries := mailCacheEntriesFromMessages(nil)
	if len(entries) != 0 {
		t.Fatalf("expected no entries for empty input, got %+v", entries)
	}
}

func TestBuildNativeNotificationText(t *testing.T) {
	tests := []struct {
		name      string
		msg       imapadapter.Message
		wantTitle string
		wantBody  string
	}{
		{
			name:      "sender and subject",
			msg:       imapadapter.Message{Sender: "alice@example.com", Subject: "Invoice #42"},
			wantTitle: "alice@example.com",
			wantBody:  "Invoice #42",
		},
		{
			name:      "missing subject",
			msg:       imapadapter.Message{Sender: "bob@example.com"},
			wantTitle: "bob@example.com",
			wantBody:  "You have a new email.",
		},
		{
			name:      "missing sender",
			msg:       imapadapter.Message{Subject: "Meeting notes"},
			wantTitle: "New Email",
			wantBody:  "Meeting notes",
		},
		{
			name:      "empty message",
			msg:       imapadapter.Message{},
			wantTitle: "New Email",
			wantBody:  "You have a new email.",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			title, body := buildNativeNotificationText(tc.msg, true)
			if title != tc.wantTitle || body != tc.wantBody {
				t.Fatalf("buildNativeNotificationText() = (%q, %q), want (%q, %q)", title, body, tc.wantTitle, tc.wantBody)
			}
		})
	}
}

func TestBuildNativePushData(t *testing.T) {
	tests := []struct {
		name     string
		msg      imapadapter.Message
		keywords []string
		title    string
		body     string
		want     map[string]string
	}{
		{
			name:     "populated message and keywords",
			msg:      imapadapter.Message{ID: " 123 ", Sender: " alice@example.com ", Subject: " Invoice #42 "},
			keywords: []string{"work", "billing"},
			title:    "alice@example.com",
			body:     "Invoice #42",
			want: map[string]string{
				"messageId":    "123",
				"sender":       "alice@example.com",
				"subject":      "Invoice #42",
				"senderName":   "alice@example.com",
				"emailSubject": "Invoice #42",
				"Keywords":     "work,billing",
				"title":        "alice@example.com",
				"body":         "Invoice #42",
				"url":          "/read",
			},
		},
		{
			name:     "nil keywords produce empty string, not panic",
			msg:      imapadapter.Message{ID: "1", Sender: "bob@example.com", Subject: "Hi"},
			keywords: nil,
			title:    "bob@example.com",
			body:     "Hi",
			want: map[string]string{
				"messageId":    "1",
				"sender":       "bob@example.com",
				"subject":      "Hi",
				"senderName":   "bob@example.com",
				"emailSubject": "Hi",
				"Keywords":     "",
				"title":        "bob@example.com",
				"body":         "Hi",
				"url":          "/read",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNativePushData(tc.msg, tc.keywords, tc.title, tc.body, true)
			for key, want := range tc.want {
				if got[key] != want {
					t.Errorf("buildNativePushData()[%q] = %q, want %q", key, got[key], want)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("buildNativePushData() has %d keys, want %d: %v", len(got), len(tc.want), got)
			}
		})
	}
}

func TestShouldSendNotification(t *testing.T) {
	tests := []struct {
		name          string
		settings      config.UserNotificationSettings
		selectedLabel string
		keywords      []string
		want          bool
	}{
		{
			name:     "none mode never sends",
			settings: config.UserNotificationSettings{Mode: "none", Keywords: []string{"Urgent"}},
			want:     false,
		},
		{
			name:     "all mode always sends",
			settings: config.UserNotificationSettings{Mode: "all"},
			want:     true,
		},
		{
			name:          "keywords mode matches selected label",
			settings:      config.UserNotificationSettings{Mode: "keywords", Keywords: []string{"Urgent"}},
			selectedLabel: "urgent",
			want:          true,
		},
		{
			name:     "keywords mode matches mapped keyword",
			settings: config.UserNotificationSettings{Mode: "keywords", Keywords: []string{"billing"}},
			keywords: []string{"Invoices", "Billing"},
			want:     true,
		},
		{
			name:          "keywords mode does not match when nothing selected",
			settings:      config.UserNotificationSettings{Mode: "keywords", Keywords: []string{"urgent"}},
			selectedLabel: "support",
			keywords:      []string{"helpdesk"},
			want:          false,
		},
		{
			name:          "keywords mode does not send when uncategorized",
			settings:      config.UserNotificationSettings{Mode: "keywords", Keywords: []string{"urgent"}},
			selectedLabel: "",
			keywords:      nil,
			want:          false,
		},
		{
			name:          "keywords mode sends from selected label before mailbox keyword readback",
			settings:      config.UserNotificationSettings{Mode: "keywords", Keywords: []string{"urgent"}},
			selectedLabel: "urgent",
			keywords:      nil,
			want:          true,
		},
		{
			name:          "all mode sends even when uncategorized",
			settings:      config.UserNotificationSettings{Mode: "all"},
			selectedLabel: "",
			keywords:      nil,
			want:          true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldSendNotification(tc.settings, tc.selectedLabel, tc.keywords); got != tc.want {
				t.Fatalf("shouldSendNotification() = %v, want %v", got, tc.want)
			}
		})
	}
}

// noopMailClient is a minimal imapadapter.Client fake for handleMessage
// tests — only the methods rules.ApplyOutcome might call do anything
// observable; everything else is an unused no-op to satisfy the interface.
// inboxActionErr, when set, is returned by ApplyInboxAction so tests can
// inject a genuine action failure (e.g. a transient IMAP error on
// archive/move/delete) instead of always succeeding.
type noopMailClient struct {
	appliedLabels  []string
	inboxActions   []string
	inboxActionErr error
}

func (c *noopMailClient) ListUnreadInbox(context.Context, string) ([]imapadapter.Message, string, error) {
	return nil, "", nil
}
func (c *noopMailClient) ListUnreadMessages(context.Context, string, int) ([]imapadapter.UnreadMessage, error) {
	return nil, nil
}
func (c *noopMailClient) ListOverviews(context.Context, string, int) ([]imapadapter.Overview, error) {
	return nil, nil
}
func (c *noopMailClient) SearchMessages(context.Context, string, string, string, int) ([]imapadapter.Overview, error) {
	return nil, nil
}
func (c *noopMailClient) GetMessageBodies(context.Context, string, []int) (map[int]imapadapter.MessageContent, error) {
	return nil, nil
}
func (c *noopMailClient) ListLabels(context.Context) ([]string, error)             { return nil, nil }
func (c *noopMailClient) ListSubfolders(context.Context, string) ([]string, error) { return nil, nil }
func (c *noopMailClient) CreateFolder(context.Context, string, string) (string, error) {
	return "", nil
}
func (c *noopMailClient) RenameFolder(context.Context, string, string) (string, error) {
	return "", nil
}
func (c *noopMailClient) DeleteFolder(context.Context, string) error { return nil }
func (c *noopMailClient) EnsureLabel(context.Context, string) error  { return nil }
func (c *noopMailClient) ApplyLabel(_ context.Context, _ string, label string) error {
	c.appliedLabels = append(c.appliedLabels, label)
	return nil
}
func (c *noopMailClient) RemoveLabel(context.Context, string, string) error { return nil }
func (c *noopMailClient) ApplyInboxAction(_ context.Context, _ string, action, _, _ string) error {
	c.inboxActions = append(c.inboxActions, action)
	return c.inboxActionErr
}
func (c *noopMailClient) ListAttachments(context.Context, string, int) ([]imapadapter.AttachmentInfo, error) {
	return nil, nil
}
func (c *noopMailClient) GetAttachment(context.Context, string, int, int) (imapadapter.AttachmentInfo, []byte, error) {
	return imapadapter.AttachmentInfo{}, nil, nil
}
func (c *noopMailClient) SaveDraft(context.Context, imapadapter.DraftMessage) error { return nil }
func (c *noopMailClient) SaveSent(context.Context, imapadapter.DraftMessage) error  { return nil }
func (c *noopMailClient) FetchHeaderFields(context.Context, []int, ...string) (map[int][]string, error) {
	return nil, nil
}
func (c *noopMailClient) FetchRawMessage(context.Context, int) ([]byte, error) { return nil, nil }

// TestShouldMarkProcessedOnError_TransientClassifierErrorLeavesUnmarked
// proves a transient classifier-outage error (the classifier service
// unreachable/timed out, classifyWithRetry already gave up retrying) tells
// the loop NOT to mark the message processed, so it is retried on the next
// poll tick instead of being silently and permanently skipped.
func TestShouldMarkProcessedOnError_TransientClassifierErrorLeavesUnmarked(t *testing.T) {
	err := &classifierErr{err: errors.New("dial tcp 127.0.0.1:11434: connect: connection refused")}
	if shouldMarkProcessedOnError(err) {
		t.Fatal("expected a transient classifier error to NOT mark the message processed")
	}
}

// TestShouldMarkProcessedOnError_PermanentClassifierErrorMarksProcessed
// proves permanent classifier failures (bad input, credits exhausted) keep
// today's behavior of marking the message processed — retrying them would
// just burn classifier calls on mail that will never succeed.
func TestShouldMarkProcessedOnError_PermanentClassifierErrorMarksProcessed(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"bad input / 422", &classifierErr{err: errors.New("classifier: 422 Unprocessable Entity")}},
		{"ai credits exhausted", &classifierErr{err: errors.New("out of ai credits")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !shouldMarkProcessedOnError(tc.err) {
				t.Fatal("expected a permanent classifier error to still mark the message processed")
			}
		})
	}
}

// TestShouldMarkProcessedOnError_UnclassifiedErrorMarksProcessed pins the
// DEFAULT, which is still to retire.
//
// An error nothing wrapped is an error nothing has judged, and the failure mode
// of guessing "transient" is a message that holds the poll checkpoint forever.
// Deferral is opt-in at a call site that knows why the failure happened; these
// errors carry no such claim.
func TestShouldMarkProcessedOnError_UnclassifiedErrorMarksProcessed(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"plain error", errors.New("imap: connection reset by peer")},
		{"wrapped, but not marked retryable", fmt.Errorf("rule action failed: %w", errors.New("imap: timeout"))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !shouldMarkProcessedOnError(tc.err) {
				t.Fatal("expected an unclassified error to retire the message rather than defer it indefinitely")
			}
		})
	}
}

// TestShouldMarkProcessedOnError_RetryableErrorLeavesUnmarked covers the
// transient IMAP and state-store failures handleMessage now marks explicitly:
// a keyword write that failed after its own retries, a rule action that lost
// the connection, an audit write that lost a lock race. Each of these is work
// the next tick can still complete, so retiring the message throws it away.
func TestShouldMarkProcessedOnError_RetryableErrorLeavesUnmarked(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"keyword apply failed", &retryableErr{err: errors.New("imap: connection reset by peer")}},
		{"rule action failed", &retryableErr{err: errors.New("archive: imap: timeout")}},
		{"state write lost a lock race", &retryableErr{err: errors.New("database is locked")}},
		{"wrapped further up", fmt.Errorf("handling message 42: %w", &retryableErr{err: errors.New("imap: eof")})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if shouldMarkProcessedOnError(tc.err) {
				t.Fatal("expected a retryable failure to leave the message unmarked so a later tick retries it")
			}
		})
	}
}

// TestRecordMessageFailure_TransientClassifierErrorLeavesMessageUnprocessed
// exercises the actual code tickUser's message loop runs on a handleMessage
// failure (recordMessageFailure), using a real state.Store, proving a
// transient classifier error leaves the message unmarked end-to-end while
// still recording the failure as a Decision.
func TestRecordMessageFailure_TransientClassifierErrorLeavesMessageUnprocessed(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := &Poller{log: logger}

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	uc := userCtx{id: "user-1", store: store, mail: &noopMailClient{}}
	msg := imapadapter.Message{ID: "50", Subject: "Hello", Sender: "a@example.com"}

	classifyErr := &classifierErr{err: errors.New("dial tcp 127.0.0.1:11434: connect: connection refused")}
	p.recordMessageFailure(store, uc.id, uc, msg, classifyErr, shouldMarkProcessedOnError(classifyErr))

	if seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message to remain unmarked after a transient classifier outage, so it is retried next poll tick")
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 || decisions[0].Status != "failed" {
		t.Fatalf("expected a failed decision to still be recorded, got %+v", decisions)
	}
}

// TestRecordMessageFailure_PermanentClassifierErrorMarksProcessed proves a
// permanent classifier error (bad input/credits exhausted) still marks the
// message processed, unchanged from today's behavior.
func TestRecordMessageFailure_PermanentClassifierErrorMarksProcessed(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := &Poller{log: logger}

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	uc := userCtx{id: "user-1", store: store, mail: &noopMailClient{}}
	msg := imapadapter.Message{ID: "51", Subject: "Hello", Sender: "a@example.com"}

	classifyErr := &classifierErr{err: errors.New("out of ai credits")}
	p.recordMessageFailure(store, uc.id, uc, msg, classifyErr, shouldMarkProcessedOnError(classifyErr))

	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message to still be marked processed for a permanent classifier error")
	}
}

// TestRecordMessageFailure_NonClassifierErrorMarksProcessed is the
// regression guard at the recordMessageFailure level: a rule/IMAP-style
// error (not a classifierErr) must still mark the message processed exactly
// as before this task's change.
func TestRecordMessageFailure_NonClassifierErrorMarksProcessed(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := &Poller{log: logger}

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	uc := userCtx{id: "user-1", store: store, mail: &noopMailClient{}}
	msg := imapadapter.Message{ID: "52", Subject: "Hello", Sender: "a@example.com"}

	ruleErr := errors.New("imap: connection reset by peer")
	p.recordMessageFailure(store, uc.id, uc, msg, ruleErr, shouldMarkProcessedOnError(ruleErr))

	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected a non-classifier (rule/IMAP) error to still mark the message processed (regression guard)")
	}
}

// TestHandleMessage_StopRuleShortCircuitsClassification proves a matched
// "stop" rule skips classifyWithRetry entirely, rather than merely skipping
// its result: the Poller's classifier field is left nil, so if handleMessage
// called classifyWithRetry anyway, HTTPClient.Classify would panic on a nil
// receiver dereference (c.baseURL inside ensureWarm) and fail this test.
// The message must still be marked processed and recorded as a Decision.
func TestHandleMessage_StopRuleShortCircuitsClassification(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	p := &Poller{log: logger} // classifier intentionally left nil

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	mail := &noopMailClient{}
	uc := userCtx{
		id:   "user-1",
		mail: mail,
		rules: []rules.Rule{
			{
				Name:    "archive and stop",
				Enabled: true,
				Match: rules.MatchGroup{
					Op:         "allof",
					Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "newsletter"}},
				},
				Actions: []rules.Action{{Type: "archive"}, {Type: "stop"}},
			},
		},
		store: store,
	}
	msg := imapadapter.Message{ID: "42", Subject: "Weekly newsletter", Sender: "news@example.com"}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	if len(mail.inboxActions) != 1 || mail.inboxActions[0] != "archive" {
		t.Fatalf("expected the archive action to be applied, got %+v", mail.inboxActions)
	}
	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message to be marked processed")
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision recorded, got %d: %+v", len(decisions), decisions)
	}
	if decisions[0].Status != "applied" || decisions[0].Detail != "rule(s) applied: archive and stop" {
		t.Fatalf("unexpected decision recorded: %+v", decisions[0])
	}
}

// TestHandleMessage_StopRuleActionFailureDefersInsteadOfClaimingSuccess proves
// a genuine action failure (a transient IMAP error on the archive call) is
// logged AND returned as a retryable error, so tickUser defers the message
// instead of retiring it.
//
// The behaviour this replaces recorded the failure in the Decision's Detail and
// then marked the message processed anyway, with Status "applied". The archive
// had not happened, the audit log said it had, and no later tick would look at
// the message again — a failed IMAP command silently discarded the user's rule.
// An earlier version of this test asserted that retirement as correct.
func TestHandleMessage_StopRuleActionFailureDefersInsteadOfClaimingSuccess(t *testing.T) {
	logDir := t.TempDir()
	logger, err := logging.New(logDir)
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	p := &Poller{log: logger} // classifier intentionally left nil

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	wantErr := "imap: connection reset by peer"
	mail := &noopMailClient{inboxActionErr: errors.New(wantErr)}
	uc := userCtx{
		id:   "user-1",
		mail: mail,
		rules: []rules.Rule{
			{
				Name:    "archive and stop",
				Enabled: true,
				Match: rules.MatchGroup{
					Op:         "allof",
					Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "newsletter"}},
				},
				Actions: []rules.Action{{Type: "archive"}, {Type: "stop"}},
			},
		},
		store: store,
	}
	msg := imapadapter.Message{ID: "42", Subject: "Weekly newsletter", Sender: "news@example.com"}

	err = p.handleMessage(context.Background(), uc, msg)
	if err == nil {
		t.Fatal("expected a failed rule action to return an error, not a silent success")
	}

	// Retryable, so tickUser defers the message and holds the checkpoint below
	// it rather than retiring it.
	var retryable *retryableErr
	if !errors.As(err, &retryable) {
		t.Fatalf("expected a retryableErr so the message is retried, got %T: %v", err, err)
	}
	if shouldMarkProcessedOnError(err) {
		t.Fatal("expected a failed rule action to leave the message unmarked for a later tick")
	}
	if !strings.Contains(err.Error(), "rule(s) applied: archive and stop") {
		t.Fatalf("expected the error to report the matched rule, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "1 action(s) failed") || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("expected the error to mention the failed action and its cause, got %q", err.Error())
	}

	// Nothing may be recorded as applied and nothing retired: handleMessage
	// returns before either write. tickUser records the failure via
	// recordMessageFailure instead.
	if seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message NOT to be retired when the archive it promised never happened")
	}
	if decisions := store.Decisions(10); len(decisions) != 0 {
		t.Fatalf("expected no decision claiming the rule was applied, got %+v", decisions)
	}

	logBytes, err := os.ReadFile(filepath.Join(logDir, "app.log"))
	if err != nil {
		t.Fatalf("reading app.log: %v", err)
	}
	logText := string(logBytes)
	if !strings.Contains(logText, "rule action failed") {
		t.Fatalf("expected an ERROR log line for the failed action, got log:\n%s", logText)
	}
	if !strings.Contains(logText, wantErr) {
		t.Fatalf("expected the log line to include the underlying error, got log:\n%s", logText)
	}
	if !strings.Contains(logText, "user-1") || !strings.Contains(logText, "42") {
		t.Fatalf("expected the log line to include user_id and message_id, got log:\n%s", logText)
	}
}

// TestHandleMessage_NonMatchingRuleStillClassifies is the mirror check:
// when no rule matches, handleMessage must still reach classification. It
// can't call the real Ollama HTTP path in a unit test, so it asserts the
// weaker but still meaningful property that a nil classifier client *does*
// panic once rule evaluation is out of the way — proving the earlier
// no-panic result above was actually caused by the stop short-circuit and
// not by some unrelated reason classifyWithRetry never runs.
func TestHandleMessage_NonMatchingRuleStillClassifies(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	p := &Poller{log: logger} // classifier intentionally left nil

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	uc := userCtx{
		id:               "user-1",
		mail:             &noopMailClient{},
		autoLabelEnabled: true,
		rules: []rules.Rule{
			{
				Name:    "never matches",
				Enabled: true,
				Match: rules.MatchGroup{
					Op:         "allof",
					Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "no-such-substring"}},
				},
				Actions: []rules.Action{{Type: "archive"}},
			},
		},
		store: store,
	}
	msg := imapadapter.Message{ID: "43", Subject: "Ordinary mail", Sender: "someone@example.com"}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected classifyWithRetry to be reached (and panic on the nil classifier client) when no rule matches")
		}
	}()
	_ = p.handleMessage(context.Background(), uc, msg)
}

// TestHandleMessage_AutoLabelDisabledUsesConfiguredLabel proves the
// auto-labeling-disabled fallback always applies a label present in the
// account's configured allowlist, rather than the hardcoded literal
// "Primary" — which silently drops mail into the invisible Uncategorized
// tab (server.go's bucket()/firstMatchingKeyword) whenever "Primary" isn't
// one of the user's configured labels, making new mail look archived and
// unsorted from the frontend's perspective (ReadPage.tsx always defaults
// activeTab to tabs[0], never to Uncategorized).
func TestHandleMessage_AutoLabelDisabledUsesConfiguredLabel(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	p := &Poller{log: logger} // classifier intentionally left nil; disabled path never calls it
	p.cfg.Labels.Allowlist = []string{"Work", "Bills"}

	mail := &noopMailClient{}
	uc := userCtx{
		id:               "user-1",
		mail:             mail,
		store:            store,
		autoLabelEnabled: false,
	}
	msg := imapadapter.Message{ID: "44", Subject: "Invoice due", Sender: "billing@example.com"}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	if len(mail.appliedLabels) == 0 {
		t.Fatal("expected a label to be applied")
	}
	got := mail.appliedLabels[0]
	found := false
	for _, allowed := range p.cfg.Labels.Allowlist {
		if strings.EqualFold(allowed, got) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("applied label %q is not in the configured allowlist %v — mail will land in the invisible Uncategorized tab", got, p.cfg.Labels.Allowlist)
	}
}

// writeTestIMAPConfig writes an encrypted IMAP/SMTP config payload at the
// path notifyMessageTooLarge reads via mailmsg.ReadIMAPConfigPayload for
// userID, sealed with a throwaway master key under keyPath. It writes a real
// envelope because the read path no longer accepts plaintext: silently
// treating an unparseable config as cleartext credentials is exactly the
// behavior that was removed (see cryptutil.OpenBytes).
func writeTestIMAPConfig(t *testing.T, configDir, keyPath, userID, username, password string) {
	t.Helper()
	payload := mailmsg.IMAPConfigPayload{
		Host:     "imap.example.com",
		Port:     993,
		Username: username,
		Password: password,
		Mailbox:  "INBOX",
		SMTPHost: "smtp.example.com",
		SMTPPort: 587,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal test imap config: %v", err)
	}
	key, err := cryptutil.LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	env, err := cryptutil.Seal(b, key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	dir := filepath.Join(configDir, "users", userID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "imap-config.json"), sealed, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// fakeRejectionSMTPCall records one invocation of sendRejectionNotice, the
// package-level test seam standing in for mailmsg.SMTPDeliver.
type fakeRejectionSMTPCall struct {
	smtpHost, addr, from, username, password string
	smtpPort                                 int
	recipients                               []string
	msg                                      []byte
}

// stubSendRejectionNotice replaces the sendRejectionNotice package var for
// the duration of a test with a fake that records its call (or fails, if
// failWith is non-nil) instead of dialing a real SMTP server, restoring the
// original via t.Cleanup.
func stubSendRejectionNotice(t *testing.T, failWith error) *[]fakeRejectionSMTPCall {
	t.Helper()
	var calls []fakeRejectionSMTPCall
	original := sendRejectionNotice
	sendRejectionNotice = func(smtpHost string, smtpPort int, addr, smtpUsername, smtpPassword, from string, recipients []string, msg []byte) error {
		calls = append(calls, fakeRejectionSMTPCall{
			smtpHost: smtpHost, smtpPort: smtpPort, addr: addr,
			username: smtpUsername, password: smtpPassword, from: from,
			recipients: recipients, msg: msg,
		})
		return failWith
	}
	t.Cleanup(func() { sendRejectionNotice = original })
	return &calls
}

// TestHandleMessage_TooLargeMessageRejectsAndNotifies is the reject-and-
// notify integration test: a message ListUnreadInbox flagged as TooLarge
// must not go through the normal rule/classify/label pipeline at all, must
// send a rejection notice to the account's own address (the IMAP username),
// and must be recorded with the distinct "rejected_too_large" status rather
// than "applied"/"skipped" — proving handleMessage's TooLarge branch, not
// just notifyMessageTooLarge in isolation.
func TestHandleMessage_TooLargeMessageRejectsAndNotifies(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	configDir := t.TempDir()
	imapKeyPath := filepath.Join(t.TempDir(), "imap-config.key")
	writeTestIMAPConfig(t, configDir, imapKeyPath, "user-1", "alice@example.com", "hunter2")
	calls := stubSendRejectionNotice(t, nil)

	// classifier intentionally nil: must never be reached
	p := &Poller{log: logger, configDir: configDir, imapKeyPath: imapKeyPath}
	mail := &noopMailClient{}
	uc := userCtx{id: "user-1", mail: mail, store: store, autoLabelEnabled: true}
	msg := imapadapter.Message{
		ID:       "900",
		Subject:  "Huge attachment",
		Sender:   "sender@example.com",
		TooLarge: true,
	}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	if len(*calls) != 1 {
		t.Fatalf("expected exactly 1 rejection notice sent, got %d: %+v", len(*calls), *calls)
	}
	call := (*calls)[0]
	if call.from != "alice@example.com" {
		t.Fatalf("expected notice From the account's own address, got %q", call.from)
	}
	if len(call.recipients) != 1 || call.recipients[0] != "alice@example.com" {
		t.Fatalf("expected notice addressed to the account's own address, got %v", call.recipients)
	}
	body := string(call.msg)
	if !strings.Contains(body, "Huge attachment") || !strings.Contains(body, "sender@example.com") {
		t.Fatalf("expected the notice to mention the rejected message's subject/sender, got:\n%s", body)
	}

	// Nothing from the normal pipeline must have run.
	if len(mail.appliedLabels) != 0 {
		t.Fatalf("expected no label to be applied to a rejected message, got %v", mail.appliedLabels)
	}
	if len(mail.inboxActions) != 0 {
		t.Fatalf("expected no rule action to be applied to a rejected message, got %v", mail.inboxActions)
	}

	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected the rejected message to be marked processed so it isn't retried every poll tick")
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 {
		t.Fatalf("expected exactly 1 decision recorded, got %d: %+v", len(decisions), decisions)
	}
	if decisions[0].Status != "rejected_too_large" {
		t.Fatalf("expected status %q, got %q (must be distinct from the ordinary processed-message statuses)", "rejected_too_large", decisions[0].Status)
	}
}

// TestHandleMessage_TooLargeMessageStillRecordsDecisionWhenNotifyFails
// proves the reject-and-notify path is best-effort: when there's no IMAP
// config on file for the account (so the notice can't be built/sent at
// all), the message is still recorded as rejected and marked processed —
// never left to be retried forever just because notification failed.
func TestHandleMessage_TooLargeMessageStillRecordsDecisionWhenNotifyFails(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	// configDir deliberately left as an empty temp dir: no imap-config.json
	// exists for this user, so notifyMessageTooLarge must fail before ever
	// reaching sendRejectionNotice.
	calls := stubSendRejectionNotice(t, nil)

	p := &Poller{log: logger, configDir: t.TempDir()}
	uc := userCtx{id: "user-1", mail: &noopMailClient{}, store: store}
	msg := imapadapter.Message{ID: "901", Subject: "Huge attachment", Sender: "sender@example.com", TooLarge: true}

	if err := p.handleMessage(context.Background(), uc, msg); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}

	if len(*calls) != 0 {
		t.Fatalf("expected sendRejectionNotice never to be reached without a stored imap config, got %d calls", len(*calls))
	}
	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message to still be marked processed even when the notice couldn't be sent")
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 || decisions[0].Status != "rejected_too_large" {
		t.Fatalf("expected a rejected_too_large decision to still be recorded, got %+v", decisions)
	}
	if !strings.Contains(decisions[0].Detail, "rejection notice could not be sent") {
		t.Fatalf("expected Detail to mention the notice failure, got %q", decisions[0].Detail)
	}
}

// TestNativePushOmitsContentByDefault is the check for the privacy default.
// A native push leaves this server for a relay Worker and then Google or
// Apple, readable at every hop, so nothing about the message may ride along
// unless the user asked for it.
func TestNativePushOmitsContentByDefault(t *testing.T) {
	msg := imapadapter.Message{
		ID:      "42",
		Sender:  "whistleblower@example.org",
		Subject: "the documents",
	}
	keywords := []string{"Important"}

	title, body := buildNativeNotificationText(msg, false)
	if strings.Contains(title, "whistleblower") || strings.Contains(body, "documents") {
		t.Fatalf("generic push leaked content: title=%q body=%q", title, body)
	}

	data := buildNativePushData(msg, keywords, title, body, false)
	for key, value := range data {
		for _, secret := range []string{"whistleblower", "example.org", "documents", "Important"} {
			if strings.Contains(value, secret) {
				t.Errorf("data[%q] = %q leaks %q", key, value, secret)
			}
		}
	}
	// The message id and deep link are the whole point: the app opens the
	// right message after syncing over its own authenticated connection.
	if data["messageId"] != "42" {
		t.Errorf("data[messageId] = %q, want %q", data["messageId"], "42")
	}
	if _, ok := data["subject"]; ok {
		t.Error("data still carries a subject key when previews are off")
	}
}

// With the opt-in on, the payload must carry both key spellings: the mobile
// client reads senderName/emailSubject on FCM and sender/subject on App Pull.
func TestNativePushCarriesBothKeySpellingsWhenOptedIn(t *testing.T) {
	msg := imapadapter.Message{ID: "7", Sender: "a@example.com", Subject: "hello"}
	title, body := buildNativeNotificationText(msg, true)
	data := buildNativePushData(msg, nil, title, body, true)
	for _, key := range []string{"sender", "senderName", "subject", "emailSubject", "title", "body"} {
		if data[key] == "" {
			t.Errorf("data[%q] is empty; the mobile client reads this key", key)
		}
	}
}

// TestDeferredMessageStaysInRangeOfTheNextFetch pins the composition the
// "retried next poll tick" contract actually rests on.
//
// Leaving a message unmarked in the processed set is only half of a retry.
// ListUnreadInbox returns UIDs strictly above the stored checkpoint and
// advances that checkpoint to the highest UID it FETCHED, so for a long time
// tickUser recorded the failure, skipped MarkProcessed exactly as intended,
// and then wrote a checkpoint that put the message permanently out of range —
// never classified, never labelled, never retried. Every test covering the
// behaviour asserted only the processed-set half, which is why it survived.
//
// Full tickUser integration is still out of reach here (no fake-goimap-Dialer
// infrastructure — see TestMailCacheEntriesFromMessages), so this covers the
// two halves meeting: the predicate that decides to defer, and the clamp that
// makes the deferral mean something.
func TestDeferredMessageStaysInRangeOfTheNextFetch(t *testing.T) {
	const (
		prevCheckpoint = "10"
		fetchedThrough = "20" // the batch's highest UID
		deferredUID    = "14"
	)

	transient := &classifierErr{err: errors.New("dial tcp 127.0.0.1:11434: connect: connection refused")}
	if shouldMarkProcessedOnError(transient) {
		t.Fatal("expected a transient classifier error to leave the message unmarked")
	}

	// tickUser adds exactly the messages it leaves unmarked to deferredIDs.
	next := imapadapter.ClampCheckpoint(prevCheckpoint, fetchedThrough, []string{deferredUID})
	if next == fetchedThrough {
		t.Fatal("checkpoint advanced past a deferred message; the next fetch will never return it")
	}
	if next >= deferredUID {
		t.Fatalf("checkpoint %q does not leave UID %s in range of the next fetch", next, deferredUID)
	}

	// A permanent failure is retired, so it must NOT hold the checkpoint back —
	// otherwise one poison message refetches the batch forever.
	permanent := &classifierErr{err: errors.New("classifier: 422 Unprocessable Entity")}
	if !shouldMarkProcessedOnError(permanent) {
		t.Fatal("expected a permanent classifier error to mark the message processed")
	}
	if got := imapadapter.ClampCheckpoint(prevCheckpoint, fetchedThrough, nil); got != fetchedThrough {
		t.Fatalf("ClampCheckpoint = %q, want the fetched checkpoint %q when nothing is deferred", got, fetchedThrough)
	}
}

// TestRecordMessageFailure_TransientErrorIsRecordedOncePerMessage is the
// counterpart to holding the checkpoint back.
//
// Deferring a message means it really is re-processed on every poll tick for
// as long as the classifier is down. The failure path appends a Decision and
// pushes a notification, so doing that unconditionally would write one audit
// row and fire one notification per message per tick — a mailbox's worth of
// them every ~90 seconds, retained for 30 days — for a single outage.
func TestRecordMessageFailure_TransientErrorIsRecordedOncePerMessage(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := &Poller{log: logger}

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	uc := userCtx{id: "user-1", store: store, mail: &noopMailClient{}}
	msg := imapadapter.Message{ID: "50", Subject: "Hello", Sender: "a@example.com"}
	classifyErr := &classifierErr{err: errors.New("dial tcp 127.0.0.1:11434: connect: connection refused")}

	// Five ticks of the same outage.
	for i := 0; i < 5; i++ {
		p.recordMessageFailure(store, uc.id, uc, msg, classifyErr, shouldMarkProcessedOnError(classifyErr))
	}

	decisions := store.Decisions(50)
	if len(decisions) != 1 {
		t.Fatalf("recorded %d decisions for one message across five ticks, want 1", len(decisions))
	}
	// Still unmarked, so the next tick still retries it.
	if seenForTest(t, store, msg.ID) {
		t.Fatal("expected the message to remain unmarked so it is still retried")
	}

	// A different message during the same outage is its own report.
	other := imapadapter.Message{ID: "51", Subject: "Other", Sender: "b@example.com"}
	p.recordMessageFailure(store, uc.id, uc, other, classifyErr, shouldMarkProcessedOnError(classifyErr))
	if got := len(store.Decisions(50)); got != 2 {
		t.Fatalf("got %d decisions, want 2 — one per affected message", got)
	}
}

// TestRecordMessageFailure_RetiredFailureStillRecordsUnconditionally guards the
// other half: a message that IS retired reaches recordMessageFailure once, so
// gating it on a prior report must not swallow its audit row.
func TestRecordMessageFailure_RetiredFailureStillRecordsUnconditionally(t *testing.T) {
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	p := &Poller{log: logger}

	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	uc := userCtx{id: "user-1", store: store, mail: &noopMailClient{}}
	msg := imapadapter.Message{ID: "60", Subject: "Hello", Sender: "a@example.com"}

	// A transient failure first, then the same message failing permanently:
	// the permanent one retires it and must be recorded even though a "failed"
	// row already exists.
	transient := &classifierErr{err: errors.New("connection refused")}
	permanent := &classifierErr{err: errors.New("out of ai credits")}
	p.recordMessageFailure(store, uc.id, uc, msg, transient, shouldMarkProcessedOnError(transient))
	p.recordMessageFailure(store, uc.id, uc, msg, permanent, shouldMarkProcessedOnError(permanent))

	if got := len(store.Decisions(50)); got != 2 {
		t.Fatalf("got %d decisions, want 2 (the deferral and the retirement)", got)
	}
	if !seenForTest(t, store, msg.ID) {
		t.Fatal("expected the permanent failure to retire the message")
	}
}
