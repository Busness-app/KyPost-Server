package rules

import (
	"context"
	"errors"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
)

func TestEvaluate_AllofMatchesAllConditions(t *testing.T) {
	rule := Rule{
		Name:    "from acme",
		Enabled: true,
		Match: MatchGroup{
			Op: "allof",
			Conditions: []Condition{
				{Field: "from", Comparator: "contains", Value: "acme"},
				{Field: "subject", Comparator: "contains", Value: "invoice"},
			},
		},
		Actions: []Action{{Type: "keyword", Value: "Billing"}},
	}

	matching := EvalInput{From: "billing@acme.com", Subject: "Your invoice is ready"}
	outcome := Evaluate(matching, []Rule{rule})
	if len(outcome.Matched) != 1 || outcome.Matched[0] != "from acme" {
		t.Fatalf("expected rule to match, got %+v", outcome)
	}

	partial := EvalInput{From: "billing@acme.com", Subject: "Hello there"}
	outcome = Evaluate(partial, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected allof to require both conditions, got %+v", outcome)
	}
}

func TestEvaluate_AnyofMatchesAnyCondition(t *testing.T) {
	rule := Rule{
		Name:    "urgent",
		Enabled: true,
		Match: MatchGroup{
			Op: "anyof",
			Conditions: []Condition{
				{Field: "subject", Comparator: "contains", Value: "urgent"},
				{Field: "subject", Comparator: "contains", Value: "asap"},
			},
		},
		Actions: []Action{{Type: "keyword", Value: "Urgent"}},
	}

	outcome := Evaluate(EvalInput{Subject: "need this ASAP please"}, []Rule{rule})
	if len(outcome.Matched) != 1 {
		t.Fatalf("expected anyof to match on second condition, got %+v", outcome)
	}

	outcome = Evaluate(EvalInput{Subject: "just saying hi"}, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected anyof to not match neither condition, got %+v", outcome)
	}
}

func TestEvaluate_Negate(t *testing.T) {
	rule := Rule{
		Name:    "not from acme",
		Enabled: true,
		Match: MatchGroup{
			Op: "allof",
			Conditions: []Condition{
				{Field: "from", Comparator: "contains", Value: "acme", Negate: true},
			},
		},
		Actions: []Action{{Type: "keyword", Value: "Other"}},
	}

	outcome := Evaluate(EvalInput{From: "someone@example.com"}, []Rule{rule})
	if len(outcome.Matched) != 1 {
		t.Fatalf("expected negated condition to match non-acme sender, got %+v", outcome)
	}

	outcome = Evaluate(EvalInput{From: "billing@acme.com"}, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected negated condition to reject acme sender, got %+v", outcome)
	}
}

func TestEvaluate_KeywordFieldMatchesAnyMessageKeyword(t *testing.T) {
	rule := Rule{
		Name:    "already flagged",
		Enabled: true,
		Match: MatchGroup{
			Op:         "allof",
			Conditions: []Condition{{Field: "keyword", Comparator: "is", Value: "VIP"}},
		},
		Actions: []Action{{Type: "archive"}},
	}

	outcome := Evaluate(EvalInput{Keywords: []string{"Work", "VIP"}}, []Rule{rule})
	if len(outcome.Matched) != 1 {
		t.Fatalf("expected keyword field to match against message keywords, got %+v", outcome)
	}

	outcome = Evaluate(EvalInput{Keywords: []string{"Work"}}, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected no match when keyword absent, got %+v", outcome)
	}
}

func TestEvaluate_FolderScope(t *testing.T) {
	rule := Rule{
		Name:    "scoped",
		Enabled: true,
		Scope:   RuleScope{Folders: []string{"Archive/2026"}},
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "delete"}},
	}

	outcome := Evaluate(EvalInput{Subject: "x", Folder: "INBOX"}, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected rule out of scope for INBOX to not match, got %+v", outcome)
	}

	outcome = Evaluate(EvalInput{Subject: "x", Folder: "Archive/2026"}, []Rule{rule})
	if len(outcome.Matched) != 1 {
		t.Fatalf("expected rule in scope to match, got %+v", outcome)
	}
}

func TestEvaluate_DisabledRuleNeverMatches(t *testing.T) {
	rule := Rule{
		Name:    "disabled",
		Enabled: false,
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "delete"}},
	}
	outcome := Evaluate(EvalInput{Subject: "x"}, []Rule{rule})
	if len(outcome.Matched) != 0 {
		t.Fatalf("expected disabled rule to never match, got %+v", outcome)
	}
}

func TestEvaluate_StopShortCircuitsRemainingRules(t *testing.T) {
	first := Rule{
		Name:    "first",
		Enabled: true,
		Order:   0,
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "archive"}, {Type: "stop"}},
	}
	second := Rule{
		Name:    "second",
		Enabled: true,
		Order:   1,
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "delete"}},
	}

	outcome := Evaluate(EvalInput{Subject: "x"}, []Rule{second, first})
	if !outcome.Stopped {
		t.Fatalf("expected Stopped=true, got %+v", outcome)
	}
	if len(outcome.Matched) != 1 || outcome.Matched[0] != "first" {
		t.Fatalf("expected only the Order=0 rule to have run before stop, got %+v", outcome.Matched)
	}
	if len(outcome.Applied) != 2 {
		t.Fatalf("expected archive+stop actions recorded, got %+v", outcome.Applied)
	}
}

func TestEvaluate_ActionOrderingAcrossMatchedRules(t *testing.T) {
	first := Rule{
		Name:    "first",
		Enabled: true,
		Order:   0,
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "keyword", Value: "A"}},
	}
	second := Rule{
		Name:    "second",
		Enabled: true,
		Order:   1,
		Match:   MatchGroup{Op: "allof", Conditions: []Condition{{Field: "subject", Comparator: "contains", Value: "x"}}},
		Actions: []Action{{Type: "keyword", Value: "B"}},
	}

	outcome := Evaluate(EvalInput{Subject: "x"}, []Rule{second, first})
	if len(outcome.Applied) != 2 || outcome.Applied[0].Value != "A" || outcome.Applied[1].Value != "B" {
		t.Fatalf("expected actions applied in rule Order regardless of input slice order, got %+v", outcome.Applied)
	}
}

// fakeClient is a minimal imapadapter.Client fake for ApplyOutcome tests —
// only ApplyLabel/RemoveLabel/ApplyInboxAction record calls; everything
// else is an unused no-op to satisfy the interface.
type fakeClient struct {
	appliedLabels []string
	removedLabels []string
	inboxActions  []string
	failLabel     error
	failInboxWith string
}

func (f *fakeClient) ListUnreadInbox(context.Context, string) ([]imapadapter.Message, string, error) {
	return nil, "", nil
}
func (f *fakeClient) ListUnreadMessages(context.Context, string, int) ([]imapadapter.UnreadMessage, error) {
	return nil, nil
}
func (f *fakeClient) ListOverviews(context.Context, string, int) ([]imapadapter.Overview, error) {
	return nil, nil
}
func (f *fakeClient) SearchMessages(context.Context, string, string, string, int) ([]imapadapter.Overview, error) {
	return nil, nil
}
func (f *fakeClient) GetMessageBodies(context.Context, string, []int) (map[int]imapadapter.MessageContent, error) {
	return nil, nil
}
func (f *fakeClient) ListLabels(context.Context) ([]string, error)             { return nil, nil }
func (f *fakeClient) ListSubfolders(context.Context, string) ([]string, error) { return nil, nil }
func (f *fakeClient) CreateFolder(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *fakeClient) RenameFolder(context.Context, string, string) (string, error) {
	return "", nil
}
func (f *fakeClient) DeleteFolder(context.Context, string) error { return nil }
func (f *fakeClient) EnsureLabel(context.Context, string) error  { return nil }
func (f *fakeClient) ApplyLabel(_ context.Context, _ string, label string) error {
	if f.failLabel != nil {
		return f.failLabel
	}
	f.appliedLabels = append(f.appliedLabels, label)
	return nil
}
func (f *fakeClient) RemoveLabel(_ context.Context, _ string, label string) error {
	f.removedLabels = append(f.removedLabels, label)
	return nil
}
func (f *fakeClient) ApplyInboxAction(_ context.Context, _ string, action, _, target string) error {
	if f.failInboxWith == action {
		return errors.New("boom")
	}
	f.inboxActions = append(f.inboxActions, action+":"+target)
	return nil
}
func (f *fakeClient) ListAttachments(context.Context, string, int) ([]imapadapter.AttachmentInfo, error) {
	return nil, nil
}
func (f *fakeClient) GetAttachment(context.Context, string, int, int) (imapadapter.AttachmentInfo, []byte, error) {
	return imapadapter.AttachmentInfo{}, nil, nil
}
func (f *fakeClient) SaveDraft(context.Context, imapadapter.DraftMessage) error { return nil }
func (f *fakeClient) SaveSent(context.Context, imapadapter.DraftMessage) error  { return nil }
func (f *fakeClient) FetchHeaderFields(context.Context, []int, ...string) (map[int][]string, error) {
	return nil, nil
}
func (f *fakeClient) FetchRawMessage(context.Context, int) ([]byte, error) { return nil, nil }

func TestApplyOutcome_MapsEachActionTypeToTheRightCall(t *testing.T) {
	outcome := Outcome{Applied: []Action{
		{Type: "keyword", Value: "VIP"},
		{Type: "unkeyword", Value: "Old"},
		{Type: "move", Value: "Archive/2026"},
		{Type: "read"},
		{Type: "archive"},
		{Type: "spam"},
		{Type: "delete"},
		{Type: "stop"},
	}}
	fake := &fakeClient{}
	results := ApplyOutcome(context.Background(), fake, "INBOX", EvalInput{MessageID: "42"}, outcome)

	if len(results) != 8 {
		t.Fatalf("expected 8 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Fatalf("action %d (%+v) failed: %v", i, r.Action, r.Err)
		}
	}
	if len(fake.appliedLabels) != 1 || fake.appliedLabels[0] != "VIP" {
		t.Fatalf("expected ApplyLabel(VIP), got %+v", fake.appliedLabels)
	}
	if len(fake.removedLabels) != 1 || fake.removedLabels[0] != "Old" {
		t.Fatalf("expected RemoveLabel(Old), got %+v", fake.removedLabels)
	}
	wantInbox := []string{"move:Archive/2026", "read:", "archive:", "spam:", "delete:"}
	if len(fake.inboxActions) != len(wantInbox) {
		t.Fatalf("expected %v, got %v", wantInbox, fake.inboxActions)
	}
	for i, want := range wantInbox {
		if fake.inboxActions[i] != want {
			t.Errorf("inboxActions[%d] = %q, want %q", i, fake.inboxActions[i], want)
		}
	}
}

// This asserted the opposite until the retry contract was traced end to end.
//
// Running on past a failure is only defensible if the caller can retry what
// failed. The poller retries by re-running an UNSEEN SEARCH over INBOX, so an
// "archive" that ran after a failed "keyword" took the message out of the only
// query that could ever find it again — the keyword was lost, permanently, and
// the audit row said the message failed while it had in fact been half applied.
func TestApplyOutcome_StopsAtTheFirstFailedAction(t *testing.T) {
	outcome := Outcome{Applied: []Action{
		{Type: "keyword", Value: "VIP"},
		{Type: "unkeyword", Value: "Old"},
	}}
	fake := &fakeClient{failLabel: errors.New("imap down")}
	results := ApplyOutcome(context.Background(), fake, "INBOX", EvalInput{MessageID: "1"}, outcome)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1 — execution must stop at the failure", len(results))
	}
	if results[0].Err == nil {
		t.Fatal("expected the first action to report its failure")
	}
	if len(fake.removedLabels) != 0 {
		t.Fatalf("the action after a failure must not run, got %+v", fake.removedLabels)
	}
}

// The specific ordering the whole contract exists for: a terminal action must
// not run after something else failed, or the message leaves the retry query
// still owing work.
func TestApplyOutcome_TerminalActionDoesNotRunAfterAFailure(t *testing.T) {
	outcome := Outcome{Applied: []Action{
		{Type: "keyword", Value: "VIP"},
		{Type: "archive"},
	}}
	fake := &fakeClient{failLabel: errors.New("imap down")}
	results := ApplyOutcome(context.Background(), fake, "INBOX", EvalInput{MessageID: "1"}, outcome)
	if len(results) != 1 || results[0].Err == nil {
		t.Fatalf("expected exactly one failed result, got %+v", results)
	}
	if len(fake.inboxActions) != 0 {
		t.Fatalf("archive must not run after the keyword write failed, got %+v", fake.inboxActions)
	}
}

// A terminal action that succeeds and is followed by a failure is the case
// ordering cannot fix on its own — ValidateRule refuses to store such a rule
// (TestValidateRule_*), and this pins the engine half: nothing runs after a
// cancelled context either.
func TestApplyOutcome_CancelledContextStopsExecution(t *testing.T) {
	outcome := Outcome{Applied: []Action{
		{Type: "keyword", Value: "VIP"},
		{Type: "unkeyword", Value: "Old"},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fake := &fakeClient{}
	results := ApplyOutcome(ctx, fake, "INBOX", EvalInput{MessageID: "1"}, outcome)
	if len(results) != 1 || !errors.Is(results[0].Err, context.Canceled) {
		t.Fatalf("expected one context.Canceled result, got %+v", results)
	}
	if len(fake.appliedLabels) != 0 {
		t.Fatalf("no action may run under a cancelled context, got %+v", fake.appliedLabels)
	}
}
