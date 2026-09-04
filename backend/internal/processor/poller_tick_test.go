package processor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	imapadapter "github.com/Busness-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busness-app/kypost-server/backend/internal/config"
	"github.com/Busness-app/kypost-server/backend/internal/health"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/mailcache"
	"github.com/Busness-app/kypost-server/backend/internal/rules"
	"github.com/Busness-app/kypost-server/backend/internal/sendas"
	"github.com/Busness-app/kypost-server/backend/internal/state"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

// Full-tick tests.
//
// Everything else in this package tests tickUser's contracts one piece at a
// time: a predicate here, a clamp there, recordMessageFailure against a real
// store. That is how a message could be classified correctly, have its label
// write fail, be recorded as handled, and have the checkpoint advance past it —
// every individual piece behaved, and nothing ran them together.
//
// These drive tickUser end to end against a scripted mailbox (via the
// newMailClient seam) and assert the three pieces of state that decide whether
// mail is retried or thrown away: the processed set, the poll checkpoint, and
// the audit log. They deliberately use the auto-labeling-disabled path so no
// classifier is involved — the failure being tested is the IMAP keyword write,
// and a live model would only add nondeterminism to it.

// scriptedMailbox is an imapadapter.Client backed by an in-memory UID list.
//
// ListUnreadInbox honours the checkpoint the way the real one does — UIDs
// strictly above it, with the returned checkpoint advanced to the highest UID
// FETCHED regardless of what happens to those messages afterwards. That detail
// is the whole reason deferral needs a clamp, so a fake that skipped it would
// test nothing.
type scriptedMailbox struct {
	msgs []imapadapter.Message

	// applyLabelErr[uid] is returned by ApplyLabel for that message, standing in
	// for a keyword write that failed after applyKeywordsWithRetry gave up.
	applyLabelErr map[string]error
	// labelled records successful ApplyLabel calls as "uid:label", in order.
	labelled []string
	// fetches counts ListUnreadInbox calls, so a test can prove a later tick
	// really re-fetched a deferred message rather than inventing it.
	fetches int

	noopMailClient
}

func (m *scriptedMailbox) ListUnreadInbox(_ context.Context, checkpoint string) ([]imapadapter.Message, string, error) {
	m.fetches++
	after, _ := strconv.Atoi(checkpoint)
	var out []imapadapter.Message
	highest := after
	for _, msg := range m.msgs {
		uid, err := strconv.Atoi(msg.ID)
		if err != nil || uid <= after {
			continue
		}
		out = append(out, msg)
		if uid > highest {
			highest = uid
		}
	}
	if len(out) == 0 {
		return nil, checkpoint, nil
	}
	return out, strconv.Itoa(highest), nil
}

func (m *scriptedMailbox) ApplyLabel(_ context.Context, id string, label string) error {
	if err := m.applyLabelErr[id]; err != nil {
		return err
	}
	m.labelled = append(m.labelled, id+":"+label)
	return nil
}

// newTickTestPoller builds a Poller wired for a whole tickUser: real temp
// state/config dirs, a real state.Store underneath, and the scripted mailbox in
// place of an IMAP connection. Auto-labeling is turned OFF for the user so
// handleMessage takes the deterministic default-label path and never reaches
// the (nil) classifier.
func newTickTestPoller(t *testing.T, mail imapadapter.Client) (*Poller, users.User) {
	t.Helper()

	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	// These tests fail keyword writes on purpose, and the production delay is
	// 30s per retry. Nothing here is testing the backoff itself.
	prevDelay := keywordRetryDelay
	keywordRetryDelay = time.Millisecond
	t.Cleanup(func() { keywordRetryDelay = prevDelay })

	cfg := config.Config{}
	cfg.Labels.Allowlist = []string{"Primary", "Promotions"}
	cfg.Labels.KeywordMappings = map[string][]string{}
	cfg.RateLimits.PerMinute = 1000
	cfg.RateLimits.PerHour = 1000

	configDir := t.TempDir()
	// tickUser's tail (ensureOwnAddressProven) looks the polled user up, so this
	// needs to be a real store rather than a nil one.
	usersStore, err := users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("users.LoadOrMigrate: %v", err)
	}

	p := &Poller{
		cfg:           cfg,
		log:           logger,
		users:         usersStore,
		health:        health.NewService(),
		stateDir:      t.TempDir(),
		configDir:     configDir,
		stores:        map[string]*state.Store{},
		mailClients:   map[string]*mailClientEntry{},
		mailCaches:    map[string]*mailcache.Store{},
		rulesStores:   map[string]*rules.Store{},
		sendAsStores:  map[string]*sendas.Store{},
		rate:          map[string][]time.Time{},
		newMailClient: func(string, string) imapadapter.Client { return mail },
	}

	u := users.User{ID: "user-tick", Username: "tick"}
	if err := os.MkdirAll(p.userConfigDir(u.ID), 0o700); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	settings := config.DefaultUserSettings()
	settings.Labels.AutoApplyEnabled = false
	if err := config.SaveUserSettings(p.userSettingsPath(u.ID), settings); err != nil {
		t.Fatalf("SaveUserSettings: %v", err)
	}
	return p, u
}

func tickStore(t *testing.T, p *Poller, u users.User) *state.Store {
	t.Helper()
	store, err := p.userStore(u.ID)
	if err != nil {
		t.Fatalf("userStore: %v", err)
	}
	return store
}

func checkpointOf(t *testing.T, store *state.Store) string {
	t.Helper()
	cp, err := store.Checkpoint()
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	return cp
}

// TestTickUser_TransientLabelFailureIsRetriedOnTheNextTick is the regression
// test for the defect this whole error taxonomy exists for.
//
// A message whose keyword write fails must be left unprocessed AND left in
// range of the next fetch. Before, it was marked processed and the checkpoint
// advanced past it: the classification succeeded, the label was never written,
// and nothing ever tried again. Green unit tests covered both halves
// separately.
func TestTickUser_TransientLabelFailureIsRetriedOnTheNextTick(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{
			{ID: "10", Subject: "first", Sender: "a@example.com"},
			{ID: "11", Subject: "second", Sender: "b@example.com"},
			{ID: "12", Subject: "third", Sender: "c@example.com"},
		},
		applyLabelErr: map[string]error{
			"11": errors.New("imap: connection reset by peer"),
		},
	}
	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)

	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("tickUser: %v", err)
	}

	// 10 and 12 are done; 11 is not, because its label never landed.
	for _, id := range []string{"10", "12"} {
		if !seenForTest(t, store, id) {
			t.Fatalf("expected message %s to be processed", id)
		}
	}
	if seenForTest(t, store, "11") {
		t.Fatal("message 11's label write failed, so it must NOT be recorded as processed")
	}

	// The other half: the checkpoint has to stay below 11 or the next fetch
	// never returns it, and "unprocessed" becomes "lost".
	if got := checkpointOf(t, store); got != "10" {
		t.Fatalf("checkpoint = %q, want %q so message 11 is still in range of the next fetch", got, "10")
	}

	// The failure is in the audit log, once, and not as a success.
	decisions := store.Decisions(50)
	var failed int
	for _, d := range decisions {
		if d.MessageID == "11" {
			if d.Status != "failed" {
				t.Fatalf("message 11 recorded with status %q, want \"failed\"", d.Status)
			}
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("got %d decisions for the failed message, want exactly 1", failed)
	}

	// The deferral is counted, which is what bounds it.
	if attempts, err := store.DeferralAttempts("11"); err != nil || attempts != 1 {
		t.Fatalf("DeferralAttempts(11) = %d, %v; want 1, nil", attempts, err)
	}

	// --- the outage clears; the next tick must actually finish the work ---
	delete(mail.applyLabelErr, "11")

	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("second tickUser: %v", err)
	}
	if mail.fetches != 2 {
		t.Fatalf("mailbox fetched %d times, want 2", mail.fetches)
	}
	if !seenForTest(t, store, "11") {
		t.Fatal("expected message 11 to be processed on the retry tick")
	}
	if got := checkpointOf(t, store); got != "12" {
		t.Fatalf("checkpoint = %q, want %q once nothing is deferred", got, "12")
	}
	if attempts, err := store.DeferralAttempts("11"); err != nil || attempts != 0 {
		t.Fatalf("DeferralAttempts(11) after success = %d, %v; want 0, nil", attempts, err)
	}

	// The label really was applied, exactly once per message, and 10/12 were
	// not re-labelled by the tick that re-fetched them.
	want := []string{"10:Primary", "12:Primary", "11:Primary"}
	if len(mail.labelled) != len(want) {
		t.Fatalf("labelled = %v, want %v", mail.labelled, want)
	}
	for i := range want {
		if mail.labelled[i] != want[i] {
			t.Fatalf("labelled = %v, want %v", mail.labelled, want)
		}
	}
}

// TestTickUser_PermanentlyFailingMessageIsRetiredAtTheCap is the other side of
// the contract, and the one the reviewer's proposed fix would have left out.
//
// Holding the checkpoint below a deferred message means a failure that NEVER
// clears holds it forever, re-fetching a growing batch on every tick and never
// making progress. The attempt cap converts that back into a retirement: the
// message is recorded as failed, the checkpoint is released, and an operator
// gets a log line saying mail was given up on.
func TestTickUser_PermanentlyFailingMessageIsRetiredAtTheCap(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{
			{ID: "10", Subject: "fine", Sender: "a@example.com"},
			{ID: "11", Subject: "poison", Sender: "b@example.com"},
		},
		applyLabelErr: map[string]error{
			// Never cleared: a mailbox that rejects this keyword forever.
			"11": errors.New("imap: NO [CANNOT] keyword rejected"),
		},
	}
	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)

	// One tick short of the cap: still deferred, still holding the checkpoint.
	for i := 0; i < maxDeferralAttempts-1; i++ {
		if err := p.tickUser(u, time.Now()); err != nil {
			t.Fatalf("tickUser %d: %v", i, err)
		}
	}
	if seenForTest(t, store, "11") {
		t.Fatalf("message retired before the cap of %d attempts", maxDeferralAttempts)
	}
	if got := checkpointOf(t, store); got != "10" {
		t.Fatalf("checkpoint = %q, want it held at %q while the message is deferred", got, "10")
	}

	// The tick that reaches the cap retires it.
	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("capping tickUser: %v", err)
	}
	if !seenForTest(t, store, "11") {
		t.Fatalf("expected the message to be retired once %d attempts were exhausted", maxDeferralAttempts)
	}
	if got := checkpointOf(t, store); got != "11" {
		t.Fatalf("checkpoint = %q, want it released to %q once nothing is deferred", got, "11")
	}
	if attempts, err := store.DeferralAttempts("11"); err != nil || attempts != 0 {
		t.Fatalf("DeferralAttempts after retirement = %d, %v; want 0, nil (row dropped)", attempts, err)
	}

	// Giving up has to be visible in the audit log, not just in the fact that
	// the message stopped coming back.
	var gaveUp bool
	for _, d := range store.Decisions(50) {
		if d.MessageID == "11" && d.Status == "failed" {
			if strings.Contains(d.Detail, "gave up after") {
				gaveUp = true
			}
		}
	}
	if !gaveUp {
		t.Fatalf("expected a decision recording that the message was given up on, got %+v", store.Decisions(50))
	}
}

// TestTickUser_FailedRuleActionDefersInsteadOfRetiring is the same contract for
// the rules engine: an archive that never happened must not retire the message
// with a decision claiming the rule was applied.
func TestTickUser_FailedRuleActionDefersInsteadOfRetiring(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{{ID: "7", Subject: "Weekly newsletter", Sender: "news@example.com"}},
	}
	mail.inboxActionErr = errors.New("imap: connection reset by peer")

	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)

	rulesStore, err := p.userRulesStore(u.ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	if _, err := rulesStore.Upsert(rules.Rule{
		Name:    "archive and stop",
		Enabled: true,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "newsletter"}},
		},
		Actions: []rules.Action{{Type: "archive"}, {Type: "stop"}},
	}); err != nil {
		t.Fatalf("rules Upsert: %v", err)
	}

	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("tickUser: %v", err)
	}

	if seenForTest(t, store, "7") {
		t.Fatal("the archive failed, so the message must not be retired as handled")
	}
	if got := checkpointOf(t, store); got != "" && got != "6" {
		t.Fatalf("checkpoint = %q, want it held below the deferred message", got)
	}
	for _, d := range store.Decisions(50) {
		if d.Status == "applied" {
			t.Fatalf("recorded the rule as applied even though its action failed: %+v", d)
		}
	}
}

// TestTickUser_FailedKeywordDoesNotArchiveTheMessage is the ordering half of
// the retry contract, driven end to end.
//
// "keyword then archive" is a legal rule (rules.ValidateRule requires the
// visibility-changing action last, precisely so this ordering is the only one
// storable). When the keyword write fails, the archive must NOT run: an
// archived message is out of INBOX, and INBOX is where the next tick looks.
// Running it anyway is how a failure that reported itself as retryable became
// one nothing could retry.
func TestTickUser_FailedKeywordDoesNotArchiveTheMessage(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{{ID: "7", Subject: "Weekly newsletter", Sender: "news@example.com"}},
		applyLabelErr: map[string]error{
			"7": errors.New("imap: connection reset by peer"),
		},
	}
	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)
	seedRule(t, p, u, rules.Rule{
		Name:    "tag then archive",
		Enabled: true,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "newsletter"}},
		},
		Actions: []rules.Action{{Type: "keyword", Value: "VIP"}, {Type: "archive"}},
	})

	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("tickUser: %v", err)
	}

	if len(mail.inboxActions) != 0 {
		t.Fatalf("archive ran after the keyword write failed (%v) — the message is now outside the retry query", mail.inboxActions)
	}
	if seenForTest(t, store, "7") {
		t.Fatal("the rule did not complete, so the message must not be retired as handled")
	}
	if got := checkpointOf(t, store); got != "" && got != "6" {
		t.Fatalf("checkpoint = %q, want it held below the deferred message", got)
	}
}

// TestTickUser_KeywordAppliedThenFailedArchiveStaysRetryable is the other side:
// the keyword landed, the archive did not, so the message is still unread in
// INBOX and the next tick genuinely can retry it. Re-running the keyword is
// harmless (setting a flag that is already set), which is what makes stopping
// at the first failure sufficient rather than needing per-action progress.
func TestTickUser_KeywordAppliedThenFailedArchiveStaysRetryable(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{{ID: "7", Subject: "Weekly newsletter", Sender: "news@example.com"}},
	}
	mail.inboxActionErr = errors.New("imap: connection reset by peer")

	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)
	seedRule(t, p, u, rules.Rule{
		Name:    "tag then archive",
		Enabled: true,
		Match: rules.MatchGroup{
			Op:         "allof",
			Conditions: []rules.Condition{{Field: "subject", Comparator: "contains", Value: "newsletter"}},
		},
		Actions: []rules.Action{{Type: "keyword", Value: "VIP"}, {Type: "archive"}},
	})

	if err := p.tickUser(u, time.Now()); err != nil {
		t.Fatalf("tickUser: %v", err)
	}

	if len(mail.labelled) != 1 || mail.labelled[0] != "7:VIP" {
		t.Fatalf("labelled = %v, want the keyword to have been applied before the archive failed", mail.labelled)
	}
	if seenForTest(t, store, "7") {
		t.Fatal("the archive failed, so the message must not be retired as handled")
	}
	if got := checkpointOf(t, store); got != "" && got != "6" {
		t.Fatalf("checkpoint = %q, want it held below the deferred message", got)
	}
	for _, d := range store.Decisions(50) {
		if d.Status == "applied" {
			t.Fatalf("recorded the rule as applied even though its archive failed: %+v", d)
		}
	}
}

func seedRule(t *testing.T, p *Poller, u users.User, r rules.Rule) {
	t.Helper()
	if err := rules.ValidateRule(r); err != nil {
		t.Fatalf("test rule is not one the API would accept: %v", err)
	}
	rulesStore, err := p.userRulesStore(u.ID)
	if err != nil {
		t.Fatalf("userRulesStore: %v", err)
	}
	if _, err := rulesStore.Upsert(r); err != nil {
		t.Fatalf("rules Upsert: %v", err)
	}
}

// breakDeferralLedger drops the deferrals table out from under an already-open
// state.Store, so RecordDeferral fails while the checkpoint and processed-set
// reads the assertions depend on keep working.
//
// A separate connection to the same file, because state.Store deliberately
// exposes no raw handle. The "sqlite" driver is registered by the state
// package's blank import, which this package pulls in transitively.
func breakDeferralLedger(t *testing.T, p *Poller, u users.User) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(p.userStateDir(u.ID), "state.db"))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TABLE deferrals`); err != nil {
		t.Fatalf("drop deferrals: %v", err)
	}
}

// TestTickUser_UnwritableDeferralLedgerHoldsTheCheckpoint is the regression
// test for the third finding: a failed RecordDeferral used to set retire=true
// and leave the message out of deferredIDs, so the checkpoint advanced past
// mail whose work had not been done — a transient SQLITE_BUSY turned "retry
// this" into "discard this".
//
// It must now fail closed: the message stays deferred, the checkpoint stays
// below it, and the tick reports failure so the state-store outage is visible
// rather than showing up as mail that quietly stopped being processed.
func TestTickUser_UnwritableDeferralLedgerHoldsTheCheckpoint(t *testing.T) {
	mail := &scriptedMailbox{
		msgs: []imapadapter.Message{{ID: "9", Subject: "first", Sender: "a@example.com"}},
		applyLabelErr: map[string]error{
			"9": errors.New("imap: connection reset by peer"),
		},
	}
	p, u := newTickTestPoller(t, mail)
	store := tickStore(t, p, u)
	breakDeferralLedger(t, p, u)

	err := p.tickUser(u, time.Now())
	if err == nil {
		t.Fatal("tickUser must report the tick as failed when the deferral ledger cannot be written")
	}
	if !strings.Contains(err.Error(), "deferral ledger") {
		t.Fatalf("tick error = %v, want it to name the deferral ledger so an operator can act on it", err)
	}

	if seenForTest(t, store, "9") {
		t.Fatal("the message's label never landed, so an unwritable attempt counter must not retire it")
	}
	if got := checkpointOf(t, store); got != "" && got != "8" {
		t.Fatalf("checkpoint = %q, want it held below message 9 — advancing past it is the mail loss this test exists for", got)
	}

	// And the hold is real: the next tick re-fetches the message rather than
	// having skipped past it forever.
	fetchesBefore := mail.fetches
	_ = p.tickUser(u, time.Now())
	if mail.fetches != fetchesBefore+1 {
		t.Fatalf("fetches = %d, want one more than %d", mail.fetches, fetchesBefore)
	}
	if seenForTest(t, store, "9") {
		t.Fatal("message 9 must still be awaiting a successful attempt")
	}
}
