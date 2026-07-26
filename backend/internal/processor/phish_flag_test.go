package processor

import (
	"context"
	"errors"
	"strings"
	"testing"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/mailcache"
	"kypost-server/backend/internal/state"
)

// phishStubClient records the label applications flagAppImpersonation makes and
// serves canned raw messages to the DKIM gate. Embeds the interface so only the
// two methods under test need implementing — same idiom as harvestStubClient.
type phishStubClient struct {
	imapadapter.Client
	raw map[int][]byte

	appliedLabels []string
	rawFetches    int
	applyAttempts int
	applyErr      error
}

func (c *phishStubClient) FetchRawMessage(_ context.Context, uid int) ([]byte, error) {
	c.rawFetches++
	return c.raw[uid], nil
}

func (c *phishStubClient) EnsureLabel(_ context.Context, _ string) error {
	return nil
}

func (c *phishStubClient) ApplyLabel(_ context.Context, _, label string) error {
	c.applyAttempts++
	if c.applyErr != nil {
		return c.applyErr
	}
	c.appliedLabels = append(c.appliedLabels, label)
	return nil
}

func newPhishTestPoller(t *testing.T) *Poller {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	return &Poller{log: logger, stateDir: t.TempDir()}
}

func newPhishTestStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.New(t.TempDir())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return store
}

// withDKIMResult forces the DKIM gate's answer. The real verifier resolves the
// signing domain's key from live DNS, which no unit test can satisfy; the crypto
// itself is covered in internal/adapters/imap/dkim_verify_test.go.
func withDKIMResult(t *testing.T, verified bool) {
	t.Helper()
	original := verifyDKIMForDomain
	verifyDKIMForDomain = func([]byte, string) bool { return verified }
	t.Cleanup(func() { verifyDKIMForDomain = original })
}

const phishingBody = "Confirm: kypost://native-pair?sub=v&srv=https://evil.example&pt=z"

// A forged message that does not authenticate as the account's own domain gets
// the durable keyword and an audit row.
func TestFlagAppImpersonationFlagsUnauthenticatedForgery(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", Body: phishingBody}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected the message to be flagged")
	}
	if len(client.appliedLabels) != 1 || client.appliedLabels[0] != phishKeyword {
		t.Fatalf("appliedLabels = %v, want exactly [%s]", client.appliedLabels, phishKeyword)
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 {
		t.Fatalf("got %d decisions, want 1", len(decisions))
	}
	if decisions[0].Status != decisionStatusFlaggedPhishing {
		t.Fatalf("Status = %q, want %q", decisions[0].Status, decisionStatusFlaggedPhishing)
	}
	if !strings.Contains(decisions[0].Detail, reasonAppDeepLink) {
		t.Fatalf("Detail = %q, want it to carry the reason %q", decisions[0].Detail, reasonAppDeepLink)
	}
	if decisions[0].Sender != "evil@attacker.tld" {
		t.Fatalf("Sender = %q, want the forged sender preserved for the audit trail", decisions[0].Sender)
	}
}

// The server emails its own /pickup/ links, so Tier A fires on legitimate mail
// by design. DKIM over the account's own domain is what tells the two apart --
// without this branch every genuine pickup notice would carry a phishing
// warning.
func TestFlagAppImpersonationDoesNotFlagMailAuthenticatedToTheOwnDomain(t *testing.T) {
	withDKIMResult(t, true)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:      "42",
		Subject: "Your secure message",
		Sender:  "noreply@corp.example",
		Body:    "Pick it up: https://corp.example/pickup/abc123",
	}

	if p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected authenticated mail not to be flagged")
	}
	if len(client.appliedLabels) != 0 {
		t.Fatalf("appliedLabels = %v, want none", client.appliedLabels)
	}
	if got := len(store.Decisions(10)); got != 0 {
		t.Fatalf("got %d decisions, want 0", got)
	}
}

// The guarantee that keeps this affordable: ordinary mail costs one regex and
// three substring scans, and never a DNS lookup or a raw-message fetch.
func TestFlagAppImpersonationDoesNoNetworkWorkForOrdinaryMail(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Your weekly digest", Sender: "news@news.example", Body: "Stories inside."}

	if p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected ordinary mail not to be flagged")
	}
	if client.rawFetches != 0 {
		t.Fatalf("rawFetches = %d, want 0 -- clean mail must not trigger a raw fetch or DKIM lookup", client.rawFetches)
	}
	if len(client.appliedLabels) != 0 {
		t.Fatalf("appliedLabels = %v, want none", client.appliedLabels)
	}
}

// A DNS outage makes verifyDKIMForDomain fail closed. That must show the banner,
// never block or move the message -- fail-safe in verdict, fail-soft in effect.
func TestFlagAppImpersonationFlagsWhenDKIMCannotBeResolved(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Your secure message", Sender: "noreply@corp.example", Body: "https://corp.example/pickup/abc"}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected an unresolvable DKIM check to leave the message flagged")
	}
	if len(client.appliedLabels) != 1 {
		t.Fatalf("appliedLabels = %v, want the keyword applied", client.appliedLabels)
	}
}

// An oversized message has no body to scan (ListUnreadInbox deliberately leaves
// it empty) and rejectOversizedMessage already owns that case.
func TestFlagAppImpersonationSkipsOversizedMessages(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", TooLarge: true}

	if p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected an oversized message to be skipped")
	}
	if client.rawFetches != 0 {
		t.Fatalf("rawFetches = %d, want 0", client.rawFetches)
	}
}

// Re-running over a message that already carries the keyword must not add a
// second audit row. handleMessage can fail and leave a message unmarked, which
// means this step sees it again on the next tick.
func TestFlagAppImpersonationIsIdempotent(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	// Lowercase on purpose: IMAP keywords are case-insensitive, so a server may
	// hand back a different case than the one that was set.
	msg := imapadapter.Message{
		ID:       "42",
		Subject:  "Action needed",
		Sender:   "evil@attacker.tld",
		Body:     phishingBody,
		Keywords: []string{"Primary", strings.ToLower(phishKeyword)},
	}

	if p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected an already-flagged message to be skipped")
	}
	if client.rawFetches != 0 {
		t.Fatalf("rawFetches = %d, want 0", client.rawFetches)
	}
	if got := len(store.Decisions(10)); got != 0 {
		t.Fatalf("got %d decisions, want 0 -- the flag was already recorded", got)
	}
}

// An IMAP server that refuses the keyword loses the banner, not the audit
// trail. The client-side scheme allowlist is unaffected either way, which is
// what makes this degradation acceptable.
func TestFlagAppImpersonationRecordsTheDecisionWhenTheKeywordCannotBeApplied(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{
		raw:      map[int][]byte{42: []byte("raw message")},
		applyErr: errors.New("server refused keyword: [PERMANENTFLAGS]"),
	}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", Body: phishingBody}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected the message to still count as flagged")
	}
	decisions := store.Decisions(10)
	if len(decisions) != 1 {
		t.Fatalf("got %d decisions, want 1 even though the keyword apply failed", len(decisions))
	}
	if !strings.Contains(decisions[0].Detail, "keyword") {
		t.Fatalf("Detail = %q, want it to record the keyword-apply failure", decisions[0].Detail)
	}
}

// The flag is advisory -- the client-side scheme allowlist is what actually
// stops the attack -- so it must not be retried. applySingleKeywordWithRetry
// would spend 3 attempts x 30s here, and a burst of flagged mail would stall
// the whole poll tick past its 8-minute context, starving every other user's
// mail to re-ask a server that already said no.
func TestFlagAppImpersonationDoesNotRetryARefusedKeyword(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{
		raw:      map[int][]byte{42: []byte("raw message")},
		applyErr: errors.New("server refused keyword: [PERMANENTFLAGS]"),
	}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", Body: phishingBody}

	p.flagAppImpersonation(context.Background(), uc, msg, "corp.example")

	if client.applyAttempts != 1 {
		t.Fatalf("applyAttempts = %d, want exactly 1 -- an advisory keyword must not be retried", client.applyAttempts)
	}
}

// The headline attack: hostile HTML part, innocuous plain-text part. The server
// only ever sees text/plain in Message.Body, so this is the case a scan over
// Body alone would miss while the clients rendered the malicious link.
func TestFlagAppImpersonationCatchesAHostileHTMLPartBehindAnInnocuousTextPart(t *testing.T) {
	withDKIMResult(t, false)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:       "42",
		Subject:  "Invoice attached",
		Sender:   "evil@attacker.tld",
		Body:     "Hi, please see the attached invoice. Thanks!",
		BodyHTML: `<a href="kypost://native-pair?sub=v&srv=https://evil.example&pt=z">Confirm</a>`,
	}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "corp.example") {
		t.Fatal("expected the html-only deep link to be flagged")
	}
	if len(client.appliedLabels) != 1 || client.appliedLabels[0] != phishKeyword {
		t.Fatalf("appliedLabels = %v, want exactly [%s]", client.appliedLabels, phishKeyword)
	}
}

// With no resolvable account domain there is nothing to authenticate against,
// so the message stays flagged rather than being quietly cleared.
func TestFlagAppImpersonationFlagsWhenTheAccountDomainIsUnknown(t *testing.T) {
	withDKIMResult(t, true) // would clear it, if the domain were consulted at all
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", Body: phishingBody}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "") {
		t.Fatal("expected a message to stay flagged when no account domain is known")
	}
	if client.rawFetches != 0 {
		t.Fatalf("rawFetches = %d, want 0 -- there is no domain to verify against", client.rawFetches)
	}
}

// tickUser warms the mail cache from the fetched batch BEFORE the per-message
// loop runs, so a message flagged inside that loop would sit in the cache with
// stale keywords until the next poll tick. The webmail classic path reads from
// that cache, so without this mirror the phishing banner would be up to ~90
// seconds late -- on exactly the message the user is most likely to open right
// now.
func TestMirrorPhishKeywordAddsTheFlagToTheCachedEntry(t *testing.T) {
	p := newPhishTestPoller(t)
	cache, err := mailcache.New(t.TempDir())
	if err != nil {
		t.Fatalf("mailcache.New: %v", err)
	}
	msg := imapadapter.Message{
		ID:       "42",
		Subject:  "Action needed",
		Sender:   "evil@attacker.tld",
		AtUTC:    "2026-07-26T12:00:00Z",
		Keywords: []string{"Primary"},
	}
	if err := cache.Upsert("INBOX", mailCacheEntriesFromMessages([]imapadapter.Message{msg})); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}

	p.mirrorPhishKeyword(cache, msg)

	// Snapshot's bool reports "safe to serve with zero IMAP calls", which needs
	// at least `limit` entries -- not "found". Only the entries matter here.
	entries, _ := cache.Snapshot("INBOX", 10)
	if len(entries) != 1 {
		t.Fatalf("got %d cached entries, want 1", len(entries))
	}
	if !hasPhishKeyword(entries[0].Keywords) {
		t.Fatalf("cached Keywords = %v, want them to carry %s", entries[0].Keywords, phishKeyword)
	}
	// The existing keywords must survive -- the flag is added, not substituted.
	if len(entries[0].Keywords) != 2 {
		t.Fatalf("cached Keywords = %v, want the original Primary kept alongside the flag", entries[0].Keywords)
	}
}

// A cache that failed to open must not take the poll tick down with it; the
// IMAP keyword is the durable channel and has already been set by this point.
func TestMirrorPhishKeywordToleratesAMissingCache(t *testing.T) {
	p := newPhishTestPoller(t)
	p.mirrorPhishKeyword(nil, imapadapter.Message{ID: "42"})
}

// The flag must not leak into the caller's slice: msg.Keywords is shared with
// the batch tickUser warmed the cache from, and mutating it in place would make
// the mirror's effect depend on iteration order.
func TestMirrorPhishKeywordDoesNotMutateTheCallersKeywords(t *testing.T) {
	p := newPhishTestPoller(t)
	cache, err := mailcache.New(t.TempDir())
	if err != nil {
		t.Fatalf("mailcache.New: %v", err)
	}
	original := []string{"Primary"}
	msg := imapadapter.Message{ID: "42", AtUTC: "2026-07-26T12:00:00Z", Keywords: original}

	p.mirrorPhishKeyword(cache, msg)

	if len(original) != 1 || original[0] != "Primary" {
		t.Fatalf("caller's keywords were mutated: %v", original)
	}
}
