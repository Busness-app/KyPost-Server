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

func (c *phishStubClient) FetchRawMessage(_ context.Context, _ string, uid int) ([]byte, error) {
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
//
// It stubs verifyDKIMCoversHeader, which is what the gate calls: a d= match
// alone does not establish that the account sent the message, because a
// signature need not cover From and a two-From message can present the signed
// copy to the verifier and the forged one to every other reader.
func withDKIMResult(t *testing.T, verified bool) {
	t.Helper()
	original := verifyDKIMCoversHeader
	verifyDKIMCoversHeader = func([]byte, string, string) bool { return verified }
	t.Cleanup(func() { verifyDKIMCoversHeader = original })
}

// TestAppImpersonationGateRequiresTheSignatureToCoverFrom pins WHICH verifier
// the gate uses. A d=-only match satisfies verifyDKIMForDomain and must not
// satisfy this gate, whose comment claims the message came from the account
// itself.
func TestAppImpersonationGateRequiresTheSignatureToCoverFrom(t *testing.T) {
	original := verifyDKIMCoversHeader
	var gotHeader string
	verifyDKIMCoversHeader = func(_ []byte, _ string, header string) bool {
		gotHeader = header
		return true
	}
	t.Cleanup(func() { verifyDKIMCoversHeader = original })

	p := newPhishTestPoller(t)
	uc := userCtx{
		id:    "u1",
		store: newPhishTestStore(t),
		mail:  &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}},
	}
	msg := imapadapter.Message{ID: "42", Subject: "Notice", Sender: ownAccountAddress, Body: phishingBody}
	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
		t.Fatal("a message the stub authenticated was flagged anyway")
	}

	if gotHeader != "From" {
		t.Fatalf("the gate asked for header %q; a signature that does not cover From does not "+
			"establish that the account sent the message", gotHeader)
	}
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

	if !p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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
// by design. DKIM over the account's own domain PLUS a From address equal to the
// account's own address is what tells the two apart -- without this branch every
// genuine pickup notice would carry a phishing warning.
func TestFlagAppImpersonationDoesNotFlagMailAuthenticatedToTheOwnAddress(t *testing.T) {
	withDKIMResult(t, true)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:      "42",
		Subject: "Your secure message",
		Sender:  "noreply@corp.example",
		Body:    "Pick it up: https://corp.example/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def",
	}

	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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

	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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
	msg := imapadapter.Message{ID: "42", Subject: "Your secure message", Sender: "noreply@corp.example", Body: "https://corp.example/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def"}

	if !p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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

	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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

	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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

	if !p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
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

	p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress)

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

	if !p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
		t.Fatal("expected the html-only deep link to be flagged")
	}
	if len(client.appliedLabels) != 1 || client.appliedLabels[0] != phishKeyword {
		t.Fatalf("appliedLabels = %v, want exactly [%s]", client.appliedLabels, phishKeyword)
	}
}

// With no resolvable account address there is nothing to authenticate against,
// so the message stays flagged rather than being quietly cleared.
func TestFlagAppImpersonationFlagsWhenTheAccountAddressIsUnknown(t *testing.T) {
	withDKIMResult(t, true) // would clear it, if the address were consulted at all
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{ID: "42", Subject: "Action needed", Sender: "evil@attacker.tld", Body: phishingBody}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "") {
		t.Fatal("expected a message to stay flagged when no account address is known")
	}
	if client.rawFetches != 0 {
		t.Fatalf("rawFetches = %d, want 0 -- there is no address to verify against", client.rawFetches)
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

// ownAccountAddress is the account's own full mail address, as
// Poller.accountAddress would return it from the sealed IMAP config. The Tier B
// gate needs the whole address, not just its domain -- see below.
const ownAccountAddress = "noreply@corp.example"

// The hole this gate used to have, and the reason it now checks the From
// address as well as the DKIM domain.
//
// Keyed on the *domain* alone, an account at victim@gmail.com made the gate
// "was this signed by gmail.com?" -- which every message from every Gmail user
// satisfies. Any attacker with a free account on the victim's own provider got
// their kypost:// deep link delivered with no warning at all, and that covers
// most people, since most people point this client at a mailbox they already
// had with a large provider.
func TestFlagAppImpersonationFlagsSharedDomainMailFromAnotherSender(t *testing.T) {
	withDKIMResult(t, true) // attacker's mail is genuinely DKIM-signed by the shared provider
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:      "42",
		Subject: "Action needed",
		Sender:  "attacker@gmail.com",
		Body:    phishingBody,
	}

	if !p.flagAppImpersonation(context.Background(), uc, msg, "victim@gmail.com") {
		t.Fatal("expected mail from a different sender on the same shared provider to stay flagged")
	}
	if len(client.appliedLabels) != 1 {
		t.Fatalf("appliedLabels = %v, want the keyword applied", client.appliedLabels)
	}
}

// The other half: a display name is sender-controlled, so it must never be what
// the address comparison matches on.
func TestFlagAppImpersonationFlagsWhenOnlyTheDisplayNameMatches(t *testing.T) {
	withDKIMResult(t, true)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:      "42",
		Subject: "Action needed",
		Sender:  `"noreply@corp.example" <attacker@corp.example>`,
		Body:    phishingBody,
	}

	if !p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
		t.Fatal("expected a forged display name not to clear the gate")
	}
}

// A genuine self-notice still clears the gate when the envelope carries a
// display name alongside the address -- the common real-world shape.
func TestFlagAppImpersonationClearsOwnAddressWithDisplayName(t *testing.T) {
	withDKIMResult(t, true)
	p := newPhishTestPoller(t)
	store := newPhishTestStore(t)
	client := &phishStubClient{raw: map[int][]byte{42: []byte("raw message")}}
	uc := userCtx{id: "u1", store: store, mail: client}
	msg := imapadapter.Message{
		ID:      "42",
		Subject: "Your secure message",
		Sender:  `KyPost <NoReply@Corp.Example>`,
		Body:    "Pick it up: https://corp.example/pickup/2f1b9a3c-1111-4222-8333-444455556666?t=abc.def",
	}

	if p.flagAppImpersonation(context.Background(), uc, msg, ownAccountAddress) {
		t.Fatal("expected the account's own notice to clear the gate regardless of display name or case")
	}
	if got := len(store.Decisions(10)); got != 0 {
		t.Fatalf("got %d decisions, want 0", got)
	}
}

func TestSameAddress(t *testing.T) {
	own := "noreply@corp.example"
	for _, tc := range []struct {
		sender string
		want   bool
	}{
		{"noreply@corp.example", true},
		{"NoReply@Corp.Example", true},
		{"KyPost <noreply@corp.example>", true},
		{`"Corp, Inc." <noreply@corp.example>`, true}, // unquoted-comma shape ParseAddress can refuse
		{"  noreply@corp.example  ", true},
		{"attacker@corp.example", false},
		{"noreply@corp.example.evil.tld", false},
		{`"noreply@corp.example" <attacker@evil.tld>`, false},
		{"", false},
	} {
		if got := sameAddress(tc.sender, own); got != tc.want {
			t.Errorf("sameAddress(%q, %q) = %v, want %v", tc.sender, own, got, tc.want)
		}
	}
	if sameAddress("noreply@corp.example", "") {
		t.Error("sameAddress with an unknown own address must be false, so the gate never clears")
	}
}
