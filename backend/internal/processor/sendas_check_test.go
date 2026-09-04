package processor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	imapadapter "github.com/Busness-app/kypost-server/backend/internal/adapters/imap"
	"github.com/Busness-app/kypost-server/backend/internal/logging"
	"github.com/Busness-app/kypost-server/backend/internal/pgpmail"
	"github.com/Busness-app/kypost-server/backend/internal/sendas"
	"github.com/Busness-app/kypost-server/backend/internal/users"
)

var errFakeRawFetch = errors.New("fake raw message fetch failure")

// stubSendAsMailClient implements imapadapter.Client by embedding the
// (nil) interface and overriding only the two methods
// checkPendingSendAsAliases calls — any other method call would panic on
// the nil embedded interface, which is fine: it means the code under test
// reached further than this test intended and should be caught, not
// silently no-op'd.
type stubSendAsMailClient struct {
	imapadapter.Client
	searchResults map[string][]imapadapter.Overview // keyed by the searched verification code
	searchErr     error
	rawResults    map[int][]byte
	rawErr        error
	searchCalls   []string
	rawCalls      []int
}

func (c *stubSendAsMailClient) SearchMessages(_ context.Context, _, _, query string, _ int) ([]imapadapter.Overview, error) {
	c.searchCalls = append(c.searchCalls, query)
	if c.searchErr != nil {
		return nil, c.searchErr
	}
	return c.searchResults[query], nil
}

func (c *stubSendAsMailClient) FetchRawMessage(_ context.Context, _ string, uid int) ([]byte, error) {
	c.rawCalls = append(c.rawCalls, uid)
	if c.rawErr != nil {
		return nil, c.rawErr
	}
	return c.rawResults[uid], nil
}

// newTestPollerForSendAs builds a minimal *Poller sufficient to exercise
// checkPendingSendAsAliases: a logger and a stateDir so userStateDir/
// userSendAsStore work, with sendAsStores initialized as New() would do.
func newTestPollerForSendAs(t *testing.T) *Poller {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })

	return &Poller{
		log:          logger,
		stateDir:     t.TempDir(),
		sendAsStores: map[string]*sendas.Store{},
	}
}

// sendAsAliasesFileForTest mirrors the unexported aliasesFile the sendas
// package persists to disk (see sendas/store.go) — used here only to
// backdate ExpiresAt/FailedAt directly on disk for boundary tests, the same
// technique sendas/store_test.go uses from inside its own package, adapted
// for use from outside the package.
type sendAsAliasesFileForTest struct {
	Aliases []sendas.Alias `json:"aliases"`
}

// backdateSendAsField rewrites a single field (by JSON round-trip through a
// map, so it doesn't matter which of Alias's string fields is targeted) of
// the alias with the given ID, directly on the on-disk send_as_aliases.json
// file, then persists it back.
func backdateSendAsField(t *testing.T, stateDir, userID, aliasID string, mutate func(a *sendas.Alias)) {
	t.Helper()
	path := filepath.Join(stateDir, "users", userID, "send_as_aliases.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read send_as_aliases.json: %v", err)
	}
	var f sendAsAliasesFileForTest
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal send_as_aliases.json: %v", err)
	}
	found := false
	for i := range f.Aliases {
		if f.Aliases[i].ID == aliasID {
			mutate(&f.Aliases[i])
			found = true
		}
	}
	if !found {
		t.Fatalf("alias %q not found in send_as_aliases.json", aliasID)
	}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal send_as_aliases.json: %v", err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write send_as_aliases.json: %v", err)
	}
}

// TestCheckPendingSendAsAliasesStaysPendingOnNoDKIMSignature covers the
// deterministic, no-DNS-required case: a matched message with no
// DKIM-Signature header at all reliably fails VerifyDKIMForDomain without
// any network access, so the alias must stay pending. Real DKIM
// pass/fail crypto outcomes (valid signature, tampered body, wrong domain,
// expired signature) are exhaustively covered in
// internal/adapters/imap/dkim_verify_test.go, which has a test-only seam
// for injecting a fake DNS lookup — this package only exercises the
// raw-fetch-then-verify plumbing (see also the two rawCalls-focused tests
// below), not the crypto itself.
func TestCheckPendingSendAsAliasesStaysPendingOnNoDKIMSignature(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "candidate@example.com", "Candidate")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{
			alias.VerificationCode: {{UID: 1}},
		},
		rawResults: map[int][]byte{
			1: []byte("From: candidate@example.com\r\nSubject: no signature here\r\n\r\nbody\r\n"),
		},
	}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatalf("Get: alias not found")
	}
	if got.Status != "pending" {
		t.Fatalf("Status = %q, want pending", got.Status)
	}
	if len(mail.rawCalls) != 1 || mail.rawCalls[0] != 1 {
		t.Fatalf("rawCalls = %v, want exactly one call for UID 1", mail.rawCalls)
	}
}

// TestCheckPendingSendAsAliasesStaysPendingOnRawFetchError confirms a
// FetchRawMessage error for a matched UID is handled gracefully (logged,
// alias left pending for the next tick) rather than propagating a crash.
func TestCheckPendingSendAsAliasesStaysPendingOnRawFetchError(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "candidate@example.com", "Candidate")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{
			alias.VerificationCode: {{UID: 1}},
		},
		rawErr: errFakeRawFetch,
	}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatalf("Get: alias not found")
	}
	if got.Status != "pending" {
		t.Fatalf("Status = %q, want pending", got.Status)
	}
}

func TestCheckPendingSendAsAliasesStaysPendingOnNoSearchMatch(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "candidate@example.com", "Candidate")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{},
	}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatalf("Get: alias not found")
	}
	if got.Status != "pending" {
		t.Fatalf("Status = %q, want pending", got.Status)
	}
	if len(mail.rawCalls) != 0 {
		t.Fatalf("rawCalls = %d, want 0 (no search match should skip raw fetch)", len(mail.rawCalls))
	}
}

func TestCheckPendingSendAsAliasesMarksExpiredAsFailed(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "candidate@example.com", "Candidate")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	backdateSendAsField(t, p.stateDir, userID, alias.ID, func(a *sendas.Alias) {
		a.ExpiresAt = time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	})

	mail := &stubSendAsMailClient{}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatalf("Get: alias not found")
	}
	if got.Status != "failed" {
		t.Fatalf("Status = %q, want failed", got.Status)
	}
	if got.FailedAt == "" {
		t.Fatalf("FailedAt not set")
	}
	if len(mail.searchCalls) != 0 {
		t.Fatalf("searchCalls = %d, want 0 (expired record should never be searched)", len(mail.searchCalls))
	}
}

func TestCheckPendingSendAsAliasesIgnoresNonPendingRecords(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	verified, err := store.Create(userID, "verified@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.MarkVerified(verified.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	failed, err := store.Create(userID, "failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.MarkFailed(failed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	mail := &stubSendAsMailClient{}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	if len(mail.searchCalls) != 0 {
		t.Fatalf("searchCalls = %d, want 0 (non-pending records must not be re-examined)", len(mail.searchCalls))
	}
}

func TestCheckPendingSendAsAliasesSweepsOldFailedRecords(t *testing.T) {
	p := newTestPollerForSendAs(t)
	userID := "user-1"

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	failed, err := store.Create(userID, "failed@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.MarkFailed(failed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	backdateSendAsField(t, p.stateDir, userID, failed.ID, func(a *sendas.Alias) {
		a.FailedAt = time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339)
	})

	mail := &stubSendAsMailClient{}

	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	if _, ok := must2(store.Get(failed.ID)); ok {
		t.Fatalf("Get: expected record to be swept, still present")
	}
}

// newTestPollerWithUsers extends newTestPollerForSendAs with the pieces the
// PGP-User-ID side of verification needs: a real users store and a
// PGP-private-key path under a temp dir.
func newTestPollerWithUsers(t *testing.T) (*Poller, string) {
	t.Helper()
	p := newTestPollerForSendAs(t)
	configDir := t.TempDir()
	usersStore, err := users.LoadOrMigrate(context.Background(), configDir, filepath.Join(configDir, "admin.env"))
	if err != nil {
		t.Fatalf("users.LoadOrMigrate: %v", err)
	}
	p.users = usersStore

	all, err := usersStore.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("expected a bootstrapped user: %v", err)
	}
	return p, all[0].ID
}

// stubVerifiedDKIM makes the DKIM check unconditionally pass for the
// duration of one test. Real DKIM crypto is covered in
// internal/adapters/imap/dkim_verify_test.go; stubbing it here is what makes
// the *verified* branch reachable at all from this package, since the real
// verifier resolves the signing domain's public key from live DNS.
func stubVerifiedDKIM(t *testing.T) {
	t.Helper()
	prev := verifyDKIMForDomain
	verifyDKIMForDomain = func([]byte, string) bool { return true }
	prevCovers := verifyDKIMCoversHeader
	// Verification now additionally requires the signature to cover the header
	// the code was found in — stub that too, for the same reason.
	verifyDKIMCoversHeader = func([]byte, string, string) bool { return true }
	t.Cleanup(func() {
		verifyDKIMForDomain = prev
		verifyDKIMCoversHeader = prevCovers
	})
}

// seedPollerPGPIdentity generates a key for email and stores it on userID,
// returning the identity so tests can compare fingerprints.
//
// The sealing path is the helper's own: the poller no longer holds the PGP
// master key, because nothing in it opens a user's private key any more.
func seedPollerPGPIdentity(t *testing.T, p *Poller, userID, name, email string) *pgpmail.Identity {
	t.Helper()
	id, err := pgpmail.GenerateIdentity(name, email)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(filepath.Join(t.TempDir(), "pgp-private-key.key"))
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := p.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-24T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	return id
}

// markVerifiedPendingAlias drives one pending alias all the way through
// checkPendingSendAsAliases's verified branch.
func verifyAliasViaPoller(t *testing.T, p *Poller, userID, email string) sendas.Alias {
	t.Helper()
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, email, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{
			alias.VerificationCode: {{UID: 1}},
		},
		// The Subject must carry the challenge code: verification requires the
		// proving message to be a response to THIS challenge, not merely any
		// DKIM-signed message from the address. This helper previously used
		// "Subject: probe" and still verified, which is exactly the defect
		// TestCheckPendingSendAsAliasesRejectsAMessageThatDoesNotCarryTheCode
		// now pins.
		rawResults: map[int][]byte{1: []byte(
			"From: " + email + "\r\nSubject: Re: Verify send-as: " + alias.VerificationCode + "\r\n\r\nbody\r\n")},
	}
	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatal("Get: alias not found after verification")
	}
	if got.Status != "verified" {
		t.Fatalf("Status = %q, want verified", got.Status)
	}
	return got
}

// TestSendAsTickVerifiesWithoutPGPKey confirms the User-ID step is strictly
// additive: a user with no PGP identity at all still gets their alias
// verified rather than having the whole verification fail.
func TestSendAsTickVerifiesWithoutPGPKey(t *testing.T) {
	stubVerifiedDKIM(t)
	p, userID := newTestPollerWithUsers(t)

	verifyAliasViaPoller(t, p, userID, "alice@other.example")

	u, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	if u.PGPPublicKey != "" {
		t.Fatalf("expected no PGP key to be created, got %q", u.PGPPublicKey)
	}
}

// TestCheckPendingSendAsAliasesRejectsAMessageThatDoesNotCarryTheCode pins the
// property the DKIM checks above are supposed to be protecting: the message
// that satisfies the challenge must actually BE a response to this challenge.
//
// The DKIM gate proves the message came from the alias's domain with a signed,
// exactly-once From equal to the alias. It does not prove the message has
// anything to do with the alias being verified — and the only thing that ever
// consulted the code was the IMAP SEARCH term, answered by a server the account
// holder chose with no ownership check (POST /api/imap/config stores any host).
// So an attacker could answer the search with one genuine, unmodified,
// DKIM-signed message the target once sent them and the alias would verify.
func TestCheckPendingSendAsAliasesRejectsAMessageThatDoesNotCarryTheCode(t *testing.T) {
	stubVerifiedDKIM(t)
	p := newTestPollerForSendAs(t)
	const userID = "user-1"
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "victim@corp.example", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{
			alias.VerificationCode: {{UID: 1}},
		},
		// Genuine, byte-for-byte unmodified, correctly signed — and utterly
		// unrelated to the challenge.
		rawResults: map[int][]byte{1: []byte(
			"From: victim@corp.example\r\nSubject: Lunch tomorrow?\r\n\r\nbody\r\n")},
	}
	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatal("alias vanished")
	}
	if got.Status == "verified" {
		t.Fatalf("alias verified by a message whose Subject %q never carried code %q",
			"Lunch tomorrow?", alias.VerificationCode)
	}
}

// TestCheckPendingSendAsAliasesRejectsAMessagePredatingTheChallenge closes the
// replay half of the same gap: even once the Subject must carry the code, a
// message that predates the challenge cannot be a response to it.
func TestCheckPendingSendAsAliasesRejectsAMessagePredatingTheChallenge(t *testing.T) {
	stubVerifiedDKIM(t)
	p := newTestPollerForSendAs(t)
	const userID = "user-1"
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "victim@corp.example", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	old := time.Now().Add(-72 * time.Hour).Format(time.RFC1123Z)
	mail := &stubSendAsMailClient{
		searchResults: map[string][]imapadapter.Overview{
			alias.VerificationCode: {{UID: 1}},
		},
		rawResults: map[int][]byte{1: []byte(
			"From: victim@corp.example\r\nDate: " + old +
				"\r\nSubject: Re: Verify send-as: " + alias.VerificationCode + "\r\n\r\nbody\r\n")},
	}
	p.checkPendingSendAsAliases(context.Background(), userID, mail)

	got, ok := must2(store.Get(alias.ID))
	if !ok {
		t.Fatal("alias vanished")
	}
	if got.Status == "verified" {
		t.Fatal("alias verified by a message sent 72h before the challenge existed")
	}
}

// TestRawIsAutoReplyRejectsMailingListRedistribution pins the send-as gate
// against a proving message that is entirely genuine.
//
// A list applying DMARC From-munging rewrites From to the list address so
// alignment holds against its own domain, which means it DKIM-signs that
// rewritten From and the echoed Subject itself. Every other gate in
// checkPendingSendAsAliases then passes on real crypto: real signature, real
// domain, real From, and a Subject that still contains the challenge code
// because the check is a substring match and a "[Tag]" prefix does not disturb
// it. The attacker does not even need the server's probe to reach the list —
// GET /api/mail/send-as returns the code, so they post their own message.
//
// rawIsAutoReply is the only gate that can see this, for the reason it already
// rejects auto-responders: a machine at the alias domain emitting a signed
// message is not a person proving control of the mailbox.
func TestRawIsAutoReplyRejectsMailingListRedistribution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"List-Id", "List-Id: Announce <announce.lists.example.org>\r\n"},
		{"List-Post", "List-Post: <mailto:announce@lists.example.org>\r\n"},
		{"List-Unsubscribe", "List-Unsubscribe: <mailto:announce-leave@lists.example.org>\r\n"},
		{"List-Help", "List-Help: <mailto:announce-help@lists.example.org>\r\n"},
		{"Precedence list", "Precedence: list\r\n"},
		{"Precedence bulk", "Precedence: bulk\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("From: Attacker via Announce <announce@lists.example.org>\r\n" +
				"Subject: [Announce] Verify send-as: kp-deadbeef\r\n" +
				tc.header + "\r\nbody\r\n")
			if !rawIsAutoReply(raw) {
				t.Fatal("a mailing-list redistribution was accepted as proof of mailbox control")
			}
		})
	}

	// An ordinary human reply must still verify, or the gate has eaten the
	// feature it guards.
	ordinary := []byte("From: Alice <alice@other.example>\r\n" +
		"Subject: Re: Verify send-as: kp-deadbeef\r\n\r\nhere you go\r\n")
	if rawIsAutoReply(ordinary) {
		t.Fatal("an ordinary reply was rejected as automated")
	}
}
