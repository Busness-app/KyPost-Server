package processor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"

	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/pgpmail"
	"kypost-server/backend/internal/sendas"
	"kypost-server/backend/internal/users"
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

func (c *stubSendAsMailClient) FetchRawMessage(_ context.Context, uid int) ([]byte, error) {
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

	got, ok := store.Get(alias.ID)
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

	got, ok := store.Get(alias.ID)
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

	got, ok := store.Get(alias.ID)
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

	got, ok := store.Get(alias.ID)
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

	if _, ok := store.Get(failed.ID); ok {
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
	p.pgpKeyPath = filepath.Join(configDir, "pgp-private-key.key")

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
func seedPollerPGPIdentity(t *testing.T, p *Poller, userID, name, email string) *pgpmail.Identity {
	t.Helper()
	id, err := pgpmail.GenerateIdentity(name, email)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	sealed, err := id.SealPrivateKey(p.pgpKeyPath)
	if err != nil {
		t.Fatalf("SealPrivateKey: %v", err)
	}
	if _, err := p.users.SetPGPIdentity(userID, id.Fingerprint, id.KeyID, id.ArmoredPublicKey, sealed, "generated", "2026-07-24T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	return id
}

// pollerKeyUserIDEmails returns the sorted, lowercased User ID emails of an
// armored key.
func pollerKeyUserIDEmails(t *testing.T, armored string) []string {
	t.Helper()
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("parse armored key: %v", err)
	}
	var out []string
	for _, uid := range key.GetEntity().Identities {
		out = append(out, strings.ToLower(uid.UserId.Email))
	}
	sort.Strings(out)
	return out
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
		rawResults: map[int][]byte{1: []byte("From: " + email + "\r\nSubject: probe\r\n\r\nbody\r\n")},
	}
	// Both calls, in the order poller.go's per-user tick makes them.
	p.checkPendingSendAsAliases(context.Background(), userID, mail)
	p.reconcilePGPUserIDs(userID)

	got, ok := store.Get(alias.ID)
	if !ok {
		t.Fatal("Get: alias not found after verification")
	}
	if got.Status != "verified" {
		t.Fatalf("Status = %q, want verified", got.Status)
	}
	return got
}

// TestSendAsTickAddsUserIDToKeyOnVerification is the ordering the
// key-generation path can't cover: the alias is proven AFTER the key already
// exists. Without a User ID for the newly verified address the key is
// unusable for it — WKD consumers and Autocrypt both reject a key that
// doesn't carry the address — so the tick must self-sign one onto the
// existing key, keeping the same fingerprint.
func TestSendAsTickAddsUserIDToKeyOnVerification(t *testing.T) {
	stubVerifiedDKIM(t)
	p, userID := newTestPollerWithUsers(t)
	original := seedPollerPGPIdentity(t, p, userID, "Alice", "alice@example.com")

	verifyAliasViaPoller(t, p, userID, "alice@other.example")

	u, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	got := pollerKeyUserIDEmails(t, u.PGPPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored public key user IDs: got %v want %v", got, want)
	}
	if u.PGPFingerprint != original.Fingerprint {
		t.Fatalf("fingerprint changed: got %s want %s", u.PGPFingerprint, original.Fingerprint)
	}

	// The re-sealed private key must still open and carry the new User ID —
	// otherwise the next verification would work from a stale key.
	reopened, err := pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, p.pgpKeyPath)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	if got := pollerKeyUserIDEmails(t, reopened.ArmoredPublicKey); !slices.Equal(got, want) {
		t.Fatalf("re-sealed private key user IDs: got %v want %v", got, want)
	}
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

// markAliasVerified records an already-verified alias without going through
// the poller — this is the state an account is left in by a verification
// that happened before keys carried alias User IDs at all, which is exactly
// what the backfill exists to repair.
func markAliasVerified(t *testing.T, p *Poller, userID, email string) {
	t.Helper()
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, email, "")
	if err != nil {
		t.Fatalf("Create %s: %v", email, err)
	}
	if err := store.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified %s: %v", email, err)
	}
}

// TestReconcilePGPUserIDsBackfillsAlreadyVerifiedAliases is the backfill
// proper: aliases verified before the key learned to carry them (or before
// this feature existed) leave the key unusable for addresses the account has
// genuinely proven. A tick must repair that without the user regenerating
// their key or re-verifying the alias.
func TestReconcilePGPUserIDsBackfillsAlreadyVerifiedAliases(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	original := seedPollerPGPIdentity(t, p, userID, "Alice", "alice@example.com")
	markAliasVerified(t, p, userID, "alice@other.example")
	markAliasVerified(t, p, userID, "sales@third.example")

	p.reconcilePGPUserIDs(userID)

	u, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	got := pollerKeyUserIDEmails(t, u.PGPPublicKey)
	want := []string{"alice@example.com", "alice@other.example", "sales@third.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored public key user IDs: got %v want %v", got, want)
	}
	if u.PGPFingerprint != original.Fingerprint {
		t.Fatalf("fingerprint changed: got %s want %s", u.PGPFingerprint, original.Fingerprint)
	}
	reopened, err := pgpmail.OpenPrivateKey(u.PGPPrivateKeyEnc, p.pgpKeyPath)
	if err != nil {
		t.Fatalf("OpenPrivateKey: %v", err)
	}
	if got := pollerKeyUserIDEmails(t, reopened.ArmoredPublicKey); !slices.Equal(got, want) {
		t.Fatalf("re-sealed private key user IDs: got %v want %v", got, want)
	}
}

// TestReconcilePGPUserIDsIsIdempotent guards the cost and the correctness of
// running this on every tick: once the key is in sync, a further pass must
// neither rewrite the stored key nor append a second User ID for an address
// the key already carries.
func TestReconcilePGPUserIDsIsIdempotent(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	seedPollerPGPIdentity(t, p, userID, "Alice", "alice@example.com")
	markAliasVerified(t, p, userID, "alice@other.example")

	p.reconcilePGPUserIDs(userID)
	first, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}

	p.reconcilePGPUserIDs(userID)
	second, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}

	if second.PGPPublicKey != first.PGPPublicKey {
		t.Fatal("second reconcile rewrote an already-in-sync key")
	}
	got := pollerKeyUserIDEmails(t, second.PGPPublicKey)
	want := []string{"alice@example.com", "alice@other.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored public key user IDs: got %v want %v", got, want)
	}
}

// TestReconcilePGPUserIDsIgnoresUnverifiedAliases pins the security boundary
// the WKD serve path depends on: only addresses the account has actually
// proven may become User IDs, since a User ID is what makes the key usable
// for that address.
func TestReconcilePGPUserIDsIgnoresUnverifiedAliases(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	seedPollerPGPIdentity(t, p, userID, "Alice", "alice@example.com")

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	if _, err := store.Create(userID, "alice@pending.example", ""); err != nil {
		t.Fatalf("Create pending: %v", err)
	}
	failed, err := store.Create(userID, "alice@failed.example", "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := store.MarkFailed(failed.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	p.reconcilePGPUserIDs(userID)

	u, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	got := pollerKeyUserIDEmails(t, u.PGPPublicKey)
	want := []string{"alice@example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored public key user IDs: got %v want %v", got, want)
	}
}

// TestReconcilePGPUserIDsWithoutPGPKeyIsANoOp confirms a user who has aliases
// but no PGP identity is left alone rather than having one created.
func TestReconcilePGPUserIDsWithoutPGPKeyIsANoOp(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	markAliasVerified(t, p, userID, "alice@other.example")

	p.reconcilePGPUserIDs(userID)

	u, err := p.users.Get(userID)
	if err != nil {
		t.Fatalf("users.Get: %v", err)
	}
	if u.PGPPublicKey != "" || u.PGPPrivateKeyEnc != "" {
		t.Fatalf("expected no PGP identity to be created, got public key %q", u.PGPPublicKey)
	}
}
