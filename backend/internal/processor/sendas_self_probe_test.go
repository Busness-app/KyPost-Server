package processor

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/mailmsg"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/sendas"
)

// run-4 finding H2 follow-up: publishableAddressesAt now serves a key over WKD
// only for addresses proven by the send-as challenge, including the account's
// own — the IMAP username alone is self-declared and proves nothing. That is
// the right gate, but on its own it silently stops publishing for every
// existing install until each user manually runs a challenge against their own
// address, which nobody would think to do.
//
// The account's own address is the one case that closes automatically: the
// probe is a self-send, so it leaves through the account's own submission
// server, is DKIM-signed by that address's own domain, and lands back in the
// same INBOX the verifier already searches. From-domain, DKIM d= and the
// candidate address all coincide, and checkPendingSendAsAliases verifies it on
// the next tick with no user action.
//
// It is not weaker than the alias flow it reuses. The attack H2 exists to stop
// is a user pointing IMAP/SMTP at a host they control while claiming a
// colleague's address as their IMAP username; they can put anything they like
// in their own INBOX, but they cannot produce that domain's DKIM signature over
// the Subject carrying the code.

// capturedProbe is one intercepted SMTP send from the self-probe path.
type capturedProbe struct {
	host       string
	port       int
	username   string
	from       string
	recipients []string
	msg        []byte
}

// stubSelfProbeSender swaps out the package's SMTP seam for one test and
// returns the slice the sends accumulate into.
func stubSelfProbeSender(t *testing.T, err error) *[]capturedProbe {
	t.Helper()
	var sent []capturedProbe
	prev := sendSendAsProbe
	sendSendAsProbe = func(host string, port int, _, username, _, from string, recipients []string, msg []byte) error {
		sent = append(sent, capturedProbe{
			host: host, port: port, username: username,
			from: from, recipients: recipients, msg: msg,
		})
		return err
	}
	t.Cleanup(func() { sendSendAsProbe = prev })
	return &sent
}

// seedSelfProbeUser builds a poller with a bootstrapped user that has an IMAP
// config naming ownAddress, a PGP key, and PublishWKD left at its default
// (on) — the state in which the own-address probe is supposed to fire.
func seedSelfProbeUser(t *testing.T, ownAddress string) (*Poller, string) {
	t.Helper()
	p, userID := newTestPollerWithUsers(t)
	p.configDir = t.TempDir()
	p.imapKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	writeTestIMAPConfig(t, p.configDir, p.imapKeyPath, userID, ownAddress, "hunter2")
	seedPollerPGPIdentity(t, p, userID, "Alice", ownAddress)
	return p, userID
}

// setPublishWKD writes a discovery settings file with PublishWKD set.
func setPublishWKD(t *testing.T, p *Poller, userID string, publish bool) {
	t.Helper()
	settings, err := pgpdiscovery.Load(p.userStateDir(userID))
	if err != nil {
		t.Fatalf("pgpdiscovery.Load: %v", err)
	}
	settings.PublishWKD = publish
	if err := pgpdiscovery.Save(p.userStateDir(userID), settings); err != nil {
		t.Fatalf("pgpdiscovery.Save: %v", err)
	}
}

func TestEnsureOwnAddressProvenSendsProbeAndRecordsPendingAlias(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 1 {
		t.Fatalf("probe sends = %d, want 1", len(*sent))
	}
	probe := (*sent)[0]
	if len(probe.recipients) != 1 || probe.recipients[0] != "alice@example.com" {
		t.Fatalf("recipients = %v, want [alice@example.com]", probe.recipients)
	}
	if probe.from != "alice@example.com" {
		t.Fatalf("from = %q, want alice@example.com", probe.from)
	}
	if probe.host != "smtp.example.com" || probe.port != 587 {
		t.Fatalf("smtp target = %s:%d, want smtp.example.com:587", probe.host, probe.port)
	}

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	list := store.List()
	if len(list) != 1 {
		t.Fatalf("alias records = %d, want 1", len(list))
	}
	alias := list[0]
	if alias.Email != "alice@example.com" {
		t.Fatalf("alias email = %q", alias.Email)
	}
	if alias.Status != "pending" {
		t.Fatalf("alias status = %q, want pending", alias.Status)
	}
	if !alias.Auto {
		t.Fatal("alias.Auto = false, want true: the record must be identifiable as server-initiated")
	}
	// The code must actually travel in the Subject, since that is the only
	// place checkPendingSendAsAliases looks for it.
	if !strings.Contains(string(probe.msg), alias.VerificationCode) {
		t.Fatal("probe message does not carry the verification code")
	}
}

func TestEnsureOwnAddressProvenSkipsWhenAlreadyVerified(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "alice@example.com", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 0 {
		t.Fatalf("probe sends = %d, want 0 for an already-proven address", len(*sent))
	}
}

func TestEnsureOwnAddressProvenSkipsWhileProbeInFlight(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)
	p.ensureOwnAddressProven(userID)
	p.ensureOwnAddressProven(userID)

	if len(*sent) != 1 {
		t.Fatalf("probe sends = %d, want 1: an unexpired pending probe must not be duplicated", len(*sent))
	}
}

func TestEnsureOwnAddressProvenSkipsWhenPublishWKDDisabled(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	setPublishWKD(t, p, userID, false)
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 0 {
		t.Fatalf("probe sends = %d, want 0: a user who publishes nothing must not be mailed", len(*sent))
	}
}

func TestEnsureOwnAddressProvenSkipsWithoutPGPKey(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	p.configDir = t.TempDir()
	p.imapKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	writeTestIMAPConfig(t, p.configDir, p.imapKeyPath, userID, "alice@example.com", "hunter2")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 0 {
		t.Fatalf("probe sends = %d, want 0: there is no key to publish", len(*sent))
	}
}

func TestEnsureOwnAddressProvenSkipsNonEmailUsername(t *testing.T) {
	// Plenty of IMAP servers take a bare login name. There is no address to
	// probe, and "alice" has no domain that could ever DKIM-sign anything.
	p, userID := seedSelfProbeUser(t, "alice")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 0 {
		t.Fatalf("probe sends = %d, want 0 for a non-address username", len(*sent))
	}
}

func TestEnsureOwnAddressProvenSkipsWithoutIMAPConfig(t *testing.T) {
	p, userID := newTestPollerWithUsers(t)
	p.configDir = t.TempDir()
	p.imapKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	seedPollerPGPIdentity(t, p, userID, "Alice", "alice@example.com")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	if len(*sent) != 0 {
		t.Fatalf("probe sends = %d, want 0 with no mail config on file", len(*sent))
	}
}

// A domain that does not DKIM-sign submitted mail can never satisfy the
// verifier, so the probe fails forever. Retrying it every tick — or even every
// day, once SweepTerminal drops the failed record — would put an unexplained
// message in the user's inbox on a loop.
func TestEnsureOwnAddressProvenBacksOffAfterRecentFailure(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)
	if len(*sent) != 1 {
		t.Fatalf("first probe sends = %d, want 1", len(*sent))
	}

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias := store.List()[0]
	if err := store.MarkFailed(alias.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	p.ensureOwnAddressProven(userID)
	if len(*sent) != 1 {
		t.Fatalf("probe sends = %d, want 1: a just-failed probe must not be retried immediately", len(*sent))
	}

	// Past the backoff window, one retry is due.
	backdateSendAsField(t, p.stateDir, userID, alias.ID, func(a *sendas.Alias) {
		a.FailedAt = time.Now().Add(-selfProbeRetryInterval - time.Hour).UTC().Format(time.RFC3339)
	})

	p.ensureOwnAddressProven(userID)
	if len(*sent) != 2 {
		t.Fatalf("probe sends = %d, want 2 once the backoff window has passed", len(*sent))
	}
}

// The failed record is the only thing that tells the user their address could
// not be auto-verified — it is what the send-as settings list renders. Losing
// it to the 24h terminal sweep would make a permanently-unpublishable key look
// like a key that was simply never set up.
func TestEnsureOwnAddressProvenFailureSurvivesTerminalSweep(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)
	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias := store.List()[0]
	if err := store.MarkFailed(alias.ID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	backdateSendAsField(t, p.stateDir, userID, alias.ID, func(a *sendas.Alias) {
		a.FailedAt = time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339)
	})

	if err := store.SweepTerminal(24 * time.Hour); err != nil {
		t.Fatalf("SweepTerminal: %v", err)
	}

	if got := len(store.List()); got != 1 {
		t.Fatalf("alias records after sweep = %d, want 1: the auto record carries the failure state", got)
	}
}

// A send failure must not leave a pending record claiming a probe is in
// flight — the next tick should be free to try again rather than waiting out
// the 5-minute expiry for a message that never left.
func TestEnsureOwnAddressProvenDropsRecordWhenSendFails(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	stubSelfProbeSender(t, errors.New("smtp refused"))

	p.ensureOwnAddressProven(userID)

	store, err := p.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	if got := len(store.List()); got != 0 {
		t.Fatalf("alias records = %d, want 0 after a failed send", got)
	}
}

// Guards the assumption the whole design rests on: the probe is addressed to
// the account itself, so it travels through the account's own submission
// server and comes back to the INBOX the verifier searches.
func TestSelfProbeUsesAccountSubmissionServer(t *testing.T) {
	p, userID := seedSelfProbeUser(t, "alice@example.com")
	sent := stubSelfProbeSender(t, nil)

	p.ensureOwnAddressProven(userID)

	probe := (*sent)[0]
	if probe.username != "alice@example.com" {
		t.Fatalf("smtp auth username = %q, want the account's own", probe.username)
	}
	if probe.from != probe.recipients[0] {
		t.Fatalf("probe is not a self-send: from %q to %v", probe.from, probe.recipients)
	}
	var cfg mailmsg.IMAPConfigPayload
	cfg, exists, err := mailmsg.ReadIMAPConfigPayload(p.userIMAPConfigPath(userID), p.imapKeyPath)
	if err != nil || !exists {
		t.Fatalf("ReadIMAPConfigPayload: %v (exists=%v)", err, exists)
	}
	if probe.username != cfg.Username {
		t.Fatalf("probe username %q does not match stored config %q", probe.username, cfg.Username)
	}
}
