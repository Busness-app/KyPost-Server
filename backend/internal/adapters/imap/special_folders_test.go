package imap

// Where deleted and junked mail actually lands.
//
// ApplyInboxAction guessed at folder names and moved on to creating one the
// moment a guess failed, so on any server that does not spell its trash
// "Trash" the mail went into a folder this application had just invented —
// which the server, the phone and every other client ignore. These tests drive
// a real IMAP conversation and assert on the commands the server received.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const inbox = "INBOX"

func inboxFolder() fakeFolder { return fakeFolder{name: inbox} }

// assertNoCreate is the heart of every case below: resolving a folder correctly
// means never reaching for CREATE at all.
func assertNoCreate(t *testing.T, s *fakeIMAPServer) {
	t.Helper()
	if created := s.commandsMatching("CREATE"); len(created) > 0 {
		t.Fatalf("created a folder instead of using the server's own: %v", created)
	}
}

func assertMovedTo(t *testing.T, s *fakeIMAPServer, folder string) {
	t.Helper()
	moves := s.uidMoves()
	if len(moves) == 0 {
		t.Fatalf("no UID MOVE was issued; commands: %v", s.commandsMatching(""))
	}
	last := moves[len(moves)-1]
	if !strings.Contains(last, `"`+folder+`"`) {
		t.Fatalf("moved to the wrong folder: %q, want a move to %q (all moves: %v)", last, folder, moves)
	}
}

func TestDelete_UsesTopLevelTrashWhenThatIsWhatTheServerHas(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", true, []fakeFolder{
		inboxFolder(),
		{name: "Trash", attrs: `\Trash`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "Trash")
	assertNoCreate(t, s)
}

// The reported bug. A dot-delimited server with its trash under INBOX: the old
// code's first candidate was the bare "Trash", which does not exist, so it
// created one and filed the mail there.
func TestDelete_FindsTrashUnderInboxWithADotDelimiter(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Trash", attrs: `\Trash`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "INBOX.Trash")
	assertNoCreate(t, s)
}

// The same shape for spam, which was worse: a single hardcoded "Spam" with no
// candidate list at all, on a server whose junk folder is the far more common
// "Junk".
func TestSpam_FindsTheServersJunkFolder(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", true, []fakeFolder{
		inboxFolder(),
		{name: "Junk", attrs: `\Junk`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "spam", inbox, ""); err != nil {
		t.Fatalf("spam: %v", err)
	}

	assertMovedTo(t, s, "Junk")
	assertNoCreate(t, s)
}

// A localized folder name is the case only SPECIAL-USE can solve: no list of
// English candidates will ever match "Papierkorb".
func TestDelete_FindsALocalizedTrashByItsSpecialUseFlag(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", true, []fakeFolder{
		inboxFolder(),
		{name: "Papierkorb", attrs: `\Trash`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "Papierkorb")
	assertNoCreate(t, s)
}

// Servers that predate RFC 6154 publish no attributes, so the name fallback has
// to carry it — including the INBOX-prefixed spelling.
func TestDelete_FallsBackToNameMatchingWithoutSpecialUse(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", false, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Trash"},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "INBOX.Trash")
	assertNoCreate(t, s)
}

func TestSpam_FallsBackToNameMatchingForDeletedItemsStyleNames(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", false, []fakeFolder{
		inboxFolder(),
		{name: "Junk E-mail"},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "spam", inbox, ""); err != nil {
		t.Fatalf("spam: %v", err)
	}

	assertMovedTo(t, s, "Junk E-mail")
	assertNoCreate(t, s)
}

// Creating is still correct when the account genuinely has no trash — the bug
// was creating without looking first, not creating at all.
func TestDelete_CreatesTrashOnlyWhenTheServerHasNone(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", true, []fakeFolder{inboxFolder()})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	created := s.commandsMatching("CREATE")
	if len(created) != 1 || !strings.Contains(created[0], "Trash") {
		t.Fatalf("expected exactly one CREATE of a trash folder, got %v", created)
	}
	assertMovedTo(t, s, "Trash")
}

// Archive files into a per-year child, so it needs the server's real hierarchy
// delimiter rather than a guess between "Archive/2026" and "Archive.2026".
func TestArchive_UsesTheServersHierarchyDelimiter(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "Archive", attrs: `\Archive`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "archive", inbox, ""); err != nil {
		t.Fatalf("archive: %v", err)
	}

	want := fmt.Sprintf("Archive.%d", time.Now().Year())
	assertMovedTo(t, s, want)
}

// The latency half of the same bug. A UID MOVE to a mailbox that does not exist
// comes back NO, and go-imap cannot tell a protocol rejection from a dropped
// socket: it closes the connection, logs in again and retries. Resolving the
// folder first means never issuing that command, so one delete is one login.
func TestDelete_DoesNotReconnectWhenTheFolderIsResolvedFirst(t *testing.T) {
	quietRetries(t, 3)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Trash", attrs: `\Trash`},
	})

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if logins := s.loginCount(); logins != 1 {
		t.Fatalf("one delete cost %d logins; a reconnect storm is a failed MOVE being retried as if the socket had dropped", logins)
	}
}

// RFC 6154 only obliges a server to publish special-use attributes under the
// selection option, so a strict one shows none in a plain LIST. Resolving a
// localized folder on such a server depends entirely on the explicit probe.
func TestDelete_AsksExplicitlyWhenTheServerOnlyPublishesAttributesOnRequest(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, "/", true, []fakeFolder{
		inboxFolder(),
		{name: "Papierkorb", attrs: `\Trash`},
	})
	s.attrsOnlyWhenAsked = true

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "Papierkorb")
	assertNoCreate(t, s)
}

// A server that advertises SPECIAL-USE and then rejects the selection option
// leaves go-imap's connection closed, because its retry helper closes on any
// failure before checking whether retries remain. Resolution has to survive
// that and fall back to name matching.
func TestDelete_SurvivesAServerThatAdvertisesSpecialUseThenRefusesIt(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Trash"},
	})
	s.attrsOnlyWhenAsked = true
	s.refuseSelectionOption = true

	if err := s.client(inbox).ApplyInboxAction(context.Background(), "5", "delete", inbox, ""); err != nil {
		t.Fatalf("delete: %v", err)
	}

	assertMovedTo(t, s, "INBOX.Trash")
	assertNoCreate(t, s)
}

// Resolution is cached: a batch delete must not re-LIST the whole mailbox tree
// once per message.
func TestDelete_ResolvesTheFolderOncePerClient(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Trash", attrs: `\Trash`},
	})
	client := s.client(inbox)

	for _, uid := range []string{"5", "6", "7"} {
		if err := client.ApplyInboxAction(context.Background(), uid, "delete", inbox, ""); err != nil {
			t.Fatalf("delete %s: %v", uid, err)
		}
	}

	if lists := s.commandsMatching("LIST"); len(lists) != 1 {
		t.Fatalf("three deletes issued %d LIST commands, want 1: %v", len(lists), lists)
	}
	if moves := s.uidMoves(); len(moves) != 3 {
		t.Fatalf("want 3 moves, got %d: %v", len(moves), moves)
	}
}

// Sent and Drafts carried the same unreachable candidate lists.
func TestSaveSent_UsesTheServersSentFolder(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Sent", attrs: `\Sent`},
	})

	err := s.client(inbox).SaveSent(context.Background(), DraftMessage{
		To: []string{"someone@example.com"}, Subject: "hi", Body: "there",
	})
	if err != nil {
		t.Fatalf("save sent: %v", err)
	}

	appends := s.commandsMatching("APPEND")
	if len(appends) != 1 || !strings.Contains(appends[0], `"INBOX.Sent"`) {
		t.Fatalf("appended to the wrong folder: %v", appends)
	}
	assertNoCreate(t, s)
}

func TestSaveDraft_UsesTheServersDraftsFolder(t *testing.T) {
	quietRetries(t, 0)
	s := newFakeIMAPServer(t, ".", true, []fakeFolder{
		inboxFolder(),
		{name: "INBOX.Drafts", attrs: `\Drafts`},
	})

	err := s.client(inbox).SaveDraft(context.Background(), DraftMessage{
		To: []string{"someone@example.com"}, Subject: "hi", Body: "there",
	})
	if err != nil {
		t.Fatalf("save draft: %v", err)
	}

	appends := s.commandsMatching("APPEND")
	if len(appends) != 1 || !strings.Contains(appends[0], `"INBOX.Drafts"`) {
		t.Fatalf("appended to the wrong folder: %v", appends)
	}
	assertNoCreate(t, s)
}
