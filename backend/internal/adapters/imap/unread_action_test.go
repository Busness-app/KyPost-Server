package imap

import (
	"context"
	"strings"
	"testing"
)

func TestApplyInboxActionUnreadClearsSeen(t *testing.T) {
	quietRetries(t, 0)
	server := newFakeIMAPServer(t, "/", true, []fakeFolder{{name: "INBOX"}})
	client := server.client("INBOX")
	if err := client.ApplyInboxAction(context.Background(), "5", "unread", "INBOX", ""); err != nil {
		t.Fatalf("unread: %v", err)
	}
	for _, c := range server.commandsMatching("UID") {
		if strings.HasPrefix(c, "UID STORE") {
			if c != `UID STORE 5 -FLAGS (\Seen)` {
				t.Fatalf("store = %q, want only \\Seen removed", c)
			}
			return
		}
	}
	t.Fatal("no UID STORE sent")
}
