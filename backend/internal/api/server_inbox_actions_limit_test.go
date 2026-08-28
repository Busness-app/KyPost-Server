package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// inboxActionsTestServer wires a server with an IMAP config and a fake client
// so POST /api/inbox/actions reaches the batch loop.
func inboxActionsTestServer(t *testing.T) (*Server, *fakeMailClient) {
	t.Helper()
	srv := newTestServer(t)
	srv.imapConfigKeyPath = filepath.Join(t.TempDir(), "imap-config.key")
	all, _ := srv.users.List()
	userID := all[0].ID
	if err := writeIMAPConfigPayload(srv.userIMAPConfigPath(userID), srv.imapConfigKeyPath, imapConfigPayload{
		Host: "imap.example.com", Port: 993, Username: "alice@example.com", Password: "pw",
		Mailbox: "INBOX", UpdatedAt: "test",
	}); err != nil {
		t.Fatalf("writeIMAPConfigPayload: %v", err)
	}
	fake := &fakeMailClient{}
	srv.userMu.Lock()
	srv.userMail[userID] = &serverMailEntry{client: fake, updatedAt: "test"}
	srv.userMu.Unlock()
	return srv, fake
}

func postInboxLabelAction(t *testing.T, srv *Server, ids []string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"action":     "label",
		"messageIds": ids,
		"keyword":    "VIP",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/inbox/actions", bytes.NewReader(body))
	authRequest(srv, req)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func inboxMessageIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	return ids
}

// TestInboxActionsRejectsOversizedBatch pins maxInboxActionIDs. The 1 MiB body
// limit admits tens of thousands of ids and each one is a separate serial IMAP
// command, so the cap — not the byte limit — is what bounds the work a single
// authorised request can make the account's one IMAP session do.
func TestInboxActionsRejectsOversizedBatch(t *testing.T) {
	srv, fake := inboxActionsTestServer(t)

	rec := postInboxLabelAction(t, srv, inboxMessageIDs(maxInboxActionIDs+1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d for maxInboxActionIDs+1 (%d); body=%s",
			rec.Code, http.StatusRequestEntityTooLarge, maxInboxActionIDs+1, rec.Body.String())
	}
	// Rejected before any IMAP work: not one command may have gone upstream.
	if len(fake.appliedLabels) != 0 {
		t.Fatalf("over-cap request reached the mail client: %d ApplyLabel calls", len(fake.appliedLabels))
	}

	var resp struct {
		Error         string `json:"error"`
		MaxMessageIDs int    `json:"maxMessageIds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	if resp.MaxMessageIDs != maxInboxActionIDs {
		t.Fatalf("maxMessageIds = %d, want %d — clients page against this value",
			resp.MaxMessageIDs, maxInboxActionIDs)
	}
}

// TestInboxActionsAcceptsBatchAtTheCap keeps the cap off by one: a client that
// paged to exactly the advertised limit must still be served.
func TestInboxActionsAcceptsBatchAtTheCap(t *testing.T) {
	srv, fake := inboxActionsTestServer(t)

	rec := postInboxLabelAction(t, srv, inboxMessageIDs(maxInboxActionIDs))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d for a batch of exactly maxInboxActionIDs (%d); body=%s",
			rec.Code, http.StatusOK, maxInboxActionIDs, rec.Body.String())
	}
	if len(fake.appliedLabels) != maxInboxActionIDs {
		t.Fatalf("ApplyLabel calls = %d, want %d", len(fake.appliedLabels), maxInboxActionIDs)
	}
}
