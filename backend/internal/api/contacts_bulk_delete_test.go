package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/pgpdiscovery"
)

// POST /api/contacts/bulk-delete used to call store.Delete once per id, with
// nothing but the 1 MiB body limit bounding the id count — around 28,000 full
// contacts.json rewrites, each under the store mutex and the cross-process file
// lock, blocking CardDAV, contact search and the poller's Autocrypt harvest for
// the duration. It is now capped and batched exactly like handleContactsSync.

func bulkDelete(t *testing.T, srv *Server, userID string, ids []string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONAuth(srv, srv.withAuth(srv.handleContactsBulkDelete), http.MethodPost,
		"/api/contacts/bulk-delete", map[string]any{"ids": ids}, userID)
}

func seededIDs(n int) []string {
	ids := make([]string, 0, n)
	for i := range n {
		ids = append(ids, fmt.Sprintf("seed-%d", i))
	}
	return ids
}

func bulkDeleteTestUser(t *testing.T, srv *Server) string {
	t.Helper()
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	return all[0].ID
}

func TestContactsBulkDeleteAcceptsBatchAtTheLimit(t *testing.T) {
	srv := newTestServer(t)
	userID := bulkDeleteTestUser(t, srv)
	seedContacts(t, srv, userID, maxContactsBulkDeleteIDs, "at the limit")

	rec := bulkDelete(t, srv, userID, seededIDs(maxContactsBulkDeleteIDs))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for exactly maxContactsBulkDeleteIDs (%d); body=%s",
			rec.Code, maxContactsBulkDeleteIDs, rec.Body.String())
	}
	var resp struct {
		OK        bool             `json:"ok"`
		Processed int              `json:"processed"`
		Failed    []map[string]any `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, rec.Body.String())
	}
	if !resp.OK || resp.Processed != maxContactsBulkDeleteIDs || len(resp.Failed) != 0 {
		t.Fatalf("ok=%v processed=%d failed=%v, want ok=true processed=%d failed=[]",
			resp.OK, resp.Processed, resp.Failed, maxContactsBulkDeleteIDs)
	}
	store := must1(srv.userContactsStore(userID))
	if left := len(must1(store.List())); left != 0 {
		t.Fatalf("%d contacts survived a bulk delete of every id", left)
	}
}

func TestContactsBulkDeleteRejectsBatchOverTheLimit(t *testing.T) {
	srv := newTestServer(t)
	userID := bulkDeleteTestUser(t, srv)
	over := maxContactsBulkDeleteIDs + 1
	seedContacts(t, srv, userID, over, "over the limit")
	store := must1(srv.userContactsStore(userID))
	before := len(must1(store.List()))

	rec := bulkDelete(t, srv, userID, seededIDs(over))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d for maxContactsBulkDeleteIDs+1 (%d); body=%s",
			rec.Code, http.StatusRequestEntityTooLarge, over, rec.Body.String())
	}
	var resp struct {
		Error  string `json:"error"`
		MaxIDs int    `json:"maxIds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("rejection body is not JSON (%v): %s", err, rec.Body.String())
	}
	if resp.MaxIDs != maxContactsBulkDeleteIDs {
		t.Fatalf("maxIds = %d, want %d — a client paging off this value would loop forever on a wrong figure",
			resp.MaxIDs, maxContactsBulkDeleteIDs)
	}
	// A refused request must commit nothing: a 413 after deleting the first
	// 500 would be the worst of both.
	if after := len(must1(store.List())); after != before {
		t.Fatalf("contact count went %d -> %d on a rejected batch; a 413 must delete nothing", before, after)
	}
}

// The batch must keep the per-id discovery bookkeeping the loop did: deleting a
// discovery-created contact records a suppression so the key-discovery ladder
// does not re-create it on the next encrypted send.
func TestContactsBulkDeleteStillSuppressesDiscoveryContacts(t *testing.T) {
	srv := newTestServer(t)
	userID := bulkDeleteTestUser(t, srv)
	store := must1(srv.userContactsStore(userID))
	if err := store.ApplyBatch([]contacts.BatchOp{
		{Contact: contacts.Contact{UID: "disc-1", FormattedName: "Ada",
			Emails: []contacts.ContactValue{{Value: "ada@example.com"}}, DiscoveryCreated: true}},
		{Contact: contacts.Contact{UID: "disc-2", FormattedName: "Bo",
			Emails: []contacts.ContactValue{{Value: "bo@example.com"}}, DiscoveryCreated: true}},
		{Contact: contacts.Contact{UID: "plain-1", FormattedName: "Cy",
			Emails: []contacts.ContactValue{{Value: "cy@example.com"}}}},
	}); err != nil {
		t.Fatalf("ApplyBatch seeding: %v", err)
	}

	rec := bulkDelete(t, srv, userID, []string{"disc-1", "disc-2", "plain-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	set := must1(pgpdiscovery.SuppressedSet(srv.userStateDir(userID)))
	if !set["ada@example.com"] || !set["bo@example.com"] {
		t.Fatalf("discovery-created addresses were not suppressed by a bulk delete: %v", set)
	}
	if set["cy@example.com"] {
		t.Fatalf("a normal contact's deletion must not suppress discovery: %v", set)
	}
	if left := len(must1(store.List())); left != 0 {
		t.Fatalf("%d contacts survived the bulk delete", left)
	}
}

// The whole point of the cap is that it bounds ONE ApplyBatch transaction. A
// per-id store.Delete would be a full-file rewrite each, which no black-box
// assertion here can distinguish from one write — so pin the call itself.
func TestContactsBulkDeleteWritesOnce(t *testing.T) {
	src, err := os.ReadFile("contacts_handlers.go")
	if err != nil {
		t.Fatalf("read handler source: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *Server) handleContactsBulkDelete(")
	if start < 0 {
		t.Fatal("handleContactsBulkDelete not found")
	}
	body = body[start:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "store.ApplyBatch(") {
		t.Error("handleContactsBulkDelete does not call store.ApplyBatch; every id would be its own full-file rewrite")
	}
	if strings.Contains(body, "store.Delete(") {
		t.Error("handleContactsBulkDelete calls store.Delete per id; that is one locked full-file rewrite each")
	}
}
