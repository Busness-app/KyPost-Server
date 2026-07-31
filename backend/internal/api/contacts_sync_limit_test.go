package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// maxContactsSyncChanges is the only thing bounding the size of the single
// ApplyBatch transaction a phone can ask for — the 1 MiB body limit is not a
// bound on work, see the constant's own comment. It had no test at all, so the
// boundary was free to drift: an off-by-one here either rejects a client that
// paged correctly to exactly the advertised limit, or admits a batch larger
// than the transaction was sized for.

// syncPushBody builds a well-formed push of n distinct upserts. Every change
// carries a non-empty fn so none is skipped by handleContactsSync's
// translation loop — these tests are about the count check, not the validity
// filter.
func syncPushBody(t *testing.T, n int) *bytes.Reader {
	t.Helper()
	push := contactsSyncPushRequest{Changes: make([]contactSyncChange, 0, n)}
	for i := 0; i < n; i++ {
		var change contactSyncChange
		change.UID = fmt.Sprintf("uid-%d", i)
		change.FormattedName = fmt.Sprintf("Contact %d", i)
		push.Changes = append(push.Changes, change)
	}
	raw, err := json.Marshal(push)
	if err != nil {
		t.Fatalf("marshal push: %v", err)
	}
	return bytes.NewReader(raw)
}

// syncPush posts a batch of the given size from a freshly paired device and
// returns the status and body.
func syncPush(t *testing.T, changes int) (int, string) {
	t.Helper()
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	deviceID, deviceSecret := pairNativeDevice(t, srv, all[0].ID, fmt.Sprintf("sync-limit-%d", changes))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/sync", syncPushBody(t, changes))
	req.Header.Set("Content-Type", "application/json")
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestContactsSyncAcceptsBatchAtTheLimit(t *testing.T) {
	code, body := syncPush(t, maxContactsSyncChanges)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want %d for a batch of exactly maxContactsSyncChanges (%d) — a client that paged to the advertised limit must not be rejected; body=%s",
			code, http.StatusOK, maxContactsSyncChanges, body)
	}
}

func TestContactsSyncRejectsBatchOverTheLimit(t *testing.T) {
	code, body := syncPush(t, maxContactsSyncChanges+1)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d for maxContactsSyncChanges+1 (%d); body=%s",
			code, http.StatusRequestEntityTooLarge, maxContactsSyncChanges+1, body)
	}

	// The client pages off this figure, so it has to be in the body and it has
	// to be the real limit rather than a hardcoded duplicate that could drift.
	var resp struct {
		Error      string `json:"error"`
		MaxChanges int    `json:"maxChanges"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("rejection body is not JSON (%v): %s", err, body)
	}
	if resp.MaxChanges != maxContactsSyncChanges {
		t.Fatalf("maxChanges = %d, want %d — a client paging off this value would loop forever on a wrong figure",
			resp.MaxChanges, maxContactsSyncChanges)
	}
}

// An oversized batch must be refused whole. Committing the first
// maxContactsSyncChanges of it and then reporting 413 would leave the client's
// cursor disagreeing with the server about what landed — the split brain
// ApplyBatch's all-or-nothing commit exists to prevent.
func TestContactsSyncOversizedBatchCommitsNothing(t *testing.T) {
	srv := newTestServer(t)
	all, err := srv.users.List()
	if err != nil || len(all) == 0 {
		t.Fatalf("no test user available: %v", err)
	}
	userID := all[0].ID
	deviceID, deviceSecret := pairNativeDevice(t, srv, userID, "sync-limit-atomic")

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	before := len(store.List())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/contacts/sync", syncPushBody(t, maxContactsSyncChanges+1))
	req.Header.Set("Content-Type", "application/json")
	setDeviceHeaders(req, deviceID, deviceSecret)
	srv.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusRequestEntityTooLarge, rec.Body.String())
	}
	if after := len(store.List()); after != before {
		t.Fatalf("contact count went %d -> %d on a rejected batch; a 413 must commit nothing", before, after)
	}
}
