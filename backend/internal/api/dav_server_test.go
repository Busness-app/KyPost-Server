package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/users"
)

func davAuthedRequest(ac AuthContext, method, target string, body *bytes.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	req.Header.Set("Content-Type", "text/vcard; charset=utf-8")
	return req.WithContext(context.WithValue(req.Context(), authContextKey{}, ac))
}

func smallVCard(uid string) string {
	return fmt.Sprintf("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:%s\r\nFN:Small Card\r\nEND:VCARD\r\n", uid)
}

// TestHandleCardDAVPutRejectsOversizedBody guards against an unbounded PUT
// body being fully buffered in memory: a request body larger than
// maxContactPhotoBytes must be rejected rather than accepted.
func TestHandleCardDAVPutRejectsOversizedBody(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "dave", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	// The oversized payload must live *inside* a vCard property (like a real
	// huge base64 PHOTO would) rather than after END:VCARD — go-vcard's
	// line-based decoder stops reading as soon as it sees END:VCARD, so
	// trailing garbage after a complete card would never actually be read
	// and wouldn't exercise the MaxBytesReader cap at all.
	hugePhoto := "PHOTO:data:image/png;base64," + strings.Repeat("A", maxContactPhotoBytes+1024)
	card := "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:oversized-card\r\nFN:Oversized Card\r\n" +
		hugePhoto + "\r\nEND:VCARD\r\n"
	body := bytes.NewReader([]byte(card))

	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/oversized-card.vcf", body)
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
		t.Fatalf("oversized PUT should have been rejected, got status %d body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := must2(store.Get("oversized-card")); ok {
		t.Fatal("oversized PUT must not have been persisted")
	}
}

// TestHandleCardDAVPutAcceptsNormalBody is the control case: a small vCard
// well under the limit must still succeed, proving the new cap doesn't break
// ordinary CardDAV PUTs.
func TestHandleCardDAVPutAcceptsNormalBody(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "erin", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	body := bytes.NewReader([]byte(smallVCard("normal-card")))
	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/normal-card.vcf", body)
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated && rec.Code != http.StatusNoContent {
		t.Fatalf("normal PUT should have succeeded, got status %d body=%s", rec.Code, rec.Body.String())
	}

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := must2(store.Get("normal-card")); !ok {
		t.Fatal("normal PUT should have been persisted")
	}
}

// TestHandleCardDAVPutRejectsHeavilyFoldedCard pins the guard that exists for
// the import route and was never applied here.
//
// go-vcard's unfolding loop is `l += strings.TrimRight(folded, ...)` — O(n^2) —
// and go.mod carries no replace directive, so run-5's remediation was an
// application-level pre-scan, checkVCardFolding, not a library patch. That
// pre-scan has exactly one call site: handleContactsImport. The CardDAV PUT
// path hands the same bytes to the same decoder with no pre-scan, and unfolding
// happens BEFORE validation so a malformed card does not bail out early.
//
// Measured through a real http.Server, a 4 MiB folded body ran until ReadTimeout
// cut it off at 60 s, while the identical payload to the import route returned
// 413 in 28.8 ms. Two concurrent requests saturate the container's 4 CPUs.
func TestHandleCardDAVPutRejectsHeavilyFoldedCard(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "folded", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	// One property folded across far more continuation lines than any real
	// vCard carries, but comfortably inside the body size cap.
	var b strings.Builder
	b.WriteString("BEGIN:VCARD\r\nVERSION:4.0\r\nUID:folded-card\r\nFN:Folded\r\nNOTE:x\r\n")
	for i := 0; i < maxFoldedLinesPerImport+1000; i++ {
		b.WriteString(" x\r\n")
	}
	b.WriteString("END:VCARD\r\n")

	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/folded-card.vcf",
		bytes.NewReader([]byte(b.String())))
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated || rec.Code == http.StatusNoContent {
		t.Fatalf("heavily folded PUT should have been rejected, got status %d", rec.Code)
	}
	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := must2(store.Get("folded-card")); ok {
		t.Fatal("heavily folded PUT must not have been persisted")
	}
}

// TestCardDAVPutDoesNotStoreAnUnusableKey pins validation that the two sibling
// key-ingest paths perform and this one does not.
//
// contactFromVCard assigns the vCard KEY property straight to c.PGPKey with no
// parse, no CheckKeyStatus and no check that the key carries the contact's
// address as a User ID. validateDiscoveredKey (WKD) and validateAutocryptKey
// both do all three, and a contact's PGPKey is a trust anchor for exactly the
// same decisions: it is what outbound mail is encrypted to and what the
// signature badge is computed against.
//
// Pinning is not validation — pinPGPKeyFingerprint derives the pin from the
// supplied key, so keyMatchesPin then passes on whatever arrived.
func TestCardDAVPutDoesNotStoreAnUnusableKey(t *testing.T) {
	srv := newTestServer(t)
	u, err := srv.users.Create(context.Background(), "keyed", "irrelevant-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ac := AuthContext{UserID: u.ID, Username: u.Username, Role: u.Role}

	card := "BEGIN:VCARD\r\nVERSION:4.0\r\nUID:junk-key\r\nFN:Junk\r\n" +
		"EMAIL:bob@example.com\r\n" +
		"KEY:not-an-openpgp-key-at-all\r\nEND:VCARD\r\n"
	req := davAuthedRequest(ac, http.MethodPut, "/dav/"+u.Username+"/contacts/default/junk-key.vcf",
		bytes.NewReader([]byte(card)))
	rec := httptest.NewRecorder()
	srv.handleCardDAV(rec, req)

	store, err := srv.userContactsStore(u.ID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, ok := must2(store.Get("junk-key"))
	if !ok {
		t.Skip("card was rejected outright, which is also acceptable")
	}
	if c.PGPKey != "" {
		t.Fatalf("stored an unparseable value as a PGP trust anchor: %q", c.PGPKey)
	}
}
