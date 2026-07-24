package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"kypost-server/backend/internal/wkdpublish"
)

// doWKDRoute drives a request through the server's real route table
// (srv.routes()) rather than calling a handler directly, so it exercises
// {domain} path-value extraction the way the mux performs it in production
// (mirrors TestContactsDedupeAcceptsDeviceCredentials's precedent for
// exercising real routing, and authRequestAs for session+CSRF auth).
func doWKDRoute(srv *Server, userID, method, path, body string) *httptest.ResponseRecorder {
	var r *strings.Reader
	if body == "" {
		r = strings.NewReader("")
	} else {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestWKDClaimVerifyDeleteFlow(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	// Give the user a mailbox whose username is alice@example.com so
	// example.com is a permitted publish domain.
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")

	// Claim a domain the user sends from.
	claimRec := doWKDRoute(srv, userID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"example.com"}`)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim: status = %d, want 200; body=%s", claimRec.Code, claimRec.Body.String())
	}
	claim := decodeJSONBody(t, claimRec)
	token, _ := claim["token"].(string)
	if token == "" {
		t.Fatalf("expected non-empty token in claim response: %+v", claim)
	}
	if claim["recordName"] != wkdpublish.TXTRecordName("example.com") {
		t.Fatalf("recordName = %v, want %v", claim["recordName"], wkdpublish.TXTRecordName("example.com"))
	}
	if claim["recordValue"] != "kypost-wkd-verify="+token {
		t.Fatalf("recordValue = %v, want kypost-wkd-verify=%s", claim["recordValue"], token)
	}

	// Verify with the DNS seam returning the wrong value first.
	orig := wkdpublish.LookupTXT
	t.Cleanup(func() { wkdpublish.LookupTXT = orig })
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return []string{"kypost-wkd-verify=not-the-token"}, nil
	}
	badRec := doWKDRoute(srv, userID, http.MethodPost, "/api/pgp/wkd/domains/example.com/verify", "")
	if badRec.Code != http.StatusOK {
		t.Fatalf("verify(wrong): status = %d, want 200; body=%s", badRec.Code, badRec.Body.String())
	}
	badResp := decodeJSONBody(t, badRec)
	if badResp["verified"] != false {
		t.Fatalf("verify(wrong): expected verified=false, got %v", badResp["verified"])
	}

	// Verify with the DNS seam returning the expected token.
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return []string{"kypost-wkd-verify=" + token}, nil
	}
	okRec := doWKDRoute(srv, userID, http.MethodPost, "/api/pgp/wkd/domains/example.com/verify", "")
	if okRec.Code != http.StatusOK {
		t.Fatalf("verify(ok): status = %d, want 200; body=%s", okRec.Code, okRec.Body.String())
	}
	okResp := decodeJSONBody(t, okRec)
	if okResp["verified"] != true {
		t.Fatalf("verify(ok): expected verified=true, got %v", okResp["verified"])
	}

	// List reflects the verified claim.
	listRec := doWKDRoute(srv, userID, http.MethodGet, "/api/pgp/wkd/domains", "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200; body=%s", listRec.Code, listRec.Body.String())
	}
	listResp := decodeJSONBody(t, listRec)
	domains, _ := listResp["domains"].([]any)
	if len(domains) != 1 {
		t.Fatalf("list: expected 1 domain, got %+v", listResp)
	}

	// Claim a domain the user does NOT send from → rejected.
	foreignRec := doWKDRoute(srv, userID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"notmine.org"}`)
	if foreignRec.Code != http.StatusBadRequest {
		t.Fatalf("foreign claim: status = %d, want 400; body=%s", foreignRec.Code, foreignRec.Body.String())
	}

	// Delete → 204, then list is empty again.
	delRec := doWKDRoute(srv, userID, http.MethodDelete, "/api/pgp/wkd/domains/example.com", "")
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", delRec.Code, delRec.Body.String())
	}
	listRec2 := doWKDRoute(srv, userID, http.MethodGet, "/api/pgp/wkd/domains", "")
	listResp2 := decodeJSONBody(t, listRec2)
	domains2, _ := listResp2["domains"].([]any)
	if len(domains2) != 0 {
		t.Fatalf("list after delete: expected 0 domains, got %+v", listResp2)
	}
}

// TestWKDClaimAllowsVerifiedSendAsDomain confirms the publishable-domain
// rule also accepts a verified send-as alias's domain, not just the IMAP
// account address's domain.
func TestWKDClaimAllowsVerifiedSendAsDomain(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")

	store, err := srv.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, "alice@other.example", "")
	if err != nil {
		t.Fatalf("Create alias: %v", err)
	}
	if err := store.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	rec := doWKDRoute(srv, userID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"other.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
