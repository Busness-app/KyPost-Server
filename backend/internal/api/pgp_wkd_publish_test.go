package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/users"
	"kypost-server/backend/internal/wkdpublish"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

// wkdVerifiedDomains is Store.VerifiedDomains with its read error asserted
// away. These tests are about which domains end up verified, not about whether
// the claims file reads — the error exists so lookupPublishedKey cannot mistake
// a stale cache for a fresh answer, and a test that swallowed it would be
// making exactly that mistake.
func wkdVerifiedDomains(t *testing.T, s *wkdpublish.Store) map[string]bool {
	t.Helper()
	vd, err := s.VerifiedDomains()
	if err != nil {
		t.Fatalf("VerifiedDomains: %v", err)
	}
	return vd
}

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

// TestWKDDomainClaimVerifyDeleteFlowAsAdmin exercises the full claim ->
// verify -> list -> delete lifecycle as the admin (bootstrap user), which is
// now the only role allowed to manage WKD domains at all: domain ownership
// is an instance-level property, not tied to any one user's send addresses.
func TestWKDDomainClaimVerifyDeleteFlowAsAdmin(t *testing.T) {
	srv := newTestServer(t)
	adminID := srv.mustBootstrapUserID(t)

	// Admin claims a domain — note the mixed case, which must be normalized.
	claimRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"Example.com"}`)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim: status = %d, want 200; body=%s", claimRec.Code, claimRec.Body.String())
	}
	claim := decodeJSONBody(t, claimRec)
	if claim["domain"] != "example.com" {
		t.Fatalf("claim domain = %v, want example.com", claim["domain"])
	}
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

	// Verify with the DNS seam returning the expected token.
	orig := wkdpublish.LookupTXT
	t.Cleanup(func() { wkdpublish.LookupTXT = orig })
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return []string{"kypost-wkd-verify=" + token}, nil
	}
	okRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains/example.com/verify", "")
	if okRec.Code != http.StatusOK {
		t.Fatalf("verify(ok): status = %d, want 200; body=%s", okRec.Code, okRec.Body.String())
	}
	okResp := decodeJSONBody(t, okRec)
	if okResp["verified"] != true {
		t.Fatalf("verify(ok): expected verified=true, got %v", okResp["verified"])
	}

	// List reflects the verified claim.
	listRec := doWKDRoute(srv, adminID, http.MethodGet, "/api/pgp/wkd/domains", "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200; body=%s", listRec.Code, listRec.Body.String())
	}
	listResp := decodeJSONBody(t, listRec)
	domains, _ := listResp["domains"].([]any)
	if len(domains) != 1 {
		t.Fatalf("list: expected 1 domain, got %+v", listResp)
	}

	// Delete → 204, then list is empty again.
	delRec := doWKDRoute(srv, adminID, http.MethodDelete, "/api/pgp/wkd/domains/example.com", "")
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204; body=%s", delRec.Code, delRec.Body.String())
	}
	listRec2 := doWKDRoute(srv, adminID, http.MethodGet, "/api/pgp/wkd/domains", "")
	listResp2 := decodeJSONBody(t, listRec2)
	domains2, _ := listResp2["domains"].([]any)
	if len(domains2) != 0 {
		t.Fatalf("list after delete: expected 0 domains, got %+v", listResp2)
	}
}

// TestWKDDomainVerifyDoesNotUnpublishOnTransientDNSError covers R2: the
// admin Verify endpoint used to discard CheckTXT's error entirely
// (`verified, _ := wkdpublish.CheckTXT(...)`) and persist the resulting
// false, unpublishing an entire domain's users on a mere transient DNS blip
// — the opposite of the invariant the background re-check preserves. A
// transient failure (a plain, non-*net.DNSError-not-found error) must leave
// the claim's stored verified value untouched.
func TestWKDDomainVerifyDoesNotUnpublishOnTransientDNSError(t *testing.T) {
	srv := newTestServer(t)
	adminID := srv.mustBootstrapUserID(t)

	claimRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"example.com"}`)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim: status = %d, want 200; body=%s", claimRec.Code, claimRec.Body.String())
	}

	store, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	orig := wkdpublish.LookupTXT
	t.Cleanup(func() { wkdpublish.LookupTXT = orig })
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return nil, errors.New("some transient resolver failure")
	}

	verifyRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains/example.com/verify", "")
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, want 200; body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	verifyResp := decodeJSONBody(t, verifyRec)
	if verifyResp["verified"] != true {
		t.Fatalf("verify response should report the claim's unchanged verified=true, got %v", verifyResp["verified"])
	}
	if _, ok := verifyResp["checkError"]; !ok {
		t.Fatalf("verify response should surface a checkError hint on transient failure: %+v", verifyResp)
	}

	if !wkdVerifiedDomains(t, store)["example.com"] {
		t.Fatal("a transient DNS error on Verify must not unpublish an already-verified domain")
	}
}

// TestWKDDomainManagementRequiresAdmin confirms a non-admin user cannot
// manage WKD domains at all, even a domain they personally send from — the
// old per-user "domain you send from" self-service premise is gone.
func TestWKDDomainManagementRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	srv.mustBootstrapUserID(t)
	regular, err := srv.users.Create(context.Background(), "regular-wkd", "regular-password", users.RoleUser)
	if err != nil {
		t.Fatalf("Create regular user: %v", err)
	}
	writeUnreachableSMTPIMAPConfig(t, srv, regular.ID, "alice@example.com")

	postRec := doWKDRoute(srv, regular.ID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"example.com"}`)
	if postRec.Code != http.StatusForbidden {
		t.Fatalf("POST as non-admin: status = %d, want 403; body=%s", postRec.Code, postRec.Body.String())
	}
	getRec := doWKDRoute(srv, regular.ID, http.MethodGet, "/api/pgp/wkd/domains", "")
	if getRec.Code != http.StatusForbidden {
		t.Fatalf("GET as non-admin: status = %d, want 403; body=%s", getRec.Code, getRec.Body.String())
	}
}

// TestWKDDomainClaimIsInstanceScoped confirms an admin's claim lands in the
// single instance-level store (reachable via srv.wkdPublishStore()), not a
// per-user file.
func TestWKDDomainClaimIsInstanceScoped(t *testing.T) {
	srv := newTestServer(t)
	adminID := srv.mustBootstrapUserID(t)

	claimRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains", `{"domain":"example.com"}`)
	if claimRec.Code != http.StatusOK {
		t.Fatalf("claim: status = %d, want 200; body=%s", claimRec.Code, claimRec.Body.String())
	}
	claim := decodeJSONBody(t, claimRec)
	token, _ := claim["token"].(string)

	orig := wkdpublish.LookupTXT
	t.Cleanup(func() { wkdpublish.LookupTXT = orig })
	wkdpublish.LookupTXT = func(string) ([]string, error) {
		return []string{"kypost-wkd-verify=" + token}, nil
	}
	verifyRec := doWKDRoute(srv, adminID, http.MethodPost, "/api/pgp/wkd/domains/example.com/verify", "")
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, want 200; body=%s", verifyRec.Code, verifyRec.Body.String())
	}

	store, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if !wkdVerifiedDomains(t, store)["example.com"] {
		t.Fatalf("expected example.com to be verified in the instance store")
	}

	if _, err := os.Stat(filepath.Join(srv.userStateDir(adminID), "wkd-domains.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no per-user wkd-domains.json, stat err = %v", err)
	}
}

// doRaw drives an unauthenticated request through the server's real route
// table (WKD serving is a public endpoint, no session/CSRF). An optional
// Host header lets the direct method's domain-from-r.Host path be exercised.
func doRaw(t *testing.T, srv *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	return rec
}

// seedVerifiedSendAs marks addr as a verified send-as alias for userID.
// WKD publication requires this: the IMAP username it used to accept is
// self-declared (POST /api/imap/config performs no ownership check), so the
// send-as challenge is now the single proof of an address, including the
// account's own. See publishableAddressesAt.
func seedVerifiedSendAs(t *testing.T, srv *Server, userID, addr string) {
	t.Helper()
	store, err := srv.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := store.Create(userID, strings.ToLower(addr), "")
	if err != nil {
		t.Fatalf("sendas Create: %v", err)
	}
	if err := store.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}
}

func TestWKDServing(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")
	seedVerifiedSendAs(t, srv, userID, "alice@example.com")
	seedUserPGPKey(t, srv, userID, "alice@example.com")

	// Claim + verify example.com in the instance-level store.
	store, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	hu := wkdHashLocalPart("alice")

	// Advanced method (domain in path)
	adv := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/"+hu, "", nil)
	if adv.Code != http.StatusOK {
		t.Fatalf("advanced: status %d body=%s", adv.Code, adv.Body.String())
	}
	if _, err := crypto.NewKey(adv.Body.Bytes()); err != nil {
		t.Fatalf("advanced body is not a binary key: %v", err)
	}
	if ct := adv.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q", ct)
	}

	// Direct method (domain from Host)
	dir := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/hu/"+hu, "", map[string]string{"Host": "example.com"})
	if dir.Code != http.StatusOK {
		t.Fatalf("direct: status %d body=%s", dir.Code, dir.Body.String())
	}
	if _, err := crypto.NewKey(dir.Body.Bytes()); err != nil {
		t.Fatalf("direct body is not a binary key: %v", err)
	}

	// Unknown domain → 404
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/unknown.test/hu/"+hu, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("unknown domain: status %d", r.Code)
	}
	// Wrong hu → 404
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/zzzzzzzz", "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("wrong hu: status %d", r.Code)
	}
	// Policy → 200 empty
	p := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/policy", "", nil)
	if p.Code != http.StatusOK || p.Body.Len() != 0 {
		t.Fatalf("policy: status %d len %d", p.Code, p.Body.Len())
	}
}

// TestWKDServingDomainScoping covers the access-control boundary that
// TestWKDServing's "unknown domain" case doesn't isolate: it uses a domain
// with no matching address at all, so a 404 there is inconclusive about
// whether domain scoping is actually enforced. Here, other.example and
// pending.example both have a REAL publishable address ("alice", the same
// local part as the verified example.com address, so it hashes to the same
// hu) — the only thing that can explain a 404 for them is the
// domain-verification gate itself, not an address/hash mismatch.
func TestWKDServingDomainScoping(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")
	seedVerifiedSendAs(t, srv, userID, "alice@example.com")
	seedUserPGPKey(t, srv, userID, "alice@example.com")

	sendAsStore, err := srv.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	otherAlias, err := sendAsStore.Create(userID, "alice@other.example", "")
	if err != nil {
		t.Fatalf("Create alice@other.example: %v", err)
	}
	if err := sendAsStore.MarkVerified(otherAlias.ID); err != nil {
		t.Fatalf("MarkVerified alice@other.example: %v", err)
	}
	pendingAlias, err := sendAsStore.Create(userID, "alice@pending.example", "")
	if err != nil {
		t.Fatalf("Create alice@pending.example: %v", err)
	}
	if err := sendAsStore.MarkVerified(pendingAlias.ID); err != nil {
		t.Fatalf("MarkVerified alice@pending.example: %v", err)
	}

	wkdStore, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	// example.com: claimed AND verified.
	if _, err := wkdStore.Create("example.com"); err != nil {
		t.Fatalf("Create example.com claim: %v", err)
	}
	if err := wkdStore.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified example.com: %v", err)
	}
	// pending.example: claimed but never verified.
	if _, err := wkdStore.Create("pending.example"); err != nil {
		t.Fatalf("Create pending.example claim: %v", err)
	}
	// other.example: no claim at all.

	hu := wkdHashLocalPart("alice")

	// Sanity check: the verified domain does serve this hu.
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/"+hu, "", nil); r.Code != http.StatusOK {
		t.Fatalf("verified domain: status %d, want 200", r.Code)
	}

	// (a) Different domain, same hu, real address, but NO verified WKD claim
	// for it → 404. A verified claim for example.com must not leak the key
	// under other.example.
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/other.example/hu/"+hu, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("domain with real address but no claim: status %d, want 404", r.Code)
	}

	// (b) Claimed-but-unverified domain, same hu, real address → 404. An
	// unverified claim must never serve.
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/pending.example/hu/"+hu, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("claimed-but-unverified domain: status %d, want 404", r.Code)
	}
}

// TestWKDServingRespectsPublishWKDOptOut confirms domain verification alone
// does not publish a user's key: PublishWKD is a separate, per-user gate
// consulted at serve time. With the domain verified and a real matching
// address, the key serves while PublishWKD defaults to true; once the user
// explicitly turns it off, the identical lookup must 404.
func TestWKDServingRespectsPublishWKDOptOut(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")
	seedVerifiedSendAs(t, srv, userID, "alice@example.com")
	seedUserPGPKey(t, srv, userID, "alice@example.com")

	store, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	hu := wkdHashLocalPart("alice")

	// Baseline: PublishWKD defaults to true, so the key serves.
	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/"+hu, "", nil); r.Code != http.StatusOK {
		t.Fatalf("baseline: status %d, want 200", r.Code)
	}

	// User opts out of WKD publication.
	settings, err := pgpdiscovery.Load(srv.userStateDir(userID))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	settings.PublishWKD = false
	if err := pgpdiscovery.Save(srv.userStateDir(userID), settings); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if r := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/"+hu, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("after opt-out: status %d, want 404", r.Code)
	}
}

// TestLookupPublishedKeySkipsCorruptKeyContinuesToNextUser covers O1:
// lookupPublishedKey used to `return nil, false` the instant it hit a user
// whose stored PGPPublicKey failed to parse, aborting the scan for every
// other user on the instance. It must instead skip only that one user and
// keep looking. The bootstrap user (always users.List()[0]) is given a
// verified claim + matching address but a corrupt key; a second user with a
// genuinely valid key at the same domain/local-part must still be found.
func TestLookupPublishedKeySkipsCorruptKeyContinuesToNextUser(t *testing.T) {
	srv := newTestServer(t)
	corruptUserID := srv.mustBootstrapUserID(t)

	writeUnreachableSMTPIMAPConfig(t, srv, corruptUserID, "alice@example.com")
	seedVerifiedSendAs(t, srv, corruptUserID, "alice@example.com")
	if _, err := srv.users.SetPGPIdentity(corruptUserID, "fp", "kid", "not a real armored key", "", "generated", "2026-07-24T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity corrupt: %v", err)
	}
	// example.com is claimed and verified once in the shared instance store —
	// both the corrupt-keyed user and the valid-keyed user below are
	// publishable addresses under this single instance-wide claim.
	wkdStore, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if _, err := wkdStore.Create("example.com"); err != nil {
		t.Fatalf("Create claim: %v", err)
	}
	if err := wkdStore.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	validUser, err := srv.users.Create(context.Background(), "valid-wkd-user", "initial-pass-123", users.RoleUser)
	if err != nil {
		t.Fatalf("Create valid user: %v", err)
	}
	writeUnreachableSMTPIMAPConfig(t, srv, validUser.ID, "alice@example.com")
	seedVerifiedSendAs(t, srv, validUser.ID, "alice@example.com")
	seedUserPGPKey(t, srv, validUser.ID, "alice@example.com")

	hu := wkdHashLocalPart("alice")
	rec := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/example.com/hu/"+hu, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 despite one user's corrupt key, got %d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := crypto.NewKey(rec.Body.Bytes()); err != nil {
		t.Fatalf("response body is not a binary key: %v", err)
	}
}

// TestWKDServedAliasKeyIsAcceptedByDiscovery is the end-to-end property the
// whole User-ID plumbing exists for: a key generated after an alias was
// verified must, when fetched over WKD at the ALIAS address, survive the
// same address-binding check every consumer applies (validateDiscoveredKey
// here; GnuPG's WKD User ID filtering in the wild). Serving the bytes is not
// enough — a key that doesn't carry the queried address is discarded on
// arrival.
func TestWKDServedAliasKeyIsAcceptedByDiscovery(t *testing.T) {
	srv := newTestServer(t)
	userID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, userID, "alice@example.com")
	seedVerifiedSendAs(t, srv, userID, "alice@example.com")

	sendAsStore, err := srv.userSendAsStore(userID)
	if err != nil {
		t.Fatalf("userSendAsStore: %v", err)
	}
	alias, err := sendAsStore.Create(userID, "alice@other.example", "")
	if err != nil {
		t.Fatalf("Create alias: %v", err)
	}
	if err := sendAsStore.MarkVerified(alias.ID); err != nil {
		t.Fatalf("MarkVerified: %v", err)
	}

	// Generate the key only now, with the alias already verified.
	genBody, _ := json.Marshal(map[string]string{"password": stepUpPassword(t, srv, userID)})
	genReq := httptest.NewRequest(http.MethodPost, "/api/pgp/identity/generate", bytes.NewReader(genBody))
	authRequest(srv, genReq)
	genRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPIdentityGenerate)(genRec, genReq)
	if genRec.Code != http.StatusOK {
		t.Fatalf("generate: expected 200, got %d: %s", genRec.Code, genRec.Body.String())
	}

	wkdStore, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if _, err := wkdStore.Create("other.example"); err != nil {
		t.Fatalf("Create other.example claim: %v", err)
	}
	if err := wkdStore.SetVerified("other.example", true, time.Now()); err != nil {
		t.Fatalf("SetVerified other.example: %v", err)
	}

	rec := doRaw(t, srv, http.MethodGet, "/.well-known/openpgpkey/other.example/hu/"+wkdHashLocalPart("alice"), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("wkd lookup at alias domain: status %d, want 200", rec.Code)
	}
	served, err := crypto.NewKey(rec.Body.Bytes()) // WKD serves binary keys
	if err != nil {
		t.Fatalf("parse served key: %v", err)
	}
	armored, err := served.GetArmoredPublicKey()
	if err != nil {
		t.Fatalf("armor served key: %v", err)
	}
	if _, err := validateDiscoveredKey(armored, "alice@other.example"); err != nil {
		t.Fatalf("served key rejected for the alias it was served under: %v", err)
	}
}

// TestWKDServingFailsClosedOnUnreadableClaims covers the fail-OPEN that
// Store.VerifiedDomains returning an error exists to close.
//
// The claims slice behind VerifiedDomains is a cache of wkd-domains.json, and
// the disk re-read's error used to be discarded (`_ = s.refreshFromDiskLocked()`).
// So a process that had already read a verified claim kept answering from that
// cache once the file stopped being readable — indefinitely, and
// indistinguishably from a healthy read. This is the authorization gate on a
// public, unauthenticated endpoint: it decides whether this instance may serve
// a user's key at a domain's Web Key Directory at all. It may fail; it may not
// fail open.
//
// The pre-damage 200 is what makes the post-damage 404 mean something: it
// proves the address, the key, the hash and the claim were all correct, so the
// only thing that changed is the unreadable file.
func TestWKDServingFailsClosedOnUnreadableClaims(t *testing.T) {
	srv := newTestServer(t)
	adminID := srv.mustBootstrapUserID(t)
	writeUnreachableSMTPIMAPConfig(t, srv, adminID, "alice@example.com")
	seedVerifiedSendAs(t, srv, adminID, "alice@example.com")
	seedUserPGPKey(t, srv, adminID, "alice@example.com")

	store, err := srv.wkdPublishStore()
	if err != nil {
		t.Fatalf("wkdPublishStore: %v", err)
	}
	if _, err := store.Create("example.com"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.SetVerified("example.com", true, time.Now()); err != nil {
		t.Fatalf("SetVerified: %v", err)
	}

	hu := wkdHashLocalPart("alice")
	path := "/.well-known/openpgpkey/example.com/hu/" + hu
	if r := doRaw(t, srv, http.MethodGet, path, "", nil); r.Code != http.StatusOK {
		t.Fatalf("precondition: expected the key to be served, status %d body=%s", r.Code, r.Body.String())
	}

	// Corrupt the file the claim lives in, leaving the store's warm in-memory
	// copy exactly as it was. This stands in for any read failure — a truncated
	// write, a damaged volume, a permissions change — all of which reach
	// VerifiedDomains as the same refresh error.
	claimsPath := filepath.Join(srv.stateDir, "wkd-domains.json")
	if err := os.WriteFile(claimsPath, []byte("{ this is not the claims file"), 0o600); err != nil {
		t.Fatalf("corrupt claims file: %v", err)
	}

	if r := doRaw(t, srv, http.MethodGet, path, "", nil); r.Code != http.StatusNotFound {
		t.Fatalf("published a key from a cached claim after the claims file became unreadable: status %d", r.Code)
	}

	// The admin list must report the breakage rather than present the stale
	// cache as current: an admin reading it is deciding whether their domains
	// are published, and a confident wrong answer is the worst outcome.
	listRec := doWKDRoute(srv, adminID, http.MethodGet, "/api/pgp/wkd/domains", "")
	if listRec.Code != http.StatusInternalServerError {
		t.Fatalf("admin list served stale claims instead of surfacing the read failure: status %d", listRec.Code)
	}
}
