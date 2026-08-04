package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpmail"
)

func TestWKDHashLocalPart(t *testing.T) {
	// Canonical vector from the WKD spec (draft-koch-openpgp-webkey-service):
	// local-part "Joe.Doe" hashes to this z-base-32 string.
	got := wkdHashLocalPart("Joe.Doe")
	want := "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
	if got != want {
		t.Fatalf("wkdHashLocalPart = %q, want %q", got, want)
	}
}

func TestValidateDiscoveredKeyAcceptsMatchingUsableKey(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	fp, err := validateDiscoveredKey(id.ArmoredPublicKey, "alice@example.com")
	if err != nil {
		t.Fatalf("validateDiscoveredKey: %v", err)
	}
	if fp == "" {
		t.Fatalf("expected a non-empty fingerprint")
	}
}

func TestValidateDiscoveredKeyRejectsWrongUID(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Alice", "alice@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if _, err := validateDiscoveredKey(id.ArmoredPublicKey, "mallory@example.com"); err == nil {
		t.Fatalf("expected rejection when the queried address is not a UID")
	}
}

// TestWKDCandidateURLsRejectsMalformedDomain pins the invariant that a
// recipient's domain is pasted into a URL only after it has been confirmed to
// be a hostname and nothing else.
//
// The domain arrives from a recipient address the user chose, and
// mail.ParseAddress is considerably more permissive than DNS: '/', '?' and '#'
// are all valid atext, so "a@evil.com/admin" parses as an address and, taken
// verbatim, produces https://evil.com/admin/.well-known/... — a GET this
// server makes on the user's behalf to a path the user picked. The SSRF guard
// does not catch it, because the host really is the public host it appears to
// be; what has been subverted is the rest of the URL.
//
// Rejection belongs here rather than in validateOutboundURL: by the time a
// string has been through url.Parse the injected path is indistinguishable
// from a legitimate one.
func TestWKDCandidateURLsRejectsMalformedDomain(t *testing.T) {
	// Not in this list, deliberately: "localhost", "169.254.169.254" and
	// friends. Those are syntactically fine hostnames, and refusing them is
	// the IP guard's job, not this function's. Duplicating that decision here
	// would mean two places to keep in agreement.
	for _, domain := range []string{
		"evil.com/admin",    // path injection
		"ev/il.com",         // ... which also truncates the host to "ev"
		"ev?il.com",         // query injection
		"evil.com#frag",     // fragment
		"evil.com:8080",     // port selection
		"evil.com@internal", // userinfo, moving the real host to the right
		"[127.0.0.1]",       // domain-literal
		"ev il.com",         // space
		" evil.com",         // leading space
		"evil..com",         // empty label
		"-evil.com",         // label starts with a hyphen
		"evil-.com",         // label ends with a hyphen
		"ev%2Fil.com",       // percent-encoding
		"evil.com\x00",      // NUL
		"",                  // empty
		".",                 //
		"..",                //
	} {
		if got := wkdCandidateURLs("alice", domain); len(got) != 0 {
			t.Errorf("wkdCandidateURLs(%q) = %q, want no candidates", domain, got)
		}
	}
}

// TestWKDCandidateURLsBuildsBothMethodsForValidDomain is the other half of the
// rejection test above: it fails if the domain check is tightened so far that
// ordinary addresses stop resolving. Hyphens, digit-leading labels, deep
// subdomains and punycode are all legitimate and must survive.
func TestWKDCandidateURLsBuildsBothMethodsForValidDomain(t *testing.T) {
	for _, domain := range []string{
		"example.com",
		"mail.example.co.uk",
		"my-host.example.com",
		"123.example.com",
		"xn--bcher-kva.example",
	} {
		urls := wkdCandidateURLs("Joe.Doe", domain)
		if len(urls) != 2 {
			t.Errorf("wkdCandidateURLs(%q) returned %d candidates, want 2 (advanced, direct)", domain, len(urls))
			continue
		}
		// Whatever the method, the request must land on the domain we were
		// asked about, under the well-known prefix, carrying only l=.
		for _, raw := range urls {
			u, err := url.Parse(raw)
			if err != nil {
				t.Errorf("wkdCandidateURLs(%q) produced unparseable %q: %v", domain, raw, err)
				continue
			}
			if u.Scheme != "https" {
				t.Errorf("%q: scheme = %q, want https", raw, u.Scheme)
			}
			if h := u.Hostname(); h != domain && h != "openpgpkey."+domain {
				t.Errorf("%q: host = %q, want %q or openpgpkey.%s", raw, h, domain, domain)
			}
			if u.Port() != "" {
				t.Errorf("%q: unexpected port %q", raw, u.Port())
			}
			if u.User != nil {
				t.Errorf("%q: unexpected userinfo", raw)
			}
			if !strings.HasPrefix(u.Path, "/.well-known/openpgpkey/") {
				t.Errorf("%q: path = %q, want the /.well-known/openpgpkey/ prefix", raw, u.Path)
			}
			if !strings.Contains(u.Path, "/hu/"+wkdHashLocalPart("Joe.Doe")) {
				t.Errorf("%q: path = %q, missing the hashed local-part", raw, u.Path)
			}
			if u.Query().Get("l") != "Joe.Doe" || len(u.Query()) != 1 {
				t.Errorf("%q: query = %q, want exactly l=Joe.Doe", raw, u.RawQuery)
			}
			if u.Fragment != "" {
				t.Errorf("%q: unexpected fragment %q", raw, u.Fragment)
			}
		}
	}
}

func TestFetchWKDKeyDirectMethod(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Bob", "bob@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	// WKD serves the BINARY key. Convert the armored test key to bytes.
	key, err := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	binKey, err := key.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	hu := wkdHashLocalPart("bob")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(binKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	armored, fp, err := fetchWKDKey(context.Background(), "bob@example.com")
	if err != nil {
		t.Fatalf("fetchWKDKey: %v", err)
	}
	if fp != key.GetFingerprint() {
		t.Fatalf("fingerprint = %q, want %q", fp, key.GetFingerprint())
	}
	if !strings.Contains(armored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("expected armored key, got: %q", armored[:min(40, len(armored))])
	}
}

func TestFetchWKDKeyNotFound(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	if _, _, err := fetchWKDKey(context.Background(), "nobody@example.com"); err == nil {
		t.Fatalf("expected error when no key is published")
	}
}
