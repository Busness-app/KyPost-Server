package api

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/groups"

	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"
)

// allowLoopbackOutboundForTest relaxes the SSRF guard (see ssrf_guard.go)
// for the duration of a test so syncCardDAVClient can reach an
// httptest.Server, which always listens on a loopback address AND speaks
// plain http. Production code must never touch outboundIPGuard or
// outboundCardDAVSchemes.
func allowLoopbackOutboundForTest(t *testing.T) {
	t.Helper()
	oldGuard := outboundIPGuard
	outboundIPGuard = func(net.IP) bool { return false }
	oldSchemes := outboundCardDAVSchemes
	outboundCardDAVSchemes = []string{"http", "https"}
	t.Cleanup(func() {
		outboundIPGuard = oldGuard
		outboundCardDAVSchemes = oldSchemes
	})
}

// fakeMultiBookBackend serves two address books for a single fixed user: an
// empty one (listed first, mirroring servers like mailbox.org/SOGo that put
// a "Collected addresses" style book ahead of the personal one) and a second
// one holding the real contact. It exists to prove syncCardDAVClient probes
// every discovered book instead of trusting the server's ordering.
type fakeMultiBookBackend struct {
	prefix string
}

const (
	// fakeUsername mirrors the reported bug's shape: a numeric account
	// segment under the real CardDAV mount ("/carddav/"), not a nicely
	// human-readable one, and not itself the mount point.
	fakeUsername  = "33"
	fakeEmptyPath = "/carddav/33/contacts/empty/"
	fakeMainPath  = "/carddav/33/contacts/main/"
	fakeCardUID   = "remote-card-1"
)

func (b *fakeMultiBookBackend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return path.Join(b.prefix, fakeUsername) + "/", nil
}

func (b *fakeMultiBookBackend) AddressBookHomeSetPath(ctx context.Context) (string, error) {
	return path.Join(b.prefix, fakeUsername, "contacts") + "/", nil
}

func (b *fakeMultiBookBackend) ListAddressBooks(ctx context.Context) ([]carddav.AddressBook, error) {
	return []carddav.AddressBook{
		{Path: fakeEmptyPath, Name: "Collected"},
		{Path: fakeMainPath, Name: "Contacts"},
	}, nil
}

func (b *fakeMultiBookBackend) GetAddressBook(ctx context.Context, p string) (*carddav.AddressBook, error) {
	books, _ := b.ListAddressBooks(ctx)
	for _, ab := range books {
		if ab.Path == p {
			return &ab, nil
		}
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound, nil)
}

func (b *fakeMultiBookBackend) CreateAddressBook(ctx context.Context, _ *carddav.AddressBook) error {
	return webdav.NewHTTPError(http.StatusForbidden, nil)
}

func (b *fakeMultiBookBackend) DeleteAddressBook(ctx context.Context, _ string) error {
	return webdav.NewHTTPError(http.StatusForbidden, nil)
}

func (b *fakeMultiBookBackend) mainCard() vcard.Card {
	card := make(vcard.Card)
	card.SetValue(vcard.FieldVersion, "4.0")
	card.SetValue(vcard.FieldUID, fakeCardUID)
	card.SetValue(vcard.FieldFormattedName, "Remote Person")
	card.Add(vcard.FieldEmail, &vcard.Field{Value: "remote@example.com"})
	return card
}

func (b *fakeMultiBookBackend) ListAddressObjects(ctx context.Context, p string, _ *carddav.AddressDataRequest) ([]carddav.AddressObject, error) {
	if p != fakeMainPath {
		return nil, nil
	}
	return []carddav.AddressObject{{
		Path: fakeMainPath + fakeCardUID + ".vcf",
		ETag: "rev-1",
		Card: b.mainCard(),
	}}, nil
}

func (b *fakeMultiBookBackend) QueryAddressObjects(ctx context.Context, p string, query *carddav.AddressBookQuery) ([]carddav.AddressObject, error) {
	return b.ListAddressObjects(ctx, p, &query.DataRequest)
}

func (b *fakeMultiBookBackend) GetAddressObject(ctx context.Context, p string, _ *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	if p == fakeMainPath+fakeCardUID+".vcf" {
		return &carddav.AddressObject{Path: p, ETag: "rev-1", Card: b.mainCard()}, nil
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound, nil)
}

func (b *fakeMultiBookBackend) PutAddressObject(ctx context.Context, p string, card vcard.Card, opts *carddav.PutAddressObjectOptions) (*carddav.AddressObject, error) {
	return nil, webdav.NewHTTPError(http.StatusForbidden, nil)
}

func (b *fakeMultiBookBackend) DeleteAddressObject(ctx context.Context, p string) error {
	return webdav.NewHTTPError(http.StatusForbidden, nil)
}

// TestSyncCardDAVClientProbesEveryDiscoveredBook guards against two bugs at
// once, using routing that mirrors our real server (and, per the bug report
// against mailbox.org, real third-party ones too): CardDAV is mounted under
// a path prefix ("/carddav/"), not served at the bare domain root, and the
// configured URL is a deeper, account-specific path under that prefix
// ("/carddav/33") rather than the prefix itself.
//
//  1. Discovery must walk up from the configured URL to find the actual
//     mount point ("/carddav/") rather than either trusting the exact
//     configured path (which RFC 6352 current-user-principal discovery
//     rejects here) or jumping straight to the bare domain root (which
//     isn't the CardDAV mount and would wrongly fall through to treating
//     the configured URL as if it were itself an address book).
//  2. Once discovered, the server lists an empty collection before the one
//     holding the actual contact (a real-world ordering seen on servers
//     like mailbox.org/SOGo), and the sync must still end up importing the
//     contact from the second one instead of blindly using the first.
func TestSyncCardDAVClientProbesEveryDiscoveredBook(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	backend := &fakeMultiBookBackend{prefix: "/carddav"}
	handler := &carddav.Handler{Backend: backend, Prefix: "/carddav"}

	mux := http.NewServeMux()
	mux.Handle("/carddav/", handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	store, err := contacts.New(dir)
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	groupsStore, err := groups.New(dir)
	if err != nil {
		t.Fatalf("groups.New: %v", err)
	}

	cfg := carddavClientConfigPayload{
		ServerURL: srv.URL + "/carddav/" + fakeUsername,
		Username:  fakeUsername,
		Password:  "irrelevant",
	}

	imported, updated, addressBookPath, discovered, err := syncCardDAVClient(context.Background(), cfg, store, groupsStore, nil)
	if err != nil {
		t.Fatalf("syncCardDAVClient returned error: %v", err)
	}
	if addressBookPath != fakeMainPath {
		t.Errorf("addressBookPath = %q, want %q (should skip the empty book)", addressBookPath, fakeMainPath)
	}
	if imported != 1 || updated != 0 {
		t.Errorf("imported=%d updated=%d, want imported=1 updated=0", imported, updated)
	}
	if len(discovered) != 2 {
		t.Fatalf("discovered = %d books, want 2 (discovery should have succeeded, not fallen through to the direct-query last resort)", len(discovered))
	}
	if discovered[0].ContactCount != 0 || discovered[1].ContactCount != 1 {
		t.Errorf("discovered counts = %+v, want [0, 1]", discovered)
	}

	list := store.List()
	if len(list) != 1 || list[0].FormattedName != "Remote Person" {
		t.Fatalf("store.List() = %+v, want one contact named Remote Person", list)
	}
	if list[0].UID != "carddav-import-"+fakeCardUID {
		t.Errorf("UID = %q, want namespaced remote UID", list[0].UID)
	}
}

// weakETagMultiStatusResponse is a hand-crafted REPORT response shaped like
// one seen from mailbox.org/SOGo: a weak ETag (`W/"..."`) that does not
// round-trip through strict HTTP-quote parsing. go-webdav's own
// carddav.Client.QueryAddressBook aborts entirely on this (see
// https://github.com/emersion/go-webdav internal.ETag.UnmarshalText), even
// though the address-data underneath is perfectly valid — this is exactly
// the bug fetchAddressBookCards exists to sidestep by never decoding
// DAV:getetag at all.
const weakETagMultiStatusResponse = `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:response>
    <D:href>/carddav/33/contacts/weak-etag-card.vcf</D:href>
    <D:propstat>
      <D:prop>
        <D:getetag>W/"abc123"</D:getetag>
        <C:address-data>BEGIN:VCARD
VERSION:4.0
UID:weak-etag-card
FN:Weak Etag Person
EMAIL:weak@example.com
END:VCARD
</C:address-data>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`

func TestFetchAddressBookCardsToleratesMalformedETag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "REPORT" {
			http.Error(w, "expected REPORT", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte(weakETagMultiStatusResponse))
	}))
	defer srv.Close()

	cards, err := fetchAddressBookCards(context.Background(), http.DefaultClient, srv.URL, "/carddav/33/contacts/")
	if err != nil {
		t.Fatalf("fetchAddressBookCards returned error (should tolerate the weak ETag): %v", err)
	}
	if len(cards) != 1 {
		t.Fatalf("cards = %d, want 1", len(cards))
	}
	if fn := cards[0].Card.Value(vcard.FieldFormattedName); fn != "Weak Etag Person" {
		t.Errorf("FN = %q, want %q", fn, "Weak Etag Person")
	}
}

// TestResolveCardDAVPathPinsHost guards against a credential-exfiltration
// regression: every request built from resolveCardDAVPath's result carries
// this account's CardDAV Basic Auth credentials (see fetchAddressBookCards /
// syncCardDAVClient), so an absolute or protocol-relative p — whether from a
// user-supplied AddressBookPath or, in principle, a value returned by a
// compromised remote server during discovery — must never redirect those
// credentials to a different host than the configured CardDAV server.
func TestResolveCardDAVPathPinsHost(t *testing.T) {
	cases := []struct {
		name     string
		hostRoot string
		path     string
		want     string
	}{
		{"relative path", "https://carddav.example.com", "/dav/contacts/", "https://carddav.example.com/dav/contacts/"},
		{"absolute path same scheme+host", "https://carddav.example.com", "https://carddav.example.com/dav/other/", "https://carddav.example.com/dav/other/"},
		{"absolute URL to a different host is pinned back to hostRoot", "https://carddav.example.com", "http://attacker.example/steal", "https://carddav.example.com/steal"},
		{"protocol-relative host is pinned back to hostRoot", "https://carddav.example.com", "//attacker.example/steal", "https://carddav.example.com/steal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveCardDAVPath(c.hostRoot, c.path)
			if err != nil {
				t.Fatalf("resolveCardDAVPath: %v", err)
			}
			if got != c.want {
				t.Errorf("resolveCardDAVPath(%q, %q) = %q, want %q", c.hostRoot, c.path, got, c.want)
			}
		})
	}
}

// TestCardDAVClientRefusesPlaintextURL pins the https-only rule on the
// outbound CardDAV URL.
//
// Every request to that URL carries the user's address-book password in an
// HTTP Basic header, and outboundIPGuard already refuses loopback and private
// space — so an http:// target is by construction a public internet host
// reached in the clear. This asserts the default value of the production
// variable, NOT behaviour under allowLoopbackOutboundForTest's relaxation,
// which is exactly the widening that would otherwise go unnoticed.
func TestCardDAVClientRefusesPlaintextURL(t *testing.T) {
	if len(outboundCardDAVSchemes) != 1 || outboundCardDAVSchemes[0] != "https" {
		t.Fatalf("outboundCardDAVSchemes = %v, want exactly [https]; widening this puts "+
			"the user's CardDAV password on the wire in the clear", outboundCardDAVSchemes)
	}

	if err := validateOutboundURL("http://carddav.example.com/dav/", outboundCardDAVSchemes...); err == nil {
		t.Error("validateOutboundURL accepted an http:// CardDAV URL, want refusal")
	}
	// A bad scheme must be refused before any DNS resolution decides the
	// outcome, so the check holds for a host that does not resolve either way.
	if err := validateOutboundURL("http://nonexistent.invalid/dav/", outboundCardDAVSchemes...); err == nil {
		t.Error("validateOutboundURL accepted http:// for an unresolvable host, want refusal on scheme alone")
	}
}

// TestSSRFSafeClientBoundsResponseBodies pins a bound the CardDAV client's own
// REPORT path has and its discovery PROPFINDs do not.
//
// go-webdav's internal client decodes a PROPFIND multistatus with
// xml.NewDecoder(resp.Body).Decode(&ms) and no LimitReader — upstream carries a
// TODO saying the response can be quite large. The 16 MiB LimitReader in
// fetchAddressBookCards covers only the REPORT, so the three discovery
// PROPFINDs (repeated per candidate path by the walk-up loop) are unbounded.
// The remote server is user-configured and the SSRF guard permits any public
// host by design, so the size is chosen by whoever runs it.
//
// Bounding at the transport is what covers every go-webdav call site at once,
// including ones added later.
func TestSSRFSafeClientBoundsResponseBodies(t *testing.T) {
	allowLoopbackOutboundForTest(t)

	huge := bytes.Repeat([]byte("A"), maxOutboundResponseBytes+(1<<20))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(huge)
	}))
	defer srv.Close()

	client := newSSRFSafeHTTPClient(30 * time.Second)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err == nil && len(read) > maxOutboundResponseBytes {
		t.Fatalf("read %d bytes from a user-chosen host; the transport must bound "+
			"response bodies at %d", len(read), maxOutboundResponseBytes)
	}
}
