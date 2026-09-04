package api

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Busness-app/kypost-server/backend/internal/contacts"
	"github.com/Busness-app/kypost-server/backend/internal/groups"

	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"
)

// carddavClientConfigPayload is the caller's outbound CardDAV client
// configuration: credentials for an external CardDAV server (e.g. iCloud,
// Nextcloud, Google) that this account should pull contacts from. It is
// encrypted at rest the same way as imapConfigPayload. AddressBookPath is
// discovered once (principal -> home set -> address book) and cached so
// later syncs skip the discovery round trips; the sync-status fields
// (LastSynced*) are informational and rewritten after every sync attempt.
type carddavClientConfigPayload struct {
	ServerURL       string `json:"serverUrl"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	AddressBookPath string `json:"addressBookPath,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`

	LastSyncedAt           string                  `json:"lastSyncedAt,omitempty"`
	LastSyncError          string                  `json:"lastSyncError,omitempty"`
	LastSyncImported       int                     `json:"lastSyncImported,omitempty"`
	LastSyncUpdated        int                     `json:"lastSyncUpdated,omitempty"`
	DiscoveredAddressBooks []discoveredAddressBook `json:"discoveredAddressBooks,omitempty"`
}

// discoveredAddressBook is one address book collection found on the remote
// server during auto-discovery, reported back to the caller so they can see
// what was found and, if the auto-picked one is wrong, paste a different
// path into AddressBookPath to pin it explicitly.
type discoveredAddressBook struct {
	Path         string `json:"path"`
	Name         string `json:"name,omitempty"`
	ContactCount int    `json:"contactCount"`
}

func normalizeCardDAVClientPayload(p carddavClientConfigPayload) carddavClientConfigPayload {
	p.ServerURL = strings.TrimSpace(p.ServerURL)
	p.Username = strings.TrimSpace(p.Username)
	p.Password = strings.TrimSpace(p.Password)
	p.AddressBookPath = strings.TrimSpace(p.AddressBookPath)
	return p
}

func readCardDAVClientConfigPayload(path, keyPath string) (carddavClientConfigPayload, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return carddavClientConfigPayload{}, false, nil
		}
		return carddavClientConfigPayload{}, false, err
	}
	plain, err := decryptEncryptedPayload(b, keyPath)
	if err != nil {
		return carddavClientConfigPayload{}, false, err
	}
	var payload carddavClientConfigPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return carddavClientConfigPayload{}, false, err
	}
	return normalizeCardDAVClientPayload(payload), true, nil
}

func writeCardDAVClientConfigPayload(path, keyPath string, payload carddavClientConfigPayload) error {
	plain, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return writeEncryptedPayload(path, keyPath, plain)
}

// handleContactsCardDAVClientConfig manages the caller's outbound CardDAV
// client credentials: GET reports the stored config (never the password),
// POST (re)saves it, DELETE removes it.
func (s *Server) handleContactsCardDAVClientConfig(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	cfgPath := s.userCardDAVClientConfigPath(ac.UserID)
	switch r.Method {
	case http.MethodGet:
		payload, exists, err := readCardDAVClientConfigPayload(cfgPath, s.imapConfigKeyPath)
		if err != nil {
			http.Error(w, "failed to read carddav client configuration", http.StatusInternalServerError)
			return
		}
		if !exists {
			writeJSON(w, http.StatusOK, map[string]any{"configured": false})
			return
		}
		writeJSON(w, http.StatusOK, cardDAVClientStatusResponse(payload))
	case http.MethodPost:
		var payload carddavClientConfigPayload
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		payload = normalizeCardDAVClientPayload(payload)
		if payload.ServerURL == "" || payload.Username == "" || payload.Password == "" {
			http.Error(w, "serverUrl, username, and password are required", http.StatusBadRequest)
			return
		}
		// https only. Every request to this URL carries the user's address-book
		// password in an HTTP Basic header, and validateOutboundURL refuses
		// private and loopback addresses — so an http:// target here is, by
		// construction, a PUBLIC internet host reached in the clear. There is no
		// deployment in which that combination is what the user wanted.
		// (newSSRFSafeHTTPClient already refuses an https->http redirect
		// downgrade for the same reason; allowing the caller to simply start at
		// http made that guard decorative.)
		if err := validateOutboundURL(payload.ServerURL, outboundCardDAVSchemes...); err != nil {
			// Constant: the detail named the resolved private address and the
			// resolver, turning this into an internal-network oracle for any
			// authenticated user. Same treatment as the push-endpoint path.
			s.logger.Info("carddav server url refused", "user_id", ac.UserID, "error", err.Error())
			http.Error(w, "serverUrl is not reachable", http.StatusBadRequest)
			return
		}
		payload.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

		if err := writeCardDAVClientConfigPayload(cfgPath, s.imapConfigKeyPath, payload); err != nil {
			http.Error(w, "failed to save carddav client configuration", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, cardDAVClientStatusResponse(payload))
	case http.MethodDelete:
		if err := os.Remove(cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			http.Error(w, "failed to remove carddav client configuration", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "configured": false})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func cardDAVClientStatusResponse(payload carddavClientConfigPayload) map[string]any {
	return map[string]any{
		"configured":             true,
		"serverUrl":              payload.ServerURL,
		"username":               payload.Username,
		"addressBookPath":        payload.AddressBookPath,
		"updatedAt":              payload.UpdatedAt,
		"lastSyncedAt":           payload.LastSyncedAt,
		"lastSyncError":          payload.LastSyncError,
		"lastSyncImported":       payload.LastSyncImported,
		"lastSyncUpdated":        payload.LastSyncUpdated,
		"discoveredAddressBooks": payload.DiscoveredAddressBooks,
	}
}

// handleContactsCardDAVClientSync pulls the caller's address book down from
// the configured external CardDAV server now, upserting every remote card
// into the caller's local contacts.Store. From there the existing mobile
// sync endpoint (handleContactsSync) and CardDAV server surface pick the
// imported contacts up exactly like any locally-created one — this handler
// only ever reads from the remote server, never writes back to it.
func (s *Server) handleContactsCardDAVClientSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	cfgPath := s.userCardDAVClientConfigPath(ac.UserID)
	payload, exists, err := readCardDAVClientConfigPayload(cfgPath, s.imapConfigKeyPath)
	if err != nil {
		http.Error(w, "failed to read carddav client configuration", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "carddav client is not configured", http.StatusBadRequest)
		return
	}
	store, err := s.userContactsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	groupsStore, err := s.userGroupsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open groups store", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	storePhoto := func(data []byte) (string, error) { return s.storeContactPhoto(ac.UserID, data) }
	imported, updated, addressBookPath, discovered, syncErr := syncCardDAVClient(ctx, payload, store, groupsStore, storePhoto)

	payload.LastSyncedAt = time.Now().UTC().Format(time.RFC3339)
	if discovered != nil {
		payload.DiscoveredAddressBooks = discovered
	}
	if syncErr != nil {
		payload.LastSyncError = syncErr.Error()
	} else {
		payload.LastSyncError = ""
		payload.LastSyncImported = imported
		payload.LastSyncUpdated = updated
		if addressBookPath != "" {
			payload.AddressBookPath = addressBookPath
		}
	}
	// The sync outcome is persisted even when the sync failed, so the UI can
	// show the last error without a separate status endpoint — but the write
	// is not best-effort. It carries the discovered address-book path, the
	// timestamp and the counters, so a discarded failure means the next sync
	// repeats discovery and re-imports while the UI reports a success whose
	// state was never recorded.
	persistErr := writeCardDAVClientConfigPayload(cfgPath, s.imapConfigKeyPath, payload)
	if persistErr != nil {
		s.logger.Error("failed to persist carddav client sync state",
			"user_id", ac.UserID, "error", persistErr.Error())
	}

	if syncErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": syncErr.Error(), "discoveredAddressBooks": discovered})
		return
	}
	if persistErr != nil {
		http.Error(w, "contacts synchronized but sync state could not be saved", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                     true,
		"imported":               imported,
		"updated":                updated,
		"addressBookPath":        addressBookPath,
		"syncedAt":               payload.LastSyncedAt,
		"discoveredAddressBooks": discovered,
	})
}

// remoteCard is one vCard resource fetched from an external CardDAV server,
// stripped down to exactly what syncCardDAVClient needs.
//
// It is fetched with a hand-rolled, ETag-tolerant REPORT request rather than
// go-webdav's carddav.Client.QueryAddressBook: that helper unconditionally
// tries to decode each response's DAV:getetag property, and some real-world
// servers (seen on mailbox.org/SOGo) emit ETags that don't round-trip
// through Go's strict HTTP-quote parsing (e.g. weak validators like
// `W/"..."`), which aborts the *entire* fetch even though every vCard body
// underneath is perfectly valid. Sync only ever reads forward into our own
// store — it never makes conditional requests back — so the ETag was never
// used for anything here, and skipping it entirely sidesteps the bug rather
// than working around it.
type remoteCard struct {
	Path string
	Card vcard.Card
}

// addressbookQueryReportBody is a minimal CardDAV REPORT body (RFC 6352
// §8.6) requesting every card in the target collection: an empty
// C:filter test="anyof" matches everything, and only C:address-data is
// requested (deliberately omitting D:getetag, see remoteCard).
const addressbookQueryReportBody = `<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <C:address-data/>
  </D:prop>
  <C:filter test="anyof"/>
</C:addressbook-query>`

type davMultiStatus struct {
	XMLName   xml.Name      `xml:"DAV: multistatus"`
	Responses []davResponse `xml:"DAV: response"`
}

type davResponse struct {
	Href      string        `xml:"DAV: href"`
	PropStats []davPropStat `xml:"DAV: propstat"`
}

type davPropStat struct {
	Prop davProp `xml:"DAV: prop"`
}

type davProp struct {
	AddressData string `xml:"urn:ietf:params:xml:ns:carddav address-data"`
}

// resolveCardDAVPath resolves p (an absolute or relative resource path, as
// returned by address book discovery or configured directly) against
// hostRoot, producing a full request URL. The result's scheme/host are
// always pinned to hostRoot's — p only ever contributes path/query/fragment
// — because p can be a user-supplied AddressBookPath (or, in principle, a
// value smuggled back from a compromised remote server during discovery),
// and every request built from it carries this account's CardDAV Basic Auth
// credentials (see syncCardDAVClient); without pinning, an absolute p like
// "http://attacker.example/steal" would silently redirect those credentials
// to an arbitrary host that validateOutboundURL never gets a chance to check.
func resolveCardDAVPath(hostRoot, p string) (string, error) {
	base, err := url.Parse(hostRoot)
	if err != nil {
		return "", err
	}
	ref, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	resolved := base.ResolveReference(ref)
	resolved.Scheme = base.Scheme
	resolved.Host = base.Host
	return resolved.String(), nil
}

// fetchAddressBookCards issues a minimal addressbook-query REPORT against
// path (resolved against hostRoot) and returns every vCard found. Entries
// whose address-data fails to parse are skipped rather than aborting the
// whole fetch, so one malformed remote card can't block importing the rest.
func fetchAddressBookCards(ctx context.Context, httpClient webdav.HTTPClient, hostRoot, path string) ([]remoteCard, error) {
	target, err := resolveCardDAVPath(hostRoot, path)
	if err != nil {
		return nil, fmt.Errorf("resolve address book url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "REPORT", target, strings.NewReader(addressbookQueryReportBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("Depth", "1")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var ms davMultiStatus
	if err := xml.Unmarshal(body, &ms); err != nil {
		return nil, fmt.Errorf("decode multistatus response: %w", err)
	}

	cards := make([]remoteCard, 0, len(ms.Responses))
	for _, r := range ms.Responses {
		var raw string
		for _, ps := range r.PropStats {
			if strings.TrimSpace(ps.Prop.AddressData) != "" {
				raw = ps.Prop.AddressData
				break
			}
		}
		if raw == "" {
			continue
		}
		// Same quadratic-unfolding guard the import route applies. The body is
		// fully buffered above before parsing, so the 45s context deadline set
		// by the caller is never consulted during the decode — a heavily folded
		// card from a user-configured server would run to completion whatever
		// the deadline says.
		if err := checkVCardFolding([]byte(raw)); err != nil {
			continue
		}
		card, err := vcard.NewDecoder(strings.NewReader(raw)).Decode()
		if err != nil {
			continue
		}
		cards = append(cards, remoteCard{Path: r.Href, Card: card})
	}
	return cards, nil
}

// cardDAVHostRoot returns the bare scheme+host root ("https://host/") of a
// CardDAV server URL, discarding any path component. Used as a client base
// for resolving address-book-relative paths (which are always absolute on
// the host, regardless of which discovery candidate found them).
func cardDAVHostRoot(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	root := url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}
	return root.String(), nil
}

// cardDAVURLPath returns just the path component of a CardDAV server URL,
// for use as a resource path relative to a client rooted at the same host.
func cardDAVURLPath(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if u.Path == "" {
		return "/", nil
	}
	return u.Path, nil
}

// cardDAVDiscoveryCandidates returns endpoints to try discovery against, from
// most to least specific: the URL as configured, then each ancestor path one
// segment at a time, down to the bare scheme+host root.
//
// This matters because CardDAV discovery (current-user-principal) only
// resolves correctly when run against a server's actual DAV mount point —
// and a user-supplied URL is often a deeper, account-specific path (e.g. an
// address someone copied while already logged into their account, like
// ".../carddav/33") that isn't itself the mount point (which might be
// ".../carddav/", one level up). Walking up one segment at a time finds that
// mount point without assuming it's the bare domain root, which many
// providers don't use for CardDAV at all.
func cardDAVDiscoveryCandidates(rawURL string) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	candidates := []string{u.String()}

	p := u.Path
	for {
		trimmed := strings.TrimRight(p, "/")
		idx := strings.LastIndex(trimmed, "/")
		if idx < 0 {
			break
		}
		p = trimmed[:idx+1]
		next := *u
		next.Path = p
		candidates = append(candidates, next.String())
		if p == "/" {
			break
		}
	}
	if p != "/" {
		root := *u
		root.Path = "/"
		candidates = append(candidates, root.String())
	}
	return candidates, nil
}

// discoverAddressBooksFrom runs the full RFC 6352 discovery chain (current
// user principal -> address book home set -> address books) starting at
// endpoint.
func discoverAddressBooksFrom(ctx context.Context, httpClient webdav.HTTPClient, endpoint string) ([]carddav.AddressBook, error) {
	client, err := carddav.NewClient(httpClient, endpoint)
	if err != nil {
		return nil, err
	}
	principal, err := client.FindCurrentUserPrincipal(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover current user principal: %w", err)
	}
	homeSet, err := client.FindAddressBookHomeSet(ctx, principal)
	if err != nil {
		return nil, fmt.Errorf("discover address book home set: %w", err)
	}
	books, err := client.FindAddressBooks(ctx, homeSet)
	if err != nil {
		return nil, fmt.Errorf("discover address books: %w", err)
	}
	if len(books) == 0 {
		return nil, errors.New("no address books found on remote server")
	}
	return books, nil
}

// syncCardDAVClient connects to the external CardDAV server described by cfg,
// resolves its address book, and upserts every card it finds into store.
//
// When cfg.AddressBookPath is already cached from a previous sync (or was
// explicitly pinned by the caller), that exact collection is queried
// directly. Otherwise it discovers the account's address books:
//
//  1. Try discovery starting at the exact URL the caller configured.
//  2. If that fails, walk up the URL one path segment at a time toward the
//     bare scheme+host root, retrying discovery at each level — servers only
//     resolve current-user-principal correctly at their actual DAV mount
//     point, and a user-supplied URL is often a deeper, account-specific
//     path under that mount (e.g. ".../carddav/33") rather than the mount
//     itself (".../carddav/"), which can otherwise silently resolve to the
//     wrong account/collection rather than erroring.
//  3. If discovery fails outright, fall back to treating the configured URL
//     itself as the exact address book collection (some providers document
//     that directly instead of a discovery root).
//
// When discovery succeeds, every returned address book is probed — a single
// account commonly has more than one collection (a personal book alongside
// shared/collected/GAL ones) — and the first one that actually contains
// contacts is used rather than trusting the server's ordering. discovered
// reports every collection found (with its contact count) so the caller can
// see what was found and pin a specific path if the auto-pick is still
// wrong.
// maxRemoteCardsPerSync bounds one pull from a user-configured CardDAV server,
// mirroring maxContactsSyncChanges on the mobile-sync path.
const maxRemoteCardsPerSync = 5000

func syncCardDAVClient(ctx context.Context, cfg carddavClientConfigPayload, store *contacts.Store, groupsStore *groups.Store, storePhoto func([]byte) (string, error)) (imported, updated int, addressBookPath string, discovered []discoveredAddressBook, err error) {
	// https only — see the matching check in the POST handler. This one also
	// catches a config written before that check existed, so an install that
	// already stored an http:// URL stops syncing credentials in the clear
	// rather than being grandfathered into it.
	//
	// The reason is not wrapped in: this error reaches the caller both in the
	// sync response and persisted in LastSyncError, and validateOutboundURL's
	// text names the resolved private address and the resolver.
	if verr := validateOutboundURL(cfg.ServerURL, outboundCardDAVSchemes...); verr != nil {
		return 0, 0, "", nil, errors.New("refusing to sync: the configured server URL is not reachable")
	}
	httpClient := newSSRFSafeHTTPClient(30 * time.Second)
	authed := webdav.HTTPClientWithBasicAuth(httpClient, cfg.Username, cfg.Password)
	hostRoot, err := cardDAVHostRoot(cfg.ServerURL)
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("parse server url: %w", err)
	}
	var cards []remoteCard
	addressBookPath = cfg.AddressBookPath
	if addressBookPath != "" {
		cards, err = fetchAddressBookCards(ctx, authed, hostRoot, addressBookPath)
		if err != nil {
			return 0, 0, addressBookPath, nil, fmt.Errorf("fetch address book contents: %w", err)
		}
	} else {
		candidates, cerr := cardDAVDiscoveryCandidates(cfg.ServerURL)
		if cerr != nil {
			return 0, 0, "", nil, fmt.Errorf("parse server url: %w", cerr)
		}
		var books []carddav.AddressBook
		var discoverErr error
		for _, candidate := range candidates {
			books, discoverErr = discoverAddressBooksFrom(ctx, authed, candidate)
			if discoverErr == nil {
				break
			}
		}
		if discoverErr != nil {
			// Last resort: maybe the configured URL already *is* the exact
			// address book collection.
			directPath, perr := cardDAVURLPath(cfg.ServerURL)
			if perr != nil {
				return 0, 0, "", nil, fmt.Errorf("discover address books: %w", discoverErr)
			}
			fetched, qerr := fetchAddressBookCards(ctx, authed, hostRoot, directPath)
			if qerr != nil {
				return 0, 0, "", nil, fmt.Errorf("discover address books: %w", discoverErr)
			}
			addressBookPath = directPath
			cards = fetched
		} else {
			discovered = make([]discoveredAddressBook, len(books))
			perBookCards := make([][]remoteCard, len(books))
			chosen := 0
			foundNonEmpty := false
			for i, b := range books {
				fetched, qerr := fetchAddressBookCards(ctx, authed, hostRoot, b.Path)
				count := 0
				if qerr == nil {
					count = len(fetched)
					perBookCards[i] = fetched
				}
				discovered[i] = discoveredAddressBook{Path: b.Path, Name: b.Name, ContactCount: count}
				if qerr == nil && count > 0 && !foundNonEmpty {
					chosen = i
					foundNonEmpty = true
				}
			}
			addressBookPath = books[chosen].Path
			cards = perBookCards[chosen]
		}
	}

	// Bound the remote address book. Each Upsert re-reads and rewrites the whole
	// contacts file with two fsyncs, so the loop is quadratic in card count —
	// and the attacker supplies the server, so nothing else bounded it. At the
	// 16 MiB response limit that was hours of shared-volume I/O per request.
	if len(cards) > maxRemoteCardsPerSync {
		return imported, updated, addressBookPath, discovered, fmt.Errorf("remote address book too large: %d cards (limit %d)", len(cards), maxRemoteCardsPerSync)
	}

	for _, c := range cards {
		// Honour the caller's deadline. The handler builds a 45s context and
		// this loop never consulted it, so a client disconnect left the work
		// running to completion regardless.
		if err := ctx.Err(); err != nil {
			return imported, updated, addressBookPath, discovered, err
		}
		uid := remoteContactUID(c)
		_, existed, err := store.Get(uid)
		if err != nil {
			return imported, updated, addressBookPath, discovered, fmt.Errorf("read contact %s: %w", uid, err)
		}
		parsed := contactFromVCard(uid, c.Card)
		newContact := parsed.contact
		if len(parsed.categoryNames) > 0 && groupsStore != nil {
			newContact.GroupIDs = resolveGroupIDsByName(groupsStore, parsed.categoryNames)
		}
		if len(parsed.photoData) > 0 && storePhoto != nil {
			if ref, err := storePhoto(parsed.photoData); err == nil {
				newContact.PhotoRef = ref
			}
		}
		if _, err := store.Upsert(newContact); err != nil {
			return imported, updated, addressBookPath, discovered, fmt.Errorf("save contact %s: %w", uid, err)
		}
		if existed {
			updated++
		} else {
			imported++
		}
	}
	return imported, updated, addressBookPath, discovered, nil
}

// remoteContactUID derives the local store UID for a card pulled from an
// external CardDAV server: the vCard's own UID when it has one, so re-syncing
// updates the same local contact instead of duplicating it, or a stable hash
// of its resource path otherwise. Namespaced so it can never collide with a
// UUID assigned to a locally-created contact.
func remoteContactUID(c remoteCard) string {
	if uid := strings.TrimSpace(c.Card.Value(vcard.FieldUID)); uid != "" {
		return "carddav-import-" + uid
	}
	sum := sha1.Sum([]byte(c.Path))
	return "carddav-import-" + hex.EncodeToString(sum[:])
}
