package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/groups"
	"kypost-server/backend/internal/pgpmail"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/emersion/go-vcard"
	"github.com/emersion/go-webdav"
	"github.com/emersion/go-webdav/carddav"
)

// imServiceCatalog maps our fixed IM/social service codes to the
// X-SERVICE-TYPE param value Apple's own vCard export uses for the same
// service, so importing into iOS/macOS Contacts (and reading its exports)
// round-trips recognizably. Unlisted/"other" codes fall back to
// X-SOCIALPROFILE.
var imServiceCatalog = map[string]string{
	"whatsapp":  "WhatsApp",
	"signal":    "Signal",
	"telegram":  "Telegram",
	"instagram": "Instagram",
	"x":         "Twitter",
	"linkedin":  "LinkedIn",
	"facebook":  "Facebook",
	"mastodon":  "Mastodon",
	"matrix":    "Matrix",
}

var imServiceCatalogReverse = func() map[string]string {
	m := make(map[string]string, len(imServiceCatalog))
	for code, label := range imServiceCatalog {
		m[strings.ToLower(label)] = code
	}
	return m
}()

// davPrefix is the fixed mount point for the CardDAV surface. Address book
// discovery paths (principal, home set, address book, address objects) are
// all built under it per the depth-based resource typing that
// emersion/go-webdav's carddav.Handler expects.
const davPrefix = "/dav"

// handleCardDAV mounts the CardDAV protocol handler for the caller's own
// contacts. It is reached only after withDAVBasicAuth has authenticated the
// request (session cookies are not accepted here — native CardDAV clients
// only speak HTTP Basic Auth). When the request path names a username (i.e.
// everything under davPrefix except the well-known discovery endpoint), it
// must match the authenticated identity, or the request is rejected — this
// keeps a valid app password from one account from being pointed at another
// account's URL and getting a confusing response.
func (s *Server) handleCardDAV(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if rel, cut := strings.CutPrefix(r.URL.Path, davPrefix+"/"); cut {
		segment, _, _ := strings.Cut(rel, "/")
		if segment != "" && segment != ac.Username {
			http.Error(w, "forbidden: address book belongs to a different user", http.StatusForbidden)
			return
		}
	}
	// Cap the request body (PUT, REPORT, ...) the same way the JSON
	// contact-photo upload path does: without this, a PUT with an
	// arbitrarily large body (e.g. a vCard carrying a huge base64 PHOTO data
	// URI) would be fully buffered in memory and base64-decoded with no
	// limit at all.
	r.Body = http.MaxBytesReader(w, r.Body, maxContactPhotoBytes)
	// Pre-scan a card-bearing body for pathological folding before go-webdav's
	// decoder ever sees it.
	//
	// go-vcard unfolds with `l += ...` in a loop, which is quadratic, and it
	// unfolds BEFORE validating, so a malformed card does not bail out early.
	// checkVCardFolding exists for exactly this and had one call site, on the
	// import route. This path cannot reuse it by wrapping the decoder, because
	// the decode happens inside go-webdav and is never called from this repo —
	// so the body has to be scanned and replaced here.
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		if err := checkVCardFolding(body); err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	handler := &carddav.Handler{Backend: &contactsDAVBackend{server: s}, Prefix: davPrefix}
	handler.ServeHTTP(w, r)
}

// contactsDAVBackend adapts contacts.Store to carddav.Backend. It resolves
// the acting user from the AuthContext already injected into the request
// context by withDAVBasicAuth (Backend methods only receive a context.Context,
// not the *http.Request).
type contactsDAVBackend struct {
	server *Server
}

func (b *contactsDAVBackend) userAndStore(ctx context.Context) (AuthContext, *contacts.Store, error) {
	ac, ok := authContextFromContext(ctx)
	if !ok {
		return AuthContext{}, nil, errors.New("missing auth context")
	}
	store, err := b.server.userContactsStore(ac.UserID)
	if err != nil {
		return AuthContext{}, nil, err
	}
	return ac, store, nil
}

func (b *contactsDAVBackend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	ac, ok := authContextFromContext(ctx)
	if !ok {
		return "", errors.New("missing auth context")
	}
	return path.Join(davPrefix, ac.Username) + "/", nil
}

func (b *contactsDAVBackend) AddressBookHomeSetPath(ctx context.Context) (string, error) {
	ac, ok := authContextFromContext(ctx)
	if !ok {
		return "", errors.New("missing auth context")
	}
	return path.Join(davPrefix, ac.Username, "contacts") + "/", nil
}

// addressBookPath is the one, fixed address book every user has. There is no
// multi-address-book support in v1.
func (b *contactsDAVBackend) addressBookPath(ac AuthContext) string {
	return path.Join(davPrefix, ac.Username, "contacts", "default") + "/"
}

func (b *contactsDAVBackend) objectPath(ac AuthContext, uid string) string {
	return path.Join(b.addressBookPath(ac), uid+".vcf")
}

func uidFromObjectPath(p string) string {
	return strings.TrimSuffix(path.Base(p), ".vcf")
}

func (b *contactsDAVBackend) ListAddressBooks(ctx context.Context) ([]carddav.AddressBook, error) {
	ac, ok := authContextFromContext(ctx)
	if !ok {
		return nil, errors.New("missing auth context")
	}
	return []carddav.AddressBook{{
		Path:        b.addressBookPath(ac),
		Name:        "Contacts",
		Description: "KyPost contacts",
	}}, nil
}

func (b *contactsDAVBackend) GetAddressBook(ctx context.Context, p string) (*carddav.AddressBook, error) {
	books, err := b.ListAddressBooks(ctx)
	if err != nil {
		return nil, err
	}
	for _, ab := range books {
		if ab.Path == p {
			return &ab, nil
		}
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("address book not found"))
}

func (b *contactsDAVBackend) CreateAddressBook(ctx context.Context, _ *carddav.AddressBook) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("creating address books is not supported"))
}

func (b *contactsDAVBackend) DeleteAddressBook(ctx context.Context, _ string) error {
	return webdav.NewHTTPError(http.StatusForbidden, errors.New("deleting the address book is not supported"))
}

func (b *contactsDAVBackend) GetAddressObject(ctx context.Context, p string, _ *carddav.AddressDataRequest) (*carddav.AddressObject, error) {
	ac, store, err := b.userAndStore(ctx)
	if err != nil {
		return nil, err
	}
	c, ok, err := store.Get(uidFromObjectPath(p))
	if err != nil {
		return nil, err
	}
	if !ok || c.Deleted {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("contact not found"))
	}
	return &carddav.AddressObject{
		Path:    p,
		ETag:    c.ETag(),
		ModTime: parseContactTime(c.UpdatedAt),
		Card:    b.toVCard(ac.UserID, c),
	}, nil
}

func (b *contactsDAVBackend) ListAddressObjects(ctx context.Context, p string, _ *carddav.AddressDataRequest) ([]carddav.AddressObject, error) {
	ac, store, err := b.userAndStore(ctx)
	if err != nil {
		return nil, err
	}
	list, err := store.List()
	if err != nil {
		return nil, err
	}
	out := make([]carddav.AddressObject, 0, len(list))
	// Photo bytes are inlined as base64 data: URIs, and go-webdav builds the
	// entire MultiStatus in memory before encoding it (its ServeMultiStatus
	// carries a "TODO: streaming"). Contacts may share one photo by content
	// hash — one file on disk, charged to the quota once — so the response
	// could be orders of magnitude larger than anything stored. Budget it.
	inlined := 0
	for _, c := range list {
		card, photoBytes := b.toVCardWithPhotoBudget(ac.UserID, c, inlined < maxInlinedPhotoBytesPerResponse)
		inlined += photoBytes
		out = append(out, carddav.AddressObject{
			Path:    b.objectPath(ac, c.UID),
			ETag:    c.ETag(),
			ModTime: parseContactTime(c.UpdatedAt),
			Card:    card,
		})
	}
	return out, nil
}

// toVCard resolves the per-user side data contactToVCard needs (group names,
// photo bytes) that Contact itself only holds by reference (GroupIDs,
// PhotoRef), then renders the vCard.
func (b *contactsDAVBackend) toVCard(userID string, c contacts.Contact) vcard.Card {
	return b.server.contactToVCardForUser(userID, c)
}

// maxInlinedPhotoBytesPerResponse bounds the photo bytes one multistatus may
// inline. go-webdav buffers the whole response before encoding, and base64
// inflates by ~1.37, so without a budget the peak heap for a single PROPFIND is
// set by the caller's contact count rather than by anything they stored.
const maxInlinedPhotoBytesPerResponse = 32 << 20

// maxValuesPerField bounds how many entries one repeatable vCard field family
// may contribute to a stored contact.
//
// maxCategoriesPerCard already capped CATEGORIES, with a comment noting a
// single 1.49 MB vCard can carry 200,000 of them — but every other repeatable
// field was left unbounded, so the same shape through EMAIL turned a 10 MiB
// import into a permanent multi-megabyte contacts.json that every later read,
// search and write re-parses.
const maxValuesPerField = 64

// appendCappedValue appends v to dst unless dst is already at maxValuesPerField.
func appendCappedValue[T any](dst []T, v T) []T {
	if len(dst) >= maxValuesPerField {
		return dst
	}
	return append(dst, v)
}

// toVCardWithPhotoBudget renders c, inlining its photo only when the caller
// still has budget. Returns the vCard and how many photo bytes it consumed.
func (b *contactsDAVBackend) toVCardWithPhotoBudget(userID string, c contacts.Contact, allowPhoto bool) (vcard.Card, int) {
	if !allowPhoto {
		return b.server.contactToVCardForUser(userID, contactWithoutPhoto(c)), 0
	}
	card := b.server.contactToVCardForUser(userID, c)
	if c.PhotoRef == "" {
		return card, 0
	}
	data, _, ok := b.server.loadContactPhoto(userID, c.PhotoRef)
	if !ok {
		return card, 0
	}
	return card, len(data)
}

// contactWithoutPhoto is c with its photo reference cleared, so rendering it
// resolves no photo bytes at all.
func contactWithoutPhoto(c contacts.Contact) contacts.Contact {
	c.PhotoRef = ""
	return c
}

// contactToVCardForUser resolves a Contact's GroupIDs/PhotoRef references
// against the given user's groups/photo storage and renders the vCard.
// Shared by the CardDAV surface and vCard export.
func (s *Server) contactToVCardForUser(userID string, c contacts.Contact) vcard.Card {
	var groupNames []string
	if len(c.GroupIDs) > 0 {
		if gs, err := s.userGroupsStore(userID); err == nil {
			// One List, then a map lookup per id. Get() re-reads and
			// re-unmarshals the whole groups file every call, so the previous
			// per-id loop re-paid that cost once per group on every PROPFIND
			// and every vCard export — turning an import's one-off expense into
			// a permanent one.
			all, lerr := gs.List()
			if lerr != nil {
				// Render the card without CATEGORIES rather than with a stale
				// group list. A vCard is what a sync client writes back, so a
				// name resolved from an unreadable file would be persisted.
				all = nil
			}
			byID := make(map[string]string, len(c.GroupIDs))
			for _, g := range all {
				byID[g.ID] = g.Name
			}
			for _, id := range c.GroupIDs {
				if name, ok := byID[id]; ok {
					groupNames = append(groupNames, name)
				}
			}
		}
	}
	var photoData []byte
	var photoContentType string
	if c.PhotoRef != "" {
		photoData, photoContentType, _ = s.loadContactPhoto(userID, c.PhotoRef)
	}
	return contactToVCard(c, groupNames, photoData, photoContentType)
}

// contactFromVCardForUser parses an inbound vCard into a Contact, resolving
// CATEGORIES names to GroupIDs (creating groups as needed) and storing an
// inline PHOTO to disk as a PhotoRef, against the given user's storage.
// Shared by the CardDAV surface and vCard import.
func (s *Server) contactFromVCardForUser(userID, uid string, card vcard.Card) contacts.Contact {
	parsed := contactFromVCard(uid, card)
	c := parsed.contact
	if len(parsed.categoryNames) > 0 {
		if gs, err := s.userGroupsStore(userID); err == nil {
			c.GroupIDs = resolveGroupIDsByName(gs, parsed.categoryNames)
		}
	}
	if len(parsed.photoData) > 0 {
		if ref, err := s.storeContactPhoto(userID, parsed.photoData); err == nil {
			c.PhotoRef = ref
		}
	}
	return c
}

// QueryAddressObjects implements the addressbook-query REPORT. v1 does not
// evaluate CARDDAV:filter prop-filters — it returns the full address book
// (a safe superset of any real match set) rather than filtering server-side.
// Clients that rely on server-side filtering will simply receive more
// results than strictly necessary; this is a documented limitation, not a
// correctness bug (see backend/internal/contacts/AGENTS.md).
func (b *contactsDAVBackend) QueryAddressObjects(ctx context.Context, p string, query *carddav.AddressBookQuery) ([]carddav.AddressObject, error) {
	return b.ListAddressObjects(ctx, p, &query.DataRequest)
}

func (b *contactsDAVBackend) PutAddressObject(ctx context.Context, p string, card vcard.Card, opts *carddav.PutAddressObjectOptions) (*carddav.AddressObject, error) {
	ac, store, err := b.userAndStore(ctx)
	if err != nil {
		return nil, err
	}
	uid := uidFromObjectPath(p)

	// Evaluate the If-Match/If-None-Match precondition atomically with the
	// write (UpsertWithPrecondition holds the store's lock across both), so
	// two concurrent PUTs racing the same precondition can't both pass the
	// check and silently clobber each other.
	var precondition contacts.ContactPrecondition
	if opts != nil {
		if opts.IfNoneMatch.IsSet() && opts.IfNoneMatch.IsWildcard() {
			precondition.RequireAbsent = true
		}
		if opts.IfMatch.IsSet() {
			etag, err := opts.IfMatch.ETag()
			if err != nil {
				return nil, webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("etag mismatch"))
			}
			precondition.RequireETag = etag
		}
	}

	updated, err := store.UpsertWithPrecondition(b.server.contactFromVCardForUser(ac.UserID, uid, card), precondition)
	if errors.Is(err, contacts.ErrPreconditionFailed) {
		if precondition.RequireAbsent {
			return nil, webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("contact already exists"))
		}
		return nil, webdav.NewHTTPError(http.StatusPreconditionFailed, errors.New("etag mismatch"))
	}
	if err != nil {
		return nil, err
	}
	return &carddav.AddressObject{
		Path:    b.objectPath(ac, updated.UID),
		ETag:    updated.ETag(),
		ModTime: parseContactTime(updated.UpdatedAt),
		Card:    card,
	}, nil
}

func (b *contactsDAVBackend) DeleteAddressObject(ctx context.Context, p string) error {
	_, store, err := b.userAndStore(ctx)
	if err != nil {
		return err
	}
	removed, err := store.Delete(uidFromObjectPath(p))
	if err != nil {
		return err
	}
	if !removed {
		return webdav.NewHTTPError(http.StatusNotFound, errors.New("contact not found"))
	}
	return nil
}

func parseContactTime(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// contactToVCard renders a Contact as a vCard 4.0 card for CardDAV GET/REPORT
// responses. groupNames/photoData/photoContentType are resolved by the
// caller (toVCard) since Contact itself only holds references (GroupIDs,
// PhotoRef), not the group names or photo bytes.
func contactToVCard(c contacts.Contact, groupNames []string, photoData []byte, photoContentType string) vcard.Card {
	card := make(vcard.Card)
	card.SetValue(vcard.FieldVersion, "4.0")
	card.SetValue(vcard.FieldUID, c.UID)

	fn := strings.TrimSpace(c.FormattedName)
	if fn == "" {
		fn = "Unnamed Contact"
	}
	card.SetValue(vcard.FieldFormattedName, fn)

	if c.GivenName != "" || c.FamilyName != "" || c.MiddleName != "" || c.Prefix != "" || c.Suffix != "" {
		card.SetName(&vcard.Name{
			FamilyName:      c.FamilyName,
			GivenName:       c.GivenName,
			AdditionalName:  c.MiddleName,
			HonorificPrefix: c.Prefix,
			HonorificSuffix: c.Suffix,
		})
	}
	if c.Nickname != "" {
		card.SetValue(vcard.FieldNickname, c.Nickname)
	}
	if c.Org != "" || c.Department != "" {
		orgValue := c.Org
		if c.Department != "" {
			orgValue += ";" + c.Department
		}
		card.SetValue(vcard.FieldOrganization, orgValue)
	}
	if c.Title != "" {
		card.SetValue(vcard.FieldTitle, c.Title)
	}
	if c.Notes != "" {
		card.SetValue(vcard.FieldNote, c.Notes)
	}
	if c.Birthday != "" {
		card.SetValue(vcard.FieldBirthday, c.Birthday)
	}
	for _, e := range c.Emails {
		f := &vcard.Field{Value: e.Value}
		if e.Label != "" {
			f.Params = vcard.Params{vcard.ParamType: []string{e.Label}}
		}
		card.Add(vcard.FieldEmail, f)
	}
	for _, ph := range c.Phones {
		f := &vcard.Field{Value: ph.Value}
		if ph.Label != "" {
			f.Params = vcard.Params{vcard.ParamType: []string{ph.Label}}
		}
		card.Add(vcard.FieldTelephone, f)
	}
	for _, a := range c.Addresses {
		addr := &vcard.Address{
			Field:         &vcard.Field{},
			StreetAddress: a.Street,
			Locality:      a.City,
			Region:        a.Region,
			PostalCode:    a.PostalCode,
			Country:       a.Country,
		}
		if a.Label != "" {
			addr.Params = vcard.Params{vcard.ParamType: []string{a.Label}}
		}
		card.AddAddress(addr)
	}
	if len(groupNames) > 0 {
		card.SetCategories(groupNames)
	}
	if len(photoData) > 0 {
		card.SetValue(vcard.FieldPhoto, "data:"+photoContentType+";base64,"+base64.StdEncoding.EncodeToString(photoData))
	}
	if c.PGPKey != "" {
		card.SetValue(vcard.FieldKey, "data:application/pgp-keys;base64,"+base64.StdEncoding.EncodeToString([]byte(c.PGPKey)))
	}
	for _, im := range c.IMs {
		if serviceLabel, ok := imServiceCatalog[im.Service]; ok {
			card.Add(vcard.FieldIMPP, &vcard.Field{Value: im.Value, Params: vcard.Params{"X-SERVICE-TYPE": []string{serviceLabel}}})
			continue
		}
		label := im.Label
		if label == "" {
			label = "Other"
		}
		card.Add("X-SOCIALPROFILE", &vcard.Field{Value: im.Value, Params: vcard.Params{vcard.ParamType: []string{label}}})
	}
	for _, u := range c.Websites {
		f := &vcard.Field{Value: u.Value}
		if u.Label != "" {
			f.Params = vcard.Params{vcard.ParamType: []string{u.Label}}
		}
		card.Add(vcard.FieldURL, f)
	}
	for _, rel := range c.Relations {
		f := &vcard.Field{Value: rel.Name}
		if rel.Label != "" {
			f.Params = vcard.Params{vcard.ParamType: []string{rel.Label}}
		}
		card.Add(vcard.FieldRelated, f)
	}
	for _, ev := range c.Events {
		if ev.Label == "anniversary" {
			card.SetValue(vcard.FieldAnniversary, ev.Date)
			continue
		}
		label := ev.Label
		if label == "" {
			label = "other"
		}
		card.Add("X-ABDATE", &vcard.Field{Value: ev.Date, Params: vcard.Params{vcard.ParamType: []string{label}}})
	}
	if c.PhoneticGivenName != "" {
		card.SetValue("X-PHONETIC-FIRST-NAME", c.PhoneticGivenName)
	}
	if c.PhoneticFamilyName != "" {
		card.SetValue("X-PHONETIC-LAST-NAME", c.PhoneticFamilyName)
	}
	if c.Pronouns != "" {
		card.SetValue("X-ABPRONOUNS", c.Pronouns)
	}
	for i, cf := range c.CustomFields {
		card.Add(fmt.Sprintf("X-CUSTOM-%d", i+1), &vcard.Field{Value: cf.Value, Params: vcard.Params{vcard.ParamType: []string{cf.Label}}})
	}
	return card
}

// parsedVCardContact is contactFromVCard's result: the Contact fields it can
// populate directly, plus the pieces that need external resolution before
// they can be written onto a Contact — CATEGORIES names need a groups.Store
// lookup to become GroupIDs, and an inline PHOTO data: URI needs to go
// through the same on-disk photo storage as a JSON upload before becoming a
// PhotoRef.
type parsedVCardContact struct {
	contact          contacts.Contact
	categoryNames    []string
	photoData        []byte
	photoContentType string
}

// contactFromVCard maps an incoming vCard (from a CardDAV PUT) onto a
// Contact, assigning uid as the identity regardless of what the card's own
// UID property says — the DAV resource path is authoritative.
func contactFromVCard(uid string, card vcard.Card) parsedVCardContact {
	c := contacts.Contact{UID: uid}
	c.FormattedName = strings.TrimSpace(card.Value(vcard.FieldFormattedName))
	if n := card.Name(); n != nil {
		c.GivenName = n.GivenName
		c.FamilyName = n.FamilyName
		c.MiddleName = n.AdditionalName
		c.Prefix = n.HonorificPrefix
		c.Suffix = n.HonorificSuffix
	}
	c.Nickname = card.Value(vcard.FieldNickname)
	if org := card.Value(vcard.FieldOrganization); org != "" {
		parts := strings.SplitN(org, ";", 2)
		c.Org = parts[0]
		if len(parts) > 1 {
			c.Department = parts[1]
		}
	}
	c.Title = card.Value(vcard.FieldTitle)
	c.Notes = card.Value(vcard.FieldNote)
	c.Birthday = card.Value(vcard.FieldBirthday)

	for _, f := range card[vcard.FieldEmail] {
		c.Emails = appendCappedValue(c.Emails, contacts.ContactValue{Label: f.Params.Get(vcard.ParamType), Value: f.Value})
	}
	for _, f := range card[vcard.FieldTelephone] {
		c.Phones = appendCappedValue(c.Phones, contacts.ContactValue{Label: f.Params.Get(vcard.ParamType), Value: f.Value})
	}
	for _, a := range card.Addresses() {
		label := ""
		if a.Field != nil {
			label = a.Params.Get(vcard.ParamType)
		}
		c.Addresses = appendCappedValue(c.Addresses, contacts.ContactAddress{
			Label:      label,
			Street:     a.StreetAddress,
			City:       a.Locality,
			Region:     a.Region,
			PostalCode: a.PostalCode,
			Country:    a.Country,
		})
	}
	for _, f := range card[vcard.FieldIMPP] {
		service := ""
		if st := f.Params.Get("X-SERVICE-TYPE"); st != "" {
			service = imServiceCatalogReverse[strings.ToLower(st)]
		}
		label := ""
		if service == "" {
			label = f.Params.Get("X-SERVICE-TYPE")
			if label == "" {
				label = f.Params.Get(vcard.ParamType)
			}
		}
		c.IMs = appendCappedValue(c.IMs, contacts.ContactIM{Service: service, Label: label, Value: f.Value})
	}
	for _, f := range card["X-SOCIALPROFILE"] {
		c.IMs = appendCappedValue(c.IMs, contacts.ContactIM{Label: f.Params.Get(vcard.ParamType), Value: f.Value})
	}
	for _, f := range card[vcard.FieldURL] {
		c.Websites = appendCappedValue(c.Websites, contacts.ContactURL{Label: f.Params.Get(vcard.ParamType), Value: f.Value})
	}
	for _, f := range card[vcard.FieldRelated] {
		c.Relations = appendCappedValue(c.Relations, contacts.ContactRelation{Label: f.Params.Get(vcard.ParamType), Name: f.Value})
	}
	if anniv := card.Value(vcard.FieldAnniversary); anniv != "" {
		// appendCappedValue like every sibling: this was the one remaining bare
		// append in this function, and a bound with one hole in it is not a bound.
		c.Events = appendCappedValue(c.Events, contacts.ContactEvent{Label: "anniversary", Date: anniv})
	}
	for _, f := range card["X-ABDATE"] {
		label := f.Params.Get(vcard.ParamType)
		if label == "" {
			label = "other"
		}
		c.Events = appendCappedValue(c.Events, contacts.ContactEvent{Label: label, Date: f.Value})
	}
	c.PhoneticGivenName = card.Value("X-PHONETIC-FIRST-NAME")
	c.PhoneticFamilyName = card.Value("X-PHONETIC-LAST-NAME")
	c.Pronouns = card.Value("X-ABPRONOUNS")
	for k, fields := range card {
		if !strings.HasPrefix(k, "X-CUSTOM-") {
			continue
		}
		for _, f := range fields {
			// Capped like every other repeatable family. This one was missed when
			// maxValuesPerField was introduced, and X-CUSTOM- is unbounded in the
			// number of distinct keys as well as values, so one 6 MB card stored
			// 200,000 entries — re-parsed on every contacts read thereafter,
			// including the poller's Autocrypt harvest inside the shared tick.
			c.CustomFields = appendCappedValue(c.CustomFields, contacts.ContactCustomField{Label: f.Params.Get(vcard.ParamType), Value: f.Value})
		}
	}
	if pgp := card.Value(vcard.FieldKey); pgp != "" {
		armored := pgp
		if data, _ := decodeDataURI(pgp); data != nil {
			armored = string(data)
		}
		// A contact's PGPKey is a trust anchor: it is what outbound mail is
		// encrypted to and what the signature badge is checked against. The two
		// sibling ingest paths, validateDiscoveredKey (WKD) and
		// validateAutocryptKey, both require the key to parse, to be usable, and
		// to carry the address as a User ID; this one stored whatever arrived.
		//
		// Note that pinning does NOT substitute for this: pinPGPKeyFingerprint
		// derives the pin from the supplied key, so keyMatchesPin passes on any
		// value, and an unparseable key yields an empty pin which is accepted by
		// design.
		//
		// This function backs CardDAV pull, CardDAV PUT and vCard import, so
		// validating here covers all three.
		if err := validateContactVCardKey(armored, c.Emails); err != nil {
			c.PGPKey = ""
		} else {
			c.PGPKey = armored
		}
	}

	var photoData []byte
	var photoContentType string
	if photo := card.Value(vcard.FieldPhoto); photo != "" {
		photoData, photoContentType = decodeDataURI(photo)
	}

	if c.FormattedName == "" {
		c.FormattedName = strings.TrimSpace(c.GivenName + " " + c.FamilyName)
	}
	return parsedVCardContact{
		contact:          c,
		categoryNames:    card.Categories(),
		photoData:        photoData,
		photoContentType: photoContentType,
	}
}

// decodeDataURI parses a minimal "data:<contentType>;base64,<payload>" URI —
// the only shape this package ever emits for PHOTO/KEY — returning nil if v
// isn't in that exact form.
func decodeDataURI(v string) (data []byte, contentType string) {
	rest, ok := strings.CutPrefix(v, "data:")
	if !ok {
		return nil, ""
	}
	meta, b64, ok := strings.Cut(rest, ",")
	if !ok {
		return nil, ""
	}
	contentType, _, _ = strings.Cut(meta, ";")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, ""
	}
	return decoded, contentType
}

// maxCategoriesPerCard bounds how many CATEGORIES entries one inbound vCard may
// contribute.
//
// The size limits above it do not bound this: the import cap is 10 MiB of body
// and 5,000 cards, but neither restricts categories *per card*, and a single
// 1.49 MB vCard can carry 200,000 of them. 64 is far more than any real card
// uses — address books organise people into a handful of groups, not hundreds.
const maxCategoriesPerCard = 64

// resolveGroupIDsByName maps CATEGORIES names from an inbound vCard to group
// IDs, creating a group for any name that doesn't already exist so nothing
// from an imported card is silently dropped.
//
// One batched call, not one Upsert per name. Each Upsert takes the file lock,
// reads and unmarshals the whole file, marshals it back and writes it with two
// fsyncs, so the old loop was quadratic in the number of categories — 5,000 on
// a single card measured 32 seconds on tmpfs, against caps that permit far
// more than that.
//
// A store already at its own ceiling does not fail the import: the batch is
// retried with only the names that already exist, so a card's known categories
// still resolve and only genuinely new ones are dropped. Losing a category is
// a much smaller harm than refusing the contact.
func resolveGroupIDsByName(store *groups.Store, names []string) []string {
	if len(names) > maxCategoriesPerCard {
		names = names[:maxCategoriesPerCard]
	}
	ids, err := store.EnsureByName(names)
	if err == nil {
		return ids
	}
	if !errors.Is(err, groups.ErrTooManyGroups) {
		return nil
	}

	existing, err := store.List()
	if err != nil {
		return nil
	}
	known := make(map[string]bool, len(existing))
	for _, g := range existing {
		known[strings.ToLower(g.Name)] = true
	}
	kept := make([]string, 0, len(names))
	for _, name := range names {
		if known[strings.ToLower(strings.TrimSpace(name))] {
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	ids, err = store.EnsureByName(kept)
	if err != nil {
		return nil
	}
	return ids
}

// validateContactVCardKey reports why a vCard KEY value is unusable as a
// contact's PGP trust anchor, or nil.
//
// Mirrors validateDiscoveredKey (WKD) and processor.validateAutocryptKey: the
// key must parse, be neither revoked nor expired, and carry one of the
// contact's own addresses as a User ID. Without the last check a remote CardDAV
// server — which the code elsewhere in this package already treats as hostile
// for size bounds — could attach any key to any contact.
func validateContactVCardKey(armored string, emails []contacts.ContactValue) error {
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return fmt.Errorf("parse contact key: %w", err)
	}
	status, err := pgpmail.CheckKeyStatus(armored)
	if err != nil {
		return err
	}
	if !status.Usable() {
		return errors.New("contact key is revoked or expired")
	}
	entity := key.GetEntity()
	if entity == nil {
		return errors.New("contact key has no entity")
	}
	if len(emails) == 0 {
		// Nothing to bind to. A key on an address-less contact can never be
		// selected for encryption or signature verification anyway, so keeping
		// it would only be a way to smuggle one in ahead of an address.
		return errors.New("contact has no address to bind the key to")
	}
	for _, e := range emails {
		target := strings.ToLower(strings.TrimSpace(e.Value))
		if target == "" {
			continue
		}
		for _, uid := range entity.Identities {
			if strings.ToLower(strings.TrimSpace(uid.UserId.Email)) == target {
				return nil
			}
		}
	}
	return errors.New("contact key does not carry any of the contact's addresses as a user ID")
}
