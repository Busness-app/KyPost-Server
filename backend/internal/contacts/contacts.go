// Package contacts implements the per-user address book: a local, CardDAV-
// syncable contact list stored as a sibling file next to state.json and
// decisions.json in each user's state directory.
package contacts

import "fmt"

const (
	PGPSourceManual    = "manual"
	PGPSourceQR        = "qr"
	PGPSourceWKD       = "wkd"
	PGPSourceKeyserver = "keyserver"
)

func etagForRev(rev int64) string {
	return fmt.Sprintf("rev-%d", rev)
}

// Contact is one address book entry. UID is the stable CardDAV/vCard
// identity (also the DAV resource name); Rev is a per-user monotonic
// revision bumped on every mutation, and is the single mechanism behind
// both the CardDAV ETag and the mobile sync cursor.
type Contact struct {
	UID       string `json:"uid"`
	Rev       int64  `json:"rev"`
	Deleted   bool   `json:"deleted,omitempty"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`

	// IsSelf marks this as the caller's own contact card — the (at most
	// one, enforced by Store.SetSelf) contact whose fields
	// api.handlePGPQRKey includes in the PGP QR key-exchange response.
	IsSelf bool `json:"isSelf,omitempty"`

	FormattedName string           `json:"fn"`
	GivenName     string           `json:"givenName,omitempty"`
	FamilyName    string           `json:"familyName,omitempty"`
	MiddleName    string           `json:"middleName,omitempty"`
	Prefix        string           `json:"prefix,omitempty"`
	Suffix        string           `json:"suffix,omitempty"`
	Nickname      string           `json:"nickname,omitempty"`
	Org           string           `json:"org,omitempty"`
	Title         string           `json:"title,omitempty"`
	Emails        []ContactValue   `json:"emails,omitempty"`
	Phones        []ContactValue   `json:"phones,omitempty"`
	Addresses     []ContactAddress `json:"addresses,omitempty"`
	Notes         string           `json:"notes,omitempty"`
	Birthday      string           `json:"birthday,omitempty"` // YYYY-MM-DD

	PhotoRef           string               `json:"photoRef,omitempty"` // "<sha256hex>.<ext>", servable filename under contact-photos/
	GroupIDs           []string             `json:"groupIDs,omitempty"`
	PGPKey             string               `json:"pgpKey,omitempty"`            // opaque armored ASCII public key text
	PGPKeySource       string               `json:"pgpKeySource,omitempty"`      // manual|qr|wkd|keyserver
	PGPKeyFingerprint  string               `json:"pgpKeyFingerprint,omitempty"` // TOFU pin (first-seen fingerprint)
	PGPKeyVerified     bool                 `json:"pgpKeyVerified,omitempty"`    // user eyeballed the fingerprint / came via QR
	IMs                []ContactIM          `json:"ims,omitempty"`
	Websites           []ContactURL         `json:"websites,omitempty"`
	Relations          []ContactRelation    `json:"relations,omitempty"`
	Events             []ContactEvent       `json:"events,omitempty"` // anniversary, custom dates — Birthday stays a separate field
	PhoneticGivenName  string               `json:"phoneticGivenName,omitempty"`
	PhoneticFamilyName string               `json:"phoneticFamilyName,omitempty"`
	Department         string               `json:"department,omitempty"`
	CustomFields       []ContactCustomField `json:"customFields,omitempty"`
	Pronouns           string               `json:"pronouns,omitempty"`

	// Server-side-only provenance from deduplication. MergedUIDs lists the
	// UIDs a survivor absorbed; MergedInto points a loser's tombstone at the
	// survivor it was folded into. Both ride existing CardDAV/mobile sync as
	// plain JSON; clients that don't understand them ignore them.
	MergedUIDs []string `json:"mergedUIDs,omitempty"`
	MergedInto string   `json:"mergedInto,omitempty"`
}

// ETag is the CardDAV entity tag / mobile-sync change marker for this
// revision of the contact. It is derived from Rev rather than stored, so
// there is exactly one source of truth for "has this changed".
func (c Contact) ETag() string {
	return etagForRev(c.Rev)
}

type ContactValue struct {
	Label string `json:"label,omitempty"` // "home", "work", "mobile", etc.
	Value string `json:"value"`
}

type ContactAddress struct {
	Label      string `json:"label,omitempty"`
	Street     string `json:"street,omitempty"`
	City       string `json:"city,omitempty"`
	Region     string `json:"region,omitempty"`
	PostalCode string `json:"postalCode,omitempty"`
	Country    string `json:"country,omitempty"`
}

// ContactIM is one IM/social-media identity. Service is a code from a fixed
// catalog (see the frontend's IM service list — "whatsapp", "signal",
// "telegram", "instagram", "x", "linkedin", "facebook", "mastodon",
// "matrix") or "" for the generic "Other" case, in which case Label carries
// the user-supplied service name.
type ContactIM struct {
	Service string `json:"service,omitempty"`
	Label   string `json:"label,omitempty"`
	Value   string `json:"value"`
}

// ContactURL is one website entry (vCard URL property). Label is a
// free-text qualifier ("homepage", "blog", "work"), not a fixed vocabulary.
type ContactURL struct {
	Label string `json:"label,omitempty"`
	Value string `json:"value"`
}

// ContactRelation is one named relationship (spouse, manager, etc.). Name is
// free text — it does not link to another Contact record.
type ContactRelation struct {
	Label string `json:"label,omitempty"`
	Name  string `json:"name"`
}

// ContactEvent is a date beyond Birthday (anniversary, or a custom-labeled
// date), sharing Birthday's YYYY-MM-DD convention.
type ContactEvent struct {
	Label string `json:"label,omitempty"`
	Date  string `json:"date"`
}

// ContactCustomField is a free-form label/value pair, an escape hatch for
// anything imported from a device contact that doesn't fit a typed field.
type ContactCustomField struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// tombstone clears every PII-bearing field, keeping only the identity and
// bookkeeping fields, so a deleted contact doesn't leak its data forever in
// the sync history.
func (c *Contact) tombstone() {
	c.Deleted = true
	c.FormattedName = ""
	c.GivenName = ""
	c.FamilyName = ""
	c.MiddleName = ""
	c.Prefix = ""
	c.Suffix = ""
	c.Nickname = ""
	c.Org = ""
	c.Title = ""
	c.Emails = nil
	c.Phones = nil
	c.Addresses = nil
	c.Notes = ""
	c.Birthday = ""
	c.PhotoRef = ""
	c.GroupIDs = nil
	c.PGPKey = ""
	c.IMs = nil
	c.Websites = nil
	c.Relations = nil
	c.Events = nil
	c.PhoneticGivenName = ""
	c.PhoneticFamilyName = ""
	c.Department = ""
	c.CustomFields = nil
	c.Pronouns = ""
	c.IsSelf = false
	c.MergedUIDs = nil
	// MergedInto is intentionally preserved: a merge tombstones the loser and
	// then records which survivor it was folded into.
}
