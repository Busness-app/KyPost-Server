package processor

import (
	"strings"

	"kypost-server/backend/internal/contacts"
)

// harvestAction records what harvestPinAutocryptKey did, for logging/tests.
type harvestAction string

const (
	harvestCreated   harvestAction = "created"   // new contact + key pinned
	harvestPinned    harvestAction = "pinned"    // existing contact had no key
	harvestUpdated   harvestAction = "updated"   // autocrypt->autocrypt, newest wins
	harvestSkipped   harvestAction = "skipped"   // stronger/non-autocrypt key kept
	harvestUnchanged harvestAction = "unchanged" // same autocrypt fingerprint
)

// findContactByEmail returns the first contact carrying email (case-
// insensitive). Mirrors the api package's findContact; duplicated here because
// that one is unexported in a different package/process.
func findContactByEmail(store *contacts.Store, email string) (contacts.Contact, bool) {
	target := strings.ToLower(strings.TrimSpace(email))
	for _, c := range store.List() {
		for _, e := range c.Emails {
			if strings.ToLower(strings.TrimSpace(e.Value)) == target {
				return c, true
			}
		}
	}
	return contacts.Contact{}, false
}

// harvestPinAutocryptKey applies the source-based precedence rule for a
// validated, DKIM-authenticated Autocrypt key. Harvest is the weakest rung: it
// never overrides a non-autocrypt key (manual/qr/wkd/keyserver), fills a gap
// when the contact has no key, creates a DiscoveryCreated contact when none
// exists, and for an existing autocrypt key lets the newest fingerprint win.
func harvestPinAutocryptKey(store *contacts.Store, addr, armored, fingerprint string) (harvestAction, error) {
	c, ok := findContactByEmail(store, addr)
	if !ok {
		_, err := store.Upsert(contacts.Contact{
			FormattedName:     addr,
			Emails:            []contacts.ContactValue{{Value: addr}},
			PGPKey:            armored,
			PGPKeyFingerprint: fingerprint,
			PGPKeySource:      contacts.PGPSourceAutocrypt,
			DiscoveryCreated:  true,
		})
		return harvestCreated, err
	}
	if c.PGPKey == "" {
		c.PGPKey = armored
		c.PGPKeyFingerprint = fingerprint
		c.PGPKeySource = contacts.PGPSourceAutocrypt
		c.PGPKeyVerified = false
		_, err := store.Upsert(c)
		return harvestPinned, err
	}
	if c.PGPKeySource != contacts.PGPSourceAutocrypt {
		return harvestSkipped, nil
	}
	if strings.EqualFold(c.PGPKeyFingerprint, fingerprint) {
		return harvestUnchanged, nil
	}
	c.PGPKey = armored
	c.PGPKeyFingerprint = fingerprint
	c.PGPKeyVerified = false
	_, err := store.Upsert(c)
	return harvestUpdated, err
}
