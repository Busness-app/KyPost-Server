package processor

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpautocrypt"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
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

// authenticatedForContact reports whether storing a key proven for addr on
// contact c stays within what that proof covers.
//
// True when the contact carries only addr (nothing else can inherit the key),
// or when addr is the contact's primary address — the one a record-wide key is
// legitimately about. False for a secondary address on a multi-address card,
// where a record-wide write would silently authorize the key for the other
// addresses too.
func authenticatedForContact(c contacts.Contact, addr string) bool {
	target := strings.ToLower(strings.TrimSpace(addr))
	seen := map[string]bool{}
	for _, e := range c.Emails {
		v := strings.ToLower(strings.TrimSpace(e.Value))
		if v != "" {
			seen[v] = true
		}
	}
	if len(seen) <= 1 {
		return true
	}
	for _, e := range c.Emails {
		if v := strings.ToLower(strings.TrimSpace(e.Value)); v != "" {
			return v == target
		}
	}
	return false
}

// harvestPinAutocryptKey applies the source-based precedence rule for a
// validated, DKIM-authenticated Autocrypt key. Harvest is the weakest rung: it
// never overrides a non-autocrypt key (manual/qr/wkd/keyserver), fills a gap
// when the contact has no key, creates a DiscoveryCreated contact when none
// exists, and for an existing autocrypt key lets the newest fingerprint win.
func harvestPinAutocryptKey(store *contacts.Store, addr, armored, fingerprint string) (harvestAction, error) {
	c, ok := findContactByEmail(store, addr)
	if ok && !authenticatedForContact(c, addr) {
		// DKIM proved control of `addr` and of nothing else. The key, however,
		// is stored on the contact RECORD, and findContact,
		// findContactByEmail and contactBindsAddress all match ANY address on
		// a contact — so writing it here would authorize this key for
		// addresses whose domains never signed anything.
		//
		// Concretely: a contact card carrying bob@example.com plus a lapsed
		// bob@old-domain.example lets whoever acquires the lapsed domain
		// become the encryption target for bob@example.com. That is a
		// confidentiality break, not just a forged signature badge, and the
		// newest-fingerprint-wins branch below means it REPLACES a
		// legitimately harvested key rather than only filling a gap.
		//
		// The principled fix is to bind a harvested key to the address it was
		// authenticated for rather than to the record; the data model has no
		// per-address key slot yet (ContactValue is {Label, Value}), so until
		// it does, refuse the cases where record-wide storage would overreach.
		// A single-address contact cannot overreach, and neither can the
		// contact's own primary address.
		return harvestSkipped, nil
	}
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
		_, err := store.UpsertWithPrecondition(c, contacts.ContactPrecondition{RequireETag: c.ETag()})
		if errors.Is(err, contacts.ErrPreconditionFailed) {
			// The contact changed between our read and our write (e.g. the
			// api process pinned a key). Abort rather than clobber it; the
			// next poll tick re-evaluates.
			return harvestSkipped, nil
		}
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
	_, err := store.UpsertWithPrecondition(c, contacts.ContactPrecondition{RequireETag: c.ETag()})
	if errors.Is(err, contacts.ErrPreconditionFailed) {
		// The contact changed between our read and our write (e.g. the api
		// process pinned a key). Abort rather than clobber it; the next poll
		// tick re-evaluates.
		return harvestSkipped, nil
	}
	return harvestUpdated, err
}

// verifyAutocryptDKIM is the DKIM gate for harvesting, a package var so tests
// can substitute a deterministic result instead of standing up real DKIM
// crypto + DNS (the crypto itself is covered in
// internal/adapters/imap/dkim_verify_test.go). Same test-seam idiom as
// sendRejectionNotice in poller.go.
// It checks that the signature actually covers the Autocrypt header, not
// merely that the message carries some valid signature from the right domain.
// A DKIM pass says nothing about a header the signer never included in h= —
// and no ordinary sender signs Autocrypt — so the previous gate could be
// satisfied by replaying any genuinely signed message from the target domain
// with one Autocrypt header stapled on. DMARC still passes for such a replay,
// because the original signature is untouched. The header must therefore be
// inside the signed, non-duplicated set, or the "the signing domain vouches
// for this key" claim this gate exists to make is not one we can make.
var verifyAutocryptDKIM = func(raw []byte, domain string) bool {
	return imapadapter.VerifyDKIMCoversHeader(raw, domain, "Autocrypt")
}

// autocryptHarvestConfig loads the per-user harvest gate once per tick:
// harvesting is enabled only when StoreDiscoveredKeys is on, and returns the
// suppressed-address set to skip. Best-effort: any load error disables
// harvesting for this tick.
func (p *Poller) autocryptHarvestConfig(userID string) (bool, map[string]bool) {
	settings, err := pgpdiscovery.Load(p.userStateDir(userID))
	if err != nil || !settings.StoreDiscoveredKeys {
		return false, nil
	}
	suppressed, err := pgpdiscovery.SuppressedSet(p.userStateDir(userID))
	if err != nil {
		suppressed = nil
	}
	return true, suppressed
}

// splitHeaderLine splits a "Field-Name: value" header line (as returned by
// FetchHeaderFields) into its name and value.
func splitHeaderLine(line string) (name, value string) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", strings.TrimSpace(line)
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
}

// parseFromAddress extracts the lowercased addr-spec from a From header value
// (which may be "Display Name <addr>" or a bare address).
func parseFromAddress(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if a, err := mail.ParseAddress(value); err == nil {
		return strings.ToLower(strings.TrimSpace(a.Address))
	}
	v := strings.ToLower(strings.TrimSpace(value))
	if strings.Contains(v, "@") {
		return v
	}
	return ""
}

// validateAutocryptKey parses harvested binary keydata and confirms it is safe
// to auto-use: usable (not revoked/expired) and carrying addr as a UID.
// Mirrors api.validateDiscoveredKey (unexported, different package).
func validateAutocryptKey(keydata []byte, addr string) (armored, fingerprint string, err error) {
	key, err := crypto.NewKey(keydata)
	if err != nil {
		return "", "", fmt.Errorf("parse autocrypt key: %w", err)
	}
	armored, err = key.GetArmoredPublicKey()
	if err != nil {
		return "", "", err
	}
	status, err := pgpmail.CheckKeyStatus(armored)
	if err != nil {
		return "", "", err
	}
	if !status.Usable() {
		return "", "", fmt.Errorf("autocrypt key for %s is revoked or expired", addr)
	}
	target := strings.ToLower(strings.TrimSpace(addr))
	entity := key.GetEntity()
	if entity == nil {
		return "", "", fmt.Errorf("autocrypt key has no entity")
	}
	for _, uid := range entity.Identities {
		if strings.ToLower(strings.TrimSpace(uid.UserId.Email)) == target {
			return armored, key.GetFingerprint(), nil
		}
	}
	return "", "", fmt.Errorf("autocrypt key does not carry %s as a user id", addr)
}

// harvestAutocrypt is the poller's best-effort receive-side key-harvest step,
// run once per newly-seen inbound message when harvesting is enabled. It never
// returns an error — every failure is logged and swallowed, so it can never
// disturb mail processing. Steps: cheap header pre-check, single-header rule,
// parse, addr/From match, suppression, DKIM gate, key validation, precedence
// pin.
func (p *Poller) harvestAutocrypt(ctx context.Context, uc userCtx, msg imapadapter.Message, suppressed map[string]bool) {
	uid, err := strconv.Atoi(strings.TrimSpace(msg.ID))
	if err != nil {
		return
	}
	fields, err := uc.mail.FetchHeaderFields(ctx, []int{uid}, "Autocrypt", "From")
	if err != nil {
		p.log.Info("autocrypt harvest: header fetch failed", "user_id", uc.id, "message_id", msg.ID, "error", err.Error())
		return
	}
	var autocryptValues []string
	fromValue := ""
	for _, line := range fields[uid] {
		name, val := splitHeaderLine(line)
		switch strings.ToLower(name) {
		case "autocrypt":
			autocryptValues = append(autocryptValues, val)
		case "from":
			fromValue = val
		}
	}
	// 0 = no Autocrypt header; >1 = treat as none (Autocrypt spec).
	if len(autocryptValues) != 1 {
		return
	}
	addr, keydata, err := pgpautocrypt.ParseAutocryptHeader(autocryptValues[0])
	if err != nil {
		return
	}
	normAddr := strings.ToLower(strings.TrimSpace(addr))
	if fromAddr := parseFromAddress(fromValue); fromAddr == "" || fromAddr != normAddr {
		return
	}
	if suppressed[normAddr] {
		return
	}
	raw, err := uc.mail.FetchRawMessage(ctx, "INBOX", uid)
	if err != nil || len(raw) == 0 {
		return
	}
	if !verifyAutocryptDKIM(raw, domainOf(normAddr)) {
		return
	}
	armored, fingerprint, err := validateAutocryptKey(keydata, addr)
	if err != nil {
		return
	}
	store, err := p.userContactsStore(uc.id)
	if err != nil {
		p.log.Error("autocrypt harvest: open contacts store failed", "user_id", uc.id, "error", err.Error())
		return
	}
	action, err := harvestPinAutocryptKey(store, addr, armored, fingerprint)
	if err != nil {
		p.log.Error("autocrypt harvest: pin failed", "user_id", uc.id, "addr", addr, "error", err.Error())
		return
	}
	if action != harvestUnchanged && action != harvestSkipped {
		p.log.Info("autocrypt key harvested", "user_id", uc.id, "message_id", msg.ID, "addr", addr, "fingerprint", fingerprint, "action", string(action))
	}
}
