package processor

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	imapadapter "kypost-server/backend/internal/adapters/imap"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/logging"
	"kypost-server/backend/internal/pgpmail"
)

// autocryptTestKey returns a fresh armored public key + fingerprint for addr.
func autocryptTestKey(t *testing.T, name, addr string) (armored, fingerprint string) {
	t.Helper()
	id, err := pgpmail.GenerateIdentity(name, addr)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id.ArmoredPublicKey, id.Fingerprint
}

func TestHarvestPinCreatesContact(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Alice", "alice@example.com")

	action, err := harvestPinAutocryptKey(store, "alice@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestCreated {
		t.Fatalf("action = %q, want created", action)
	}
	c, ok := must2(findContactByEmail(store, "alice@example.com"))
	if !ok {
		t.Fatalf("expected a created contact")
	}
	if c.PGPKeySource != contacts.PGPSourceAutocrypt || c.PGPKeyFingerprint != fp || c.PGPKeyVerified {
		t.Fatalf("unexpected provenance: %+v", c)
	}
	if !c.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=true on an auto-created contact")
	}
}

func TestHarvestPinFillsExistingContactGap(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails:        []contacts.ContactValue{{Value: "bob@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Bob", "bob@example.com")

	action, err := harvestPinAutocryptKey(store, "bob@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestPinned {
		t.Fatalf("action = %q, want pinned", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKeySource != contacts.PGPSourceAutocrypt || c.PGPKeyFingerprint != fp {
		t.Fatalf("expected autocrypt key pinned, got %+v", c)
	}
	if c.DiscoveryCreated {
		t.Fatalf("DiscoveryCreated must stay false on a pre-existing contact")
	}
}

func TestHarvestPinSkipsStrongerSource(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	manualArmored, manualFP := autocryptTestKey(t, "Carol Manual", "carol@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Carol",
		Emails:            []contacts.ContactValue{{Value: "carol@example.com"}},
		PGPKey:            manualArmored,
		PGPKeyFingerprint: manualFP,
		PGPKeySource:      contacts.PGPSourceWKD,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	autoArmored, autoFP := autocryptTestKey(t, "Carol Auto", "carol@example.com")

	action, err := harvestPinAutocryptKey(store, "carol@example.com", autoArmored, autoFP)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestSkipped {
		t.Fatalf("action = %q, want skipped", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKeyFingerprint != manualFP || c.PGPKeySource != contacts.PGPSourceWKD {
		t.Fatalf("existing wkd key must be untouched, got %+v", c)
	}
}

func TestHarvestPinUpdatesOlderAutocryptKey(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	oldArmored, oldFP := autocryptTestKey(t, "Dave Old", "dave@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Dave",
		Emails:            []contacts.ContactValue{{Value: "dave@example.com"}},
		PGPKey:            oldArmored,
		PGPKeyFingerprint: oldFP,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	newArmored, newFP := autocryptTestKey(t, "Dave New", "dave@example.com")
	if newFP == oldFP {
		t.Fatalf("test setup: expected two distinct fingerprints")
	}

	action, err := harvestPinAutocryptKey(store, "dave@example.com", newArmored, newFP)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestUpdated {
		t.Fatalf("action = %q, want updated", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKeyFingerprint != newFP {
		t.Fatalf("expected newest autocrypt key to win, got %+v", c)
	}
}

func TestHarvestPinSameAutocryptFingerprintIsNoop(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Erin", "erin@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName:     "Erin",
		Emails:            []contacts.ContactValue{{Value: "erin@example.com"}},
		PGPKey:            armored,
		PGPKeyFingerprint: fp,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	action, err := harvestPinAutocryptKey(store, "erin@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestUnchanged {
		t.Fatalf("action = %q, want unchanged", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.Rev != existing.Rev {
		t.Fatalf("no-op must not bump Rev: was %d now %d", existing.Rev, c.Rev)
	}
}

// harvestStubClient implements imapadapter.Client by embedding the (nil)
// interface — any method the harvester does not use panics if called, exactly
// like stubSendAsMailClient. It serves canned header fields and raw bytes.
type harvestStubClient struct {
	imapadapter.Client
	headerFields map[int][]string
	raw          map[int][]byte
	// rawMailbox is the folder this fake will serve raw bytes for. Zero value
	// "" is the account's configured folder, which is what FetchHeaderFields
	// reads and therefore the only folder the harvest may authenticate against.
	rawMailbox string
	// rawMailboxes records every mailbox FetchRawMessage was asked for.
	rawMailboxes []string
}

func (c *harvestStubClient) FetchHeaderFields(_ context.Context, uids []int, _ ...string) (map[int][]string, error) {
	out := map[int][]string{}
	for _, u := range uids {
		if v, ok := c.headerFields[u]; ok {
			out[u] = v
		}
	}
	return out, nil
}

// FetchRawMessage records the mailbox it was asked for, and serves raw bytes
// only for the folder the rest of this fake reads from.
//
// Every fake in the repo used to discard the mailbox argument, which is why a
// caller passing a literal "INBOX" while its sibling call read the account's
// configured folder could not be caught by any test. rawMailbox is "" here for
// the same reason the production callers pass "": that means "the configured
// folder", and the header fetch this is paired with has no mailbox argument at
// all.
func (c *harvestStubClient) FetchRawMessage(_ context.Context, mailbox string, uid int) ([]byte, error) {
	c.rawMailboxes = append(c.rawMailboxes, mailbox)
	if mailbox != c.rawMailbox {
		return nil, nil
	}
	return c.raw[uid], nil
}

// newTestPollerForHarvest builds a minimal *Poller sufficient to exercise
// harvestAutocrypt: a logger, a stateDir (so userStateDir/userContactsStore
// work), and an initialized contactsStores map.
func newTestPollerForHarvest(t *testing.T) *Poller {
	t.Helper()
	logger, err := logging.New(t.TempDir())
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	return &Poller{
		log:            logger,
		stateDir:       t.TempDir(),
		contactsStores: map[string]*contacts.Store{},
	}
}

// autocryptHeaderFor builds an `Autocrypt` header value carrying addr's
// public key as base64 keydata, matching what a real sender would send.
func autocryptHeaderFor(t *testing.T, name, addr string) string {
	t.Helper()
	id, err := pgpmail.GenerateIdentity(name, addr)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, err := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	if err != nil {
		t.Fatalf("NewKeyFromArmored: %v", err)
	}
	bin, err := key.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	return "addr=" + addr + "; prefer-encrypt=mutual; keydata=" + base64.StdEncoding.EncodeToString(bin)
}

func TestHarvestAutocryptPinsOnDKIMPass(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return true }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	header := autocryptHeaderFor(t, "Faythe", "faythe@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {
			"Autocrypt: " + header,
			"From: Faythe <faythe@example.com>",
		}},
		raw: map[int][]byte{7: []byte("raw message bytes")},
	}
	uc := userCtx{id: "u1", mail: client}
	msg := imapadapter.Message{ID: "7", Sender: "faythe@example.com"}

	p.harvestAutocrypt(context.Background(), uc, msg, nil)

	store, err := p.userContactsStore("u1")
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, ok := must2(findContactByEmail(store, "faythe@example.com"))
	if !ok || c.PGPKeySource != contacts.PGPSourceAutocrypt || !c.DiscoveryCreated {
		t.Fatalf("expected a harvested autocrypt contact, got ok=%v %+v", ok, c)
	}
}

// The bytes the DKIM gate authenticates must come from the SAME message the
// Autocrypt header was read from. FetchHeaderFields takes no mailbox and so
// reads the account's configured folder; passing a literal "INBOX" to the raw
// fetch authenticated a different message at the same UID for any account
// polling another folder, and usually found no such UID at all — killing
// harvesting silently.
func TestHarvestAutocryptAuthenticatesTheFolderItReadHeadersFrom(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return true }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	header := autocryptHeaderFor(t, "Heidi", "heidi@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {
			"Autocrypt: " + header,
			"From: Heidi <heidi@example.com>",
		}},
		raw: map[int][]byte{7: []byte("raw message bytes")},
		// Serve raw bytes only for the configured folder.
		rawMailbox: "",
	}
	uc := userCtx{id: "u1", mail: client}

	p.harvestAutocrypt(context.Background(), uc, imapadapter.Message{ID: "7", Sender: "heidi@example.com"}, nil)

	for _, got := range client.rawMailboxes {
		if got != "" {
			t.Fatalf("raw fetch asked for %q; it must read the same folder as the header fetch, which is the configured one (\"\")", got)
		}
	}
	store, err := p.userContactsStore("u1")
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	if _, ok := must2(findContactByEmail(store, "heidi@example.com")); !ok {
		t.Fatal("expected the key to be harvested; a mismatched folder makes the raw fetch return nothing and the harvest die silently")
	}
}

func TestHarvestAutocryptSkipsOnDKIMFail(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return false }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	header := autocryptHeaderFor(t, "Grace", "grace@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {"Autocrypt: " + header, "From: grace@example.com"}},
		raw:          map[int][]byte{7: []byte("raw")},
	}
	uc := userCtx{id: "u1", mail: client}

	p.harvestAutocrypt(context.Background(), uc, imapadapter.Message{ID: "7"}, nil)

	store, _ := p.userContactsStore("u1")
	if _, ok := must2(findContactByEmail(store, "grace@example.com")); ok {
		t.Fatalf("DKIM failure must harvest nothing")
	}
}

func TestHarvestAutocryptSkipsAddrMismatch(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return true }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	// Autocrypt addr differs from the From address.
	header := autocryptHeaderFor(t, "Heidi", "heidi@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {"Autocrypt: " + header, "From: mallory@evil.example"}},
		raw:          map[int][]byte{7: []byte("raw")},
	}
	uc := userCtx{id: "u1", mail: client}

	p.harvestAutocrypt(context.Background(), uc, imapadapter.Message{ID: "7"}, nil)

	store, _ := p.userContactsStore("u1")
	if _, ok := must2(findContactByEmail(store, "heidi@example.com")); ok {
		t.Fatalf("addr/From mismatch must harvest nothing")
	}
}

func TestHarvestAutocryptSkipsMultipleHeaders(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return true }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	h1 := autocryptHeaderFor(t, "Ivan", "ivan@example.com")
	h2 := autocryptHeaderFor(t, "Ivan2", "ivan@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {
			"Autocrypt: " + h1,
			"Autocrypt: " + h2,
			"From: ivan@example.com",
		}},
		raw: map[int][]byte{7: []byte("raw")},
	}
	uc := userCtx{id: "u1", mail: client}

	p.harvestAutocrypt(context.Background(), uc, imapadapter.Message{ID: "7"}, nil)

	store, _ := p.userContactsStore("u1")
	if _, ok := must2(findContactByEmail(store, "ivan@example.com")); ok {
		t.Fatalf("multiple Autocrypt headers must be treated as none")
	}
}

func TestHarvestAutocryptSkipsSuppressedAddress(t *testing.T) {
	prev := verifyAutocryptDKIM
	verifyAutocryptDKIM = func(_ []byte, _ string) bool { return true }
	defer func() { verifyAutocryptDKIM = prev }()

	p := newTestPollerForHarvest(t)
	header := autocryptHeaderFor(t, "Judy", "judy@example.com")
	client := &harvestStubClient{
		headerFields: map[int][]string{7: {"Autocrypt: " + header, "From: judy@example.com"}},
		raw:          map[int][]byte{7: []byte("raw")},
	}
	uc := userCtx{id: "u1", mail: client}

	p.harvestAutocrypt(context.Background(), uc, imapadapter.Message{ID: "7"}, map[string]bool{"judy@example.com": true})

	store, _ := p.userContactsStore("u1")
	if _, ok := must2(findContactByEmail(store, "judy@example.com")); ok {
		t.Fatalf("suppressed address must harvest nothing")
	}
}

// TestHarvestPinSkipsSecondaryAddressOnMultiAddressContact pins the scope of
// what the DKIM gate actually proves.
//
// verifyAutocryptDKIM authenticates the Autocrypt header against the domain of
// the FROM address — the sender's own domain. That proves control of that one
// address and nothing else. But the key is written onto the contact RECORD, and
// findContact/findContactByEmail/contactBindsAddress all match ANY address on a
// contact, so the key becomes the encryption target and signature anchor for
// every other address on the card.
//
// An attacker who acquires a lapsed secondary domain sitting on a contact card
// therefore takes over the PRIMARY address: their key is what the victim's next
// encrypted message to bob@example.com is encrypted to.
func TestHarvestPinSkipsSecondaryAddressOnMultiAddressContact(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails: []contacts.ContactValue{
			{Value: "bob@example.com"},
			{Value: "bob@lapsed-domain.example"},
		},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// Mallory owns lapsed-domain.example, so her key legitimately carries that
	// address as its only User ID and she can legitimately DKIM-sign for it.
	armored, fp := autocryptTestKey(t, "Mallory", "bob@lapsed-domain.example")

	action, err := harvestPinAutocryptKey(store, "bob@lapsed-domain.example", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestSkipped {
		t.Fatalf("action = %q, want skipped", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKey != "" || c.PGPKeyFingerprint != "" {
		t.Fatalf("a key proven only for a secondary address must not become the "+
			"contact-wide anchor for bob@example.com, got fp=%q", c.PGPKeyFingerprint)
	}
}

// TestHarvestPinSecondaryAddressCannotReplaceAnExistingKey is the sharper half:
// the newest-fingerprint-wins branch means this is not merely gap-filling. A
// contact that already holds a legitimately harvested key for its primary
// address has that key REPLACED by one proven only for a secondary address.
func TestHarvestPinSecondaryAddressCannotReplaceAnExistingKey(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	realArmored, realFP := autocryptTestKey(t, "Bob", "bob@example.com")
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails: []contacts.ContactValue{
			{Value: "bob@example.com"},
			{Value: "bob@lapsed-domain.example"},
		},
		PGPKey:            realArmored,
		PGPKeyFingerprint: realFP,
		PGPKeySource:      contacts.PGPSourceAutocrypt,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	mallory, malloryFP := autocryptTestKey(t, "Mallory", "bob@lapsed-domain.example")

	action, err := harvestPinAutocryptKey(store, "bob@lapsed-domain.example", mallory, malloryFP)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestSkipped {
		t.Fatalf("action = %q, want skipped", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKeyFingerprint != realFP {
		t.Fatalf("Bob's real key was replaced by one proven only for a secondary "+
			"address: fp = %q, want %q", c.PGPKeyFingerprint, realFP)
	}
}

// TestHarvestPinStillWorksForThePrimaryAddress guards against over-correcting:
// the ordinary case — a key proven for the contact's own primary address — must
// keep working on a multi-address card.
func TestHarvestPinStillWorksForThePrimaryAddress(t *testing.T) {
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	existing, err := store.Upsert(contacts.Contact{
		FormattedName: "Bob",
		Emails: []contacts.ContactValue{
			{Value: "bob@example.com"},
			{Value: "bob@lapsed-domain.example"},
		},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	armored, fp := autocryptTestKey(t, "Bob", "bob@example.com")

	action, err := harvestPinAutocryptKey(store, "bob@example.com", armored, fp)
	if err != nil {
		t.Fatalf("harvestPinAutocryptKey: %v", err)
	}
	if action != harvestPinned {
		t.Fatalf("action = %q, want pinned", action)
	}
	c, _ := must2(store.Get(existing.UID))
	if c.PGPKeyFingerprint != fp {
		t.Fatalf("primary-address harvest must still pin, got fp=%q", c.PGPKeyFingerprint)
	}
}
