# PGP Autocrypt Harvesting (Spec B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harvest correspondents' PGP public keys from the `Autocrypt:` header of DKIM-authenticated inbound mail and pin them to contacts, so the existing send-time ladder has real E2E keys for people who never published to WKD/keyserver.

**Architecture:** A new best-effort step in the poller (`processor/`) parses the `Autocrypt` header of each newly-seen inbound message, requires the sender's domain to pass cryptographic DKIM verification, validates the key, and pins it to the per-user `contacts` store as `source=autocrypt`. The send resolver is unchanged — a harvested key is just a usable pinned contact key it already consumes. Reuses D1's suppression + `DiscoveryCreated` + the `StoreDiscoveredKeys` toggle and Spec A's provenance fields.

**Tech Stack:** Go (module root `backend/`), `github.com/ProtonMail/gopenpgp/v3/crypto`, `github.com/emersion/go-msgauth/dkim` (via the existing `imapadapter.VerifyDKIMForDomain`), `net/mail`, `encoding/base64`.

## Global Constraints

- Module root is `backend/` — run all Go commands with `cd /home/yoshi/git/kypost-server/backend` first.
- Harvest **only** from DKIM-authenticated inbound: the sender-domain DKIM check (`imapadapter.VerifyDKIMForDomain(raw, domain)`) must pass; otherwise harvest nothing. Never silently trust an unauthenticated `Autocrypt` header.
- **Precedence is source-based** (harvest is the weakest rung):
  - no contact → create a minimal contact, pin `source=autocrypt`, `DiscoveryCreated=true`.
  - contact with **no** `PGPKey` → pin `source=autocrypt` (`DiscoveryCreated` stays as-is).
  - contact with a **non-autocrypt** key (`manual`/`qr`/`wkd`/`keyserver`) → leave untouched, always (even if that key is expired).
  - contact with an existing `autocrypt` key → **newest wins**: different fingerprint updates it, same fingerprint is a no-op.
- Harvested keys are always `PGPKeyVerified=false`.
- Governance: harvest nothing when the user's `StoreDiscoveredKeys` toggle is off; skip an address in the D1 `SuppressedSet`.
- Isolation: the harvest step is best-effort. Every error is logged and swallowed — it never returns into `handleMessage`, never affects `MarkProcessed`, the checkpoint, the rate-limit budget, or notifications.
- The `Autocrypt` "more than one header ⇒ treat as none" rule is enforced at the harvest call site (the parser handles a single header value).
- Address normalization everywhere is `strings.ToLower(strings.TrimSpace(...))`.
- New source value string is exactly `"autocrypt"`.

---

### Task 1: Autocrypt header parser (`pgpautocrypt` package)

**Files:**
- Create: `backend/internal/pgpautocrypt/autocrypt.go`
- Test: `backend/internal/pgpautocrypt/autocrypt_test.go`

**Interfaces:**
- Produces: `ParseAutocryptHeader(value string) (addr string, keydata []byte, err error)` — parses one `Autocrypt` header *value* (the text after `Autocrypt:`); returns the `addr` attribute and the base64-decoded `keydata` bytes. Errors on missing `addr`/`keydata`, malformed attributes, an unknown **critical** (non-`_`-prefixed) attribute, or undecodable base64. `prefer-encrypt` is parsed-and-ignored.

- [ ] **Step 1: Write the failing tests**

Create `backend/internal/pgpautocrypt/autocrypt_test.go`:

```go
package pgpautocrypt

import (
	"bytes"
	"testing"
)

func TestParseValid(t *testing.T) {
	// keydata "hello" base64 = aGVsbG8= ; the parser does not parse the key,
	// it only returns the decoded bytes.
	addr, keydata, err := ParseAutocryptHeader("addr=alice@example.com; prefer-encrypt=mutual; keydata=aGVsbG8=")
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if addr != "alice@example.com" {
		t.Fatalf("addr = %q, want alice@example.com", addr)
	}
	if !bytes.Equal(keydata, []byte("hello")) {
		t.Fatalf("keydata = %q, want hello", keydata)
	}
}

func TestParseFoldedKeydataStripsWhitespace(t *testing.T) {
	// keydata may arrive with folding whitespace inside the base64.
	_, keydata, err := ParseAutocryptHeader("addr=a@b.com; keydata=aGVs\r\n bG8=")
	if err != nil {
		t.Fatalf("ParseAutocryptHeader: %v", err)
	}
	if !bytes.Equal(keydata, []byte("hello")) {
		t.Fatalf("keydata = %q, want hello", keydata)
	}
}

func TestParseUnderscoreAttributeIgnored(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; _futurehint=x; keydata=aGVsbG8="); err != nil {
		t.Fatalf("non-critical _attribute should be ignored, got %v", err)
	}
}

func TestParseUnknownCriticalAttributeFails(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; danger=1; keydata=aGVsbG8="); err == nil {
		t.Fatalf("expected error for unknown critical attribute")
	}
}

func TestParseMissingKeydata(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com"); err == nil {
		t.Fatalf("expected error for missing keydata")
	}
}

func TestParseMissingAddr(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("keydata=aGVsbG8="); err == nil {
		t.Fatalf("expected error for missing addr")
	}
}

func TestParseBadBase64(t *testing.T) {
	if _, _, err := ParseAutocryptHeader("addr=a@b.com; keydata=not!!base64"); err == nil {
		t.Fatalf("expected error for undecodable base64")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/pgpautocrypt/ -v`
Expected: FAIL — `undefined: ParseAutocryptHeader` (build failed).

- [ ] **Step 3: Write the parser**

Create `backend/internal/pgpautocrypt/autocrypt.go`:

```go
// Package pgpautocrypt parses the RFC-Autocrypt `Autocrypt:` mail header,
// extracting the sender's advertised address and public-key bytes.
package pgpautocrypt

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode"
)

// ParseAutocryptHeader parses one `Autocrypt` header value (the text after
// "Autocrypt:") into its addr attribute and base64-decoded keydata bytes.
//
// Per the Autocrypt spec, attributes are `;`-separated `name=value` pairs.
// `prefer-encrypt` is parsed and ignored (we only want a usable key). Any
// unknown attribute whose name does NOT start with "_" is "critical" and
// makes the whole header invalid; unknown "_"-prefixed attributes are
// non-critical and ignored. keydata is standard base64, possibly folded with
// whitespace, so all whitespace is stripped before decoding.
func ParseAutocryptHeader(value string) (addr string, keydata []byte, err error) {
	var keyB64 string
	haveAddr, haveKey := false, false
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			return "", nil, fmt.Errorf("autocrypt: malformed attribute %q", part)
		}
		name := strings.TrimSpace(part[:eq])
		v := strings.TrimSpace(part[eq+1:])
		switch strings.ToLower(name) {
		case "addr":
			addr, haveAddr = v, true
		case "keydata":
			keyB64, haveKey = v, true
		case "prefer-encrypt":
			// parsed and ignored
		default:
			if !strings.HasPrefix(name, "_") {
				return "", nil, fmt.Errorf("autocrypt: unknown critical attribute %q", name)
			}
			// non-critical (underscore) attribute: ignore
		}
	}
	if !haveAddr || strings.TrimSpace(addr) == "" {
		return "", nil, fmt.Errorf("autocrypt: missing addr")
	}
	if !haveKey {
		return "", nil, fmt.Errorf("autocrypt: missing keydata")
	}
	keyB64 = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, keyB64)
	decoded, derr := base64.StdEncoding.DecodeString(keyB64)
	if derr != nil {
		return "", nil, fmt.Errorf("autocrypt: keydata base64: %w", derr)
	}
	if len(decoded) == 0 {
		return "", nil, fmt.Errorf("autocrypt: empty keydata")
	}
	return addr, decoded, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/pgpautocrypt/ -v`
Expected: PASS (all seven tests).

- [ ] **Step 5: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/pgpautocrypt/
git commit -m "feat(pgp): add Autocrypt header parser"
```

---

### Task 2: `autocrypt` source constant + precedence-pin helper

**Files:**
- Modify: `backend/internal/contacts/contacts.go` (add const to the source enum, ~line 9-13)
- Create: `backend/internal/processor/autocrypt_harvest.go`
- Test: `backend/internal/processor/autocrypt_harvest_test.go`

**Interfaces:**
- Consumes: `contacts.Store` (`New`, `Upsert`, `List`, `Get`), `contacts.Contact`.
- Produces:
  - `contacts.PGPSourceAutocrypt = "autocrypt"`.
  - `findContactByEmail(store *contacts.Store, email string) (contacts.Contact, bool)` — first contact with a matching email (case-insensitive).
  - `harvestAction` string type with consts `harvestCreated`, `harvestPinned`, `harvestUpdated`, `harvestSkipped`, `harvestUnchanged`.
  - `harvestPinAutocryptKey(store *contacts.Store, addr, armored, fingerprint string) (harvestAction, error)` — applies the source-based precedence rule.

- [ ] **Step 1: Add the source constant**

In `backend/internal/contacts/contacts.go`, extend the const block:

```go
const (
	PGPSourceManual    = "manual"
	PGPSourceQR        = "qr"
	PGPSourceWKD       = "wkd"
	PGPSourceKeyserver = "keyserver"
	PGPSourceAutocrypt = "autocrypt"
)
```

- [ ] **Step 2: Write the failing tests**

Create `backend/internal/processor/autocrypt_harvest_test.go`:

```go
package processor

import (
	"testing"

	"kypost-server/backend/internal/contacts"
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
	c, ok := findContactByEmail(store, "alice@example.com")
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
	c, _ := store.Get(existing.UID)
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
	c, _ := store.Get(existing.UID)
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
	c, _ := store.Get(existing.UID)
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
	c, _ := store.Get(existing.UID)
	if c.Rev != existing.Rev {
		t.Fatalf("no-op must not bump Rev: was %d now %d", existing.Rev, c.Rev)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/processor/ -run TestHarvestPin -v`
Expected: FAIL — `undefined: harvestPinAutocryptKey` / `undefined: findContactByEmail` (build failed).

- [ ] **Step 4: Write the helper**

Create `backend/internal/processor/autocrypt_harvest.go`:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/processor/ -run TestHarvestPin -v`
Expected: PASS (all five tests).

- [ ] **Step 6: Run the contacts + processor suites**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/contacts/ ./internal/processor/`
Expected: PASS (no regressions).

- [ ] **Step 7: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/contacts/contacts.go backend/internal/processor/autocrypt_harvest.go backend/internal/processor/autocrypt_harvest_test.go
git commit -m "feat(pgp): add Autocrypt source constant and precedence-pin helper"
```

---

### Task 3: Harvest orchestration + poller wiring

**Files:**
- Modify: `backend/internal/processor/autocrypt_harvest.go` (add the orchestration + IMAP/DKIM plumbing to the file Task 2 created)
- Modify: `backend/internal/processor/poller.go` (`Poller` struct field + `New` init + `userContactsStore` + call in `tickUser`'s loop)
- Test: `backend/internal/processor/autocrypt_harvest_test.go` (add integration tests)

**Interfaces:**
- Consumes: `harvestPinAutocryptKey`, `findContactByEmail` (Task 2); `pgpautocrypt.ParseAutocryptHeader` (Task 1); `imapadapter.Client.FetchHeaderFields`/`FetchRawMessage`/`imapadapter.VerifyDKIMForDomain`; `pgpdiscovery.Load`/`SuppressedSet`; `domainOf` (already in package, `sendas_check.go`); `contacts.New`; `pgpmail.CheckKeyStatus`; `crypto.NewKey`.
- Produces:
  - `Poller.contactsStores map[string]*contacts.Store` + `(p *Poller) userContactsStore(userID string) (*contacts.Store, error)`.
  - `(p *Poller) autocryptHarvestConfig(userID string) (enabled bool, suppressed map[string]bool)`.
  - `(p *Poller) harvestAutocrypt(ctx context.Context, uc userCtx, msg imapadapter.Message, suppressed map[string]bool)`.
  - package var `var verifyAutocryptDKIM = imapadapter.VerifyDKIMForDomain` (test seam).

- [ ] **Step 1: Write the failing integration tests**

Add to `backend/internal/processor/autocrypt_harvest_test.go`. Add these imports to the file's import block (in addition to `testing`, `contacts`, and `pgpmail` already there from Task 2): `context`, `encoding/base64`, `github.com/ProtonMail/gopenpgp/v3/crypto`, `kypost-server/backend/internal/adapters/imap` (as `imapadapter`), `kypost-server/backend/internal/logging`. (Do not add `strings` — the integration tests below don't use it.)

```go
// harvestStubClient implements imapadapter.Client by embedding the (nil)
// interface — any method the harvester does not use panics if called, exactly
// like stubSendAsMailClient. It serves canned header fields and raw bytes.
type harvestStubClient struct {
	imapadapter.Client
	headerFields map[int][]string
	raw          map[int][]byte
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

func (c *harvestStubClient) FetchRawMessage(_ context.Context, uid int) ([]byte, error) {
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
	c, ok := findContactByEmail(store, "faythe@example.com")
	if !ok || c.PGPKeySource != contacts.PGPSourceAutocrypt || !c.DiscoveryCreated {
		t.Fatalf("expected a harvested autocrypt contact, got ok=%v %+v", ok, c)
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
	if _, ok := findContactByEmail(store, "grace@example.com"); ok {
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
	if _, ok := findContactByEmail(store, "heidi@example.com"); ok {
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
	if _, ok := findContactByEmail(store, "ivan@example.com"); ok {
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
	if _, ok := findContactByEmail(store, "judy@example.com"); ok {
		t.Fatalf("suppressed address must harvest nothing")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/processor/ -run TestHarvestAutocrypt -v`
Expected: FAIL — `undefined: verifyAutocryptDKIM`, `p.harvestAutocrypt undefined`, `p.userContactsStore undefined`, `contactsStores` unknown field (build failed).

- [ ] **Step 3: Add the poller struct field, init, and `userContactsStore`**

In `backend/internal/processor/poller.go`:

Add the import `"kypost-server/backend/internal/contacts"` to the import block.

Add the field to the `Poller` struct (alongside `sendAsStores`):

```go
	sendAsStores map[string]*sendas.Store
	contactsStores map[string]*contacts.Store
```

In `New(...)`, initialize it (alongside `sendAsStores: map[string]*sendas.Store{}`):

```go
		sendAsStores:         map[string]*sendas.Store{},
		contactsStores:       map[string]*contacts.Store{},
```

Add the accessor near `userSendAsStore` (in `sendas_check.go`) or `userRulesStore` (in `poller.go`) — put it in `poller.go` next to `userRulesStore`:

```go
// userContactsStore returns the cached contacts store for a user, mirroring
// userRulesStore — the api process independently constructs its own
// contacts.Store over the same on-disk contacts.json, so
// refreshFromDiskLocked keeps the two processes' in-memory views coherent,
// exactly as with state.Store.
func (p *Poller) userContactsStore(userID string) (*contacts.Store, error) {
	p.userMu.Lock()
	defer p.userMu.Unlock()
	if st, ok := p.contactsStores[userID]; ok {
		return st, nil
	}
	st, err := contacts.New(p.userStateDir(userID))
	if err != nil {
		return nil, err
	}
	p.contactsStores[userID] = st
	return st, nil
}
```

- [ ] **Step 4: Add the orchestration to `autocrypt_harvest.go`**

Append to `backend/internal/processor/autocrypt_harvest.go`, and update its import block to:

```go
import (
	"context"
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
```

Append:

```go
// verifyAutocryptDKIM is the DKIM gate for harvesting, a package var so tests
// can substitute a deterministic result instead of standing up real DKIM
// crypto + DNS (the crypto itself is covered in
// internal/adapters/imap/dkim_verify_test.go). Same test-seam idiom as
// sendRejectionNotice in poller.go.
var verifyAutocryptDKIM = imapadapter.VerifyDKIMForDomain

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
	raw, err := uc.mail.FetchRawMessage(ctx, uid)
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
```

- [ ] **Step 5: Wire the call into `tickUser`**

In `backend/internal/processor/poller.go`, in `tickUser`, immediately before the `for _, msg := range messages {` loop, add:

```go
	harvestEnabled, harvestSuppressed := p.autocryptHarvestConfig(u.ID)
```

Then inside the loop, immediately after the `store.Seen(msg.ID)` skip block and before the rate-limit check, add:

```go
		if harvestEnabled {
			p.harvestAutocrypt(ctx, uc, msg, harvestSuppressed)
		}
```

For reference, the loop head becomes:

```go
	for _, msg := range messages {
		if store.Seen(msg.ID) {
			skippedSeenCount++
			continue
		}
		if harvestEnabled {
			p.harvestAutocrypt(ctx, uc, msg, harvestSuppressed)
		}
		if !p.allowByRate(u.ID) {
```

- [ ] **Step 6: Run the harvest integration tests**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/processor/ -run TestHarvestAutocrypt -v`
Expected: PASS (all five integration tests).

- [ ] **Step 7: Run vet + the full processor suite**

Run: `cd /home/yoshi/git/kypost-server/backend && gofmt -l internal/processor internal/pgpautocrypt internal/contacts && go vet ./internal/processor/ && go test ./internal/processor/`
Expected: `gofmt -l` prints nothing; vet clean; tests PASS (harvest tests + all existing poller/sendas tests).

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/processor/autocrypt_harvest.go backend/internal/processor/autocrypt_harvest_test.go backend/internal/processor/poller.go
git commit -m "feat(pgp): harvest Autocrypt keys from DKIM-authenticated inbound mail"
```

---

## Final verification

- [ ] **Backend:** `cd /home/yoshi/git/kypost-server/backend && gofmt -l internal/... ; go vet ./... && go test ./internal/pgpautocrypt/ ./internal/processor/ ./internal/contacts/`
- [ ] Whole-branch code review (opus) per subagent-driven-development, then finishing-a-development-branch.

## Spec coverage note

The spec's §4 precedence bullet "contact with no usable key → pin" is refined here to the **source-based** rule in Global Constraints: a non-autocrypt key is never overwritten *even when expired* (the "leave untouched, always" clause governs), because overwriting a user's manual/QR key — or a domain-authoritative WKD key — with a header-sourced key is never desirable, and the send-time ladder re-discovers a fresh WKD/keyserver key at send time anyway. Only autocrypt→autocrypt is mutable (newest wins).

## Deferred (from the spec, unchanged)

- **Client provenance label** ("via Autocrypt") — bundled with Spec A's already-deferred mobile/desktop provenance work; `pgpKeySource="autocrypt"` rides existing sync as an opaque string today.
- **`prefer-encrypt` hint**, **Autocrypt-Gossip**, **Autocrypt Setup Message**, per-sender counters — out of scope.
