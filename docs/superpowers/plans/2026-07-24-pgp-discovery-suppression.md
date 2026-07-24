# PGP Discovery Suppression (Spec D1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user opt an address out of automatic PGP key discovery so a removed/rejected discovered key is not silently re-found, and mark discovery-created contacts with a clean, filterable flag.

**Architecture:** Add a `DiscoveryCreated` marker to `contacts.Contact`, set only when the send-time resolver auto-creates a brand-new contact. Add a per-user suppression store (`pgp-discovery-suppressions.json`) in the existing `pgpdiscovery` package. The resolver consults a suppressed-set (built in the send handler) and, for a suppressed address, returns `tierNone` before any WKD/keyserver lookup. Suppression is triggered implicitly on deleting a discovery-created contact and explicitly via a "remove key & stop rediscovering" action, and is managed through three new HTTP endpoints plus a minimal web UI.

**Tech Stack:** Go (module root `backend/`), `github.com/ProtonMail/gopenpgp/v3/crypto`, `net/http` ServeMux (Go 1.22 method+wildcard routes), React/TypeScript/Vite (`frontend/`).

## Global Constraints

- Module root is `backend/` — run all Go commands with `cd /home/yoshi/git/kypost-server/backend` first.
- Suppression is keyed by the **normalized** email: `strings.ToLower(strings.TrimSpace(email))`. Empty normalized addresses are never stored.
- Suppression blocks **discovery only**. A key the user already holds (manual/QR, used at resolve step 1) must still be used for a suppressed address.
- Suppression persistence is per-user under `s.userStateDir(userID)`, atomic writes, mode `0o600` — mirror `pgpdiscovery/settings.go`.
- Suppression reasons are exactly `"deleted"` (implicit, on delete) and `"explicit"` (the keep-contact/reject-key action).
- `DiscoveryCreated` is set to `true` **only** in `pin()`'s create branch (no pre-existing contact). It is never set when pinning a key onto a contact the user already had.
- Server-side writes triggered by discovery suppression are best-effort where the primary operation already succeeded (a failed suppression write after a successful delete must not fail the delete).
- Follow existing test patterns: `contacts.New(t.TempDir())`, `newTestServer(t)`, `doJSONAuth`, `authRequestAs`, `req.SetPathValue`, `wkdBaseURLOverride`.

---

### Task 1: `DiscoveryCreated` contact marker + resolver create-branch

**Files:**
- Modify: `backend/internal/contacts/contacts.go` (add field ~line 71; clear in `tombstone()` ~line 166)
- Modify: `backend/internal/api/pgp_resolver.go:82-100` (`pin()` create branch)
- Test: `backend/internal/api/pgp_resolver_test.go`

**Interfaces:**
- Consumes: existing `keyResolver.resolve`, `pin`, `findContact`.
- Produces: `contacts.Contact.DiscoveryCreated bool` (json `discoveryCreated,omitempty`), set `true` by `pin()` only when creating a brand-new contact.

- [ ] **Step 1: Write the failing tests**

Add to `backend/internal/api/pgp_resolver_test.go`:

```go
func TestResolveMarksDiscoveryCreatedOnNewContact(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Gale", "gale@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("gale")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	kr := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	if got := kr.resolve(context.Background(), "gale@example.com"); got.Tier != tierWKD {
		t.Fatalf("expected tierWKD, got %+v", got)
	}
	c, ok := findContact(store, "gale@example.com")
	if !ok {
		t.Fatalf("expected an auto-created contact")
	}
	if !c.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=true on an auto-created contact")
	}
}

func TestResolveDoesNotMarkDiscoveryCreatedOnExistingContact(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Hana", "hana@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("hana")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/hu/"+hu) {
			_, _ = w.Write(binKey)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	// Pre-existing contact with no key — the user made this one.
	pinned, err := store.Upsert(contacts.Contact{
		FormattedName: "Hana",
		Emails:        []contacts.ContactValue{{Value: "hana@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	kr := &keyResolver{store: store, settings: pgpdiscovery.Settings{StoreDiscoveredKeys: true}, discover: true}

	if got := kr.resolve(context.Background(), "hana@example.com"); got.Tier != tierWKD {
		t.Fatalf("expected tierWKD, got %+v", got)
	}
	after, ok := store.Get(pinned.UID)
	if !ok {
		t.Fatalf("expected contact %s to still exist", pinned.UID)
	}
	if after.DiscoveryCreated {
		t.Fatalf("expected DiscoveryCreated=false when pinning onto a pre-existing contact")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestResolve.*DiscoveryCreated' -v`
Expected: FAIL — `c.DiscoveryCreated undefined (type contacts.Contact has no field DiscoveryCreated)`.

- [ ] **Step 3: Add the field to `contacts.Contact`**

In `backend/internal/contacts/contacts.go`, immediately after the `MergedInto` field (currently ~line 71), add:

```go
	// DiscoveryCreated marks a contact the send-time key-discovery ladder
	// created from scratch (no prior contact for the address) when it pinned a
	// WKD/keyserver key — distinct from PGPKeySource, which describes the key,
	// not the contact. Drives the "added automatically" badge and the implicit
	// discovery-suppression-on-delete trigger. Rides existing CardDAV/mobile
	// sync as plain JSON; clients that don't understand it ignore it.
	DiscoveryCreated bool `json:"discoveryCreated,omitempty"`
```

- [ ] **Step 4: Clear the field in `tombstone()`**

In `backend/internal/contacts/contacts.go`, in `tombstone()`, add alongside the other cleared fields (e.g. after `c.MergedUIDs = nil`):

```go
	c.DiscoveryCreated = false
```

- [ ] **Step 5: Set the field in `pin()`'s create branch**

In `backend/internal/api/pgp_resolver.go`, change the create branch of `pin()`:

```go
	c, ok := findContact(kr.store, email)
	if !ok {
		c = contacts.Contact{
			FormattedName:    email,
			Emails:           []contacts.ContactValue{{Value: email}},
			DiscoveryCreated: true,
		}
	}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestResolve.*DiscoveryCreated' -v`
Expected: PASS (both tests).

- [ ] **Step 7: Run the affected packages' suites**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ ./internal/contacts/`
Expected: PASS (no regression in existing resolver/pin tests).

- [ ] **Step 8: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/contacts/contacts.go backend/internal/api/pgp_resolver.go backend/internal/api/pgp_resolver_test.go
git commit -m "feat(pgp): mark discovery-created contacts with DiscoveryCreated"
```

---

### Task 2: Suppression store (`pgpdiscovery/suppress.go`)

**Files:**
- Create: `backend/internal/pgpdiscovery/suppress.go`
- Test: `backend/internal/pgpdiscovery/suppress_test.go`

**Interfaces:**
- Produces:
  - `type Suppression struct { Email, SuppressedAt, Reason string }` (json `email`/`suppressedAt`/`reason`)
  - `const ReasonDeleted = "deleted"`, `const ReasonExplicit = "explicit"`
  - `LoadSuppressions(dir string) ([]Suppression, error)` — absent file → `nil, nil`
  - `AddSuppression(dir, email, reason string) error` — idempotent on normalized email; refreshes timestamp/reason
  - `RemoveSuppression(dir, email string) (bool, error)` — reports whether an entry existed
  - `SuppressedSet(dir string) (map[string]bool, error)` — normalized-email set

- [ ] **Step 1: Write the failing tests**

Create `backend/internal/pgpdiscovery/suppress_test.go`:

```go
package pgpdiscovery

import "testing"

func TestSuppressionsAbsentIsEmpty(t *testing.T) {
	list, err := LoadSuppressions(t.TempDir())
	if err != nil {
		t.Fatalf("LoadSuppressions: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected empty, got %+v", list)
	}
}

func TestAddListRemoveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := AddSuppression(dir, "Bob@Example.com", ReasonDeleted); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	list, err := LoadSuppressions(dir)
	if err != nil {
		t.Fatalf("LoadSuppressions: %v", err)
	}
	if len(list) != 1 || list[0].Email != "bob@example.com" || list[0].Reason != ReasonDeleted {
		t.Fatalf("unexpected list after add: %+v", list)
	}
	if list[0].SuppressedAt == "" {
		t.Fatalf("expected SuppressedAt to be set")
	}

	removed, err := RemoveSuppression(dir, "bob@example.com")
	if err != nil {
		t.Fatalf("RemoveSuppression: %v", err)
	}
	if !removed {
		t.Fatalf("expected removed=true")
	}
	list, _ = LoadSuppressions(dir)
	if len(list) != 0 {
		t.Fatalf("expected empty after remove, got %+v", list)
	}
}

func TestAddIsIdempotentAndUpdatesReason(t *testing.T) {
	dir := t.TempDir()
	if err := AddSuppression(dir, "carol@example.com", ReasonDeleted); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	if err := AddSuppression(dir, "CAROL@example.com", ReasonExplicit); err != nil {
		t.Fatalf("AddSuppression (re-add): %v", err)
	}
	list, _ := LoadSuppressions(dir)
	if len(list) != 1 {
		t.Fatalf("expected one entry after idempotent re-add, got %+v", list)
	}
	if list[0].Reason != ReasonExplicit {
		t.Fatalf("expected reason updated to %q, got %q", ReasonExplicit, list[0].Reason)
	}
}

func TestRemoveAbsentReturnsFalse(t *testing.T) {
	removed, err := RemoveSuppression(t.TempDir(), "nobody@example.com")
	if err != nil {
		t.Fatalf("RemoveSuppression: %v", err)
	}
	if removed {
		t.Fatalf("expected removed=false for an address that was never suppressed")
	}
}

func TestSuppressedSet(t *testing.T) {
	dir := t.TempDir()
	_ = AddSuppression(dir, "  Dave@Example.com  ", ReasonExplicit)
	set, err := SuppressedSet(dir)
	if err != nil {
		t.Fatalf("SuppressedSet: %v", err)
	}
	if !set["dave@example.com"] {
		t.Fatalf("expected normalized address in set, got %+v", set)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/pgpdiscovery/ -run 'TestSuppress|TestAdd|TestRemove|TestSuppressedSet' -v`
Expected: FAIL — `undefined: LoadSuppressions` (and the rest).

- [ ] **Step 3: Write the store**

Create `backend/internal/pgpdiscovery/suppress.go`:

```go
package pgpdiscovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kypost-server/backend/internal/fsutil"
)

// Discovery-suppression reasons.
const (
	ReasonDeleted  = "deleted"  // the discovery-created contact was deleted
	ReasonExplicit = "explicit" // the user rejected the key but kept the contact
)

// Suppression is one address the user has opted out of automatic PGP key
// discovery. Email is stored normalized (lowercased, trimmed).
type Suppression struct {
	Email        string `json:"email"`
	SuppressedAt string `json:"suppressedAt"`
	Reason       string `json:"reason"`
}

func suppressionsPath(dir string) string {
	return filepath.Join(dir, "pgp-discovery-suppressions.json")
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// LoadSuppressions reads the caller's opt-out list, returning an empty slice
// when the file does not exist.
func LoadSuppressions(dir string) ([]Suppression, error) {
	b, err := os.ReadFile(suppressionsPath(dir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Suppression
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func saveSuppressions(dir string, list []Suppression) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(suppressionsPath(dir), b, 0o600)
}

// AddSuppression records (or refreshes) a discovery opt-out for email. It is
// idempotent on the normalized address: re-adding updates the timestamp and
// reason instead of appending a duplicate. An empty address is a no-op.
func AddSuppression(dir, email, reason string) error {
	e := normalizeEmail(email)
	if e == "" {
		return nil
	}
	list, err := LoadSuppressions(dir)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range list {
		if normalizeEmail(list[i].Email) == e {
			list[i].Email = e
			list[i].SuppressedAt = now
			list[i].Reason = reason
			return saveSuppressions(dir, list)
		}
	}
	list = append(list, Suppression{Email: e, SuppressedAt: now, Reason: reason})
	return saveSuppressions(dir, list)
}

// RemoveSuppression deletes the opt-out for email ("allow discovery again"),
// reporting whether an entry was present.
func RemoveSuppression(dir, email string) (bool, error) {
	e := normalizeEmail(email)
	list, err := LoadSuppressions(dir)
	if err != nil {
		return false, err
	}
	kept := make([]Suppression, 0, len(list))
	removed := false
	for _, s := range list {
		if normalizeEmail(s.Email) == e {
			removed = true
			continue
		}
		kept = append(kept, s)
	}
	if !removed {
		return false, nil
	}
	return true, saveSuppressions(dir, kept)
}

// SuppressedSet returns the normalized suppressed addresses as a set for the
// resolver's O(1) skip check.
func SuppressedSet(dir string) (map[string]bool, error) {
	list, err := LoadSuppressions(dir)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(list))
	for _, s := range list {
		set[normalizeEmail(s.Email)] = true
	}
	return set, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/pgpdiscovery/ -v`
Expected: PASS (new suppression tests + existing settings tests).

- [ ] **Step 5: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/pgpdiscovery/suppress.go backend/internal/pgpdiscovery/suppress_test.go
git commit -m "feat(pgp): add per-user discovery suppression store"
```

---

### Task 3: Resolver skips suppressed addresses

**Files:**
- Modify: `backend/internal/api/pgp_resolver.go` (`keyResolver` struct + `resolve`)
- Test: `backend/internal/api/pgp_resolver_test.go`

**Interfaces:**
- Consumes: `pgpdiscovery` (imported already), normalized-email keys.
- Produces: `keyResolver.suppressed map[string]bool`; when set and `discover` is true, a suppressed address resolves to `resolvedKey{Tier: tierNone}` before any WKD/keyserver lookup.

- [ ] **Step 1: Write the failing tests**

Add to `backend/internal/api/pgp_resolver_test.go`:

```go
func TestResolveSkipsSuppressedAddress(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	// A WKD server that FAILS the test if it is ever hit — a suppressed
	// address must not trigger any discovery lookup.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("WKD lookup fired for a suppressed address: %s", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	wkdBaseURLOverride = srv.URL
	defer func() { wkdBaseURLOverride = "" }()

	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	kr := &keyResolver{
		store:      store,
		settings:   pgpdiscovery.Settings{StoreDiscoveredKeys: true},
		discover:   true,
		suppressed: map[string]bool{"erin@example.com": true},
	}

	got := kr.resolve(context.Background(), "Erin@Example.com")
	if got.Tier != tierNone {
		t.Fatalf("expected tierNone for a suppressed address, got %+v", got)
	}
	if _, ok := findContact(store, "erin@example.com"); ok {
		t.Fatalf("expected no contact to be auto-created for a suppressed address")
	}
}

func TestResolveSuppressionDoesNotBlockManualKey(t *testing.T) {
	allowLoopbackOutboundForTest(t)
	id, err := pgpmail.GenerateIdentity("Fred", "fred@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	store, err := contacts.New(t.TempDir())
	if err != nil {
		t.Fatalf("contacts.New: %v", err)
	}
	if _, err := store.Upsert(contacts.Contact{
		FormattedName:     "Fred",
		Emails:            []contacts.ContactValue{{Value: "fred@example.com"}},
		PGPKey:            id.ArmoredPublicKey,
		PGPKeyFingerprint: key.GetFingerprint(),
		PGPKeySource:      contacts.PGPSourceManual,
		PGPKeyVerified:    true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	kr := &keyResolver{
		store:      store,
		settings:   pgpdiscovery.Settings{StoreDiscoveredKeys: true},
		discover:   true,
		suppressed: map[string]bool{"fred@example.com": true},
	}

	got := kr.resolve(context.Background(), "fred@example.com")
	if !got.Usable || got.Tier != tierContactVerified {
		t.Fatalf("expected a suppressed address to still use its manual pinned key, got %+v", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestResolveSuppress|TestResolveSkipsSuppressed' -v`
Expected: FAIL — `unknown field 'suppressed' in struct literal`.

- [ ] **Step 3: Add the `suppressed` field**

In `backend/internal/api/pgp_resolver.go`, extend `keyResolver`:

```go
type keyResolver struct {
	store    *contacts.Store
	settings pgpdiscovery.Settings
	// discover gates whether WKD/keyserver lookups run at all; false means
	// only the already-pinned contact key is considered (e.g. discovery
	// disabled by policy, or a caller that only wants the local view).
	discover bool
	// suppressed is the set of normalized addresses the user has opted out of
	// discovery. A suppressed address does no WKD/keyserver lookup, pin, or
	// auto-create — it falls through to the pickup path. A key the user
	// already holds (resolve step 1) is unaffected.
	suppressed map[string]bool
}
```

- [ ] **Step 4: Add the skip check in `resolve`**

In `backend/internal/api/pgp_resolver.go`, in `resolve`, immediately after the existing `if !kr.discover { return resolvedKey{Tier: tierNone} }` block and before the WKD lookup:

```go
	if kr.suppressed[strings.ToLower(strings.TrimSpace(email))] {
		return resolvedKey{Tier: tierNone}
	}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestResolve' -v`
Expected: PASS (new suppression tests + all existing resolver tests).

- [ ] **Step 6: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/api/pgp_resolver.go backend/internal/api/pgp_resolver_test.go
git commit -m "feat(pgp): skip discovery for suppressed addresses in resolver"
```

---

### Task 4: Wire suppressed-set into send + implicit suppression on delete

**Files:**
- Modify: `backend/internal/api/server.go` (`handleMailSend` resolver construction, ~line 1027-1032)
- Modify: `backend/internal/api/contacts_handlers.go` (`handleContactByID` DELETE case; `handleContactsBulkDelete`; new helpers)
- Test: `backend/internal/api/contacts_handlers_test.go` (new file)

**Interfaces:**
- Consumes: `pgpdiscovery.SuppressedSet`, `pgpdiscovery.AddSuppression`, `pgpdiscovery.ReasonDeleted`, `contacts.Contact.DiscoveryCreated`.
- Produces:
  - `handleMailSend` builds `keyResolver.suppressed` from `pgpdiscovery.SuppressedSet(s.userStateDir(ac.UserID))`.
  - `discoveryCreatedEmails(store *contacts.Store, uid string) []string`
  - `(s *Server) suppressDiscoveryOnDelete(userID string, emails []string)`

- [ ] **Step 1: Write the failing tests**

Create `backend/internal/api/contacts_handlers_test.go`:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
)

func TestDeletingDiscoveryCreatedContactSuppresses(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName:    "Ivy",
		Emails:           []contacts.ContactValue{{Value: "ivy@example.com"}},
		DiscoveryCreated: true,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/contacts/"+c.UID, nil)
	req.SetPathValue("id", c.UID)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactByID)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	set, err := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if err != nil {
		t.Fatalf("SuppressedSet: %v", err)
	}
	if !set["ivy@example.com"] {
		t.Fatalf("expected ivy@example.com to be suppressed after deleting its discovery-created contact")
	}
}

func TestDeletingNormalContactDoesNotSuppress(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName: "Jon",
		Emails:        []contacts.ContactValue{{Value: "jon@example.com"}},
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/contacts/"+c.UID, nil)
	req.SetPathValue("id", c.UID)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handleContactByID)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if set["jon@example.com"] {
		t.Fatalf("did not expect a normal contact's deletion to suppress discovery")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestDeleting.*Contact' -v`
Expected: FAIL — the discovery-created delete does not record a suppression (`expected ivy@example.com to be suppressed`).

- [ ] **Step 3: Add the delete-suppression helpers**

In `backend/internal/api/contacts_handlers.go`, add these helpers (e.g. just below `backfillPGPKeyFingerprint`). Note `pgpdiscovery` must be added to the import block:

```go
// discoveryCreatedEmails returns the email addresses of the contact at uid if
// it exists and was created by the key-discovery ladder — the set to suppress
// when it is deleted. A non-discovery contact (or a missing one) yields nil,
// so deleting it records no suppression.
func discoveryCreatedEmails(store *contacts.Store, uid string) []string {
	c, ok := store.Get(uid)
	if !ok || !c.DiscoveryCreated {
		return nil
	}
	emails := make([]string, 0, len(c.Emails))
	for _, e := range c.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			emails = append(emails, v)
		}
	}
	return emails
}

// suppressDiscoveryOnDelete records a discovery opt-out (reason "deleted") for
// each address of a removed discovery-created contact, so the ladder does not
// silently re-create it on the next encrypted send. Best-effort: a failed
// write is swallowed because the delete itself already succeeded.
func (s *Server) suppressDiscoveryOnDelete(userID string, emails []string) {
	dir := s.userStateDir(userID)
	for _, e := range emails {
		_ = pgpdiscovery.AddSuppression(dir, e, pgpdiscovery.ReasonDeleted)
	}
}
```

Add `"kypost-server/backend/internal/pgpdiscovery"` to the imports of `contacts_handlers.go`.

- [ ] **Step 4: Trigger suppression in the single-delete path**

In `backend/internal/api/contacts_handlers.go`, replace the `handleContactByID` DELETE case:

```go
	case http.MethodDelete:
		emails := discoveryCreatedEmails(store, uid)
		removed, err := store.Delete(uid)
		if err != nil {
			http.Error(w, "failed to delete contact", http.StatusInternalServerError)
			return
		}
		if removed && len(emails) > 0 {
			if ac, ok := authFromContext(r); ok {
				s.suppressDiscoveryOnDelete(ac.UserID, emails)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": removed})
```

- [ ] **Step 5: Trigger suppression in the bulk-delete path**

In `backend/internal/api/contacts_handlers.go`, in `handleContactsBulkDelete`, replace the delete loop so each successful delete of a discovery-created contact suppresses its addresses:

```go
	ac, _ := authFromContext(r)
	failures := make([]bulkDeleteFailure, 0)
	processed := 0
	for _, uid := range uniqueIDs {
		emails := discoveryCreatedEmails(store, uid)
		if _, err := store.Delete(uid); err != nil {
			failures = append(failures, bulkDeleteFailure{ID: uid, Error: err.Error()})
			continue
		}
		processed++
		if len(emails) > 0 {
			s.suppressDiscoveryOnDelete(ac.UserID, emails)
		}
	}
```

(The `type bulkDeleteFailure struct {...}` declaration stays where it is, immediately above this block.)

- [ ] **Step 6: Build the suppressed-set in `handleMailSend`**

In `backend/internal/api/server.go`, replace the resolver-construction block (currently ~line 1027-1032):

```go
	discoverySettings, derr := pgpdiscovery.Load(s.userStateDir(ac.UserID))
	if derr != nil {
		http.Error(w, "failed to load pgp discovery settings", http.StatusInternalServerError)
		return
	}
	suppressed, serr := pgpdiscovery.SuppressedSet(s.userStateDir(ac.UserID))
	if serr != nil {
		http.Error(w, "failed to load pgp discovery suppressions", http.StatusInternalServerError)
		return
	}
	resolver := &keyResolver{store: contactsStore, settings: discoverySettings, discover: req.Encrypt, suppressed: suppressed}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestDeleting.*Contact' -v`
Expected: PASS (both).

- [ ] **Step 8: Run the full api suite**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/`
Expected: PASS (no regression in existing contacts/mail-send tests).

- [ ] **Step 9: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/api/server.go backend/internal/api/contacts_handlers.go backend/internal/api/contacts_handlers_test.go
git commit -m "feat(pgp): suppress discovery on deleting a discovery-created contact"
```

---

### Task 5: Management API (list / clear / explicit suppress-contact)

**Files:**
- Modify: `backend/internal/api/pgp_discovery_handlers.go` (three new handlers)
- Modify: `backend/internal/api/server.go` (three new routes, near line 348)
- Test: `backend/internal/api/pgp_discovery_handlers_test.go`

**Interfaces:**
- Consumes: `pgpdiscovery.LoadSuppressions`, `RemoveSuppression`, `AddSuppression`, `ReasonExplicit`; `s.userContactsStore`, `s.userStateDir`.
- Produces routes:
  - `GET /api/pgp/discovery/suppressions` → `{"suppressions":[{email,suppressedAt,reason}]}`
  - `DELETE /api/pgp/discovery/suppressions/{email}` → `{"ok":true}` (404 if absent)
  - `POST /api/pgp/discovery/suppress-contact` `{"contactUID":"..."}` → updated `contacts.Contact`

- [ ] **Step 1: Write the failing tests**

Add to `backend/internal/api/pgp_discovery_handlers_test.go`:

```go
func TestSuppressionsListAndClear(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	if err := pgpdiscovery.AddSuppression(srv.userStateDir(userID), "kim@example.com", pgpdiscovery.ReasonDeleted); err != nil {
		t.Fatalf("seed AddSuppression: %v", err)
	}

	getRec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySuppressions), http.MethodGet,
		"/api/pgp/discovery/suppressions", nil, userID)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET list: expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}
	var listResp struct {
		Suppressions []pgpdiscovery.Suppression `json:"suppressions"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Suppressions) != 1 || listResp.Suppressions[0].Email != "kim@example.com" {
		t.Fatalf("unexpected list: %+v", listResp.Suppressions)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/discovery/suppressions/kim%40example.com", nil)
	delReq.SetPathValue("email", "kim@example.com")
	authRequestAs(srv, delReq, userID)
	delRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPDiscoverySuppressionByEmail)(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE: expected 200, got %d: %s", delRec.Code, delRec.Body.String())
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if set["kim@example.com"] {
		t.Fatalf("expected kim@example.com cleared after DELETE")
	}
}

func TestUnsuppressAbsentReturns404(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	delReq := httptest.NewRequest(http.MethodDelete, "/api/pgp/discovery/suppressions/ghost%40example.com", nil)
	delReq.SetPathValue("email", "ghost@example.com")
	authRequestAs(srv, delReq, userID)
	delRec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPDiscoverySuppressionByEmail)(delRec, delReq)
	if delRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an address that was never suppressed, got %d", delRec.Code)
	}
}

func TestSuppressContactClearsKeyAndSuppresses(t *testing.T) {
	srv := newTestServer(t)
	all, _ := srv.users.List()
	userID := all[0].ID

	store, err := srv.userContactsStore(userID)
	if err != nil {
		t.Fatalf("userContactsStore: %v", err)
	}
	id, err := pgpmail.GenerateIdentity("Lee", "lee@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	c, err := store.Upsert(contacts.Contact{
		FormattedName:     "Lee",
		Emails:            []contacts.ContactValue{{Value: "lee@example.com"}},
		PGPKey:            id.ArmoredPublicKey,
		PGPKeyFingerprint: id.Fingerprint,
		PGPKeySource:      contacts.PGPSourceWKD,
	})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	rec := doJSONAuth(srv, srv.withAuth(srv.handlePGPDiscoverySuppressContact), http.MethodPost,
		"/api/pgp/discovery/suppress-contact", map[string]string{"contactUID": c.UID}, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("suppress-contact: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var updated contacts.Contact
	if err := json.NewDecoder(rec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated contact: %v", err)
	}
	if updated.PGPKey != "" || updated.PGPKeyFingerprint != "" || updated.PGPKeySource != "" || updated.PGPKeyVerified {
		t.Fatalf("expected key fields cleared, got %+v", updated)
	}

	set, _ := pgpdiscovery.SuppressedSet(srv.userStateDir(userID))
	if !set["lee@example.com"] {
		t.Fatalf("expected lee@example.com suppressed after explicit action")
	}
}
```

Ensure the test file's import block includes `"net/http/httptest"`, `"kypost-server/backend/internal/contacts"`, `"kypost-server/backend/internal/pgpdiscovery"`, and `"kypost-server/backend/internal/pgpmail"` (add any that are missing).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestSuppressions|TestUnsuppress|TestSuppressContact' -v`
Expected: FAIL — `srv.handlePGPDiscoverySuppressions undefined` (and the other two handlers).

- [ ] **Step 3: Write the handlers**

Append to `backend/internal/api/pgp_discovery_handlers.go` (the `strings` import must be added to its import block):

```go
// handlePGPDiscoverySuppressions lists the caller's discovery opt-outs.
func (s *Server) handlePGPDiscoverySuppressions(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	list, err := pgpdiscovery.LoadSuppressions(s.userStateDir(ac.UserID))
	if err != nil {
		http.Error(w, "failed to read discovery suppressions", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []pgpdiscovery.Suppression{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"suppressions": list})
}

// handlePGPDiscoverySuppressionByEmail removes one opt-out ("allow discovery
// again"). {email} is percent-decoded by the router; 404 when the address was
// not suppressed.
func (s *Server) handlePGPDiscoverySuppressionByEmail(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	email := strings.TrimSpace(r.PathValue("email"))
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	removed, err := pgpdiscovery.RemoveSuppression(s.userStateDir(ac.UserID), email)
	if err != nil {
		http.Error(w, "failed to update discovery suppressions", http.StatusInternalServerError)
		return
	}
	if !removed {
		http.Error(w, "suppression not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handlePGPDiscoverySuppressContact is the explicit "remove key & stop
// rediscovering" action: it clears the contact's PGP key fields (keeping the
// contact) and records an explicit discovery opt-out for each of its
// addresses.
func (s *Server) handlePGPDiscoverySuppressContact(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		ContactUID string `json:"contactUID"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(req.ContactUID)
	if uid == "" {
		http.Error(w, "contactUID is required", http.StatusBadRequest)
		return
	}
	store, err := s.userContactsStore(ac.UserID)
	if err != nil {
		http.Error(w, "failed to open contacts store", http.StatusInternalServerError)
		return
	}
	c, found := store.Get(uid)
	if !found || c.Deleted {
		http.Error(w, "contact not found", http.StatusNotFound)
		return
	}
	dir := s.userStateDir(ac.UserID)
	for _, e := range c.Emails {
		if v := strings.TrimSpace(e.Value); v != "" {
			if err := pgpdiscovery.AddSuppression(dir, v, pgpdiscovery.ReasonExplicit); err != nil {
				http.Error(w, "failed to record discovery suppression", http.StatusInternalServerError)
				return
			}
		}
	}
	c.PGPKey = ""
	c.PGPKeySource = ""
	c.PGPKeyFingerprint = ""
	c.PGPKeyVerified = false
	updated, err := store.Upsert(c)
	if err != nil {
		http.Error(w, "failed to update contact", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
```

- [ ] **Step 4: Register the routes**

In `backend/internal/api/server.go`, immediately after the `PUT /api/pgp/discovery/settings` line (~line 348), add:

```go
	mux.HandleFunc("GET /api/pgp/discovery/suppressions", s.withAuth(s.handlePGPDiscoverySuppressions))
	mux.HandleFunc("DELETE /api/pgp/discovery/suppressions/{email}", s.withAuth(s.handlePGPDiscoverySuppressionByEmail))
	mux.HandleFunc("POST /api/pgp/discovery/suppress-contact", s.withAuth(s.handlePGPDiscoverySuppressContact))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /home/yoshi/git/kypost-server/backend && go test ./internal/api/ -run 'TestSuppressions|TestUnsuppress|TestSuppressContact' -v`
Expected: PASS (all three).

- [ ] **Step 6: Vet + full api suite**

Run: `cd /home/yoshi/git/kypost-server/backend && gofmt -l internal/api internal/pgpdiscovery internal/contacts && go vet ./internal/api/ && go test ./internal/api/`
Expected: `gofmt -l` prints nothing; vet clean; tests PASS.

- [ ] **Step 7: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add backend/internal/api/pgp_discovery_handlers.go backend/internal/api/server.go backend/internal/api/pgp_discovery_handlers_test.go
git commit -m "feat(pgp): add discovery-suppression management API"
```

---

### Task 6: Frontend — opt-out list, contact badge, explicit action

**Files:**
- Modify: `frontend/src/api/pgp.ts` (types + three clients)
- Modify: `frontend/src/api/contacts.ts` (extend the `Contact` type)
- Modify: `frontend/src/pages/SecurityPage.tsx` (opt-out list under the discovery section)
- Modify: `frontend/src/pages/ContactsPage.tsx` (badge + "remove key & stop rediscovering" action)

**Interfaces:**
- Consumes: the three Task 5 endpoints.
- Produces: `DiscoverySuppression` type, `listDiscoverySuppressions`, `removeDiscoverySuppression`, `suppressContactDiscovery` in `api/pgp.ts`; `discoveryCreated?`/`pgpKeySource?` on the frontend `Contact` type.

> Frontend verification is `tsc` + `vite build` (these pages have no unit-test harness, matching Spec A's frontend task).

- [ ] **Step 1: Add the API clients + types**

In `frontend/src/api/pgp.ts`, append:

```ts
export type DiscoverySuppression = {
  email: string;
  suppressedAt: string;
  reason: "deleted" | "explicit";
};

export function listDiscoverySuppressions(): Promise<{ suppressions: DiscoverySuppression[] }> {
  return getJSON<{ suppressions: DiscoverySuppression[] }>("/api/pgp/discovery/suppressions");
}

export function removeDiscoverySuppression(email: string): Promise<{ ok: boolean }> {
  return deleteJSON<{ ok: boolean }>(`/api/pgp/discovery/suppressions/${encodeURIComponent(email)}`);
}

export function suppressContactDiscovery(contactUID: string): Promise<{ uid: string }> {
  return postJSON<{ uid: string }>("/api/pgp/discovery/suppress-contact", { contactUID });
}
```

- [ ] **Step 2: Extend the frontend `Contact` type**

In `frontend/src/api/contacts.ts`, in `ContactExtendedFields`, add the discovery/provenance fields:

```ts
  pgpKey?: string;
  pgpKeySource?: string;
  pgpKeyFingerprint?: string;
  pgpKeyVerified?: boolean;
  discoveryCreated?: boolean;
```

(Replace the single existing `pgpKey?: string;` line with the block above.)

- [ ] **Step 3: Add the opt-out list to SecurityPage**

In `frontend/src/pages/SecurityPage.tsx`:

Add to the imports from `../api/pgp`:

```ts
  listDiscoverySuppressions,
  removeDiscoverySuppression,
  type DiscoverySuppression
```

Add state near the other discovery state (after `discoveryStatus`):

```tsx
  const [suppressions, setSuppressions] = useState<DiscoverySuppression[]>([]);
```

Add a load effect near the existing discovery-settings load effect:

```tsx
  useEffect(() => {
    let cancelled = false;
    listDiscoverySuppressions()
      .then((r) => {
        if (!cancelled) setSuppressions(r.suppressions);
      })
      .catch(() => {
        if (!cancelled) setSuppressions([]);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function allowDiscoveryAgain(email: string) {
    try {
      await removeDiscoverySuppression(email);
      setSuppressions((prev) => prev.filter((s) => s.email !== email));
    } catch {
      setDiscoveryStatus("Failed to update discovery opt-outs.");
    }
  }
```

Inside the `discoverySettings ? (...)` block, after the `{discoveryStatus ? ... : null}` line and before the closing `</div>`, add:

```tsx
              {suppressions.length > 0 ? (
                <div className="security-subsection">
                  <h5>Discovery opt-outs</h5>
                  <ul className="security-list">
                    {suppressions.map((s) => (
                      <li key={s.email}>
                        <span>
                          {s.email} <span className="contacts-muted">({s.reason})</span>
                        </span>
                        <button type="button" onClick={() => void allowDiscoveryAgain(s.email)}>
                          Allow discovery again
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
```

- [ ] **Step 4: Add the contact badge + explicit action to ContactsPage**

In `frontend/src/pages/ContactsPage.tsx`:

Extend the existing pgp import to include the new client:

```ts
import { getPGPIdentity, lookupPGPKeyserver, suppressContactDiscovery } from "../api/pgp";
```

In the contact-details PGP section (currently the `selectedContactPgpKey ? (...)` block around line 1593), add the badge and action inside that block, after the `<PGPKeyInfo .../>` line:

```tsx
                  {selectedContact.discoveryCreated ? (
                    <p className="contacts-muted">
                      Added automatically by key discovery
                      {selectedContact.pgpKeySource ? ` (${selectedContact.pgpKeySource})` : ""}
                    </p>
                  ) : null}
                  {!selectedContact.isSelf &&
                  (selectedContact.pgpKeySource === "wkd" || selectedContact.pgpKeySource === "keyserver") ? (
                    <button
                      type="button"
                      onClick={() => {
                        if (!selectedContact) return;
                        void suppressContactDiscovery(selectedContact.uid).then(() => void loadContacts());
                      }}
                    >
                      Remove key &amp; stop rediscovering
                    </button>
                  ) : null}
```

`loadContacts()` (defined ~line 302) is the existing re-fetch used after save/delete; calling it here refreshes the list so the cleared key + badge disappear.

- [ ] **Step 5: Typecheck**

Run: `cd /home/yoshi/git/kypost-server/frontend && npx tsc --noEmit`
Expected: no errors. (If the reload-function name was wrong, fix it here.)

- [ ] **Step 6: Build**

Run: `cd /home/yoshi/git/kypost-server/frontend && npm run build`
Expected: build succeeds.

- [ ] **Step 7: Commit**

```bash
cd /home/yoshi/git/kypost-server
git add frontend/src/api/pgp.ts frontend/src/api/contacts.ts frontend/src/pages/SecurityPage.tsx frontend/src/pages/ContactsPage.tsx
git commit -m "feat(pgp): surface discovery opt-outs and the reject-key action in the UI"
```

---

## Final verification

- [ ] **Backend:** `cd /home/yoshi/git/kypost-server/backend && gofmt -l internal/... ; go vet ./... && go test ./internal/api/ ./internal/pgpdiscovery/ ./internal/contacts/`
- [ ] **Frontend:** `cd /home/yoshi/git/kypost-server/frontend && npx tsc --noEmit && npm run build`
- [ ] Whole-branch code review (opus) per subagent-driven-development, then finishing-a-development-branch.

## Deferred (revisit only if it shows value)

- **D2** — dedicated "Discovered Keys" address book (segregate `DiscoveryCreated` contacts). Depends on multi-collection support (D3). `DiscoveryCreated` is the predicate it would segregate on.
- **D3** — general user-created multiple address books over CardDAV.
- **Sync-path parity** — implicit suppression is wired only on the web API delete paths (`handleContactByID`, `handleContactsBulkDelete`); CardDAV and mobile-sync deletes do not auto-suppress in D1 (same boundary as Spec A's manual-key fingerprint backfill).
