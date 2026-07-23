# PGP Key Discovery Ladder (Spec A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At encrypted-send time, automatically discover a recipient's real PGP public key (WKD, then keyserver) and send true end-to-end mail instead of the cleartext pickup-link fallback, pinning discovered keys to the contact with TOFU protection.

**Architecture:** A new `keyResolver` runs an ordered ladder — pinned contact key → WKD (auto-trust) → keyserver (confirm-first) → none — and is injected into `buildPGPRecipientPlan`. Discovered keys and their provenance (source, fingerprint pin, verified flag) are stored on the contact, gated by two new per-user settings. WKD lookups reuse the existing SSRF-safe HTTP client.

**Tech Stack:** Go 1.x, `github.com/ProtonMail/gopenpgp/v3/crypto`, stdlib `net/http` + `crypto/sha1`, existing `net/http.ServeMux`. Design doc: `docs/superpowers/specs/2026-07-23-pgp-key-discovery-design.md`.

## Global Constraints

- All outbound discovery HTTP MUST go through `newSSRFSafeHTTPClient` (`backend/internal/api/ssrf_guard.go:111`) — never `http.DefaultClient`.
- Discovery lookups run ONLY when encryption is enabled for a send (no speculative lookups).
- New contact JSON fields are optional and must be tolerated-when-absent (legacy contacts), matching `MergedUIDs`/`MergedInto` (`backend/internal/contacts/contacts.go:56-61`).
- Response bodies from remote hosts MUST be read through `io.LimitReader(body, 1<<20)`, as `pgp_keyserver.go:56` does.
- Follow existing table-test style; point remote base URLs at `httptest.Server` via a package var, mirroring `keyserverBaseURL` (`pgp_keyserver.go:18`).
- Run `gofmt` and `go vet ./...` before every commit; commit only backend files unless a task says otherwise.

---

### Task 1: WKD hashed-local-part encoder

**Files:**
- Create: `backend/internal/api/pgp_wkd.go`
- Test: `backend/internal/api/pgp_wkd_test.go`

**Interfaces:**
- Produces: `func wkdHashLocalPart(localPart string) string` — Z-Base-32 of SHA-1(lowercased local-part), 32 chars, no padding.

- [ ] **Step 1: Write the failing test**

```go
package api

import "testing"

func TestWKDHashLocalPart(t *testing.T) {
	// Canonical vector from the WKD spec (draft-koch-openpgp-webkey-service):
	// local-part "Joe.Doe" hashes to this z-base-32 string.
	got := wkdHashLocalPart("Joe.Doe")
	want := "iy9q119eutrkn8s1mk4r39qejnbu3n5q"
	if got != want {
		t.Fatalf("wkdHashLocalPart = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestWKDHashLocalPart -v`
Expected: FAIL — `undefined: wkdHashLocalPart`.

- [ ] **Step 3: Write minimal implementation**

```go
package api

import (
	"crypto/sha1"
	"strings"
)

// zBase32 is the alphabet from the Z-Base-32 encoding used by WKD.
const zBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

// wkdHashLocalPart returns the WKD "hashed local-part": the lowercased
// local-part hashed with SHA-1 and encoded with Z-Base-32 (no padding).
func wkdHashLocalPart(localPart string) string {
	sum := sha1.Sum([]byte(strings.ToLower(localPart)))
	var b strings.Builder
	bits := 0
	var acc uint32
	for _, c := range sum {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			b.WriteByte(zBase32[(acc>>uint(bits))&0x1f])
		}
	}
	if bits > 0 {
		b.WriteByte(zBase32[(acc<<uint(5-bits))&0x1f])
	}
	return b.String()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/api/ -run TestWKDHashLocalPart -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git add backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git commit -m "feat(pgp): add WKD hashed-local-part encoder"
```

---

### Task 2: Discovered-key validation helper

**Files:**
- Modify: `backend/internal/api/pgp_wkd.go`
- Test: `backend/internal/api/pgp_wkd_test.go`

**Interfaces:**
- Consumes: `pgpmail.CheckKeyStatus` (`backend/internal/pgpmail/keystatus.go:28`), `pgpmail.GenerateIdentity`.
- Produces: `func validateDiscoveredKey(armored, email string) (fingerprint string, err error)` — returns the key fingerprint iff the key parses, is usable (not revoked/expired), and carries `email` as a UID; otherwise an error.

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"testing"

	"kypost-server/backend/internal/pgpmail"
)

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestValidateDiscoveredKey -v`
Expected: FAIL — `undefined: validateDiscoveredKey`.

- [ ] **Step 3: Write minimal implementation**

Append to `pgp_wkd.go`:

```go
import (
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpmail"
)

// validateDiscoveredKey parses an armored public key obtained from an
// untrusted discovery source and confirms it is safe to auto-use for email:
// it must be usable (not revoked/expired) and actually carry email as a UID.
func validateDiscoveredKey(armored, email string) (string, error) {
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return "", fmt.Errorf("parse discovered key: %w", err)
	}
	status, err := pgpmail.CheckKeyStatus(armored)
	if err != nil {
		return "", err
	}
	if !status.Usable() {
		return "", fmt.Errorf("discovered key for %s is revoked or expired", email)
	}
	target := strings.ToLower(strings.TrimSpace(email))
	entity := key.GetEntity()
	if entity == nil {
		return "", fmt.Errorf("discovered key has no entity")
	}
	for _, uid := range entity.Identities {
		if strings.ToLower(strings.TrimSpace(uid.UserId.Email)) == target {
			return key.GetFingerprint(), nil
		}
	}
	return "", fmt.Errorf("discovered key does not carry %s as a user ID", email)
}
```

Merge the two `import` blocks in `pgp_wkd.go` into one (keep `crypto/sha1`, `strings`, `fmt`, `crypto`, `pgpmail`).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/api/ -run TestValidateDiscoveredKey -v`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git add backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git commit -m "feat(pgp): validate discovered keys against UID and status"
```

---

### Task 3: WKD fetch (advanced then direct)

**Files:**
- Modify: `backend/internal/api/pgp_wkd.go`
- Test: `backend/internal/api/pgp_wkd_test.go`

**Interfaces:**
- Consumes: `newSSRFSafeHTTPClient` (`ssrf_guard.go:111`), `validateDiscoveredKey` (Task 2).
- Produces:
  - `var wkdBaseURLOverride string` — when non-empty, tests use it as the scheme+host in place of the derived `https://openpgpkey.<domain>` / `https://<domain>`.
  - `func fetchWKDKey(ctx context.Context, email string) (armored, fingerprint string, err error)` — tries advanced then direct method, returns an armored public key validated for `email`.

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/pgpmail"
)

func TestFetchWKDKeyDirectMethod(t *testing.T) {
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
	_ = base64.StdEncoding // keep import if trimmed
}

func TestFetchWKDKeyNotFound(t *testing.T) {
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
```

> Note: `min` is a Go 1.21+ builtin; the repo targets ≥1.21. Remove the trailing `base64` line if `gofmt`/vet flags it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestFetchWKDKey -v`
Expected: FAIL — `undefined: fetchWKDKey` / `undefined: wkdBaseURLOverride`.

- [ ] **Step 3: Write minimal implementation**

Append to `pgp_wkd.go` (add `context`, `io`, `net/http`, `net/url`, `time` to imports):

```go
// wkdBaseURLOverride, when set (tests only), replaces the derived
// scheme+host so lookups hit an httptest.Server. Mirrors keyserverBaseURL.
var wkdBaseURLOverride string

// wkdCandidateURLs returns the advanced-method URL first, then the
// direct-method URL, for the given local-part/domain.
func wkdCandidateURLs(localPart, domain string) []string {
	hu := wkdHashLocalPart(localPart)
	l := url.QueryEscape(localPart)
	if wkdBaseURLOverride != "" {
		// Tests: single host serves the direct-method path.
		return []string{
			wkdBaseURLOverride + "/.well-known/openpgpkey/hu/" + hu + "?l=" + l,
		}
	}
	return []string{
		"https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + "/hu/" + hu + "?l=" + l,
		"https://" + domain + "/.well-known/openpgpkey/hu/" + hu + "?l=" + l,
	}
}

// fetchWKDKey attempts Web Key Directory discovery for email, trying the
// advanced method then the direct method. It returns an armored public key
// validated to carry email as a UID and to be currently usable.
func fetchWKDKey(ctx context.Context, email string) (string, string, error) {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", fmt.Errorf("invalid email %q", email)
	}
	localPart, domain := email[:at], email[at+1:]
	client := newSSRFSafeHTTPClient(10 * time.Second)

	var lastErr error
	for _, u := range wkdCandidateURLs(localPart, domain) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || readErr != nil {
			lastErr = fmt.Errorf("wkd %s: status %d", u, resp.StatusCode)
			continue
		}
		key, err := crypto.NewKey(body) // WKD serves binary keys
		if err != nil {
			lastErr = fmt.Errorf("wkd %s: parse: %w", u, err)
			continue
		}
		armored, err := key.GetArmoredPublicKey()
		if err != nil {
			lastErr = err
			continue
		}
		fp, err := validateDiscoveredKey(armored, email)
		if err != nil {
			lastErr = err
			continue
		}
		return armored, fp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no WKD key for %s", email)
	}
	return "", "", lastErr
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/api/ -run TestFetchWKDKey -v`
Expected: PASS (both cases).

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git add backend/internal/api/pgp_wkd.go backend/internal/api/pgp_wkd_test.go
git commit -m "feat(pgp): add WKD fetch (advanced then direct method)"
```

---

### Task 4: Extract reusable keyserver lookup

**Files:**
- Modify: `backend/internal/api/pgp_keyserver.go`
- Test: `backend/internal/api/pgp_keyserver_test.go`

**Interfaces:**
- Produces: `func keyserverLookup(ctx context.Context, email string) (armored, fingerprint string, err error)` — the core of `handlePGPKeyserverLookup`, returning a validated armored key.
- `handlePGPKeyserverLookup` is refactored to call it.

- [ ] **Step 1: Write the failing test**

```go
func TestKeyserverLookupReturnsKey(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Carol", "carol@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(id.ArmoredPublicKey))
	}))
	defer srv.Close()
	old := keyserverBaseURL
	keyserverBaseURL = srv.URL
	defer func() { keyserverBaseURL = old }()

	armored, fp, err := keyserverLookup(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("keyserverLookup: %v", err)
	}
	if fp == "" || !strings.Contains(armored, "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("unexpected result fp=%q", fp)
	}
}
```

Add imports `context`, `strings`, `net/http`, `net/http/httptest`, `kypost-server/backend/internal/pgpmail` to the test file if missing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestKeyserverLookupReturnsKey -v`
Expected: FAIL — `undefined: keyserverLookup`.

- [ ] **Step 3: Write minimal implementation**

Add to `pgp_keyserver.go`:

```go
// keyserverLookup queries keys.openpgp.org for email and returns a validated
// armored key. Shared by handlePGPKeyserverLookup and the send-time ladder.
func keyserverLookup(ctx context.Context, email string) (string, string, error) {
	lookupURL := keyserverBaseURL + "/vks/v1/by-email/" + url.PathEscape(email)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := newSSRFSafeHTTPClient(10 * time.Second).Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("keyserver status %d", resp.StatusCode)
	}
	armored, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	fp, err := validateDiscoveredKey(string(armored), email)
	if err != nil {
		return "", "", err
	}
	return string(armored), fp, nil
}
```

Then simplify `handlePGPKeyserverLookup` to call `keyserverLookup(r.Context(), email)` and map its error to the existing 404/502 responses (preserve current status-code behavior for the not-found and bad-gateway cases).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./backend/internal/api/ -run 'TestKeyserver|TestPGPKeyserver' -v`
Expected: PASS, including the pre-existing keyserver handler tests.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/pgp_keyserver.go backend/internal/api/pgp_keyserver_test.go
git add backend/internal/api/pgp_keyserver.go backend/internal/api/pgp_keyserver_test.go
git commit -m "refactor(pgp): extract reusable keyserverLookup"
```

---

### Task 5: Contact provenance fields + setter

**Files:**
- Modify: `backend/internal/contacts/contacts.go`
- Test: `backend/internal/contacts/contacts_provenance_test.go` (create)

**Interfaces:**
- Produces on `contacts.Contact`: `PGPKeySource string`, `PGPKeyFingerprint string`, `PGPKeyVerified bool` (JSON `pgpKeySource`, `pgpKeyFingerprint`, `pgpKeyVerified`, all `omitempty`).
- Source constants: `PGPSourceManual`, `PGPSourceQR`, `PGPSourceWKD`, `PGPSourceKeyserver`.

- [ ] **Step 1: Write the failing test**

```go
package contacts

import (
	"encoding/json"
	"testing"
)

func TestContactProvenanceRoundTrips(t *testing.T) {
	c := Contact{
		FormattedName:     "Dana",
		PGPKey:            "ARMORED",
		PGPKeySource:      PGPSourceWKD,
		PGPKeyFingerprint: "ABC123",
		PGPKeyVerified:    false,
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Contact
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.PGPKeySource != PGPSourceWKD || back.PGPKeyFingerprint != "ABC123" {
		t.Fatalf("provenance not preserved: %+v", back)
	}
}

func TestLegacyContactMissingProvenanceIsTolerated(t *testing.T) {
	var c Contact
	if err := json.Unmarshal([]byte(`{"fn":"Old","pgpKey":"K"}`), &c); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if c.PGPKeySource != "" || c.PGPKeyVerified {
		t.Fatalf("legacy defaults wrong: %+v", c)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/contacts/ -run 'Provenance|Legacy' -v`
Expected: FAIL — `undefined: PGPSourceWKD` / unknown fields.

- [ ] **Step 3: Write minimal implementation**

In `contacts.go`, add after the `PGPKey` field (line 45):

```go
	PGPKeySource       string               `json:"pgpKeySource,omitempty"`      // manual|qr|wkd|keyserver
	PGPKeyFingerprint  string               `json:"pgpKeyFingerprint,omitempty"` // TOFU pin (first-seen fingerprint)
	PGPKeyVerified     bool                 `json:"pgpKeyVerified,omitempty"`    // user eyeballed the fingerprint / came via QR
```

And package-level constants:

```go
const (
	PGPSourceManual    = "manual"
	PGPSourceQR        = "qr"
	PGPSourceWKD       = "wkd"
	PGPSourceKeyserver = "keyserver"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/contacts/ -run 'Provenance|Legacy' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/contacts/contacts.go backend/internal/contacts/contacts_provenance_test.go
git add backend/internal/contacts/contacts.go backend/internal/contacts/contacts_provenance_test.go
git commit -m "feat(contacts): add PGP key provenance fields"
```

---

### Task 6: Per-user PGP discovery settings store

**Files:**
- Create: `backend/internal/pgpdiscovery/settings.go`
- Test: `backend/internal/pgpdiscovery/settings_test.go`

**Interfaces:**
- Produces:
  - `type Settings struct { AutoEncryptWhenKeyKnown bool; StoreDiscoveredKeys bool }`
  - `func Load(dir string) (Settings, error)` — reads `<dir>/pgp-discovery.json`; when the file is absent returns defaults `{AutoEncryptWhenKeyKnown:false, StoreDiscoveredKeys:true}`.
  - `func Save(dir string, s Settings) error` — atomic write, `0o600`.

- [ ] **Step 1: Write the failing test**

```go
package pgpdiscovery

import (
	"testing"
)

func TestDefaultsWhenAbsent(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s.AutoEncryptWhenKeyKnown {
		t.Fatalf("AutoEncryptWhenKeyKnown default should be false")
	}
	if !s.StoreDiscoveredKeys {
		t.Fatalf("StoreDiscoveredKeys default should be true")
	}
}

func TestSaveThenLoad(t *testing.T) {
	dir := t.TempDir()
	want := Settings{AutoEncryptWhenKeyKnown: true, StoreDiscoveredKeys: false}
	if err := Save(dir, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/pgpdiscovery/ -v`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Write minimal implementation**

```go
package pgpdiscovery

import (
	"encoding/json"
	"os"
	"path/filepath"

	"kypost-server/backend/internal/fsutil"
)

type Settings struct {
	AutoEncryptWhenKeyKnown bool `json:"autoEncryptWhenKeyKnown"`
	StoreDiscoveredKeys     bool `json:"storeDiscoveredKeys"`
}

func path(dir string) string { return filepath.Join(dir, "pgp-discovery.json") }

// Load reads settings, returning defaults (auto-encrypt off, store keys on)
// when the file does not exist.
func Load(dir string) (Settings, error) {
	b, err := os.ReadFile(path(dir))
	if os.IsNotExist(err) {
		return Settings{AutoEncryptWhenKeyKnown: false, StoreDiscoveredKeys: true}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, err
	}
	return s, nil
}

func Save(dir string, s Settings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return fsutil.AtomicWriteFile(path(dir), b, 0o600)
}
```

> `fsutil.AtomicWriteFile` is the same helper `pickup.go:88` uses. Confirm its signature by reading `backend/internal/fsutil`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/pgpdiscovery/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/pgpdiscovery/
git add backend/internal/pgpdiscovery/
git commit -m "feat(pgp): per-user key-discovery settings store"
```

---

### Task 7: Key resolver with TOFU pinning + write-back

**Files:**
- Create: `backend/internal/api/pgp_resolver.go`
- Test: `backend/internal/api/pgp_resolver_test.go`

**Interfaces:**
- Consumes: `findContactPGPKey` (`server.go:765`), `fetchWKDKey` (Task 3), `keyserverLookup` (Task 4), `contacts.Store`, `pgpmail.CheckKeyStatus`, `pgpdiscovery.Settings`.
- Produces:
  - `type resolveTier string` with values `tierContactVerified`, `tierWKD`, `tierKeyserverConfirm`, `tierKeyChanged`, `tierNone`.
  - `type resolvedKey struct { Armored string; Fingerprint string; Tier resolveTier; Usable bool }`
  - `type keyResolver struct { store *contacts.Store; settings pgpdiscovery.Settings; discover bool }`
  - `func (kr *keyResolver) resolve(ctx context.Context, email string) resolvedKey`

Behavior:
1. Pinned contact key present & usable → `{Usable:true, Tier:tierContactVerified}` (silent).
2. Else if `discover`: WKD → validate; if a contact key is pinned with a *different* fingerprint → `{Usable:false, Tier:tierKeyChanged}` (no switch). Otherwise `{Usable:true, Tier:tierWKD}` and, if `settings.StoreDiscoveredKeys`, pin to contact (`source=wkd`, `verified=false`, create minimal contact if none).
3. Else if `discover`: keyserver → same TOFU check; on hit return `{Usable:false, Tier:tierKeyserverConfirm}` (needs user confirm — not auto-encrypted this pass; pin only after explicit confirm via the existing keyserver-confirm UI).
4. Else `{Usable:false, Tier:tierNone}`.

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

func TestResolveUsesWKDAndPinsContact(t *testing.T) {
	id, err := pgpmail.GenerateIdentity("Erin", "erin@example.com")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	key, _ := crypto.NewKeyFromArmored(id.ArmoredPublicKey)
	binKey, _ := key.GetPublicKey()
	hu := wkdHashLocalPart("erin")
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

	got := kr.resolve(context.Background(), "erin@example.com")
	if !got.Usable || got.Tier != tierWKD {
		t.Fatalf("expected usable WKD tier, got %+v", got)
	}
	if _, ok := findContactPGPKey(store, "erin@example.com"); !ok {
		t.Fatalf("expected the WKD key to be pinned to a contact")
	}
}

func TestResolveTOFUMismatchDoesNotSwitch(t *testing.T) {
	// Contact pinned with fingerprint X; WKD returns a different key Y.
	// Expect tierKeyChanged and Usable == false.
	// (Construct via two GenerateIdentity calls; pin the first, serve the second.)
	t.Skip("implement with two identities per the resolver contract")
}
```

> Replace the `t.Skip` with a full mismatch test once the happy path compiles — pin identity A's key + fingerprint to a contact, serve identity B over WKD, assert `tierKeyChanged` and no pin change. Confirm `contacts.New` and the store's create/update methods by reading `backend/internal/contacts/store.go` before writing.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestResolveUsesWKD -v`
Expected: FAIL — resolver types undefined.

- [ ] **Step 3: Write minimal implementation**

Create `pgp_resolver.go`:

```go
package api

import (
	"context"
	"strings"

	"kypost-server/backend/internal/contacts"
	"kypost-server/backend/internal/pgpdiscovery"
	"kypost-server/backend/internal/pgpmail"
)

type resolveTier string

const (
	tierContactVerified  resolveTier = "verified"
	tierWKD              resolveTier = "wkd"
	tierKeyserverConfirm resolveTier = "keyserver_confirm"
	tierKeyChanged       resolveTier = "key_changed"
	tierNone             resolveTier = "none"
)

type resolvedKey struct {
	Armored     string
	Fingerprint string
	Tier        resolveTier
	Usable      bool
}

type keyResolver struct {
	store    *contacts.Store
	settings pgpdiscovery.Settings
	discover bool
}

// findContact returns the first contact whose email matches, case-insensitively.
func findContact(store *contacts.Store, email string) (contacts.Contact, bool) {
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

// pin writes a discovered key + provenance to the matching contact, creating
// a minimal contact if none exists. Upsert assigns the UID when empty.
func (kr *keyResolver) pin(email, armored, fingerprint, source string) {
	c, ok := findContact(kr.store, email)
	if !ok {
		c = contacts.Contact{
			FormattedName: email,
			Emails:        []contacts.ContactValue{{Value: email}},
		}
	}
	c.PGPKey = armored
	c.PGPKeySource = source
	c.PGPKeyFingerprint = fingerprint
	c.PGPKeyVerified = false
	_, _ = kr.store.Upsert(c)
}

// resolve runs the discovery ladder for one recipient.
func (kr *keyResolver) resolve(ctx context.Context, email string) resolvedKey {
	c, hasContact := findContact(kr.store, email)
	pinnedFP := ""
	if hasContact && c.PGPKey != "" {
		if st, err := pgpmail.CheckKeyStatus(c.PGPKey); err == nil && st.Usable() {
			return resolvedKey{Armored: c.PGPKey, Fingerprint: c.PGPKeyFingerprint, Tier: tierContactVerified, Usable: true}
		}
		pinnedFP = c.PGPKeyFingerprint
	}
	if !kr.discover {
		return resolvedKey{Tier: tierNone}
	}

	if armored, fp, err := fetchWKDKey(ctx, email); err == nil {
		if pinnedFP != "" && !strings.EqualFold(pinnedFP, fp) {
			return resolvedKey{Tier: tierKeyChanged}
		}
		if kr.settings.StoreDiscoveredKeys {
			kr.pin(email, armored, fp, contacts.PGPSourceWKD)
		}
		return resolvedKey{Armored: armored, Fingerprint: fp, Tier: tierWKD, Usable: true}
	}

	if _, fp, err := keyserverLookup(ctx, email); err == nil {
		if pinnedFP != "" && !strings.EqualFold(pinnedFP, fp) {
			return resolvedKey{Tier: tierKeyChanged}
		}
		return resolvedKey{Fingerprint: fp, Tier: tierKeyserverConfirm}
	}

	return resolvedKey{Tier: tierNone}
}
```

Confirm `contacts.ContactValue`'s field name (`Value`) against `contacts.go:37` before compiling.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./backend/internal/api/ -run TestResolve -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/pgp_resolver.go backend/internal/api/pgp_resolver_test.go
git add backend/internal/api/pgp_resolver.go backend/internal/api/pgp_resolver_test.go
git commit -m "feat(pgp): key resolver with WKD/keyserver ladder and TOFU pinning"
```

---

### Task 8: Wire the resolver into the send path

**Files:**
- Modify: `backend/internal/api/server.go` (`buildPGPRecipientPlan` ~804-848, call site ~1031)
- Modify: `backend/internal/api/server_mail_pgp_test.go` (call sites 222, 426)
- Test: add `backend/internal/api/server_mail_pgp_discovery_test.go`

**Interfaces:**
- Consumes: `keyResolver` (Task 7).
- Produces: `buildPGPRecipientPlan(ctx, toList, ccList, bccList, resolver *keyResolver) pgpRecipientPlan`, where the `resolve` closure delegates to `resolver.resolve(ctx, recipient)` and treats only `Usable` keys as encryptable (WKD/contact); `tierKeyserverConfirm` and `tierKeyChanged` fall into `withoutKeyEmails` for this pass (surfaced to the user by Task 9 for confirmation).

- [ ] **Step 1: Write the failing test**

Add a test that builds a resolver with `discover:true` pointed at a WKD `httptest.Server` (as in Task 7) and asserts `buildPGPRecipientPlan` places the WKD recipient in `toCCEmails`/`toCCKeys`, not `withoutKeyEmails`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestBuildPlanUsesDiscovery -v`
Expected: FAIL (signature mismatch / recipient in wrong bucket).

- [ ] **Step 3: Write minimal implementation**

Change `buildPGPRecipientPlan` to take `ctx context.Context` and `resolver *keyResolver`; replace the inline `resolve` closure body with:

```go
	resolve := func(recipient string) (string, bool) {
		rk := resolver.resolve(ctx, recipient)
		return rk.Armored, rk.Usable
	}
```

Update the call site (server.go:1031) to construct the resolver from the calling user's contacts store + loaded `pgpdiscovery.Settings` + `discover = <encryption requested for this send>`, and pass `r.Context()`. Update the two existing test call sites to pass `context.Background()` and a contact-only resolver (`&keyResolver{store: contactsStore, discover: false}`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./backend/internal/api/ -run 'TestBuildPlan|TestBuildPGPDeliveries|TestPGP' -v`
Expected: PASS (new discovery test + all pre-existing plan/delivery tests).

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/server.go backend/internal/api/server_mail_pgp_test.go backend/internal/api/server_mail_pgp_discovery_test.go
git add backend/internal/api/server.go backend/internal/api/server_mail_pgp_test.go backend/internal/api/server_mail_pgp_discovery_test.go
git commit -m "feat(pgp): use key-discovery resolver in the send path"
```

---

### Task 9: HTTP surface — settings endpoints + recipient-check tiers

**Files:**
- Modify: `backend/internal/api/pgp_keyserver.go` (`handlePGPRecipientsCheck` ~82)
- Create: `backend/internal/api/pgp_discovery_handlers.go` (settings GET/PUT)
- Modify: `backend/internal/api/server.go` (route registration ~265)
- Test: `backend/internal/api/pgp_discovery_handlers_test.go`

**Interfaces:**
- `GET /api/pgp/discovery/settings` → `{autoEncryptWhenKeyKnown, storeDiscoveredKeys}`.
- `PUT /api/pgp/discovery/settings` (same body) → persists via `pgpdiscovery.Save(s.userStateDir(userID), …)`.
- `handlePGPRecipientsCheck` response `addressStatus` gains `Tier string` (`verified` | `wkd` | `keyserver_confirm` | `key_changed` | `none`) computed via a `keyResolver` with `discover` set from a query flag (only run network lookups when the client signals encryption is on).

- [ ] **Step 1: Write the failing test**

Test the settings round-trip through the handlers with `doJSONAuth` (used in `server_push_mfa_test.go:29`): PUT `{autoEncryptWhenKeyKnown:true,storeDiscoveredKeys:false}`, then GET returns the same.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./backend/internal/api/ -run TestDiscoverySettingsRoundTrip -v`
Expected: FAIL — handlers/routes undefined.

- [ ] **Step 3: Write minimal implementation**

Implement the two handlers reading/writing `pgpdiscovery` under `s.userStateDir(ac.UserID)` (auth via `authFromContext`, as `handlePGPRecipientsCheck` does at `pgp_keyserver.go:83`). Register:

```go
	mux.HandleFunc("GET /api/pgp/discovery/settings", s.withAuth(s.handlePGPDiscoverySettings))
	mux.HandleFunc("PUT /api/pgp/discovery/settings", s.withAuth(s.handlePGPDiscoverySettings))
```

Extend `handlePGPRecipientsCheck` to set `Tier` per address (contact-only unless the request opts into discovery).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./backend/internal/api/ -run 'TestDiscoverySettings|TestPGPRecipients' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w backend/internal/api/
git add backend/internal/api/pgp_discovery_handlers.go backend/internal/api/pgp_keyserver.go backend/internal/api/server.go backend/internal/api/pgp_discovery_handlers_test.go
git commit -m "feat(pgp): discovery settings API and recipient-check tiers"
```

---

### Task 10: Frontend wiring (web)

**Files:**
- Modify: `frontend/src/pages/SecurityPage.tsx` — two toggles bound to `GET/PUT /api/pgp/discovery/settings`.
- Modify: the compose recipient-status component + `frontend/src/api/pgp.ts` — render the new `tier` values (verified 🔒 / wkd 🔒 / keyserver_confirm ⚠️ / key_changed ⚠️ / none) and collect the one-time keyserver/key-changed confirmations before send.

**Interfaces:**
- Consumes: the Task 9 endpoints and the extended `handlePGPRecipientsCheck` response.

- [ ] **Step 1: Add the settings toggles**

In `SecurityPage.tsx`, add "Encrypt automatically when I have a recipient's key" (`autoEncryptWhenKeyKnown`) and "Save keys I discover to my contacts" (`storeDiscoveredKeys`, default on), following the existing settings-row pattern in that file. Load on mount from the GET endpoint; PUT on change.

- [ ] **Step 2: Render recipient tiers in compose**

In `frontend/src/api/pgp.ts`, extend the recipients-check response type with `tier`. In the compose recipient chips/status area, map each tier to its badge and, for `keyserver_confirm` / `key_changed`, show the fingerprint and a confirm control that pins the key (reuse the existing keyserver-lookup confirm path).

- [ ] **Step 3: Manual verification**

Run the app (`/run` or the repo's dev command), open Security settings, toggle both switches, reload, confirm they persist. Compose to an address with a WKD-published key with encryption on; confirm it shows "found via WKD 🔒" and sends encrypted (not a pickup link).

- [ ] **Step 4: Commit**

```bash
git add frontend/src/pages/SecurityPage.tsx frontend/src/api/pgp.ts frontend/src/<compose-component>
git commit -m "feat(pgp): surface discovery settings and recipient key tiers in the UI"
```

---

## Verification (whole feature)

- [ ] `go test ./backend/...` passes.
- [ ] `go vet ./backend/...` clean; `gofmt -l backend` prints nothing.
- [ ] **Ladder**: contact key → silent; WKD key → auto-pin + encrypt; keyserver-only → confirm prompt; none → pickup fallback (unchanged).
- [ ] **TOFU**: pinned fingerprint + changed WKD result → `key_changed`, no silent switch, no auto-encrypt.
- [ ] **Auto-encrypt switch**: ON + all recipients have known keys → encryption auto-enabled; one unknown → not forced; no WKD lookup fires until encryption is on.
- [ ] **Storage toggle**: OFF → send still encrypts via discovery but no contact/pin is written; ON → key pinned / minimal contact created.
- [ ] **E2E**: with a real WKD-published test address, an encrypted send delivers ciphertext, not a pickup link.

## Notes / follow-ups (out of scope here)

- Auto-created discovered-key contacts currently land in the user's single contacts store; **Spec D** later segregates them into a "Discovered Keys" address book and adds remove-and-suppress. The `StoreDiscoveredKeys` toggle (Task 6) is the global off-switch until then.
- Autocrypt tier (**Spec B**) and outbound WKD/Autocrypt publishing (**Spec C**) are separate specs; the `resolveTier` enum and `PGPKeySource` constants are designed to extend with an `autocrypt` value.
