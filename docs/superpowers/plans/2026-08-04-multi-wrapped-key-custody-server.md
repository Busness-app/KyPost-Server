# Multi-Wrapped Key Custody (server side) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one client-protected PGP identity carry several independent wrapped envelopes, so a forgotten account password stops destroying the mailbox.

**Architecture:** The password envelope stays exactly where it is, in `User.PGPPrivateKeyWrapped`. Additional sealings — a recovery-code envelope now, per-device envelopes later — go in a new `PGPWrappedEnvelopes` list, and a `WrappedEnvelopes()` accessor presents both as one set. That keeps every existing read path working, needs no migration pass over `users.json`, and gives exactly one writer per slot kind. The server never interprets any envelope.

**Tech Stack:** Go 1.x, stdlib `net/http` with `mux.HandleFunc`, JSON-file user store, table-driven `testing` tests with no mocking framework.

**Scope:** This plan is the **server side only**. The browser work — generating the recovery code, wrapping under it, showing it once, and unlocking from it — is a separate plan against `frontend/src/lib/keyVault.ts` and the Security page, to be written after these endpoints exist. Nothing here is user-visible on its own; it is the storage and transport the browser plan builds on.

**Spec:** `docs/superpowers/specs/2026-08-04-multi-wrapped-key-custody-design.md` (Change 1).

## Global Constraints

- Read the DOX chain before editing: root `AGENTS.md`, then `backend/AGENTS.md`. Run a DOX pass after.
- Ponytail rules apply: reuse before adding, no unrequested abstractions, shortest working diff once the problem is understood.
- **The server never interprets an envelope.** It stores an opaque string and bounds its length. No parsing, no validation of contents.
- Envelope size cap is the existing `maxWrappedKeyBytes` (`backend/internal/api/pgp_client_keys.go:17`), 128 KiB. Reuse it; do not define a second cap.
- Slot-writing endpoints are `s.withAuth` (**session only**), never `s.withMailAuth`. A paired device must not be able to mint an envelope slot — that is the enforcement point the spec's tier-3 relies on.
- Existing response fields keep their current names and meanings. `wrappedPrivateKey` in `/api/pgp/bootstrap` stays the password envelope; older clients must not notice this change.
- Tests use `t.TempDir()` + `LoadOrMigrate`, per `backend/internal/users/pgp_test.go:9-18`. No mocking framework.
- New user-store errors go in the existing `var (...)` block at `backend/internal/users/users.go:202` and get mapped in `writeUserStoreError`.

## File Structure

| File | Responsibility |
|---|---|
| `backend/internal/users/users.go` | `WrappedEnvelope` type, slot constants, slot validation, `User.WrappedEnvelopes()`, store write/delete methods, stale-slot clearing |
| `backend/internal/users/multi_envelope_test.go` (new) | Every test in Tasks 1–3 |
| `backend/internal/api/pgp_client_keys.go` | The two new HTTP handlers |
| `backend/internal/api/pgp_bootstrap.go` | Expose which slots exist |
| `backend/internal/api/server.go` | Two route registrations |
| `backend/internal/api/pgp_multi_envelope_test.go` (new) | Handler-level tests for Tasks 4–5 |

---

### Task 1: The envelope set and its accessor

**Files:**
- Modify: `backend/internal/users/users.go` (type + constants near the PGP block at :90-133; validation helper alongside)
- Test: `backend/internal/users/multi_envelope_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `users.WrappedEnvelope{Slot, Envelope, AddedAt string}`; constants `users.EnvelopeSlotPassword = "password"`, `users.EnvelopeSlotRecovery = "recovery"`, `users.EnvelopeSlotDevicePrefix = "device:"`; `users.ValidEnvelopeSlot(slot string) bool`; method `(User).WrappedEnvelopes() []WrappedEnvelope`.

- [ ] **Step 1: Write the failing test**

Create `backend/internal/users/multi_envelope_test.go`:

```go
package users

import "testing"

func TestValidEnvelopeSlot(t *testing.T) {
	tests := []struct {
		slot string
		want bool
	}{
		{"recovery", true},
		{"device:abc123", true},
		{"password", false}, // written only via RewrapPGPPrivateKey
		{"device:", false},
		{"", false},
		{"nonsense", false},
		{"device:has space", false},
		{"device:has\nnewline", false},
	}
	for _, tc := range tests {
		if got := ValidEnvelopeSlot(tc.slot); got != tc.want {
			t.Errorf("ValidEnvelopeSlot(%q) = %v, want %v", tc.slot, got, tc.want)
		}
	}
}

// The legacy single-blob field must present as the password slot, so callers
// have one way to ask "every sealing of this key" and legacy accounts need no
// migration pass over users.json.
func TestWrappedEnvelopesSynthesisesLegacyPasswordSlot(t *testing.T) {
	u := User{PGPPrivateKeyWrapped: `{"v":2}`}
	got := u.WrappedEnvelopes()
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[0].Envelope != `{"v":2}` {
		t.Fatalf("unexpected entry: %+v", got[0])
	}
}

func TestWrappedEnvelopesCombinesLegacyAndList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: `{"v":2,"slot":"pw"}`,
		PGPWrappedEnvelopes: []WrappedEnvelope{
			{Slot: EnvelopeSlotRecovery, Envelope: `{"v":2,"slot":"rec"}`},
		},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if got[0].Slot != EnvelopeSlotPassword || got[1].Slot != EnvelopeSlotRecovery {
		t.Fatalf("unexpected order/slots: %+v", got)
	}
}

// A list entry claiming the password slot must not shadow the legacy field:
// one slot, one writer. Otherwise a caller that could write the list could
// replace the password envelope without going through RewrapPGPPrivateKey and
// its ErrNotClientProtected guard.
func TestWrappedEnvelopesIgnoresPasswordSlotInList(t *testing.T) {
	u := User{
		PGPPrivateKeyWrapped: "legit",
		PGPWrappedEnvelopes:  []WrappedEnvelope{{Slot: EnvelopeSlotPassword, Envelope: "impostor"}},
	}
	got := u.WrappedEnvelopes()
	if len(got) != 1 || got[0].Envelope != "legit" {
		t.Fatalf("list entry shadowed the legacy password envelope: %+v", got)
	}
}

func TestWrappedEnvelopesEmptyWhenNoIdentity(t *testing.T) {
	if got := (User{}).WrappedEnvelopes(); len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/users/ -run 'TestValidEnvelopeSlot|TestWrappedEnvelopes' -v`
Expected: FAIL — compile error, `WrappedEnvelope`, `ValidEnvelopeSlot`, `PGPWrappedEnvelopes` and `WrappedEnvelopes` are undefined.

- [ ] **Step 3: Write minimal implementation**

In `backend/internal/users/users.go`, add the field to `User` immediately after `PGPPrivateKeyWrapped` (:113):

```go
	// PGPWrappedEnvelopes holds every sealing of the private key OTHER than the
	// password one, which stays in PGPPrivateKeyWrapped above. Splitting them
	// this way is what lets existing users.json files load unchanged: the legacy
	// field is still the password envelope, and WrappedEnvelopes() presents both
	// as one set. Each entry is opaque here, exactly like PGPPrivateKeyWrapped.
	PGPWrappedEnvelopes []WrappedEnvelope `json:"pgpWrappedEnvelopes,omitempty"`
```

Then, after the `PGPProtection()` method (which this deliberately mirrors — both synthesise a modern view from legacy fields):

```go
// WrappedEnvelope is one sealing of an account's PGP private key.
//
// Several may exist for one identity, each sealed under a different
// key-encryption key — the account password, a recovery code, an enrolled
// device — so that losing any single one is survivable. Envelope is opaque to
// this server in exactly the sense PGPPrivateKeyWrapped is: stored, returned to
// the owning user, never interpreted.
type WrappedEnvelope struct {
	Slot     string `json:"slot"`
	Envelope string `json:"envelope"`
	AddedAt  string `json:"addedAt,omitempty"`
}

// Envelope slot names. "password" is not writable through the slot API: it
// lives in PGPPrivateKeyWrapped and is written only by RewrapPGPPrivateKey,
// which carries the ErrNotClientProtected guard that endpoint needs.
const (
	EnvelopeSlotPassword   = "password"
	EnvelopeSlotRecovery   = "recovery"
	EnvelopeSlotDevicePrefix = "device:"
)

// maxDeviceSlotIDLen bounds the caller-chosen half of a device slot name. The
// name is echoed back to clients and used as a map-ish key, so it is bounded
// and kept free of whitespace rather than trusted.
const maxDeviceSlotIDLen = 128

// ValidEnvelopeSlot reports whether slot may be written through the slot API.
func ValidEnvelopeSlot(slot string) bool {
	if slot == EnvelopeSlotRecovery {
		return true
	}
	id, ok := strings.CutPrefix(slot, EnvelopeSlotDevicePrefix)
	return ok && id != "" && len(id) <= maxDeviceSlotIDLen && !strings.ContainsAny(id, " \t\r\n")
}

// WrappedEnvelopes returns every sealing of this identity's private key, with
// PGPPrivateKeyWrapped synthesised as the password slot and listed first.
//
// A list entry claiming the password slot is ignored rather than merged: one
// slot has one writer, and honouring it here would let the slot API replace the
// password envelope without RewrapPGPPrivateKey's guard.
func (u User) WrappedEnvelopes() []WrappedEnvelope {
	out := make([]WrappedEnvelope, 0, len(u.PGPWrappedEnvelopes)+1)
	if strings.TrimSpace(u.PGPPrivateKeyWrapped) != "" {
		out = append(out, WrappedEnvelope{
			Slot:     EnvelopeSlotPassword,
			Envelope: u.PGPPrivateKeyWrapped,
		})
	}
	for _, e := range u.PGPWrappedEnvelopes {
		if e.Slot == EnvelopeSlotPassword {
			continue
		}
		out = append(out, e)
	}
	return out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/users/ -run 'TestValidEnvelopeSlot|TestWrappedEnvelopes' -v`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/users/users.go backend/internal/users/multi_envelope_test.go
git commit -m "feat(pgp): add the wrapped-envelope set alongside the password envelope"
```

---

### Task 2: Store writes for non-password slots

**Files:**
- Modify: `backend/internal/users/users.go` (new methods after `RewrapPGPPrivateKey`; new error in the `var (...)` block at :202)
- Test: `backend/internal/users/multi_envelope_test.go` (append)

**Interfaces:**
- Consumes: `WrappedEnvelope`, `ValidEnvelopeSlot`, `EnvelopeSlotRecovery` from Task 1.
- Produces: `(*Store).SetPGPWrappedEnvelope(id, slot, envelope, addedAt string) (User, error)`; `(*Store).DeletePGPWrappedEnvelope(id, slot string) (User, error)`; `users.ErrInvalidEnvelopeSlot`.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/users/multi_envelope_test.go`. **Merge these imports into the file's existing single import block** — Task 1 created it with only `"testing"`, and a second `import (...)` after a function declaration does not compile. The block becomes `context`, `errors`, `path/filepath`, `testing`:

```go
func newClientProtectedUser(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "slotuser", "pw-slotuser-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPGPIdentityClientProtected(u.ID, "FPR", "KID",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":true}`, "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return store, u.ID
}

func TestSetPGPWrappedEnvelopeAddsAndReplaces(t *testing.T) {
	store, id := newClientProtectedUser(t)

	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":1}`, "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got, err := store.Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.PGPWrappedEnvelopes) != 1 || got.PGPWrappedEnvelopes[0].Envelope != `{"v":2,"rec":1}` {
		t.Fatalf("after add: %+v", got.PGPWrappedEnvelopes)
	}

	// Replacing the same slot must overwrite in place, not append a second one:
	// two entries for one slot means an unlock path with no deterministic answer.
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"rec":2}`, "2026-08-05T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope replace: %v", err)
	}
	got, _ = store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 1 || got.PGPWrappedEnvelopes[0].Envelope != `{"v":2,"rec":2}` {
		t.Fatalf("after replace: %+v", got.PGPWrappedEnvelopes)
	}
	// The password envelope is untouched by slot writes.
	if got.PGPPrivateKeyWrapped != `{"v":2,"pw":true}` {
		t.Fatalf("password envelope was disturbed: %q", got.PGPPrivateKeyWrapped)
	}
}

func TestSetPGPWrappedEnvelopeRejectsPasswordSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	_, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotPassword, `{"v":2}`, "")
	if !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}

func TestSetPGPWrappedEnvelopeRejectsUnknownSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, "nonsense", `{"v":2}`, ""); !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}

func TestSetPGPWrappedEnvelopeRequiresClientProtection(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadOrMigrate(context.Background(), dir, filepath.Join(dir, "admin.env"))
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	u, err := store.Create(context.Background(), "legacy", "pw-legacy-testpassword", RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.SetPGPIdentity(u.ID, "FPR", "KID", "pub", "sealed", "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentity: %v", err)
	}
	// A server-custody account has no browser envelope, so an extra sealing of
	// "the key" would seal nothing the user holds.
	if _, err := store.SetPGPWrappedEnvelope(u.ID, EnvelopeSlotRecovery, `{"v":2}`, ""); !errors.Is(err, ErrNotClientProtected) {
		t.Fatalf("err = %v, want ErrNotClientProtected", err)
	}
}

func TestDeletePGPWrappedEnvelope(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("DeletePGPWrappedEnvelope: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("still present: %+v", got.PGPWrappedEnvelopes)
	}
	// Deleting an absent slot is not an error: the caller's goal is "this slot
	// is gone", and that is already true.
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotRecovery); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	// The password envelope survives, so the account is never left unopenable.
	got, _ = store.Get(id)
	if got.PGPPrivateKeyWrapped == "" {
		t.Fatal("delete removed the password envelope")
	}
}

func TestDeletePGPWrappedEnvelopeRejectsPasswordSlot(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.DeletePGPWrappedEnvelope(id, EnvelopeSlotPassword); !errors.Is(err, ErrInvalidEnvelopeSlot) {
		t.Fatalf("err = %v, want ErrInvalidEnvelopeSlot", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/users/ -run 'TestSetPGPWrappedEnvelope|TestDeletePGPWrappedEnvelope' -v`
Expected: FAIL — compile error, `SetPGPWrappedEnvelope`, `DeletePGPWrappedEnvelope` and `ErrInvalidEnvelopeSlot` are undefined.

- [ ] **Step 3: Write minimal implementation**

Add to the `var (...)` error block at `backend/internal/users/users.go:202`:

```go
	// ErrInvalidEnvelopeSlot is returned for a slot name the slot API does not
	// write — an unknown name, or "password", which is owned by
	// RewrapPGPPrivateKey so that its ErrNotClientProtected guard cannot be
	// bypassed by writing the same envelope through a different door.
	ErrInvalidEnvelopeSlot = errors.New("invalid wrapped-envelope slot")
```

Add after `RewrapPGPPrivateKey`:

```go
// SetPGPWrappedEnvelope adds or replaces one non-password sealing of the
// private key. envelope is opaque here, exactly as in RewrapPGPPrivateKey.
//
// Replacing writes in place rather than appending: two entries for one slot
// would leave the unlock path with no deterministic answer about which sealing
// a given secret opens.
func (s *Store) SetPGPWrappedEnvelope(id, slot, envelope, addedAt string) (User, error) {
	if !ValidEnvelopeSlot(slot) {
		return User{}, ErrInvalidEnvelopeSlot
	}
	if strings.TrimSpace(envelope) == "" {
		return User{}, errors.New("wrapped envelope is required")
	}
	return s.mutate(id, func(u *User) error {
		if u.PGPFingerprint == "" {
			return errors.New("no pgp identity to wrap")
		}
		// Same guard, and same reason, as RewrapPGPPrivateKey: a server-custody
		// account has no browser-held envelope, so an additional "sealing of the
		// key" would seal nothing the user can open, while making the account look
		// recoverable.
		if u.PGPProtection() != PGPProtectionClient {
			return ErrNotClientProtected
		}
		for i := range u.PGPWrappedEnvelopes {
			if u.PGPWrappedEnvelopes[i].Slot == slot {
				u.PGPWrappedEnvelopes[i].Envelope = envelope
				u.PGPWrappedEnvelopes[i].AddedAt = addedAt
				return nil
			}
		}
		u.PGPWrappedEnvelopes = append(u.PGPWrappedEnvelopes, WrappedEnvelope{
			Slot: slot, Envelope: envelope, AddedAt: addedAt,
		})
		return nil
	})
}

// DeletePGPWrappedEnvelope removes one non-password sealing — a revoked device,
// or a recovery code the user is replacing.
//
// Deleting an absent slot succeeds: the caller's goal is that the slot is gone,
// and it already is. Refusing the password slot is what keeps this from being a
// way to make an account permanently unopenable.
func (s *Store) DeletePGPWrappedEnvelope(id, slot string) (User, error) {
	if !ValidEnvelopeSlot(slot) {
		return User{}, ErrInvalidEnvelopeSlot
	}
	return s.mutate(id, func(u *User) error {
		kept := u.PGPWrappedEnvelopes[:0]
		for _, e := range u.PGPWrappedEnvelopes {
			if e.Slot != slot {
				kept = append(kept, e)
			}
		}
		u.PGPWrappedEnvelopes = kept
		return nil
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/users/ -run 'TestSetPGPWrappedEnvelope|TestDeletePGPWrappedEnvelope' -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/users/users.go backend/internal/users/multi_envelope_test.go
git commit -m "feat(pgp): store and delete non-password wrapped-envelope slots"
```

---

### Task 3: Replacing or clearing an identity drops stale slots

This is the correctness task. A recovery envelope seals *a specific key*. When the identity is replaced, every non-password slot still seals the **old** key — so a recovery code would open a key that is no longer this account's identity, and the user would be told their mail is recoverable when it is not.

**Files:**
- Modify: `backend/internal/users/users.go` (`SetPGPIdentityClientProtected` :1105-1125, `SetPGPIdentity` :1047-1066, `ClearPGPIdentity` :1148-1160)
- Test: `backend/internal/users/multi_envelope_test.go` (append)

**Interfaces:**
- Consumes: everything from Tasks 1–2.
- Produces: no new symbols; changes the post-conditions of three existing methods.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/users/multi_envelope_test.go`:

```go
// A new identity means every non-password slot seals a key this account no
// longer advertises. Leaving them would tell the user a recovery code still
// opens their mail when it opens a key nobody encrypts to any more.
func TestSetPGPIdentityClientProtectedDropsStaleSlots(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2,"old":true}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.SetPGPIdentityClientProtected(id, "FPR2", "KID2",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":2}`, "generated", "2026-08-06T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("stale slots survived an identity replacement: %+v", got.PGPWrappedEnvelopes)
	}
}

func TestClearPGPIdentityDropsSlots(t *testing.T) {
	store, id := newClientProtectedUser(t)
	if _, err := store.SetPGPWrappedEnvelope(id, EnvelopeSlotRecovery, `{"v":2}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	if _, err := store.ClearPGPIdentity(id); err != nil {
		t.Fatalf("ClearPGPIdentity: %v", err)
	}
	got, _ := store.Get(id)
	if len(got.PGPWrappedEnvelopes) != 0 {
		t.Fatalf("slots survived ClearPGPIdentity: %+v", got.PGPWrappedEnvelopes)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/users/ -run 'DropsStaleSlots|DropsSlots' -v`
Expected: FAIL — `stale slots survived an identity replacement: [{recovery ...}]`.

- [ ] **Step 3: Write minimal implementation**

In `SetPGPIdentityClientProtected`, alongside the existing `u.PGPPrivateKeyEnc = ""`:

```go
		// Every non-password slot seals the OLD key. Keeping them across an
		// identity replacement would leave a recovery code that opens a key this
		// account no longer advertises — the user is told their mail is
		// recoverable, and it is not.
		u.PGPWrappedEnvelopes = nil
```

The same line goes in `ClearPGPIdentity` (alongside `u.PGPPrivateKeyWrapped = ""`) and in `SetPGPIdentity` (alongside `u.PGPPrivateKeyWrapped = ""`). `SetPGPIdentity` refuses client-protected accounts already, so its case is only reachable for an account that had no slots — clear it anyway, so the three identity writers cannot drift apart. That "restated rather than inherited" reasoning is already the convention here; see the comment at `SetPGPIdentityClientProtected`'s sibling guard.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/users/ -v`
Expected: PASS, whole package including the pre-existing PGP tests.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/users/users.go backend/internal/users/multi_envelope_test.go
git commit -m "fix(pgp): drop stale envelope slots when the identity changes"
```

---

### Task 4: Bootstrap reports which slots exist

The browser needs to know a recovery envelope exists without downloading it — that is what drives "you have a recovery code" versus "set one up". Envelope **bodies** for non-password slots are not served here; they are fetched only when actually unlocking (Task 5's GET).

**Files:**
- Modify: `backend/internal/api/pgp_bootstrap.go:60-83` (the `PGPProtectionClient` case)
- Test: `backend/internal/api/pgp_multi_envelope_test.go` (create)

**Interfaces:**
- Consumes: `(User).WrappedEnvelopes()` from Task 1.
- Produces: `/api/pgp/bootstrap` response gains `envelopeSlots` — a JSON array of slot-name strings, always present (empty array, never null) for client-protected accounts.

- [ ] **Step 1: Write the failing test**

Create `backend/internal/api/pgp_multi_envelope_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"kypost-server/backend/internal/users"
)

func clientProtectedUser(t *testing.T, srv *Server) string {
	t.Helper()
	u, err := srv.users.Create(context.Background(), "slotapi", "pw-slotapi-testpassword", users.RoleUser)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := srv.users.SetPGPIdentityClientProtected(u.ID, "FPR", "KID",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----",
		`{"v":2,"pw":true}`, "generated", "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("SetPGPIdentityClientProtected: %v", err)
	}
	return u.ID
}

func bootstrapSlots(t *testing.T, srv *Server, userID string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, userID)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		EnvelopeSlots     []string `json:"envelopeSlots"`
		WrappedPrivateKey string   `json:"wrappedPrivateKey"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The legacy field must keep meaning exactly what it meant, or every
	// already-shipped client breaks on upgrade.
	if out.WrappedPrivateKey != `{"v":2,"pw":true}` {
		t.Fatalf("wrappedPrivateKey changed meaning: %q", out.WrappedPrivateKey)
	}
	return out.EnvelopeSlots
}

func TestBootstrapReportsPasswordSlotOnly(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)
	got := bootstrapSlots(t, srv, id)
	if len(got) != 1 || got[0] != users.EnvelopeSlotPassword {
		t.Fatalf("slots = %v, want [password]", got)
	}
}

func TestBootstrapReportsRecoverySlot(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)
	if _, err := srv.users.SetPGPWrappedEnvelope(id, users.EnvelopeSlotRecovery, `{"v":2,"rec":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	got := bootstrapSlots(t, srv, id)
	if len(got) != 2 || got[1] != users.EnvelopeSlotRecovery {
		t.Fatalf("slots = %v, want [password recovery]", got)
	}
}

// Slot names are metadata; the sealed bytes of a non-password slot are not
// part of the bootstrap payload. Serving them here would put a second
// brute-forceable envelope in every cold-start response for no reason.
func TestBootstrapDoesNotServeNonPasswordEnvelopeBodies(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)
	if _, err := srv.users.SetPGPWrappedEnvelope(id, users.EnvelopeSlotRecovery, `{"v":2,"SECRETBODY":1}`, ""); err != nil {
		t.Fatalf("SetPGPWrappedEnvelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/pgp/bootstrap", nil)
	authRequestAs(srv, req, id)
	rec := httptest.NewRecorder()
	srv.withMailAuth(srv.handlePGPBootstrap)(rec, req)
	if body := rec.Body.String(); strings.Contains(body, "SECRETBODY") {
		t.Fatalf("bootstrap leaked a non-password envelope body: %s", body)
	}
}
```

**Imports:** this file needs one import block containing `context`, `encoding/json`, `net/http`, `net/http/httptest`, `strings`, `testing`, and `kypost-server/backend/internal/users`. Task 5 appends to this same file and adds no further imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestBootstrap -v`
Expected: FAIL — `slots = [], want [password]`; `envelopeSlots` is absent from the response.

- [ ] **Step 3: Write minimal implementation**

In `backend/internal/api/pgp_bootstrap.go`, inside the `case users.PGPProtectionClient:` block, after `resp["wrappedPrivateKey"] = u.PGPPrivateKeyWrapped`:

```go
		// Slot NAMES only. The browser needs to know a recovery envelope exists
		// to decide between "recover with your code" and "set one up"; it does
		// not need the sealed bytes until it is actually unlocking, and putting a
		// second brute-forceable envelope in every cold-start response would be a
		// cost with no matching benefit.
		slots := []string{}
		for _, e := range u.WrappedEnvelopes() {
			slots = append(slots, e.Slot)
		}
		resp["envelopeSlots"] = slots
```

Add `resp["envelopeSlots"] = []string{}` to the `PGPProtectionServer` and `default` branches, so the field's absence never has to be distinguished from an empty list by a client.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/api/ -run TestBootstrap -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add backend/internal/api/pgp_bootstrap.go backend/internal/api/pgp_multi_envelope_test.go
git commit -m "feat(pgp): report available envelope slots from bootstrap"
```

---

### Task 5: Endpoints to write, read and delete a slot

**Files:**
- Modify: `backend/internal/api/pgp_client_keys.go` (append handlers)
- Modify: `backend/internal/api/server.go:537` (register routes next to the existing rewrap route)
- Modify: `backend/internal/api/server_users.go:250-262` (`writeUserStoreError` mapping)
- Test: `backend/internal/api/pgp_multi_envelope_test.go` (append)

**Interfaces:**
- Consumes: `SetPGPWrappedEnvelope`, `DeletePGPWrappedEnvelope`, `ErrInvalidEnvelopeSlot` (Task 2); `WrappedEnvelopes()` (Task 1).
- Produces: `PUT /api/pgp/identity/envelope/{slot}` (body `{"envelope": "..."}`), `GET /api/pgp/identity/envelope/{slot}` (returns `{"slot":"...","envelope":"..."}`), `DELETE /api/pgp/identity/envelope/{slot}`. All `s.withAuth`.

- [ ] **Step 1: Write the failing test**

Append to `backend/internal/api/pgp_multi_envelope_test.go`. No new imports — `strings` is already in the block from Task 4.

```go
func TestEnvelopeSlotRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)

	put := httptest.NewRequest(http.MethodPut, "/api/pgp/identity/envelope/recovery",
		strings.NewReader(`{"envelope":"{\"v\":2,\"rec\":1}"}`))
	put.SetPathValue("slot", "recovery")
	authRequestAs(srv, put, id)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPPutEnvelopeSlot)(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; body=%s", rec.Code, rec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/pgp/identity/envelope/recovery", nil)
	get.SetPathValue("slot", "recovery")
	authRequestAs(srv, get, id)
	rec = httptest.NewRecorder()
	srv.withAuth(srv.handlePGPGetEnvelopeSlot)(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Slot     string `json:"slot"`
		Envelope string `json:"envelope"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Slot != "recovery" || out.Envelope != `{"v":2,"rec":1}` {
		t.Fatalf("round trip lost data: %+v", out)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/pgp/identity/envelope/recovery", nil)
	del.SetPathValue("slot", "recovery")
	authRequestAs(srv, del, id)
	rec = httptest.NewRecorder()
	srv.withAuth(srv.handlePGPDeleteEnvelopeSlot)(rec, del)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if got := bootstrapSlots(t, srv, id); len(got) != 1 {
		t.Fatalf("slots after delete = %v, want [password]", got)
	}
}

// The password envelope has exactly one writer, POST /api/pgp/identity/rewrap,
// because that route carries the guard that stops a server-custody account
// having its only readable key cleared. A second door to the same field would
// be a way around it.
func TestEnvelopeSlotRefusesPasswordSlot(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)
	put := httptest.NewRequest(http.MethodPut, "/api/pgp/identity/envelope/password",
		strings.NewReader(`{"envelope":"x"}`))
	put.SetPathValue("slot", "password")
	authRequestAs(srv, put, id)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPPutEnvelopeSlot)(rec, put)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestGetEnvelopeSlotMissingIs404(t *testing.T) {
	srv := newTestServer(t)
	id := clientProtectedUser(t, srv)
	get := httptest.NewRequest(http.MethodGet, "/api/pgp/identity/envelope/recovery", nil)
	get.SetPathValue("slot", "recovery")
	authRequestAs(srv, get, id)
	rec := httptest.NewRecorder()
	srv.withAuth(srv.handlePGPGetEnvelopeSlot)(rec, get)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && go test ./internal/api/ -run TestEnvelopeSlot -v`
Expected: FAIL — compile error, the three handlers are undefined.

- [ ] **Step 3: Write minimal implementation**

Append to `backend/internal/api/pgp_client_keys.go`:

```go
// Envelope slots are the additional sealings of a client-protected private key
// — a recovery code today, enrolled devices later. See
// docs/superpowers/specs/2026-08-04-multi-wrapped-key-custody-design.md.
//
// All three are withAuth (session only), never withMailAuth. A paired device
// must not be able to mint a sealing of the account key: that is the property
// the passphrase-only tier is enforced by, and enforcing it at the route is the
// only place the server can enforce it at all.

func (s *Server) handlePGPPutEnvelopeSlot(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	var req struct {
		Envelope string `json:"envelope"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxWrappedKeyBytes)).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if _, err := s.users.SetPGPWrappedEnvelope(
		ac.UserID, r.PathValue("slot"), strings.TrimSpace(req.Envelope),
		time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("pgp envelope slot stored", "user_id", ac.UserID, "slot", r.PathValue("slot"))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePGPGetEnvelopeSlot(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	u, err := s.users.Get(ac.UserID)
	if err != nil {
		http.Error(w, "user unavailable", http.StatusInternalServerError)
		return
	}
	slot := r.PathValue("slot")
	for _, e := range u.WrappedEnvelopes() {
		if e.Slot == slot {
			writeJSON(w, http.StatusOK, map[string]any{"slot": e.Slot, "envelope": e.Envelope})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "no envelope in that slot"})
}

func (s *Server) handlePGPDeleteEnvelopeSlot(w http.ResponseWriter, r *http.Request) {
	ac, ok := authFromContext(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	if _, err := s.users.DeletePGPWrappedEnvelope(ac.UserID, r.PathValue("slot")); err != nil {
		writeUserStoreError(w, err)
		return
	}
	s.logger.Info("pgp envelope slot deleted", "user_id", ac.UserID, "slot", r.PathValue("slot"))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
```

Register in `backend/internal/api/server.go`, immediately after the rewrap route at :537:

```go
	mux.HandleFunc("PUT /api/pgp/identity/envelope/{slot}", s.withAuth(s.handlePGPPutEnvelopeSlot))
	mux.HandleFunc("GET /api/pgp/identity/envelope/{slot}", s.withAuth(s.handlePGPGetEnvelopeSlot))
	mux.HandleFunc("DELETE /api/pgp/identity/envelope/{slot}", s.withAuth(s.handlePGPDeleteEnvelopeSlot))
```

In `writeUserStoreError` (`backend/internal/api/server_users.go`), map the new error before the generic fallthrough:

```go
	if errors.Is(err, users.ErrInvalidEnvelopeSlot) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && go test ./internal/api/ -run 'TestEnvelopeSlot|TestGetEnvelopeSlot|TestBootstrap' -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Run the whole backend suite**

Run: `cd backend && go build ./... && go test ./...`
Expected: PASS. `run4_security_fixes_test.go` asserts a paired device cannot reach `withAuth` PGP routes; the new routes must not break it.

- [ ] **Step 6: DOX pass and commit**

Update `backend/AGENTS.md` if it documents the PGP route surface or the `User` PGP fields — the envelope set and the three routes are new behaviour it may own.

```bash
git add backend/internal/api/pgp_client_keys.go backend/internal/api/server.go \
        backend/internal/api/server_users.go backend/internal/api/pgp_multi_envelope_test.go \
        backend/AGENTS.md
git commit -m "feat(pgp): add envelope-slot endpoints for recovery and device sealings"
```

---

## Follow-on work, not in this plan

- **Browser plan.** Generate a recovery code at key creation, wrap under it with the existing `wrapPrivateKey`, `PUT` it to the `recovery` slot, show the code exactly once, and add a "recover with code" unlock path. `frontend/src/lib/keyVault.ts` already has `createRecoveryBackup`/`restoreRecoveryBackup` and the hex-group secret format to reuse — the new work is storing the envelope server-side instead of only as a downloaded file.
- **Device enrollment** (spec Change 2) is what the `device:` slot prefix exists for. No endpoint mints one yet, deliberately.
- **`docs/E2E_PGP.md`** still says an admin password reset destroying the key is "inherent to the model". It stops being true when the browser plan ships, not when this one does; update it there.
