# KyPost Server — Findings Detail (run-11)

This file expands the three confirmed findings from `REPORT.md` with full data flows, exact requests, and baseline comparison. Two prior medium MIME findings are now fixed and are documented as verified remediation rather than findings.

---

## 1. Session-authorized re-registration hijacks an existing paired device — MEDIUM

### Data flow

| Step | Kind | File:Line | Scope | What happens |
|------|------|-----------|-------|--------------|
| 1 | entrypoint | `backend/internal/api/server_userscope.go:568` | `reserveDeviceID` | Checks `existing != ownerID` — stolen session's `ownerID == existing` so check passes; re-registration of victim's live `deviceId` is not blocked |
| 2 | propagation | `backend/internal/api/server_userscope.go:600` | `handleNativeDeviceRegister` | Handler is `withTokenAuth` (inert marker) — no `AuthContext`, no step-up, only pairing-token HMAC check |
| 3 | sink | `backend/internal/state/store.go:966` | `upsertNativeDeviceTx` | Matches by `device_id` alone, merges — overwrites `SecretHash`, `PushToken`, `DeviceName`, `Platform`, `Transport`, preserves `RegisteredAt`, `MFAApprover`, enrollment columns |

Also readable via `GET /api/notifications/native/devices` (`withAuth` lists `deviceId` in `Redacted()` — `enrollmentPublicKey` etc. remain).

### Exact requests (stolen session cookie only)

```http
GET /api/notifications/native/devices HTTP/1.1
Cookie: kypost_session=<stolen>

GET /api/notifications/pairing HTTP/1.1
Cookie: kypost_session=<stolen>

POST /api/notifications/native/register HTTP/1.1
Content-Type: application/json
X-Kypost-Pairing-Token: <token from previous step>

{"deviceId":"<victim deviceId>","deviceName":"Attacker","platform":"android","pushToken":"attacker-fcm-token"}
```

### What attacker gets

- Device count stays 1, `RegisteredAt` unchanged, `MFAApprover` still true (default), old secret no longer authenticates, attacker's secret authenticates as that device (run-10 live reproduction).
- Redirects every new-mail push title (`From <sender>: <subject>`) to attacker-controlled FCM token.
- Denies legitimate physical device (its secret is overwritten).

### Baseline

Signal/Messenger device pairing requires physical confirmation on the existing device (QR scan that binds the new device's key without overwriting the old). KyPost's `reserveDeviceID` check is the equivalent gate but fails for same-owner re-registration — no comparable has this bypass.

### Remediation

Require possession of the existing device's current secret (device-auth header) to re-bind an already-registered `deviceId`. Alternative: refuse to reuse `deviceId` at all via pairing token — force a fresh `deviceId` per registration. Note: step-up is not available on this `withTokenAuth` route — the handler has no `AuthContext` to re-prove (see `pgp_stepup.go`).

---

## 2. Pairing token minted before password reset still mints a device credential afterward — MEDIUM

### Data flow

| Step | Kind | File:Line | Scope | What happens |
|------|------|-----------|-------|--------------|
| 1 | entrypoint | `backend/internal/api/server_userscope.go:420` | `handlePairingQR` / `handlePairingToken` | `GET /api/notifications/pairing` mints a pairing token (HMAC over `userID` + `POW_SECRET`, TTL ~15min) returned to browser |
| 2 | propagation | `backend/internal/api/server_admin.go:180` | `handleResetPassword` | Admin `POST /api/users/{id}/reset-password` clears sessions, clears `native_devices`, rotates `scrypt` hash — but does not delete outstanding `pairing_token` rows/KV entries |
| 3 | sink | `backend/internal/api/server_userscope.go:590` | `handleNativeDeviceRegister` | `POST /api/notifications/native/register` validates the old token's HMAC (still valid, still within TTL) and creates a new `native_devices` row under the new password |

### Exact requests

```http
# Before reset — attacker captures token (via XSS or stolen session)
GET /api/notifications/pairing HTTP/1.1
Cookie: kypost_session=<victim session>
→ {"token":"<HMAC>","expiresAt":"... "}

# Admin remediates
POST /api/users/<id>/reset-password HTTP/1.1
Cookie: kypost_session=<admin>
→ 200 OK (sessions cleared)

# After reset — old token still works
POST /api/notifications/native/register HTTP/1.1
Content-Type: application/json
X-Kypost-Pairing-Token: <captured token>
{"deviceId":"new-attacker-device","pushToken":"..."}
→ 201 Created (attacker now has a working device credential)
```

### What attacker gets

Re-establishes persistence after the admin's intended full revocation. Password reset is documented as the break-glass revocation primitive — this bypasses it.

### Baseline

Roundcube/SOGo and Signal both invalidate outstanding device-pairing grants on password change (Signal forces re-link). KyPost's pairing token is the outlier that survives.

### Remediation

On `reset-password` (and `clear-mfa`/`deactivate`), delete outstanding pairing tokens for that `userID` — same store as session invalidation, plus `KV` `pairing_token:<id>` if present. See `state/store.go:ClearUserPairingTokens` (to be added).

---

## 3. Per-account write meter not applied to pure-`withDeviceAuth` routes — LOW

### Data flow

| Step | Kind | File:Line | Scope | What happens |
|------|------|-----------|-------|--------------|
| 1 | entrypoint | `backend/internal/api/server_request_context.go:88` | `meterAccountWrite` | Per-account token bucket checked in `withAuth`/`withMailAuth`/`withDAVBasicAuth` |
| 2 | propagation | `backend/internal/api/server.go:607` | `routesNotifications` | `POST /api/pgp/device/enrollment-key`, `GET /api/pgp/device/envelope`, `POST /api/contacts/sync`, `POST /api/mfa/push/respond`, `POST /api/notifications/native/deregister`, `GET /api/notifications/native/pull` are all `withDeviceAuth` only |
| 3 | sink | `backend/internal/state/store.go:1115` | `SetNativeDeviceEnrollmentKey` etc. | Mutating store writes happen without `meterAccountWrite` — device credential can drive them at line rate |

### Exact requests

```http
POST /api/pgp/device/enrollment-key HTTP/1.1
X-Kypost-Device-Id: <deviceId>
X-Kypost-Device-Secret: <deviceSecret>
Content-Type: application/json
{"publicKey":"<base64 SEC1>"}
→ 200 OK (mutates, no per-account write meter)
```

Repeat at will — no `meterAccountWrite` budget consumed.

### What attacker gets

No cross-account impact (bounded to device owner's own data), but allows a compromised or malicious device to drive mutating writes at device-auth rate rather than the account write budget the comments describe as the intended control. LOW per run-10 downgrade.

### Baseline

Comparable device-sync endpoints (e.g., DAV, push) typically share the same account write budget as session-authenticated writes. KyPost's `withMailAuth` already does — `withDeviceAuth` omits it.

### Remediation

Wrap mutating `withDeviceAuth` handlers with `meterAccountWrite` (or a device-scoped equivalent), consistent with `withMailAuth`.

---

## Verified remediation — MIME differentials (previously findings 1–2, now fixed)

### Filename differential — FIXED

- **Was:** `backend/internal/pgpmail/mime.go:554` `part.FileName()` only honored `Content-Disposition: filename=` while `frontend/src/lib/mimeContent.ts:140` honored both `Content-Type: name=` and `Content-Disposition: filename=`. A part named solely by `Content-Type: name=` was body to Go, attachment to JS — one signed ciphertext rendered two bodies.
- **Now:** `backend/internal/pgpmail/mime.go:515` `partFileName()` checks `part.FileName()` then `mime.ParseMediaType(Content-Type).params["name"]`, matching JS. Verified by reading `mime.go:515-523` and `mimeContent.ts:158` on HEAD `b4350c2` (both honor `name=`).
- **Tests:** `testdata/mime-corpus.json` executed by both suites (Go `pgpmail/mime_test.go`, TS `mimeContent.test.ts`). `git diff main..HEAD -- pgpmail/mime.go mimeContent.ts` empty — fix `73831ec` is on `main`.

### Boundary anchoring — FIXED

- **Was:** `frontend/src/lib/mimeContent.ts:104` `body.split('--'+boundary)` matched token anywhere, truncating client-protected body when sender embedded boundary mid-text.
- **Now:** `mimeContent.ts:119` `splitParts` anchors to `\r?\n--boundary` (`anchored.split(new RegExp(`\\r?\\n${escaped}`))`), matching Go `multipart.Reader` (RFC 2046 line-start). Verified on HEAD `b4350c2`.

No further action on these two — the shared corpus is the durable control.

---

## Addendum (2026-08-07 13:30, Phase 6 verification)

Independent verification (3 parallel verifiers, each given one finding from the initial draft) **disproved** the three device/meter findings that the initial draft had re-confirmed as still open. On HEAD `b4350c2` (which is `1a84cc5` + `b4350c2`), all three fix commits are ancestors:

- Device hijack + pairing-token survival fixed by `aa61c58 fix(devices): stop device credentials outliving what authorized them` — `git merge-base --is-ancestor aa61c58 b4350c2` and reading `server_notifications.go:488-496` (secret proof) and `server_userscope.go:776-800` (subscriber-ID rotation).
- Per-account write meter fixed by `50692d9 fix(api): meter the device-authenticated mutating routes` — `git merge-base --is-ancestor 50692d9 b4350c2` and `grep meterDeviceWrite` (4 sites).

The initial draft's `findings.json` (3 confirmed) was therefore stale. It has been replaced with 4 `rejected` entries documenting the fixes (see `findings.json`), and `REPORT.md` has been rewritten to report **0 confirmed new findings** — the delta is clean and the prior run-10 class is now closed. The MIME differentials were already fixed by `73831ec` on `main` and remain fixed here.
