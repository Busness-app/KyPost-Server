# KyPost Server — Architecture Summary (run-11)

**Target** `/home/yoshi/git/kypost-server`, branch `fix/client-protected-pgp-flags`, HEAD `b4350c2` (2026-08-07 13:20)
**Base** `main` at `fc5af11`. **Delta** 8 commits: PGP signer binding, deterministic sender binding, client-protected bodyless PGP flags (`2c05dc5`, `b509e33`, `91226f7`, `d2bdb01`, `1a84cc5`), plus CI fixes (`b4350c2`: QF1001 De Morgan, dompurify 3.4.13).
**Prior runs** 1–10 (~150 confirmed findings, run-10: 5 confirmed medium/low). run-6 empty. Output requested at `~/security-audit-skill/kypost-server/run-11`; sandbox `ro` on `~/` forces writable fallback to `/tmp/security-audit-skill/kypost-server/run-11` and `/home/yoshi/git/kypost-server/.audit-output/run-11` (see REPORT.md).

## What this is

Self-hosted, multi-user **IMAP webmail client** (not an MTA), AGPL-3.0, with LLM auto-labeling daemon, PGP/E2E mail in two custody modes (server-decrypt vs client-decrypt), CardDAV server+client, Sieve-style rules, mobile push via two Cloudflare Worker relays (`worker/` FCM, `worker-apns/` APNs, shared `push-relay-shared/`), native-device pairing + PGP key enrollment.

**Deployables:** One Docker image with `supervisord` running two Go processes — `--mode server` (HTTP `:5866`, SPA + `/api/*` + `/dav` + `/pickup` + `/.well-known/openpgpkey`) and `--mode daemon` (IMAP poll, classify, push, WKD recheck, Autocrypt harvest) sharing `STATE_DIR` (SQLite WAL) + `CONFIG_DIR` (YAML), plus bundled Ollama. See `Dockerfile`, `docker-compose.yml`, `supervisord.conf`, `backend/internal/app/app.go`.

## Tech stack

- **Backend** Go 1.26.5, stdlib `net/http` with Go 1.22 method-pattern `ServeMux`, CGO off. `go-imap`, `gopenpgp/v3` + `go-crypto`, `go-webdav`, `go-vcard`, `go-msgauth` (DKIM), `enmime/v2`, `webpush-go`, `modernc.org/sqlite`, `x/crypto` (scrypt). `backend/go.mod` pins `golang:1.26.5`.
- **Storage** SQLite (`STATE_DIR/state.db` WAL) for `native_devices`, notifications, pairing. **JSON files** for `users.json` (scrypt hashes, TOTP, sealed IMAP/SMTP creds, wrapped PGP envelopes), contacts, rules. `users.json` rewritten whole under global cross-process `fsutil.WithFileLock`. `SECRET_DIR=/kypost/private` holds AES-GCM master keys. Sessions in-memory only.
- **Frontend** React 19 + Vite 8 + TypeScript. `openpgp`, `dompurify` (now `3.4.13`), `quill`. Email bodies render in sandboxed iframe without `allow-scripts` (`frontend/src/pages/read/EmailBodyFrame.tsx`). CSP `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`.
- **Workers** TypeScript Cloudflare Workers, Durable Object `RelayCoordinator`.

## Trust model

Eight route wrappers. **Four real middlewares that reject:** `withAuth` (session cookie + CSRF double-submit + `MustChangePassword` confinement + `meterAccountWrite`), `withMailAuth` (session OR device), `withAdmin`, `withDAVBasicAuth` (Basic, app CardDAV password, scrypt). **Four inert markers** that are passthroughs: `withPublicRoute`, `withTokenAuth`, `withDeviceAuth`, `withSelfAuth`. Enforced by AST meta-test `backend/internal/api/route_auth_test.go`.

| Actor | Credential | Can | Cannot |
|---|---|---|---|
| Anonymous | none | login, MFA, WKD fetch, pickup/QR/register redemption (token-gated), `GET /api/setup` | anything else |
| Session (user) | `kypost_session` + CSRF | all `withAuth`/`withMailAuth`; PGP identity+envelope mutation **with step-up** | admin routes |
| Session (admin) | + `Role==admin` | user mgmt, config write, logs, WKD domains | — |
| Paired device | `X-Kypost-Device-Id` + `X-Kypost-Device-Secret` (192-bit, hashed) | mail read/send, contacts sync, PGP bootstrap + wrapped-key read, publish enrollment key, read own envelope, approve push-MFA | IMAP config, envelope slot write/delete, other devices' data, admin |
| CardDAV client | Basic (app password) | contacts CRUD over `/dav` | JSON API |

Step-up (`backend/internal/api/pgp_stepup.go`): `requirePGPStepUp` → `confirmAccountCredential`, per-`(userID,clientIP)` lockout, gates identity generate/import/replace, DELETE, `PUT`/`DELETE` envelope slots, `export-legacy`. `GET` envelope deliberately exempt.

## This PR's delta — what changed

- `backend/internal/api/pgp_receive.go` (`decryptPGPMessageContent`, `decryptPGPUnreadMessage`, `decryptPGPPayload`): client-protected path returns `KeepPayload=true` with no decrypt; server-protected decrypts via `pgpmail.DecryptMIME` + `ParseContent`. Preserves `PGPEncrypted=true` on both, leaves `PGPEncryptedPayload` for client when `KeepPayload`.
- `backend/internal/api/pgp_client_read.go` (`handlePGPPayload`): `withMailAuth`, only for `PGPProtectionClient`, fetches `GetMessageBodies` for one UID and returns `encryptedPayload`/`signaturePayload` + `signerKeys=boundSignerKeysForSender(resolvedSender)`. Sends `sender` (display) and `resolvedSender` (addr-spec) separately — verified fix for prior display-name binding bug.
- `backend/internal/adapters/imap/client.go` (`collectPGPEnvelopes`, `pgpEnvelopePayload`): detects `multipart/encrypted` vs `multipart/signed`, populates `PGPEncryptedPayload`/`PGPSignaturePayload` from `e.Attachments`. Bodyless requirement enforced there.
- `backend/internal/api/server_inbox.go:513` (`serveInbox` delta warm): previous `!(c.PGPEncrypted && c.PGPDecryptError == "")` flagged QF1001; now `(!c.PGPEncrypted || c.PGPDecryptError != "")`. Keeps PGP flags for bodyless client-protected messages (empty Body but healthy `PGPEncrypted && DecryptError==""`) so inbox list shows correct PGP badge without body. Prior `main` branch had `c.Body != ""` guard only.
- `frontend/src/styles.css`: Email Details dialog flex fix (`email-reader-content` now `flex:1`; body `min-height:240px`) — no security surface.
- `frontend/package.json` / `package-lock.json`: `dompurify 3.4.12 → 3.4.13` (GHSA-55q2-fjhq-7xh7).

## Prior-run coverage — do not re-derive

Runs 1–10 heavily covered: injection, mail/MIME parsing, DKIM/send-as, Autocrypt harvest, push relay claiming, rate limiting/lockouts, `users.json` global lock, PGP badge forgery via User-ID differentials (runs 7–8), pickup links, CardDAV/vCard, device enrollment (run-10). **Run-10 (perf/bound-lockout-tests @00feae6) still applies verbatim to this branch** — this PR touched none of those files. Its 5 confirmed findings are:
1. MIME filename differential (Go `FileName()` only checks `Content-Disposition` vs JS checks `Content-Type name=`) — **still present** (`pgpmail/mime.go:554` vs `mimeContent.ts:140`).
2. JS boundary not line-anchored (`mimeContent.ts:104 split('--'+boundary)`) — **still present**.
3. Session-authorized re-registration hijacks existing device — **still present** (`server_userscope.go:568`, `store.go:966`).
4. Pairing token survives password reset — **still present**.
5. `meterAccountWrite` not on `withDeviceAuth` routes — **still present** (low).

Do not re-hunt those from scratch; verify they still apply, then focus delta.

## Open leads for this run (facts, not yet findings)

1. **Bodyless PGP warm path** (`server_inbox.go:513`): warming cache with empty Body but `PGPEncrypted=true` — does `mailcache.Entry` or `inboxEmail` rendering assume Body non-empty when `PGPEncrypted` is true? Does empty Body with `PGPVerified` false vs missing flag confuse badge logic? `decryptPGPMessageContent` for `KeepPayload` leaves original `c.Body==""` and `PGPDecryptError==""` — correct, but downstream `inboxSubject` and `PGPProtectedSubject` handling should be checked.
2. **`handlePGPPayload` mailbox/uid fetch**: `attachmentRequestParams` parses `?mailbox=&messageId=` — is mailbox path traversal checked via `safeUserPathComponent` + `filepath.Base`? Verify `GetMessageBodies` scoping to `ac.UserID`.
3. **`signedOnlyBody`**: returns `content.Body` for signed-only messages — is `Body` already sanitized? `EmailBodyFrame` sanitizes via `dompurify` (now patched), but `signedOnlyBody` is used in JSON response for client-protected — does client sanitize again?
4. **Styles.css** no security impact, but confirm no `unsafe-inline` added.
5. **dompurify bump** closes GHSA-55q2-fjhq-7xh7 — verify lockfile integrity matches registry (`sha512-2vmYIoqjze...`).

## Key file paths for hunters

- **Delta under review:** `backend/internal/api/pgp_receive.go`, `backend/internal/api/pgp_client_read.go`, `backend/internal/adapters/imap/client.go`, `backend/internal/api/server_inbox.go`, `frontend/src/lib/mimeContent.ts` (still vulnerable, for baseline), `backend/internal/pgpmail/mime.go`, `frontend/package.json`
- **Enrollment still relevant:** `backend/internal/api/pgp_device_enrollment.go`, `backend/internal/api/pgp_client_keys.go`, `backend/internal/state/store.go`, `frontend/src/lib/deviceEnrollment.ts`
- **Auth/lockout:** `backend/internal/api/server_request_context.go`, `backend/internal/api/server.go`, `backend/internal/api/pgp_stepup.go`, `backend/internal/api/route_auth_test.go`
- **Relay:** `push-relay-shared/push-relay-common.ts`, `worker/src/index.ts`
- **Sanitizer:** `frontend/src/lib/emailHtml.ts`, `frontend/src/pages/read/EmailBodyFrame.tsx`, `backend/internal/api/security_headers.go`
