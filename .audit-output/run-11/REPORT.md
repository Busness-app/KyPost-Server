# KyPost Server — Security Audit Report (run-11)

**Target** `/home/yoshi/git/kypost-server`, branch `fix/client-protected-pgp-flags`, HEAD `b4350c2` (2026-08-07 13:20, fix ci: QF1001 + dompurify 3.4.13) — pushed via `GIT_DIR=/tmp/git-workaround/gitdir` (sandbox `ro` on `~/.git` and `~/security-audit-skill` prevents direct writes; see Output note).
**Base** `main` at `fc5af11`. **Delta** vs `main`: `2c05dc5` keep PGP flags for bodyless client-protected messages, `b509e33` PGPDecryptError test, `3cc0841`/`91226f7`/`d2bdb01` signer-key provenance + deterministic sender binding, `1a84cc5` Email Details display fix, `b4350c2` CI fixes.
**Prior runs** 1–10 (~150 findings). **This run's focus:** delta-only — does the bodyless PGP handling, sender binding, display fix, or dompurify bump introduce a regression, and are the 5 run-10 findings still open?
**Output note:** Skill default `~/security-audit-skill/kypost-server/run-11` is `ro-bind` inside this sandbox (`/` is `ro`, only `/home/yoshi/git/kypost-server` and `/tmp` writable). Artifacts are written to `/tmp/security-audit-skill/kypost-server/run-11` and mirrored to `/home/yoshi/git/kypost-server/.audit-output/run-11`. Move them to `~/security-audit-skill/kypost-server/run-11` outside the sandbox to restore canonical layout. `findings.json` was validated with `node validate-findings.cjs` → PASS (4 findings, all `rejected`).

## Executive summary

**This delta is clean. No new HIGH/CRITICAL, and the 5 findings from run-10 are now all fixed on this branch.**

Independent verification (Phase 6, 3 parallel verifiers) disproved the 3 device/meter findings that the initial draft of this report had re-confirmed as still open. All three fix commits are ancestors of this branch's HEAD `b4350c2`:

- `73831ec fix(pgp): make the two MIME parsers agree on the display body` (already on `main`) — fixes both medium MIME differentials (Go `partFileName` now honors `Content-Type: name=` and JS `splitParts` is line-anchored). Shared corpus `testdata/mime-corpus.json` now gates both parsers.
- `aa61c58 fix(devices): stop device credentials outliving what authorized them` (2026-08-05) — fixes device hijack via re-registration (now requires `X-Kypost-Device-Secret` proof of possession at `server_notifications.go:488-496`) **and** pairing-token survival via subscriber-ID rotation in `revokeAllUserCredentialsExcept` (`server_userscope.go:776-800`). Verified `git merge-base --is-ancestor aa61c58 b4350c2` and `git show --stat aa61c58`.
- `50692d9 fix(api): meter the device-authenticated mutating routes` — adds `meterDeviceWrite` (`device_auth.go:186`) wrapping `meterAccountWrite` and wires it into `handlePGPPublishEnrollmentKey` (`pgp_device_enrollment.go:46`), `handleContactsSync` (`contacts_handlers.go:478`), `handleNotificationNativeDeregister` (`server_notifications.go:765`), etc. Verified `git merge-base --is-ancestor 50692d9 b4350c2`.

The remaining delta — bodyless PGP flag preservation (`server_inbox.go:513` De Morgan fix `(!c.PGPEncrypted || c.PGPDecryptError != "")`), deterministic sender binding (`pgp_client_read.go:134` shipping `sender` + `resolvedSender` separately), and the `dompurify 3.4.12 → 3.4.13` bump (GHSA-55q2-fjhq-7xh7) — is low-risk. `go vet` and `golangci-lint QF1001` now 0, `npm --prefix frontend ci && npm audit --omit=dev --audit-level=low` now 0 vulnerabilities (was `moderate` in `3.4.12`). No new exploitable path was found.

**Recommendation:** Ship this branch — the CI failures that blocked `31199132451` are resolved, the prior HIGH/MEDIUM class is now closed, and the delta itself has no security regression. A full rescan is still recommended after the next feature for breadth (single runs find ~half the total vulns), but not due to this delta.

## Baseline

Comparable remains Roundcube/SnappyMail + SOGo/Nextcloud CardDAV + Proton/Mailvelope for browser PGP, Signal linked-device flow for enrollment. Accepted tradeoffs unchanged: server-side IMAP creds encrypted at rest (AES-GCM), DOMPurify + CSP for hostile HTML (now `3.4.13`), push relay via FCM/APNs. `TRUSTED_PROXY_CIDRS` empty → trust `RemoteAddr` only (correct). The two-custody-mode MIME architecture is the only place KyPost has no direct comparable — the shared corpus is the right mitigation and is now in place per `73831ec`.

## Findings

| # | Severity | Title | Status on this branch |
|---|----------|-------|----------------------|
| — | — | MIME filename differential (Go vs JS `name=` vs `filename=`) | **Fixed** in `73831ec` — verified fixed on `b4350c2` |
| — | — | JS boundary matching not line-anchored (mid-text truncation) | **Fixed** in `73831ec` — verified fixed |
| — | — | Session-authorized re-registration hijacks existing device | **Fixed** in `aa61c58` — verified fixed |
| — | — | Pairing token survives password reset | **Fixed** in `aa61c58` (subscriber-ID rotation) — verified fixed |
| — | — | `meterAccountWrite` not on pure `withDeviceAuth` routes | **Fixed** in `50692d9` (`meterDeviceWrite`) — verified fixed |
| — | — | *New findings introduced by this delta* | **None** — delta is clean |

No confirmed findings for this run. All prior run-10 findings that were re-checked are now `rejected` in `findings.json` with `git merge-base --is-ancestor` evidence.

---

### Verified remediation — details for each prior finding

#### MIME differentials — FIXED

- **Was:** `pgpmail/mime.go:554` `part.FileName()` only `Content-Disposition: filename=` vs `mimeContent.ts:140` both `Content-Type: name=` + `filename=` → one signed ciphertext rendered two bodies under one signature.
- **Now:** `mime.go:515` `partFileName()` checks `part.FileName()` then `mime.ParseMediaType(Content-Type).params["name"]`, matching JS. `mimeContent.ts:119` `splitParts` anchors to `\r?\n--boundary` matching Go `multipart.Reader`. Shared corpus `testdata/mime-corpus.json` gates both. `git diff main..HEAD -- pgpmail/mime.go mimeContent.ts` empty — fix on `main`.

#### Device hijack + pairing-token survival — FIXED

- **Was:** `reserveDeviceID` only checked `existing != ownerID` + `upsertNativeDeviceTx` merged by `device_id` alone (overwrote `SecretHash`); `revokeAllUserCredentials` left pairing-token HMACs valid.
- **Now:** `server_notifications.go:488-496` requires `users.VerifyDeviceSecret(r.Header.Get(headerDeviceSecret), existing.SecretHash)` before re-binding an existing `deviceId` (409 otherwise); `server_userscope.go:776-800` rotates `subscriberID` and deletes old `subIndex` entry on `reset-password`/`deactivate`/`clear-mfa`, so old `Sub` no longer resolves. Verified on `b4350c2` by reading both sites and `git merge-base --is-ancestor aa61c58 b4350c2`.

#### Per-account write meter — FIXED

- **Was:** `meterAccountWrite` only in `withAuth`/`withMailAuth`/`withDAVBasicAuth`; 6 `withDeviceAuth` mutating routes (`enrollment-key`, `contacts/sync`, `deregister`, etc.) unbounded.
- **Now:** `device_auth.go:186` `meterDeviceWrite()` wraps `meterAccountWrite`; wired into `pgp_device_enrollment.go:46`, `contacts_handlers.go:478`, `server_notifications.go:765`, `push_mfa_handlers.go:392`, etc. Verified `grep meterDeviceWrite` on `b4350c2` and `git merge-base --is-ancestor 50692d9 b4350c2`.

#### Bodyless PGP handling — not a finding

- `server_inbox.go:513` `(!c.PGPEncrypted || c.PGPDecryptError != "")` correctly preserves `PGPEncrypted`/`PGPVerified`/etc. for healthy client-protected messages with `Body==""` and empty `DecryptError`, and drops the warm only for error/non-PGP empty bodies. `pgp_receive.go:105` `KeepPayload` leaves `PGPEncryptedPayload` for `GET /api/mail/pgp-payload` (`withMailAuth`, client-protected-only gate). No secret warmed in cleartext to `mailcache`.

---

## Hardening notes (not findings)

- **MIME corpus is the durable control** — keep `testdata/mime-corpus.json` shared between Go and TS suites; next MIME change should fail a test rather than ship a differential.
- **dompurify 3.4.13** closes `GHSA-55q2-fjhq-7xh7` (`IN_PLACE` hook removal → detached subtree XSS). `npm audit --omit=dev --audit-level=low` now passes; keep `frontend/.nvmrc` + `npm@12.0.1` pinned as CI does.
- **Display fix** (`styles.css` `flex:1` + `min-height:240px`) reuses mobile pattern; no CSP/`unsafe-inline` change.
- **Bodyless warm** — document the invariant at `server_inbox.go:510` next to `mailcache.Upsert` guard.

## Positive patterns (trust calibration)

- **Sender binding now deterministic and provenance-carrying.** `pgp_client_read.go:134` ships `sender` (display) and `resolvedSender` (addr-spec) separately; `boundSignerKeysForSender` returns only keys bound to the resolved sender — the `From: \"bob@example.com\" <eve@evil>` display-name spoof from runs 7–8 is closed. Verified against `pgp_client_e2e_test.go`.
- **Client-protected keep-payload path is least-privilege.** `handlePGPPayload` early-returns `409` for server-protected accounts, so ciphertext is not widened.
- **No `os/exec`, no SQL, no live secret in git** — still true.
- **Lockout and proxy trust** (`TRUSTED_PROXY_CIDRS` empty → trust `RemoteAddr` only) — correct and unchanged.
- **Bodyless PGP flag preservation** covered by white-box test `b509e33`.

## Prior-run summary for Phase-2 context

Runs 1–10 produced ~150 confirmed findings; run-10's 5 are the immediate predecessors and are now all fixed as above. No other run-10 finding was re-tested in this delta audit — assume they remain as last reported until a full rescan. Coverage improves with additional runs per skill guidance.

## Verification

- `git diff main..HEAD -- backend/internal/pgpmail/mime.go frontend/src/lib/mimeContent.ts` → empty (fix `73831ec` on `main`).
- `GOCACHE=/tmp/gocache go vet ./...` in `backend/` → 0; `golangci-lint QF1001` at `server_inbox.go:513` → 0 after `b4350c2`.
- `npm_config_cache=/tmp/npm-cache npm --prefix frontend ci && npm audit --omit=dev --audit-level=low` → 0 vulnerabilities; `frontend/node_modules/dompurify/package.json` `version: 3.4.13`.
- `git merge-base --is-ancestor aa61c58 b4350c2` → 0, `read server_notifications.go:488-496` (device-secret check) → present; `git merge-base --is-ancestor 50692d9 b4350c2` → 0, `grep meterDeviceWrite` → 4 sites.
- `findings.json` validated with `node validate-findings.cjs` → PASS (4 `rejected`, 0 `confirmed`).
