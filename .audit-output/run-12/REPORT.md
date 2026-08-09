# Security Audit Report — KyPost Server (run-12)

## Executive summary

One HIGH-severity revocation race was confirmed on HEAD `95c8c0f`. A native pairing token that was valid before an admin password reset, MFA clear, or deactivation can win an interleaving with credential purge and create a new device after the purge. MFA clear leaves that device immediately usable for mailbox access; deactivation leaves it persisted for later reactivation. Prior audit coverage is extensive; additional runs are recommended after security-sensitive feature changes.

## Baseline

KyPost is comparable to Roundcube/SnappyMail plus CardDAV groupware and browser-PGP clients. Its security model depends on operator-controlled deployment, live per-user authorization, strict custody separation, and sanitization of hostile mail. Current code follows those boundaries in the paths reviewed.

## Findings

| Severity | Title | Status |
|---|---|---|
| HIGH | Pre-revocation native pairing token can recreate a device during credential purge | Confirmed |

## Hardening notes

- `release-image.yml` still uses mutable action tags (`actions/checkout@v4`, `docker/setup-buildx-action@v3`, and `docker/login-action@v3`) while the repository’s root contract requires pinned build inputs. Pin these actions to commit SHAs. This is a supply-chain hardening requirement; this run did not elevate it to a confirmed vulnerability because exploitation requires compromise or retagging of an upstream action.
- Keep the shared Go/TypeScript MIME corpus and the current bodyless client-PGP tests in CI. They are the durable control against parser differentials and custody-mode regressions.
- Re-run the audit after changes to authentication, PGP custody, attachment serving, relay claims, or release workflows. Prior runs demonstrate that coverage varies materially by run.

## Positive patterns

- Native-device authentication now checks live account/device state and password-change confinement; credential-revocation flows rotate pairing state and clear related credentials.
- PGP verification uses a deterministic sender binding and contact address/pin data rather than trusting arbitrary OpenPGP User IDs.
- Client-protected PGP payloads remain ciphertext server-side, while server-custody messages are parsed through the server path; bodyless cache warming treats healthy ciphertext as a valid state.
- MIME parsing is bounded, has a shared corpus, and current backend API/IMAP/mail-cache/PGP tests pass.
- Outbound user-controlled URL paths use centralized private/reserved-IP and dial-time checks; relay bodies are bounded and provider errors are redacted.
- Container build inputs and runtime privilege separation are mostly pinned and explicitly documented.

## Verification performed

- Read current root and applicable backend/frontend/push-relay/scripts contracts.
- Reviewed prior audit findings and run-11 artifacts before hunting.
- Completed three recon passes covering architecture, trust boundaries, and input sinks.
- Ran `go test ./internal/api/... ./internal/adapters/imap/... ./internal/mailcache/... ./internal/pgpmail/...` successfully.
- Independently reviewed current PGP payload, sender binding, attachment, MIME, release workflow, Docker, and CAPTCHA paths.

## Finding 1 — Pre-revocation native pairing token can recreate a device during credential purge

`handleNotificationNativeRegister` resolves and retains `ownerID` from the old subscriber ID before consuming the token and writing the new native-device row. The admin revocation path deletes the account’s devices and only then rotates the subscriber ID. There is no generation check or transaction spanning token validation, subscriber lookup, device deletion, and subscriber rotation. A concurrent registration can therefore resolve the owner before rotation, continue after device deletion, and persist a fresh device using a new attacker-chosen device ID. MFA clear leaves the account active, so the new credential immediately authenticates to mail routes; deactivation leaves the device stored for later reactivation.

Remediate by making subscriber generation part of the atomic authorization decision: rotate/invalidate the subscriber before deleting devices, and re-check the current subscriber ID/generation immediately before commit under the same per-user lock or transaction. Refuse registration when the generation changed or the account is no longer active.
