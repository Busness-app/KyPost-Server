# Push relay

## Purpose

The Cloudflare Workers that deliver KyPost push notifications for every self-hosted server. The published mobile apps are bound at build time to one Firebase project and one APNs key; this relay holds those credentials so a self-hoster never needs a Firebase/Apple account and never recompiles the app.

## Ownership

`push-relay-shared/` (all shared logic and the `RelayCoordinator` Durable Object), and — because they hold no rules of their own — the two provider deployments `worker/` (FCM) and `worker-apns/` (APNs). Each of those contains only its provider's `handleSend`, its credential/transport module, `wrangler.toml.example`, and a README; everything else is imported from here. A change that belongs to both goes in `push-relay-shared/`, never copied into one worker.

## Local Contracts

- Deployed by the maintainer, not by self-hosters. `worker/wrangler.toml` and `worker-apns/wrangler.toml` are gitignored; the `.example` files are the checked-in truth.
- Secrets (`FCM_*`, `APNS_*`) are wrangler secrets. Never in a `.toml`, never logged, never returned in a response body.
- `compatibility_date` is bumped deliberately, not left where it landed. It sat over a year stale once already.
- Bindings: `API_KEYS` + provider token cache (KV), `PUSH_RATE_LIMITER` / `REGISTER_RATE_LIMITER` (native rate limiting), `USAGE_ANALYTICS` (Analytics Engine), `RELAY_COORDINATOR` (Durable Object). Each Worker re-exports `RelayCoordinator` so the runtime can find the class the binding names.
- **Every control fails CLOSED when its binding is missing.** A missing rate limiter, a missing coordinator, or a request with no usable client IP is refused (503), never waved through. "Misconfigured" and "absent" are indistinguishable from outside, and the failure mode of guessing is an open relay minting permanent credentials.
- **KV is not authoritative for anything check-then-write.** Device-token ownership and one-active-key-per-IP live in `RelayCoordinator`, which serializes per token / per IP bucket. KV holds key records and the legacy seed values only.
- **A KV answer about a key is only trusted for a claim older than `CLAIM_TAKEOVER_GRACE_MS`.** KV converges globally in about a minute, so a key minted seconds ago reads as deleted at a PoP that has not seen the write; taking over a token on that basis hands a live server's device to someone else.
- **A claim is released only when nothing delivered under it.** Every allowed `/send` calls `claimTokenForSend` and then exactly one `settleToken`. The coordinator, not the caller, decides whether the claim goes back, because the caller cannot see a concurrent send from the same key that succeeded.
- **`/register` is claim, mint, COMMIT — the coordinator is consulted twice.** Public `/register` mints permanent keys; it is off by default (`REGISTRATION_ENABLED`) and, when on, is bounded by the per-IP limiter plus one active key per IP bucket. Minting happens outside the coordinator's serialized turn, so `claimRegistrationIp` alone does not leave one key standing: a registration paused between the claim and the mint has nothing in KV for its successor to revoke, the successor's revoke is a no-op, and the pauser then mints a second permanently active key. After minting, every registration must call `confirmRegistrationIp`; one that finds it was displaced deletes the key it just made and answers 503, because it is the only party left that can clean it up. Pinned by the interleaving tests in `relay-claims.test.mts`.
- **No handler calls `request.json()`.** Every body goes through `readBoundedBody` (byte ceiling read off the stream, not off Content-Length) and then `readSendPayload` or `jsonObjectBody`. The per-minute limiter caps how many requests a key may make, never how large each one is, so the ceiling is the only thing standing between one authenticated key and unbounded allocation. Field types are checked, not coerced; text is clipped (a title is a sender, a body is a subject) while a malformed token or `data` is refused.
- **Three routes: `/health`, `/register`, `/send`. There is no admin API and no admin credential.** `/admin/keys` (mint, list, revoke) behind a bearer `ADMIN_SECRET` was deleted rather than hardened: nothing called it — the Go server uses `/register` and `/send`, the apps never touch the relay — so an always-guessable credential that mints and revokes every key the relay honours was the price of saving a `wrangler kv key delete`. Key management is the CLI (see the READMEs). Re-adding an authenticated endpoint here means re-arguing that trade, and `relay-claims.test.mts` fails until you do.
- **A provider's error text never reaches a caller.** `failDelivery` is the only 502 on the send path: FCM/APNs bodies describe our project, service account, topic, and quota, and any key holder could read them by sending deliberately broken pushes. The caller gets a status and a request id, nothing else.
- **The provider's reason IS logged, clipped to 200 characters — deliberately, and only on the failure path.** `send.fcm_failed` / `send.apns_failed` carry `fcmDetail` / `apnsDetail`. This is a narrow, knowing exception to "coarse log reason over error string" below, and it was bought with a reason: `isStaleResponse` no longer retires a device on the 400s that name a token (`INVALID_ARGUMENT`, `SENDER_ID_MISMATCH`, `BadDeviceToken`, `DeviceTokenNotForTopic`), because those are relay misconfiguration rather than a dead device. That was the right call and it removed the symptom — a fleet of unpaired phones — that used to be how an operator discovered `FCM_PROJECT_ID` or `APNS_TOPIC` was wrong. This log line is what replaced it. Without the reason, a misconfigured relay fails every push and says only "502". The exception holds only while all three remain true: it is the send failure path, the destination is the operator's own Workers log, and no caller can read it. It is not licence to log a body anywhere else. The OAuth token exchange in particular is outside it: `getAccessToken` reports `status` plus the RFC 6749 error enum (`invalid_client` is a wrong `FCM_CLIENT_EMAIL`, `invalid_grant` a bad `FCM_PRIVATE_KEY` or a drifted clock), validated against `^[a-z_]{1,40}$` so the field cannot become a hole the body fits through. That request carries the service-account assertion and its 200 carries the access token, so it gets the strict treatment rather than the clip. Pinned by `worker/src/fcm-oauth-redaction.test.mts`, which asserts a sentinel string in the upstream body reaches nothing the relay throws.

## Work Guidance

- Typechecking is the floor here, not the gate. Both ownership bugs found in review typechecked perfectly; what caught them was writing the interleaving down.
- Anything touching claims, releases, key lifecycle, or rate limiting gets a case in `relay-claims.test.mts` expressed as an explicit ordering of concurrent operations.
- Prefer a coarse log reason (`token_claim_too_recent`) over an error string. These logs are operator-facing and must not carry credentials or upstream response bodies — with one recorded exception, the clipped provider reason on the send failure path, whose terms are in Local Contracts above. Widening it is a contract change, not a tidy-up.

## Verification

```sh
cd worker && npm ci && npm run typecheck       # and the same in worker-apns/
node --test push-relay-shared/relay-claims.test.mts
node --test worker/src/fcm-oauth-redaction.test.mts
```

Both run in CI as the `ci-relay` job. The test uses node's own runner and type stripping (Node >= 22.18) with no dependencies; it stubs `cloudflare:workers` through a module hook so the Durable Object can run outside workerd. The `.mts` extension is load-bearing: there is no `package.json` above this directory, so a `.ts` file would be ESM only by Node's syntax detection, and adding one later would silently turn the test into a parse error.
