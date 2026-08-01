# Push relay

## Purpose

The Cloudflare Workers that deliver KyPost push notifications for every self-hosted server. The published mobile apps are bound at build time to one Firebase project and one APNs key; this relay holds those credentials so a self-hoster never needs a Firebase/Apple account and never recompiles the app.

## Ownership

`push-relay-shared/` (all shared logic and the `RelayCoordinator` Durable Object), and — because they hold no rules of their own — the two provider deployments `worker/` (FCM) and `worker-apns/` (APNs). Each of those contains only its provider's `handleSend`, its credential/transport module, `wrangler.toml.example`, and a README; everything else is imported from here. A change that belongs to both goes in `push-relay-shared/`, never copied into one worker.

## Local Contracts

- Deployed by the maintainer, not by self-hosters. `worker/wrangler.toml` and `worker-apns/wrangler.toml` are gitignored; the `.example` files are the checked-in truth.
- Secrets (`FCM_*`, `APNS_*`, `ADMIN_SECRET`) are wrangler secrets. Never in a `.toml`, never logged, never returned in a response body.
- `compatibility_date` is bumped deliberately, not left where it landed. It sat over a year stale once already.
- Bindings: `API_KEYS` + provider token cache (KV), `PUSH_RATE_LIMITER` / `REGISTER_RATE_LIMITER` (native rate limiting), `USAGE_ANALYTICS` (Analytics Engine), `RELAY_COORDINATOR` (Durable Object). Each Worker re-exports `RelayCoordinator` so the runtime can find the class the binding names.
- **Every control fails CLOSED when its binding is missing.** A missing rate limiter, a missing coordinator, or a request with no usable client IP is refused (503), never waved through. "Misconfigured" and "absent" are indistinguishable from outside, and the failure mode of guessing is an open relay minting permanent credentials.
- **KV is not authoritative for anything check-then-write.** Device-token ownership and one-active-key-per-IP live in `RelayCoordinator`, which serializes per token / per IP bucket. KV holds key records and the legacy seed values only.
- **A KV answer about a key is only trusted for a claim older than `CLAIM_TAKEOVER_GRACE_MS`.** KV converges globally in about a minute, so a key minted seconds ago reads as deleted at a PoP that has not seen the write; taking over a token on that basis hands a live server's device to someone else.
- **A claim is released only when nothing delivered under it.** Every allowed `/send` calls `claimTokenForSend` and then exactly one `settleToken`. The coordinator, not the caller, decides whether the claim goes back, because the caller cannot see a concurrent send from the same key that succeeded.
- Public `/register` mints permanent keys; it is off by default (`REGISTRATION_ENABLED`) and, when on, is bounded by the per-IP limiter plus one active key per IP bucket.

## Work Guidance

- Typechecking is the floor here, not the gate. Both ownership bugs found in review typechecked perfectly; what caught them was writing the interleaving down.
- Anything touching claims, releases, key lifecycle, or rate limiting gets a case in `relay-claims.test.mts` expressed as an explicit ordering of concurrent operations.
- Prefer a coarse log reason (`token_claim_too_recent`) over an error string. These logs are operator-facing and must not carry credentials or upstream response bodies.

## Verification

```sh
cd worker && npm ci && npm run typecheck       # and the same in worker-apns/
node --test push-relay-shared/relay-claims.test.mts
```

Both run in CI as the `ci-relay` job. The test uses node's own runner and type stripping (Node >= 22.18) with no dependencies; it stubs `cloudflare:workers` through a module hook so the Durable Object can run outside workerd. The `.mts` extension is load-bearing: there is no `package.json` above this directory, so a `.ts` file would be ESM only by Node's syntax detection, and adding one later would silently turn the test into a parse error.
