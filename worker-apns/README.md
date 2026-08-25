# KyPost Push Relay (APNs) — Cloudflare Worker

This Worker delivers native push notifications to iOS devices via Apple Push Notification service (APNs).

The published iOS app is compiled with a single bundle ID (`com.urlxl.mail`), so only a holder of the corresponding Apple Developer Team ID can deliver push to it. Instead of shipping the APNs auth key (`.p8`) to every self-hosted server, the **maintainer** runs this Worker. Self-hosted KyPost servers forward push requests to it, each authenticated with its own API key. Self-hosters need **no Apple Developer account and never recompile the app**.

```
self-hosted Go server  --(Bearer per-server key)-->  this Worker  --(APNs provider token)-->  APNs  -->  iOS Device
```

## One-time setup (maintainer)

1. Install deps and log in:
   ```sh
   cd worker-apns
   npm install
   npx wrangler login
   ```

2. Create your local config, then create the two KV namespaces and paste the returned ids into it. `wrangler.toml` is gitignored (it holds your live KV ids); `wrangler.toml.example` is the committed template:
   ```sh
   cp wrangler.toml.example wrangler.toml
   npx wrangler kv namespace create API_KEYS
   npx wrangler kv namespace create APNS_TOKEN_CACHE
   # Paste the returned namespace IDs into wrangler.toml for their respective bindings
   ```
   The `RELAY_COORDINATOR` Durable Object needs no setup step — the
   `[[migrations]]` block in the template creates it on your first deploy. See
   [Token pinning](#token-pinning) for why it is required.

3. Obtain an APNs Auth Key from the Apple Developer portal:
   - Log in to https://developer.apple.com/account
   - Certificates, Identifiers & Profiles → Keys
   - Click "+" to create a new key
   - Check "Apple Push Notifications service (APNs)" capability
   - Click "Continue", then "Register"
   - **Download the `.p8` file immediately** (it can't be re-downloaded — losing it means revoking the Key ID and creating a new one)
   - Note the **Key ID** (shown in the list) and your **Team ID** (visible in the top-right account menu)

4. Set secrets:
   ```sh
   npx wrangler secret put APNS_AUTH_KEY    # Contents of the .p8 file (preserve all newlines)
   npx wrangler secret put APNS_KEY_ID      # Key ID from step 3
   npx wrangler secret put APNS_TEAM_ID     # Team ID from your Apple Developer account
   npx wrangler secret put APNS_TOPIC       # Bundle ID, e.g. "com.urlxl.mail"
   npx wrangler secret put APNS_ENVIRONMENT # "production" or "sandbox" (use "sandbox" for debug/TestFlight builds)
   ```
   `APNS_ENVIRONMENT` is parsed strictly. Unset means production; anything that
   is neither `production` nor `sandbox` makes `/health` report
   `configured: false` and `/send` answer 500, because a typo that silently
   picked the sandbox host would make Apple reject every production device
   token as `BadDeviceToken` — which this relay reports as a dead token, and
   the backend acts on by unregistering the device.

   There is no `ADMIN_SECRET`: the relay has no admin API. See
   [Managing keys](#managing-keys).

5. Deploy:
   ```sh
   npx wrangler deploy
   ```

## Self-registration (no maintainer involvement)

**Off by default.** `/register` is an unauthenticated key-minting endpoint, so it stays closed until you set `REGISTRATION_ENABLED = "true"` in `wrangler.toml` and redeploy; the shipped `wrangler.toml.example` leaves it `"false"`. There is no admin endpoint to mint keys with instead — with registration closed, the relay issues no keys at all, which is the point of the default.

Once open, same as the FCM worker: self-hosted servers get a key on their own. The Go backend does this automatically: on first start with `APNS_RELAY_URL` set and no `APNS_RELAY_KEY`, it calls `/register`, persists the key, and reuses it on every restart.

```sh
curl -X POST https://<your-worker>.workers.dev/register \
  -H "Content-Type: application/json" \
  -d '{"label":"alice-server"}'
# -> {"id":"...","label":"alice-server","key":"<RAW KEY>","expiresAt":null}
```

**One active key per IP.** Registering from an IP that already holds a key invalidates the previous one — so a server that loses its key file can re-register and keep working.

## Managing keys

There is no admin API, and no admin credential. The relay used to serve `/admin/keys` (mint, list, revoke) behind a bearer secret, and nothing called it — the Go server uses `/register` and `/send`, the apps never touch the relay, and the endpoints existed so the maintainer could curl them. That made the highest-value credential in the deployment permanently guessable by anyone who found the hostname, to save the CLI commands below. The routes are gone.

Everything lives in the `API_KEYS` KV namespace under three prefixes: `key:<sha256 of the raw key>` holds the record, `keyid:<id>` maps an id to that hash, and `ipkey:<bucket>` remembers which key an IP bucket currently holds.

```sh
NS=<your API_KEYS namespace id>       # from wrangler.toml

# who has a key
npx wrangler kv key list --namespace-id $NS --prefix "key:"
npx wrangler kv key get  --namespace-id $NS "key:<hash>"

# revoke one, by the id in that record
HASH=$(npx wrangler kv key get --namespace-id $NS "keyid:<id>")
npx wrangler kv key delete --namespace-id $NS "key:$HASH"
npx wrangler kv key delete --namespace-id $NS "keyid:<id>"
npx wrangler kv key delete --namespace-id $NS "ipkey:<registeredIp>"   # if it still names this id
```

Deleting the record is what revokes the key: `/send` looks the presented key up by hash on every request. It also releases that key's device-token claims for re-claiming, because a claim is only protected while its owner's key is still active — so the self-hoster can re-register and their devices come back.

Send counts and last-seen are not in KV at all; they are in Analytics Engine.

## Environment-specific deployment

If you want separate dev/sandbox and production workers:

1. Duplicate `wrangler.toml` → `wrangler.prod.toml`
2. Update each config's namespace IDs and `APNS_ENVIRONMENT` secret accordingly
3. Deploy:
   ```sh
   npx wrangler deploy --env dev
   npx wrangler deploy --env prod
   ```
4. Point the Go backend to both:
   - `APNS_RELAY_URL=https://<your-worker-dev>.workers.dev` (uses sandbox)
   - Or override per-environment via your infrastructure's environment promotion pipeline

## Endpoints

| Method | Path              | Auth                   | Purpose                          |
| ------ | ----------------- | ---------------------- | -------------------------------- |
| GET    | `/health`         | none                   | Liveness + whether configured    |
| POST   | `/register`       | none                   | Self-issue a per-server key      |
| POST   | `/send`           | Bearer per-server key  | Deliver one push                 |

Three routes, and that is the entire surface — anything else is `404`, including the `/admin/keys` endpoints that used to be here.

`POST /send` body:

```json
{
  "token": "<raw APNs device token (64-char hex)>",
  "title": "Alice Smith",
  "body": "Project Update",
  "data": { "messageId": "msg-123", "url": "/read" }
}
```

Responses:
- `200 {"ok":true}` on delivery
- `403` when the token is already claimed by a different active key (see Token pinning below) — distinct from Apple's own auth-key `403` in the troubleshooting table, which surfaces through this relay as a `502`, not a top-level `403`
- `410 {"stale":true}` when the token is no longer registered (Go server then removes the device)
- `401` for a bad or expired key
- `429` when the per-key rate limit is exceeded (body has `"window":"minute"` and a `Retry-After` header)
- `413` when the body exceeds 16 KiB, `400` when it is malformed or a field has the wrong type
- `502 {"error":"push delivery failed"}` for upstream APNs errors or transient failures. Deliberately coarse: Apple's own error text describes *this relay's* topic, auth key, and routing state, so it stays in the operator logs (as a bare status code) rather than going to every key holder. Quote the `requestId` when you need the operator to look one up
- Error bodies include a `requestId` that matches the `X-Request-Id` response header

Body limits, applied before the payload reaches APNs:

| Field   | Limit                    | Over the limit                |
| ------- | ------------------------ | ----------------------------- |
| body    | 16 KiB total             | `413`                         |
| `token` | 512 chars, string        | `400`                         |
| `title` | 256 chars, string        | clipped                       |
| `body`  | 1024 chars, string       | clipped                       |
| `data`  | 16 entries, string values; keys 64 chars | `400`         |
| `data` values | 1024 chars         | clipped                       |

Text is clipped rather than refused because a title is a sender and a body is a
subject — both come from whoever emailed the self-hoster, and dropping a
notification over a long subject line is the worse failure. Unknown fields
(like `platform`) are ignored, not rejected.

## Token pinning

The first key to successfully deliver to a given device token "claims" it;
every later `/send` to that token must come from the same key, or it's
rejected with `403`. This closes the open-relay gap self-registration
otherwise leaves: without it, any registered key could spoof push to any
device token, including ones it has no business reaching. A claim is
automatically released for reclaiming if the owning key is later revoked,
disabled, or expires — so rotating your key never permanently orphans your
own devices, it just re-claims them on the next successful send.

Two details that are load-bearing rather than tuning:

- **A claim is only released when nothing was ever delivered under it.** A send
  that fails rolls its claim back so a dead token or a transient outage doesn't
  pin a device to a key that never reached it — but the coordinator, not the
  failing request, decides. A second send from the same key that succeeded in
  the meantime keeps the claim, because releasing it there would hand a device
  you legitimately own to the next key that asks.
- **A claim younger than 60 seconds is never taken over.** "Is the current
  owner's key still active?" is answered from KV, which converges globally in
  about a minute, so a key you registered seconds ago can read as deleted
  elsewhere in the network. The only cost is that reclaiming a token whose key
  you just revoked takes a minute.

Ownership is held by the `RELAY_COORDINATOR` Durable Object, not by KV. "Is this
token already claimed?" followed by "claim it" is a check-then-write, and KV is
eventually consistent — two keys racing the first send to one token could both
be told it was free, which is exactly the spoofing this rule exists to stop. All
requests for one token route to the same Durable Object instance and are handled
one at a time, so the check and the write cannot be interleaved. The same object
enforces one active self-registered key per IP on `/register`.

The binding is **required**: `/send` and `/register` both return `503` without
it, rather than silently falling back to the racy path. `/register` also returns
`503` when the request carries no usable `CF-Connecting-IP`: with no address to
bucket on there is no rate limit and no one-key-per-IP rule, and an
unauthenticated endpoint that mints permanent keys does not run without them.

Durable Objects are available on the Workers Free plan; the `[[migrations]]`
block in `wrangler.toml.example` creates the class on first deploy.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `InvalidToken` / `Unauthorized` (HTTP 403) | Auth key is incorrect, expired, or revoked | Regenerate the `.p8` key in Apple Developer portal and rotate the secret |
| `BadDeviceToken` (HTTP 400) | Device token is malformed or stale | Device was uninstalled or re-registered; backend automatically re-tries registration on next notification |
| `DeviceTokenNotForTopic` (HTTP 400) | Token was registered for a different bundle ID | Provisioning profile mismatch; rebuild the app with the correct bundle ID |
| `Unregistered` (HTTP 400) | Device revoked APNs permission or uninstalled app | Same as BadDeviceToken |
| `410 Gone` | Token is expired/revoked | Device was uninstalled; backend removes the device |
| HTTP 429 Too Many Requests | Rate limit exceeded | Increase `limit` in `wrangler.toml`'s `PUSH_RATE_LIMITER` binding or implement per-user throttling in the Go backend |

## Rate limiting

Each key is capped by a **per-minute** limit on `/send`, enforced by the native `PUSH_RATE_LIMITER` binding in `wrangler.toml` (`simple = { limit = 10, period = 60 }`) — a fixed 60s window with **no KV writes**. Change the limit there and redeploy. `RATE_LIMIT_PER_MINUTE` in `[vars]` is display-only (`/health` + the 429 body) and should be kept equal to `simple.limit`. Exceeding it returns `429` with `{"error":"rate limit exceeded","window":"minute","limit":10,"retryAfterSeconds":60}`.

> **Rolling hour/day limits were removed.** They required a KV read-modify-write on every accepted send, which capped the free tier at ~1,000 pushes/day. Dropping them keeps an accepted send at **zero KV writes**. The day tier came back as `RELAY_DAILY_BUDGET` below, built the way that note prescribed: a Durable Object counter rather than a KV read-modify-write.

### `RELAY_DAILY_BUDGET` — the daily ceiling

**Set this if you open `REGISTRATION_ENABLED`.** The per-minute limiter buckets per key, and registration mints keys on demand — so a caller who wants a second bucket registers a second key from a second address. The minute limit bounds how fast one caller sends and **nothing at all** about what the relay spends against your APNs quota in a day. `RELAY_DAILY_BUDGET` is the only setting that bounds that number.

Uncomment it in `[vars]` and redeploy:

```toml
RELAY_DAILY_BUDGET = "50000"
```

- **Aggregate, not per-key** — one shared pool across every key, because per-key would just mean an actor registers another key. It is not guarding a provider bill: FCM and APNs are free, and their quotas are send-rate limits. It guards your Cloudflare account, whose per-day KV and Durable Object limits this counter cannot see — so set it below them.
- **Unset = unmetered**, so an existing deployment that never configures it is unaffected. `"0"` is a real limit of zero (a closed relay), not "unset".
- **Per UTC day**, counted by the `RELAY_COORDINATOR` Durable Object that `/send` and `/register` already require — no extra binding to create.
- **Fails closed** when configured but uncountable: once a budget exists it is the only thing bounding daily volume, so a drifted binding refuses rather than waves sends through.

Exhausting it returns `429` with `{"error":"relay daily budget exhausted","window":"day","limit":50000,"retryAfterSeconds":...}` and a `Retry-After` header counting down to UTC midnight. Unlike the per-minute limit, the budget is not surfaced on `/health` — a public endpoint should not report how much of the relay's daily capacity is left. Watch the `budget.exhausted` log event instead.

`POST /register` has its own per-IP limiter (`REGISTER_RATE_LIMITER`), bucketed on the IPv6 /64 so one allocation can't rotate addresses past it. Both fail **closed**: a missing binding refuses the request rather than waving it through, because "misconfigured" and "absent" are indistinguishable from outside and the failure mode of guessing is an open relay.

## HTTP/2 and Payload Compatibility

APNs requires HTTP/2. Cloudflare Workers' `fetch()` automatically negotiates HTTP/2 via ALPN. All current Cloudflare plans support HTTP/2.

Both the FCM (Android) and APNs (iOS) workers receive identical request payloads from the Go backend:

```json
{
  "token": "device-token-here",
  "title": "Alice Smith",
  "body": "Project Update",
  "data": {
    "messageId": "msg-123",
    "senderName": "Alice Smith",
    "emailSubject": "Project Update",
    "Keywords": "work,important"
  }
}
```

The APNs worker translates this to the APS payload:

```json
{
  "aps": {
    "alert": { "title": "Alice Smith", "body": "Project Update" },
    "sound": "default",
    "mutable-content": 1
  },
  "messageId": "msg-123",
  "senderName": "Alice Smith",
  "emailSubject": "Project Update",
  "Keywords": "work,important"
}
```

Both platforms handle the full payload identically client-side.

## Provider Token Lifecycle

The APNs provider token (signed JWT from the `.p8` key) is cached for ~29 minutes (Apple accepts tokens valid for ~60 min). The Worker automatically refreshes it before expiry. If a token becomes invalid (key revoked, new Key ID issued), the Worker detects the failure and clears the cache, forcing regeneration on the next send.

**Annual key rotation:** Apple sends renewal notices before the `.p8` key expires (certificate expiry is separate from key validity). Plan to regenerate the key yearly — download the new `.p8`, rotate the `APNS_AUTH_KEY` secret, and redeploy. The Worker detects invalid tokens and recovers gracefully; no downtime needed.
