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
   npx wrangler secret put ADMIN_SECRET     # A long random string you choose (guards /admin/keys endpoints)
   ```

5. Deploy:
   ```sh
   npx wrangler deploy
   ```

## Self-registration (no maintainer involvement)

**Off by default.** `/register` is an unauthenticated key-minting endpoint, so it stays closed until you set `REGISTRATION_ENABLED = "true"` in `wrangler.toml` and redeploy; the shipped `wrangler.toml.example` leaves it `"false"`. Until you flip it, issue keys with [`POST /admin/keys`](#issuing-a-key-manually-optional).

Once open, same as the FCM worker: self-hosted servers get a key on their own. The Go backend does this automatically: on first start with `APNS_RELAY_URL` set and no `APNS_RELAY_KEY`, it calls `/register`, persists the key, and reuses it on every restart.

```sh
curl -X POST https://<your-worker>.workers.dev/register \
  -H "Content-Type: application/json" \
  -d '{"label":"alice-server"}'
# -> {"id":"...","label":"alice-server","key":"<RAW KEY>","expiresAt":null}
```

**One active key per IP.** Registering from an IP that already holds a key invalidates the previous one — so a server that loses its key file can re-register and keep working.

## Issuing a key manually (optional)

You can mint keys yourself — e.g. to pre-provision a server or set an expiry:

```sh
curl -X POST https://<your-worker>.workers.dev/admin/keys \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"label":"alice-server"}'
# -> {"id":"...","label":"alice-server","key":"<RAW KEY, shown only once>","expiresAt":null}
```

Optionally give the key an expiry — either a lifetime in days or an explicit ISO timestamp:

```sh
-d '{"label":"alice-server","ttlDays":90}'
-d '{"label":"alice-server","expiresAt":"2027-01-01T00:00:00Z"}'
```

Give the self-hoster the raw `key` (out of band). They set on their server:

```
APNS_RELAY_URL=https://<your-worker>.workers.dev
APNS_RELAY_KEY=<the raw key>
```

List keys: `curl -H "Authorization: Bearer $ADMIN_SECRET" .../admin/keys`
Revoke:    `curl -X DELETE -H "Authorization: Bearer $ADMIN_SECRET" .../admin/keys/<id>`

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
| POST   | `/admin/keys`     | Bearer `ADMIN_SECRET`  | Mint a key (returns raw key once)|
| GET    | `/admin/keys`     | Bearer `ADMIN_SECRET`  | List key metadata                |
| DELETE | `/admin/keys/{id}`| Bearer `ADMIN_SECRET`  | Revoke a key                     |

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
- `502` for upstream APNs errors or transient failures
- Error bodies include a `requestId` that matches the `X-Request-Id` response header

## Token pinning

The first key to successfully deliver to a given device token "claims" it;
every later `/send` to that token must come from the same key, or it's
rejected with `403`. This closes the open-relay gap self-registration
otherwise leaves: without it, any registered key could spoof push to any
device token, including ones it has no business reaching. A claim is
automatically released for reclaiming if the owning key is later revoked,
disabled, or expires — so rotating your key never permanently orphans your
own devices, it just re-claims them on the next successful send.

Ownership is held by the `RELAY_COORDINATOR` Durable Object, not by KV. "Is this
token already claimed?" followed by "claim it" is a check-then-write, and KV is
eventually consistent — two keys racing the first send to one token could both
be told it was free, which is exactly the spoofing this rule exists to stop. All
requests for one token route to the same Durable Object instance and are handled
one at a time, so the check and the write cannot be interleaved. The same object
enforces one active self-registered key per IP on `/register`.

The binding is **required**: `/send` and `/register` both return `503` without
it, rather than silently falling back to the racy path. Durable Objects are
available on the Workers Free plan; the `[[migrations]]` block in
`wrangler.toml.example` creates the class on first deploy.

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

> **Hour/day rolling limits were removed for now.** They required a KV read-modify-write on every accepted send, which capped the free tier at ~1,000 pushes/day. Dropping them keeps an accepted send at **zero KV writes**.

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
