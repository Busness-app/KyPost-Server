# KyPost Push Relay (Cloudflare Worker)

This Worker centralizes native (FCM) push delivery for KyPost.

The published mobile app is compiled against **one** Firebase project, so only a
holder of that project's service account can deliver push to it. Instead of
shipping that credential to every self-hosted server, the **maintainer** runs
this one Worker. Self-hosted KyPost servers forward push requests to it,
each authenticated with its own API key. Self-hosters need **no Firebase account
and never recompile the app**.

```
self-hosted Go server  --(Bearer per-server key)-->  this Worker  --(service account)-->  FCM
```

## One-time setup (maintainer)

1. Install deps and log in:
   ```sh
   cd worker
   npm install
   npx wrangler login
   ```
2. Create your local config, then create the two KV namespaces and paste the
   returned ids into it. `wrangler.toml` is gitignored (it holds your live KV
   ids); `wrangler.toml.example` is the committed template:
   ```sh
   cp wrangler.toml.example wrangler.toml
   npx wrangler kv namespace create API_KEYS
   npx wrangler kv namespace create OAUTH_CACHE
   ```
   The `RELAY_COORDINATOR` Durable Object needs no setup step — the
   `[[migrations]]` block in the template creates it on your first deploy. See
   [Token pinning](#token-pinning) for why it is required.
3. Set secrets from your Firebase service-account JSON (the same file the Go
   backend used as `FCM_SERVICE_ACCOUNT_FILE`):
   ```sh
   npx wrangler secret put FCM_CLIENT_EMAIL   # "client_email"
   npx wrangler secret put FCM_PRIVATE_KEY    # "private_key" (full PEM, keep newlines)
   npx wrangler secret put FCM_PROJECT_ID     # "project_id"
   npx wrangler secret put ADMIN_SECRET       # a long random string you choose
   ```
4. Deploy:
   ```sh
   npx wrangler deploy
   ```

## Self-registration (no maintainer involvement)

**Off by default.** `/register` is an unauthenticated key-minting endpoint, so it
stays closed until you set `REGISTRATION_ENABLED = "true"` in `wrangler.toml` and
redeploy. The shipped `wrangler.toml.example` leaves it `"false"`; until you flip
it, issue keys with [`POST /admin/keys`](#issuing-a-key-manually-optional).

Once open, self-hosted servers get a key on their own — you don't issue anything. The Go
backend does this automatically: on first start with `PUSH_RELAY_URL` set and no
`PUSH_RELAY_KEY`, it calls `/register`, then persists the key under `SECRET_DIR`
and reuses it on every restart. Equivalent by hand:

```sh
curl -X POST https://<your-worker>.workers.dev/register \
  -H "Content-Type: application/json" \
  -d '{"label":"alice-server"}'
# -> {"id":"...","label":"alice-server","key":"<RAW KEY>","expiresAt":null}
```

**One active key per IP.** Registering again from the same IP mints a new key and
**invalidates the previous one** — so a server that loses its key file just
re-registers and keeps working, and a single IP can't accumulate keys. Servers
behind the same public IP therefore share one key slot (the latest wins).

Self-registered keys never expire and are tagged `"source":"self"` (with the
registering IP) in the admin list, so you can audit and revoke abusers. Abuse is
further bounded by the per-key rolling rate limits and the `REGISTRATION_ENABLED
= "false"` kill-switch. To cap how often one IP can churn keys, add a Cloudflare
rate-limit rule on the `/register` route.

## Issuing a key manually (optional)

You can still mint keys yourself — e.g. to pre-provision a server or set an
expiry:

```sh
curl -X POST https://<your-worker>.workers.dev/admin/keys \
  -H "Authorization: Bearer $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"label":"alice-server"}'
# -> {"id":"...","label":"alice-server","key":"<RAW KEY, shown only once>","expiresAt":null}
```

Optionally give the key an expiry — either a lifetime in days or an explicit
ISO timestamp (an explicit `expiresAt` wins over `ttlDays`):

```sh
-d '{"label":"alice-server","ttlDays":90}'
-d '{"label":"alice-server","expiresAt":"2027-01-01T00:00:00Z"}'
```

Give the self-hoster the raw `key` (out of band). They set on their server:

```
PUSH_RELAY_URL=https://<your-worker>.workers.dev
PUSH_RELAY_KEY=<the raw key>
```

List keys: `curl -H "Authorization: Bearer $ADMIN_SECRET" .../admin/keys`
Revoke:    `curl -X DELETE -H "Authorization: Bearer $ADMIN_SECRET" .../admin/keys/<id>`

`GET /admin/keys` returns per-key metadata and source:

```json
{ "keys": [ {
  "id": "…", "label": "alice-server", "enabled": true,
  "createdAt": "2026-07-04T…", "expiresAt": null, "expired": false,
  "source": "self", "registeredIp": "203.0.113.7"
} ] }
```

Send counts and last-seen are **not** here — they're recorded in Analytics Engine
(see [Usage](#usage)). Expired keys stay listed (with `"expired": true`) until you
revoke them, so you can see which keys lapsed.

## Endpoints

| Method | Path              | Auth                   | Purpose                          |
| ------ | ----------------- | ---------------------- | -------------------------------- |
| GET    | `/health`         | none                   | Liveness + whether configured    |
| POST   | `/register`       | none                   | Self-issue a per-server key      |
| POST   | `/send`           | Bearer per-server key  | Deliver one push                 |
| POST   | `/admin/keys`     | Bearer `ADMIN_SECRET`  | Mint a key (returns raw key once)|
| GET    | `/admin/keys`     | Bearer `ADMIN_SECRET`  | List key metadata + last-used    |
| DELETE | `/admin/keys/{id}`| Bearer `ADMIN_SECRET`  | Revoke a key                     |

`POST /send` body:

```json
{ "token": "<FCM registration token>", "title": "…", "body": "…", "data": { "url": "/read" }, "platform": "android" }
```

Responses: `200 {"ok":true}` on delivery; `403` when the token is already
claimed by a different active key (see Token pinning below); `410 {"stale":true}`
when the token is no longer registered (the Go server then removes the
device); `401` for a bad or expired key; `429` when the per-key rate limit is
exceeded (body has `"window":"minute"` and a `Retry-After` header); `502` for
other upstream FCM errors. Error bodies include a `requestId` that matches the
`X-Request-Id` response header and the structured logs.

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
unauthenticated endpoint that mints permanent keys does not run without them. Durable Objects are
available on the Workers Free plan; the `[[migrations]]` block in
`wrangler.toml.example` creates the class on first deploy.

## Rate limiting

Each key is capped by a **per-minute** limit on `/send`, enforced by the native
`PUSH_RATE_LIMITER` binding in `wrangler.toml` (`simple = { limit = 10, period =
60 }`) — a fixed 60s window with **no KV writes**. Change the limit there and
redeploy. `RATE_LIMIT_PER_MINUTE` in `[vars]` is display-only (`/health` + the
429 body) and should be kept equal to `simple.limit`. Exceeding it returns `429`
with `{"error":"rate limit exceeded","window":"minute","limit":10,"retryAfterSeconds":60}`.

> **Hour/day rolling limits were removed for now.** They required a KV
> read-modify-write on every accepted send, which capped the free tier at
> ~1,000 pushes/day. Dropping them keeps an accepted send at **zero KV writes**.
> Restore rolling hour/day caps with Durable Objects (exact, atomic, no KV write
> pressure) once running on Workers Paid — see the `TODO(paid-tier)` in
> `src/index.ts`.

## Usage

Each accepted send writes one data point to the `USAGE_ANALYTICS` Analytics
Engine dataset (`kypost_push_usage`) — off the KV write path — with the key id,
label, and source. Query totals and last-seen per key via the Analytics Engine
SQL API, e.g.:

```sql
SELECT blob1 AS key_id, sum(_sample_interval * double1) AS sends, max(timestamp) AS last_seen
FROM kypost_push_usage GROUP BY key_id ORDER BY sends DESC
```

The admin list no longer carries usage counts or `lastUsedAt` — that all lives in
Analytics Engine now.

## Observability

- Every request is assigned a UUID `requestId`, returned in the `X-Request-Id`
  header (and in error bodies). Each request emits one structured JSON log line
  (plus event lines for sends, denials, and key changes). Tail them live with
  `npx wrangler tail`, or ship them via Workers Logs / Logpush.
- `GET /health` returns `{ ok, configured, rateLimits: { perMinute },
  registrationEnabled }` with no auth — use it for uptime checks. `configured` is
  false until all FCM secrets are set.

## Notes

- Only the SHA-256 hash of each API key is stored in KV; the raw key is shown
  once at creation.
- The Google OAuth access token is cached in the `OAUTH_CACHE` KV namespace and
  refreshed ~1 minute before expiry. Key records and the `ipkey:<ip>` indexes
  (one key per IP) live in `API_KEYS`.
- An accepted send performs **no KV writes**: the minute limiter uses the native
  binding, usage goes to Analytics Engine, and the hour/day KV log is gone. The
  remaining per-send KV cost is reads (key lookup + OAuth cache), so the free
  tier now scales to tens of thousands of pushes/day.
