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
   ```
   There is no `ADMIN_SECRET`: the relay has no admin API. See
   [Managing keys](#managing-keys).
4. Deploy:
   ```sh
   npx wrangler deploy
   ```

## Self-registration (no maintainer involvement)

**Off by default.** `/register` is an unauthenticated key-minting endpoint, so it
stays closed until you set `REGISTRATION_ENABLED = "true"` in `wrangler.toml` and
redeploy. The shipped `wrangler.toml.example` leaves it `"false"`. There is no
admin endpoint to mint keys with instead — with registration closed, the relay
issues no keys at all, which is the point of the default.

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
registering IP bucket) in the stored record, so you can audit and revoke abusers
— see [Managing keys](#managing-keys). Abuse is further bounded by the per-IP
`REGISTER_RATE_LIMITER`, the per-key send limit, and the `REGISTRATION_ENABLED =
"false"` kill-switch.

## Managing keys

There is no admin API, and no admin credential. The relay used to serve
`/admin/keys` (mint, list, revoke) behind a bearer secret, and nothing called it
— the Go server uses `/register` and `/send`, the apps never touch the relay,
and the endpoints existed so the maintainer could curl them. That made the
highest-value credential in the deployment permanently guessable by anyone who
found the hostname, to save the CLI commands below. The routes are gone.

Everything lives in the `API_KEYS` KV namespace under three prefixes: `key:<sha256
of the raw key>` holds the record, `keyid:<id>` maps an id to that hash, and
`ipkey:<bucket>` remembers which key an IP bucket currently holds.

```sh
NS=<your API_KEYS namespace id>       # from wrangler.toml

# who has a key
npx wrangler kv key list --namespace-id $NS --prefix "key:"
npx wrangler kv key get  --namespace-id $NS "key:<hash>"
# -> {"id":"…","label":"alice-server","enabled":true,"createdAt":"…",
#     "expiresAt":null,"source":"self","registeredIp":"203.0.113.7"}

# revoke one, by the id in that record
HASH=$(npx wrangler kv key get --namespace-id $NS "keyid:<id>")
npx wrangler kv key delete --namespace-id $NS "key:$HASH"
npx wrangler kv key delete --namespace-id $NS "keyid:<id>"
npx wrangler kv key delete --namespace-id $NS "ipkey:<registeredIp>"   # if it still names this id
```

Deleting the record is what revokes the key: `/send` looks the presented key up
by hash on every request. It also releases that key's device-token claims for
re-claiming, because a claim is only protected while its owner's key is still
active — so the self-hoster can re-register and their devices come back.

Send counts and last-seen are not in KV at all; they are in Analytics Engine
(see [Usage](#usage)).

## Endpoints

| Method | Path              | Auth                   | Purpose                          |
| ------ | ----------------- | ---------------------- | -------------------------------- |
| GET    | `/health`         | none                   | Liveness + whether configured    |
| POST   | `/register`       | none                   | Self-issue a per-server key      |
| POST   | `/send`           | Bearer per-server key  | Deliver one push                 |

Three routes, and that is the entire surface — anything else is `404`, including
the `/admin/keys` endpoints that used to be here.

`POST /send` body:

```json
{ "token": "<FCM registration token>", "title": "…", "body": "…", "data": { "url": "/read" }, "platform": "android" }
```

Responses: `200 {"ok":true}` on delivery; `403` when the token is already
claimed by a different active key (see Token pinning below); `410 {"stale":true}`
when the token is no longer registered (the Go server then removes the
device); `401` for a bad or expired key; `413` when the body exceeds 16 KiB;
`400` for a malformed one; `429` when the per-key rate limit is exceeded (body
has `"window":"minute"` and a `Retry-After` header); `502 {"error":"push
delivery failed"}` for every other upstream FCM error. Error bodies include a
`requestId` that matches the `X-Request-Id` response header and the structured
logs.

The `502` is deliberately coarse. FCM's own error text describes *this relay's*
Firebase project, service account, and quota state, so it stays in the operator
logs (as a bare status code) instead of being handed to every key holder.
Quote the `requestId` when you need the operator to look one up.

Body limits, applied before the payload reaches FCM:

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

## Rate limiting

Each key is capped by a **per-minute** limit on `/send`, enforced by the native
`PUSH_RATE_LIMITER` binding in `wrangler.toml` (`simple = { limit = 10, period =
60 }`) — a fixed 60s window with **no KV writes**. Change the limit there and
redeploy. `RATE_LIMIT_PER_MINUTE` in `[vars]` is display-only (`/health` + the
429 body) and should be kept equal to `simple.limit`. Exceeding it returns `429`
with `{"error":"rate limit exceeded","window":"minute","limit":10,"retryAfterSeconds":60}`.

> **Rolling hour/day limits were removed.** They required a KV
> read-modify-write on every accepted send, which capped the free tier at
> ~1,000 pushes/day. Dropping them keeps an accepted send at **zero KV writes**.
> The day tier came back as `RELAY_DAILY_BUDGET` below, built the way that note
> prescribed: a Durable Object counter rather than a KV read-modify-write.

### `RELAY_DAILY_BUDGET` — the daily ceiling

**Set this if you open `REGISTRATION_ENABLED`.** The per-minute limiter buckets
per key, and registration mints keys on demand — so a caller who wants a second
bucket registers a second key from a second address. The minute limit bounds how
fast one caller sends and **nothing at all** about what the relay spends against
your Firebase quota in a day. `RELAY_DAILY_BUDGET` is the only setting that
bounds that number.

Uncomment it in `[vars]` and redeploy:

```toml
RELAY_DAILY_BUDGET = "50000"
```

- **Aggregate, not per-key** — one shared pool across every key. Per-key would
  mean an actor who wants more headroom just registers another key. It is not
  guarding a provider bill: FCM and APNs are free, and their quotas are
  send-rate limits. It guards your Cloudflare account, whose per-day KV and
  Durable Object limits this counter cannot see — so set it below them.
- **Unset = unmetered**, so an existing deployment that never configures it is
  unaffected. `"0"` is a real limit of zero (a closed relay), not "unset".
- **Per UTC day**, counted by the `RELAY_COORDINATOR` Durable Object that
  `/send` and `/register` already require — no extra binding to create.
- **Fails closed** when configured but uncountable: once a budget exists it is
  the only thing bounding daily volume, so a drifted binding refuses rather than
  waves sends through.

Exhausting it returns `429` with
`{"error":"relay daily budget exhausted","window":"day","limit":50000,"retryAfterSeconds":...}`
and a `Retry-After` header counting down to UTC midnight. Unlike the per-minute
limit, the budget is not surfaced on `/health` — a public endpoint should not
report how much of the relay's daily capacity is left. Watch the
`budget.exhausted` log event instead.

`POST /register` has its own per-IP limiter (`REGISTER_RATE_LIMITER`), bucketed
on the IPv6 /64 so one allocation can't rotate addresses past it.

Both fail **closed**: a missing binding refuses the request rather than waving it
through, because "misconfigured" and "absent" are indistinguishable from outside
and the failure mode of guessing is an open relay.

## Usage

Each accepted send writes one data point to the `USAGE_ANALYTICS` Analytics
Engine dataset (`kypost_push_usage`) — off the KV write path — with the key id,
label, and source. Query totals and last-seen per key via the Analytics Engine
SQL API, e.g.:

```sql
SELECT blob1 AS key_id, sum(_sample_interval * double1) AS sends, max(timestamp) AS last_seen
FROM kypost_push_usage GROUP BY key_id ORDER BY sends DESC
```

Usage counts and `lastUsedAt` are not in KV, so the key records you read with
`wrangler kv key get` don't carry them — this is the only place they live.

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
